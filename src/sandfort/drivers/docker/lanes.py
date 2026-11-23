"""Lane runner for blocking docker-py calls (docs/driver-offload-design.md, section "Lanes").

Two limiters share one thread budget. The total limiter bounds every worker thread of the
docker driver; the bulk limiter is nested inside it and is always smaller, so at least
``total - bulk`` tokens can never be taken by bulk calls. A call takes its tokens in a fixed
order, bulk then total, and a worker thread never submits to a lane, so the order cannot
deadlock.

Cancellation contract (design section "Cancellation contract"): the token lives as long as
the thread. The call runs as its own task, started through ``anyio.to_thread.run_sync``
against a private unbounded limiter, and the caller awaits that task through
``asyncio.shield``. A cancelled caller (anyio scope or native ``Task.cancel()``) gets its
``CancelledError`` at once, the docker operation runs on to completion under its held
tokens, and a done-callback on the task frees them. A failure after cancellation is logged
once at warning level and never raised; a caller that was not cancelled receives the
worker's own exception object. Nothing here interrupts a blocked docker-py call.

Shutdown (design section "Shutdown"): ``close_lanes`` makes every new call, and every call that
was still queued for its tokens, fail with ``DriverError``; ``drain`` waits for the borrowed
tokens to reach zero. ``configure_thread_limit`` (run by each new driver) reopens the lanes.
"""

import asyncio
import contextlib
import functools
import logging
import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import anyio
import anyio.lowlevel
import anyio.to_thread

from sandfort.drivers.errors import DriverError

logger = logging.getLogger(__name__)

DEFAULT_THREAD_LIMIT = 64
DEFAULT_BULK_THREADS = 48
CLOSE_TIMEOUT_S = 10.0  # how long a closing driver waits for running calls to return
CLOSE_POLL_S = 0.05
CLOSED_MESSAGE = "docker driver is closed"


@dataclass(frozen=True)
class _Lanes:
    """The process-wide limiters; replaced as a whole by ``configure_thread_limit``."""

    total: anyio.CapacityLimiter
    bulk: anyio.CapacityLimiter
    threads: anyio.CapacityLimiter  # private and unbounded: only the held tokens bound threads


_lanes: _Lanes | None = None
_closed = False  # set by ``close_lanes``; a later ``configure_thread_limit`` reopens the lanes
_inflight: set[asyncio.Task[Any]] = set()  # strong references until each thread has returned


def effective_bulk_threads(total: int, bulk: int) -> int:
    """Ceiling of the bulk lane: ``min(bulk, max(total - 1, 1))``."""
    return min(bulk, max(total - 1, 1))


def configure_thread_limit(
    limit: int = DEFAULT_THREAD_LIMIT, bulk: int = DEFAULT_BULK_THREADS
) -> None:
    """Size the lanes and open them; the sizes are kept when they are already these."""
    global _lanes, _closed
    if limit < 1:
        raise ValueError("docker thread limit must be at least 1")
    if bulk < 1:
        raise ValueError("docker bulk threads must be at least 1")
    _closed = False  # a driver built after a close starts with open lanes
    ceiling = effective_bulk_threads(limit, bulk)
    current = _lanes
    if (
        current is not None
        and current.total.total_tokens == limit
        and current.bulk.total_tokens == ceiling
    ):
        return
    _lanes = _Lanes(
        total=anyio.CapacityLimiter(limit),
        bulk=anyio.CapacityLimiter(ceiling),
        threads=anyio.CapacityLimiter(math.inf),
    )


def _get_lanes() -> _Lanes:
    if _lanes is None:
        configure_thread_limit()
    assert _lanes is not None
    return _lanes


def total_limiter() -> anyio.CapacityLimiter:
    """The limiter that bounds every worker thread of the driver."""
    return _get_lanes().total


def bulk_limiter() -> anyio.CapacityLimiter:
    """The limiter of the bulk lane, nested inside the total."""
    return _get_lanes().bulk


def close_lanes() -> None:
    """Refuse every new lane call with ``DriverError``, including calls already queued."""
    global _closed
    _get_lanes()  # configure first: configuring reopens the lanes
    _closed = True


def reopen_lanes() -> None:
    """Clear the closed flag without resizing the lanes (test isolation helper)."""
    global _closed
    _closed = False


def _ensure_open() -> None:
    if _closed:
        raise DriverError(CLOSED_MESSAGE)


async def drain(timeout_s: float | None = None) -> int:
    """Wait until no call holds a token; return how many tokens are still borrowed.

    Polls every ``CLOSE_POLL_S`` for at most ``CLOSE_TIMEOUT_S`` (the default). On timeout the
    count still borrowed is logged at warning level and the caller continues.
    """
    lanes = _get_lanes()
    deadline = time.monotonic() + (CLOSE_TIMEOUT_S if timeout_s is None else timeout_s)
    while True:
        borrowed = lanes.total.borrowed_tokens + lanes.bulk.borrowed_tokens
        if borrowed == 0:
            return 0
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            logger.warning(
                "docker driver closing with calls still running: %d total and %d bulk tokens "
                "still borrowed",
                lanes.total.borrowed_tokens,
                lanes.bulk.borrowed_tokens,
            )
            return borrowed
        await asyncio.sleep(min(CLOSE_POLL_S, remaining))


def _describe(func: Callable[..., Any]) -> str:
    inner = func.func if isinstance(func, functools.partial) else func
    return str(getattr(inner, "__qualname__", repr(inner)))


def _release(held: tuple[anyio.CapacityLimiter, ...], borrower: object) -> None:
    for limiter in reversed(held):
        limiter.release_on_behalf_of(borrower)


async def _acquire(limiter: anyio.CapacityLimiter, borrower: object) -> None:
    try:
        limiter.acquire_on_behalf_of_nowait(borrower)
    except anyio.WouldBlock:
        await limiter.acquire_on_behalf_of(borrower)


async def _acquire_all(limiters: tuple[anyio.CapacityLimiter, ...], borrower: object) -> None:
    """Take the tokens in order; give back everything this borrower may hold on failure."""
    try:
        for limiter in limiters:
            await _acquire(limiter, borrower)
    except BaseException:
        for limiter in reversed(limiters):
            with contextlib.suppress(RuntimeError):  # not held: nothing to give back
                limiter.release_on_behalf_of(borrower)
        raise


class _Flight:
    """Bookkeeping of one call: its held tokens and whether its caller was cancelled."""

    __slots__ = ("abandoned", "borrower", "held", "name", "reported")

    def __init__(
        self, name: str, held: tuple[anyio.CapacityLimiter, ...], borrower: object
    ) -> None:
        self.name = name
        self.held = held
        self.borrower = borrower
        self.abandoned = False
        self.reported = False

    def on_done(self, task: asyncio.Task[Any]) -> None:
        """Done-callback of the call's task: the thread has returned, so free the tokens."""
        _inflight.discard(task)
        try:
            if self.abandoned:
                self.report(task)
        finally:
            _release(self.held, self.borrower)

    def on_caller_cancelled(self, task: asyncio.Task[Any]) -> None:
        """The caller was cancelled; if the call already ended, report its failure now."""
        self.abandoned = True
        if task.done():
            self.report(task)

    def report(self, task: asyncio.Task[Any]) -> None:
        """Log a failure nobody can receive any more, exactly once; drop a success."""
        if self.reported or task.cancelled():
            return
        self.reported = True
        exc = task.exception()
        if exc is not None:
            logger.warning(
                "docker call %s failed after its caller was cancelled", self.name, exc_info=exc
            )


async def _in_thread[T](call: Callable[[], T], threads: anyio.CapacityLimiter) -> T:
    return await anyio.to_thread.run_sync(call, limiter=threads)


async def _run[T](
    limiters: tuple[anyio.CapacityLimiter, ...],
    threads: anyio.CapacityLimiter,
    func: Callable[..., T],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> T:
    await anyio.lowlevel.checkpoint_if_cancelled()  # a cancelled caller starts no thread
    _ensure_open()
    borrower = object()
    await _acquire_all(limiters, borrower)
    if _closed:  # the driver closed while this call was queued for its tokens
        _release(limiters, borrower)
        raise DriverError(CLOSED_MESSAGE)
    flight = _Flight(_describe(func), limiters, borrower)
    try:
        task = asyncio.get_running_loop().create_task(
            _in_thread(functools.partial(func, *args, **kwargs), threads)
        )
    except BaseException:
        _release(limiters, borrower)
        raise
    _inflight.add(task)
    outer = asyncio.shield(task)
    task.add_done_callback(flight.on_done)
    try:
        return await outer
    except asyncio.CancelledError:
        if outer.done() and not outer.cancelled():
            outer.exception()  # nobody will read it; the flight reports it instead
        flight.on_caller_cancelled(task)
        raise


async def run_blocking[T](func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Control lane: run a blocking docker-py call in a thread under one total token."""
    lanes = _get_lanes()
    return await _run((lanes.total,), lanes.threads, func, args, kwargs)


async def run_bulk[T](func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Bulk lane: like ``run_blocking`` but takes a bulk token first, then a total token."""
    lanes = _get_lanes()
    return await _run((lanes.bulk, lanes.total), lanes.threads, func, args, kwargs)
