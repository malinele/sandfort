"""The docker lane runner (offload design, slice 2): token lifetime, cancellation, clamps.

No docker daemon: the "docker calls" are functions that park in a worker thread on a
``threading.Event`` (a ``Gate``) until the test opens it. The limiters are the real ones, so
``borrowed_tokens`` shows exactly when a token is held.
"""

import asyncio
import gc
import logging
import socket
import threading
import time
from collections.abc import Awaitable, Callable, Iterator
from typing import Any

import anyio
import pytest

import sandfort.drivers.docker.client as docker_client
from sandfort.config import Settings
from sandfort.drivers.docker import lanes
from sandfort.drivers.docker.driver import DockerDriver
from sandfort.drivers.docker.exec import _Pump

THREAD_LIMIT_ENV = "SANDFORT_DOCKER_THREAD_LIMIT"
BULK_THREADS_ENV = "SANDFORT_DOCKER_BULK_THREADS"

WAIT_S = 5.0  # generous upper bound for anything that must happen
POLL_S = 0.005
SETTLE_S = 0.05  # long enough for a wrongly started thread or a wrong release to show up
CONTROL_DEADLINE_S = 1.0
THREAD_TIMEOUT_S = 10.0  # a gate nobody opens frees its thread after this

Runner = Callable[..., Awaitable[Any]]


class Gate:
    """A blocking call: its thread parks until ``release``, then returns or raises."""

    def __init__(self) -> None:
        self.started = threading.Event()
        self._open = threading.Event()

    def call(self, fail: BaseException | None = None) -> str:
        self.started.set()
        if not self._open.wait(THREAD_TIMEOUT_S):
            raise TimeoutError("gate was never released")
        if fail is not None:
            raise fail
        return "done"

    def release(self) -> None:
        self._open.set()


@pytest.fixture(autouse=True)
def default_lanes() -> Iterator[None]:
    lanes.configure_thread_limit()
    yield
    lanes.configure_thread_limit()


@pytest.fixture
def gates() -> Iterator[Callable[[], Gate]]:
    made: list[Gate] = []

    def make() -> Gate:
        gate = Gate()
        made.append(gate)
        return gate

    yield make
    for gate in made:
        gate.release()


@pytest.fixture(params=["control", "bulk"])
def run(request: pytest.FixtureRequest) -> Runner:
    return lanes.run_blocking if request.param == "control" else lanes.run_bulk


@pytest.fixture
def lane_log() -> Iterator[list[logging.LogRecord]]:
    records: list[logging.LogRecord] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = Capture(level=logging.WARNING)
    previous_level = lanes.logger.level
    lanes.logger.setLevel(logging.WARNING)
    lanes.logger.addHandler(handler)
    yield records
    lanes.logger.removeHandler(handler)
    lanes.logger.setLevel(previous_level)


async def wait_for(predicate: Callable[[], bool], what: str) -> None:
    deadline = time.monotonic() + WAIT_S
    while not predicate():
        assert time.monotonic() < deadline, f"timed out waiting for {what}"
        await asyncio.sleep(POLL_S)


def borrowed() -> tuple[int, int]:
    """Borrowed tokens as ``(bulk, total)``."""
    return lanes.bulk_limiter().borrowed_tokens, lanes.total_limiter().borrowed_tokens


def waiting() -> int:
    """Callers queued on either limiter."""
    bulk, total = lanes.bulk_limiter(), lanes.total_limiter()
    return bulk.statistics().tasks_waiting + total.statistics().tasks_waiting


async def wait_until_idle() -> None:
    await wait_for(lambda: borrowed() == (0, 0), "every token to be freed")


async def start(run: Runner, gate: Gate, **kwargs: Any) -> asyncio.Task[Any]:
    """Run ``gate.call`` through ``run`` as a task and wait until its thread is parked."""
    task = asyncio.create_task(run(gate.call, **kwargs))
    await wait_for(gate.started.is_set, "the worker thread to start")
    return task


async def test_native_cancel_keeps_tokens_until_the_thread_returns(
    run: Runner, gates: Callable[[], Gate]
) -> None:
    gate = gates()
    task = await start(run, gate)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    await asyncio.sleep(SETTLE_S)
    assert lanes.total_limiter().borrowed_tokens == 1  # the thread still runs
    gate.release()
    await wait_until_idle()


async def test_anyio_scope_cancel_returns_at_once_and_keeps_tokens(
    run: Runner, gates: Callable[[], Gate]
) -> None:
    gate = gates()
    started_at = time.monotonic()
    with anyio.move_on_after(SETTLE_S) as scope:
        await run(gate.call)
    elapsed = time.monotonic() - started_at

    assert scope.cancelled_caught
    assert elapsed < WAIT_S  # the caller did not wait for the parked thread
    await wait_for(gate.started.is_set, "the worker thread to start")
    assert lanes.total_limiter().borrowed_tokens == 1
    gate.release()
    await wait_until_idle()


async def test_cancelled_callers_cannot_push_threads_past_the_total(
    gates: Callable[[], Gate],
) -> None:
    lanes.configure_thread_limit(2, 1)
    parked = [gates(), gates()]
    tasks = [await start(lanes.run_blocking, gate) for gate in parked]
    for task in tasks:
        task.cancel()
    outcomes = await asyncio.gather(*tasks, return_exceptions=True)
    assert all(isinstance(outcome, asyncio.CancelledError) for outcome in outcomes)

    third = gates()
    third_task = asyncio.create_task(lanes.run_blocking(third.call))
    await asyncio.sleep(SETTLE_S)
    assert not third.started.is_set()  # both threads still run, so no token is free
    assert lanes.total_limiter().borrowed_tokens == 2

    parked[0].release()
    await wait_for(third.started.is_set, "the third call to get the freed token")
    parked[1].release()
    third.release()
    assert await third_task == "done"
    await wait_until_idle()


async def test_a_caller_cancelled_before_the_call_starts_no_thread() -> None:
    ran = threading.Event()
    with anyio.CancelScope() as scope:
        scope.cancel()
        await lanes.run_blocking(ran.set)
    await asyncio.sleep(SETTLE_S)
    assert not ran.is_set()
    assert borrowed() == (0, 0)


async def test_cancel_while_queued_for_a_token_leaks_nothing(
    run: Runner, gates: Callable[[], Gate]
) -> None:
    lanes.configure_thread_limit(1, 1)
    holder = gates()
    held = await start(run, holder)
    ran = threading.Event()
    queued = asyncio.create_task(run(ran.set))
    await wait_for(lambda: waiting() == 1, "the second call to queue for a token")

    queued.cancel()
    with pytest.raises(asyncio.CancelledError):
        await queued

    holder.release()
    assert await held == "done"
    await wait_until_idle()
    assert not ran.is_set()


async def test_cancel_while_waiting_for_the_total_gives_the_bulk_token_back(
    gates: Callable[[], Gate],
) -> None:
    lanes.configure_thread_limit(2, 1)
    control = [gates(), gates()]
    control_tasks = [await start(lanes.run_blocking, gate) for gate in control]
    ran = threading.Event()
    queued = asyncio.create_task(lanes.run_bulk(ran.set))
    await wait_for(lambda: lanes.bulk_limiter().borrowed_tokens == 1, "the bulk token")

    queued.cancel()
    with pytest.raises(asyncio.CancelledError):
        await queued

    assert lanes.bulk_limiter().borrowed_tokens == 0
    for gate in control:
        gate.release()
    await asyncio.gather(*control_tasks)
    await wait_until_idle()
    assert not ran.is_set()


async def test_failure_after_cancel_is_logged_once_and_not_raised(
    run: Runner, gates: Callable[[], Gate], lane_log: list[logging.LogRecord]
) -> None:
    boom = RuntimeError("daemon went away")
    unhandled: list[dict[str, Any]] = []
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(lambda _loop, context: unhandled.append(context))
    try:
        gate = gates()
        task = await start(run, gate, fail=boom)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert lane_log == []  # nothing has failed yet

        gate.release()
        await wait_until_idle()
        await asyncio.sleep(SETTLE_S)
        gc.collect()  # an unretrieved task exception is reported when the task is collected
    finally:
        loop.set_exception_handler(None)

    assert len(lane_log) == 1
    record = lane_log[0]
    assert record.levelno == logging.WARNING
    assert "Gate.call" in record.getMessage()
    assert record.exc_info is not None
    assert record.exc_info[1] is boom
    assert unhandled == []


async def test_success_after_cancel_is_dropped_silently(
    run: Runner, gates: Callable[[], Gate], lane_log: list[logging.LogRecord]
) -> None:
    gate = gates()
    task = await start(run, gate)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    gate.release()
    await wait_until_idle()
    await asyncio.sleep(SETTLE_S)
    assert lane_log == []


async def test_awaiter_receives_the_workers_exception_object(
    run: Runner, lane_log: list[logging.LogRecord]
) -> None:
    error = ValueError("the worker's own object")

    def fail() -> None:
        raise error

    with pytest.raises(ValueError) as caught:
        await run(fail)

    assert caught.value is error
    await wait_until_idle()
    assert lane_log == []  # the caller saw it, so it is not logged


@pytest.mark.parametrize(("lane", "held"), [("run_blocking", (0, 1)), ("run_bulk", (1, 1))])
async def test_each_lane_takes_its_own_tokens(
    lane: str, held: tuple[int, int], gates: Callable[[], Gate]
) -> None:
    gate = gates()
    task = await start(getattr(lanes, lane), gate)
    assert borrowed() == held
    gate.release()
    assert await task == "done"
    await wait_until_idle()


async def test_total_four_with_bulk_three_keeps_one_token_free_for_a_control_call(
    gates: Callable[[], Gate],
) -> None:
    lanes.configure_thread_limit(4, 3)
    parked = [gates(), gates(), gates()]
    bulk_tasks = [await start(lanes.run_bulk, gate) for gate in parked]
    fourth = gates()
    queued = asyncio.create_task(lanes.run_bulk(fourth.call))
    await asyncio.sleep(SETTLE_S)
    assert not fourth.started.is_set()  # the bulk lane is full
    assert borrowed() == (3, 3)  # a queued bulk call holds no total token

    result = await asyncio.wait_for(lanes.run_blocking(lambda: "control"), CONTROL_DEADLINE_S)

    assert result == "control"
    for gate in [*parked, fourth]:
        gate.release()
    await asyncio.gather(*bulk_tasks, queued)
    await wait_until_idle()


@pytest.mark.parametrize(
    ("total", "bulk", "effective"),
    [
        (64, 48, 48),  # the defaults
        (64, 100, 63),  # never the whole total
        (4, 3, 3),
        (4, 4, 3),
        (2, 48, 1),
        (1, 48, 1),  # degrades to one shared token
        (1, 1, 1),
    ],
)
def test_bulk_ceiling_is_min_of_setting_and_total_minus_one_but_at_least_one(
    total: int, bulk: int, effective: int
) -> None:
    assert lanes.effective_bulk_threads(total, bulk) == effective
    lanes.configure_thread_limit(total, bulk)
    assert lanes.total_limiter().total_tokens == total
    assert lanes.bulk_limiter().total_tokens == effective


@pytest.mark.parametrize(("total", "bulk"), [(0, 1), (-1, 1), (4, 0), (4, -3)])
def test_invalid_sizes_are_rejected_and_keep_the_current_lanes(total: int, bulk: int) -> None:
    lanes.configure_thread_limit(4, 3)
    with pytest.raises(ValueError):
        lanes.configure_thread_limit(total, bulk)
    assert lanes.total_limiter().total_tokens == 4
    assert lanes.bulk_limiter().total_tokens == 3


def test_configure_keeps_the_limiters_when_the_effective_sizes_do_not_change() -> None:
    lanes.configure_thread_limit(8, 100)  # the bulk ceiling clamps to 7
    total, bulk = lanes.total_limiter(), lanes.bulk_limiter()

    lanes.configure_thread_limit(8, 7)
    assert lanes.total_limiter() is total
    assert lanes.bulk_limiter() is bulk

    lanes.configure_thread_limit(8, 5)
    assert lanes.total_limiter() is not total
    assert lanes.bulk_limiter().total_tokens == 5


async def test_run_bulk_works_when_the_total_is_one() -> None:
    lanes.configure_thread_limit(1, 48)
    call = lanes.run_bulk(lambda a, b=0: a + b, 3, b=4)  # args and kwargs are forwarded
    assert await asyncio.wait_for(call, CONTROL_DEADLINE_S) == 7
    await wait_until_idle()


async def test_client_helpers_delegate_to_the_lane_runner() -> None:
    assert docker_client.run_blocking is lanes.run_blocking
    assert docker_client.DEFAULT_THREAD_LIMIT == lanes.DEFAULT_THREAD_LIMIT == 64
    assert lanes.DEFAULT_BULK_THREADS == 48

    docker_client.configure_thread_limit(6)
    assert docker_client._get_limiter() is lanes.total_limiter()
    assert docker_client._get_limiter().total_tokens == 6
    assert lanes.bulk_limiter().total_tokens == 5


# --- settings (slice 3) -------------------------------------------------------------


def test_settings_defaults_are_64_total_and_48_bulk() -> None:
    for settings in (Settings(), Settings.from_env({})):
        assert settings.docker_thread_limit == 64 == lanes.DEFAULT_THREAD_LIMIT
        assert settings.docker_bulk_threads == 48 == lanes.DEFAULT_BULK_THREADS


def test_settings_read_both_thread_sizes_from_env() -> None:
    settings = Settings.from_env({THREAD_LIMIT_ENV: "32", BULK_THREADS_ENV: "20"})
    assert settings.docker_thread_limit == 32
    assert settings.docker_bulk_threads == 20


def test_settings_keep_the_total_when_only_the_bulk_size_is_given() -> None:
    settings = Settings.from_env({BULK_THREADS_ENV: "5"})
    assert settings.docker_thread_limit == 64
    assert settings.docker_bulk_threads == 5


@pytest.mark.parametrize("raw", ["0", "-1", "-48"])
def test_bulk_threads_below_one_are_rejected(raw: str) -> None:
    with pytest.raises(ValueError, match=f"{BULK_THREADS_ENV} must be at least 1"):
        Settings.from_env({BULK_THREADS_ENV: raw})


@pytest.mark.parametrize("raw", ["many", "", "1.5"])
def test_bulk_threads_that_are_not_an_integer_are_rejected(raw: str) -> None:
    with pytest.raises(ValueError, match=f"{BULK_THREADS_ENV} must be an integer"):
        Settings.from_env({BULK_THREADS_ENV: raw})


@pytest.mark.parametrize(
    ("limit", "bulk", "effective_bulk"),
    [(64, 48, 48), (10, 4, 4), (4, 48, 3), (1, 48, 1)],
)
def test_driver_sizes_both_lanes_from_settings(
    limit: int, bulk: int, effective_bulk: int
) -> None:
    lanes.configure_thread_limit(2, 1)  # a different size, so the driver must resize
    settings = Settings(docker_thread_limit=limit, docker_bulk_threads=bulk)

    DockerDriver(settings, client=object())

    assert lanes.total_limiter().total_tokens == limit
    assert lanes.bulk_limiter().total_tokens == effective_bulk


def test_driver_built_from_default_settings_gets_the_default_lanes() -> None:
    lanes.configure_thread_limit(2, 1)

    DockerDriver(Settings.from_env({}), client=object())

    assert lanes.total_limiter().total_tokens == 64
    assert lanes.bulk_limiter().total_tokens == 48


def test_pump_read_survives_a_closed_descriptor() -> None:
    left, right = socket.socketpair()
    pump = _Pump(left, None)
    left.close()  # select() on a closed descriptor raises ValueError, not OSError
    try:
        assert pump.read(0.01) == b""
    finally:
        right.close()
