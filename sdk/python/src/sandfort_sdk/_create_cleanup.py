"""Helpers of ``create_sandbox`` shared by the sync and async clients.

The request body builders, the readiness and poll-window rules of the wait for ``started``
under the one deadline of a blocking create, and the cleanup after a create request timed
out: it deletes the sandbox found under the name only when the name was free just before the
request and the sandbox found was created no earlier than the moment just before the request
(less :data:`CLOCK_SKEW_ALLOWANCE_S`). A sandbox that held the name before, or whose age
cannot be told, is left alone and a warning names it. The I/O helpers take the client's
``get`` and ``delete`` as callables (sync and ``a``-prefixed async variants).
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Protocol

import httpx

from sandfort_sdk.exceptions import (
    NotFound,
    RequestTimedOut,
    SandboxDestroyedError,
    SandboxFailedError,
    SandboxTimeoutError,
    SandfortSDKError,
    TransportError,
)
from sandfort_sdk.models import Resources, SandboxInfo

if TYPE_CHECKING:
    from sandfort_sdk.volumes import VolumeMount

logger = logging.getLogger(__name__)


class _Handle(Protocol):
    """What ``get`` returns: a sandbox handle with its record."""

    @property
    def info(self) -> SandboxInfo: ...


STATE_STARTED = "started"
STATE_DESTROYED = "destroyed"
UNREACHABLE_STATES = frozenset({"error", "destroying", STATE_DESTROYED})
MAX_LONG_POLL_S = 30.0  # server caps ``timeout_s`` at 60
# How far the server clock may run behind ours when a sandbox's ``created_at`` is compared
# with the moment just before the create request.
CLOCK_SKEW_ALLOWANCE_S = 60.0
# A long poll asks the server to answer this much before the deadline, so its answer is not
# raced by the HTTP timeout of the same request (which ends at the deadline).
LONG_POLL_HEADROOM_S = 1.0
# Floor of the timeout of the first attempt when the budget is already spent (a zero budget
# still sends the request, so the timeout error can name what it made).
MIN_ATTEMPT_TIMEOUT_S = 0.001


@dataclass(frozen=True)
class NameCheck:
    """What a by-name lookup said just before the create request.

    ``free`` is True only when the lookup answered :class:`NotFound`; ``holder`` is the id of
    the live sandbox that already had the name (``None`` when free or unknown).
    """

    name: str
    free: bool
    holder: str | None = None


@dataclass(frozen=True)
class CreateClock:
    """The one deadline of a blocking create, started just before its request is sent.

    ``deadline`` is a ``time.monotonic()`` value; ``posted_after`` is the wall clock at the
    same moment, for the comparison with a found sandbox's ``created_at``.
    """

    deadline: float
    posted_after: datetime

    @classmethod
    def start(cls, wait_timeout_s: float, now_monotonic: float) -> "CreateClock":
        return cls(now_monotonic + wait_timeout_s, datetime.now(UTC))


def may_have_been_sent(outcome: httpx.Response | httpx.HTTPError) -> bool:
    """False only for an attempt that cannot have been written: a connect or pool timeout."""
    return not isinstance(outcome, httpx.ConnectTimeout | httpx.PoolTimeout)


def deadline_timeout(deadline: float, now: float) -> httpx.Timeout:
    """The timeout of one attempt: connect, write, read and pool each at most the time left."""
    left = max(deadline - now, MIN_ATTEMPT_TIMEOUT_S)
    return httpx.Timeout(connect=left, read=left, write=left, pool=left)


def transport_error(
    method: str, path: str, exc: httpx.HTTPError, *, sent: bool, expired: bool = False
) -> TransportError:
    """A timeout (or any failure once the deadline ``expired``) is a :class:`RequestTimedOut`."""
    message = f"{method} {path} failed: {type(exc).__name__}: {exc}"
    if not (expired or isinstance(exc, httpx.TimeoutException)):
        return TransportError(message)
    return RequestTimedOut(message, request_sent=sent)


class CallAttempts:
    """The attempts of one transport call: the time left for each and whether any was sent.

    ``sent`` is True once any attempt may have left the client, so a timeout ending a later
    attempt (a connect or pool timeout after a lost connection) still says the request may
    have reached the server. With a ``deadline`` (monotonic) every attempt gets a timeout of
    the time left, none starts after it, and a failure after it is a timeout.
    """

    def __init__(self, method: str, path: str, deadline: float | None) -> None:
        self._method = method
        self._path = path
        self._deadline = deadline
        self._made = 0
        self.sent = False

    def timeout(self, default: float, now: float) -> httpx.Timeout | float:
        """The timeout of the next attempt.

        Raises :class:`RequestTimedOut` when the deadline has passed and an attempt was already
        made; the first attempt always goes out (with at least :data:`MIN_ATTEMPT_TIMEOUT_S`).
        """
        if self._deadline is None:
            return default
        if now >= self._deadline and self._made:
            raise RequestTimedOut(
                f"{self._method} {self._path} failed: the deadline passed", request_sent=self.sent
            )
        return deadline_timeout(self._deadline, now)

    def record(self, outcome: httpx.Response | httpx.HTTPError) -> None:
        self._made += 1
        self.sent = self.sent or may_have_been_sent(outcome)

    def error(self, exc: httpx.HTTPError, now: float) -> TransportError:
        expired = self._deadline is not None and now >= self._deadline
        return transport_error(self._method, self._path, exc, sent=self.sent, expired=expired)


def cleanup_applies(wait: bool, delete_on_failure: bool, name: str | None) -> bool:
    """True when a create timeout may lead to a by-name delete, so the name is checked first."""
    return wait and delete_on_failure and bool(name)


def log_left_alone(check: NameCheck) -> None:
    """Warn that no sandbox is deleted because the name was not known to be free before."""
    if check.holder is not None:
        logger.warning(
            "leaving sandbox %s ('%s') alone after a create timeout: it had the name "
            "before this create",
            check.holder,
            check.name,
        )
        return
    logger.warning(
        "deleting no sandbox named '%s' after a create timeout: the name could not be "
        "checked before this create",
        check.name,
    )


def made_by_this_create(found: SandboxInfo, posted_after: datetime) -> bool:
    """True when ``found`` was created no earlier than ``posted_after`` less the skew allowance.

    False (with a warning naming the sandbox) when it is older or reports no ``created_at``
    (an older server; the warning then says how to delete it by hand).
    """
    created = found.created_at
    if created is not None and created.tzinfo is None:
        created = created.replace(tzinfo=UTC)
    earliest = posted_after - timedelta(seconds=CLOCK_SKEW_ALLOWANCE_S)
    if created is not None and created >= earliest:
        return True
    if created is None:
        logger.warning(
            "leaving sandbox %s ('%s') alone after a create timeout: the server did not "
            "report created_at, so it cannot be told whether this create made it; if it "
            "did, delete it with `sandfort sandbox rm %s` or Client.delete('%s')",
            found.id,
            found.name,
            found.id,
            found.id,
        )
        return False
    logger.warning(
        "leaving sandbox %s ('%s') alone after a create timeout: it was created at %s, "
        "not by this create",
        found.id,
        found.name,
        created.isoformat(),
    )
    return False


def _checked(name: str, holder: str) -> NameCheck:
    return NameCheck(name, free=False, holder=holder)


def _unchecked(name: str) -> NameCheck:
    logger.warning("cannot check the name '%s' before the create", name, exc_info=True)
    return NameCheck(name, free=False)


def _cannot_delete(name: str) -> None:
    logger.warning("cannot delete sandbox '%s' after a create timeout", name, exc_info=True)


def check_name(name: str, get: Callable[[str], _Handle]) -> NameCheck:
    """Whether ``name`` is free before the create: only :class:`NotFound` says it is.

    Any other error (of any kind: the probe must never stop the create) means unknown.
    """
    try:
        return _checked(name, get(name).info.id)
    except NotFound:
        return NameCheck(name, free=True)
    except Exception:
        return _unchecked(name)


async def acheck_name(name: str, get: Callable[[str], Awaitable[_Handle]]) -> NameCheck:
    """Async :func:`check_name`."""
    try:
        return _checked(name, (await get(name)).info.id)
    except NotFound:
        return NameCheck(name, free=True)
    except Exception:
        return _unchecked(name)


def delete_after_timeout(
    check: NameCheck | None,
    posted_after: datetime,
    get: Callable[[str], _Handle],
    delete: Callable[[str], object],
) -> str | None:
    """One best-effort delete of the sandbox a timed-out create made, never another one.

    Returns the id of the sandbox deleted; ``None`` when nothing was (no ``check``: no cleanup
    applies or no attempt was sent; the name was held before or not checked; nothing found
    under it; its age is unknown or older; or the lookup or the delete failed).
    """
    if check is None:
        return None
    if not check.free:
        log_left_alone(check)
        return None
    try:
        found = get(check.name).info
        if not made_by_this_create(found, posted_after):
            return None
        delete(found.id)
    except SandfortSDKError:
        _cannot_delete(check.name)
        return None
    return found.id


async def adelete_after_timeout(
    check: NameCheck | None,
    posted_after: datetime,
    get: Callable[[str], Awaitable[_Handle]],
    delete: Callable[[str], Awaitable[object]],
) -> str | None:
    """Async :func:`delete_after_timeout`; the id of the sandbox deleted, or ``None``."""
    if check is None:
        return None
    if not check.free:
        log_left_alone(check)
        return None
    try:
        found = (await get(check.name)).info
        if not made_by_this_create(found, posted_after):
            return None
        await delete(found.id)
    except SandfortSDKError:
        _cannot_delete(check.name)
        return None
    return found.id


async def finish_tasks(tasks: set[asyncio.Task[Any]], wait_s: float) -> None:
    """Wait up to ``wait_s`` for ``tasks`` (a live set: finishing ones may add more)."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + wait_s
    while tasks:
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        await asyncio.wait(set(tasks), timeout=remaining)
    if tasks:
        logger.warning("closing the client with %d cancellation cleanup(s) unfinished", len(tasks))


def is_ready(info: SandboxInfo) -> bool:
    """True once started; raise if the sandbox can never start.

    A ``destroyed`` sandbox (e.g. a keyed create replayed after the delete) raises
    :class:`SandboxDestroyedError`; ``error`` and ``destroying`` raise ``SandboxFailedError``.
    """
    if info.state == STATE_STARTED:
        return True
    if info.state in UNREACHABLE_STATES:
        reason = f": {info.error_reason}" if info.error_reason else ""
        failure = SandboxDestroyedError if info.state == STATE_DESTROYED else SandboxFailedError
        raise failure(
            f"sandbox {info.id} is {info.state}{reason}",
            sandbox_id=info.id,
            state=info.state,
            error_reason=info.error_reason,
            error_code=info.error_code,
        )
    return False


def wait_expired(info: SandboxInfo) -> SandboxTimeoutError:
    """The error of a wait for ``started`` that ran out of time, naming the sandbox."""
    return SandboxTimeoutError(
        f"sandbox {info.id} still {info.state} after the wait budget elapsed",
        sandbox_id=info.id,
        state=info.state,
    )


def poll_budget(info: SandboxInfo, deadline: float, now: float) -> float:
    """Seconds the next long-poll may wait; raise once the deadline has passed."""
    remaining = deadline - now
    if remaining <= 0:
        raise wait_expired(info)
    return min(remaining, MAX_LONG_POLL_S)


def poll_window(info: SandboxInfo, deadline: float, now: float) -> float:
    """The long-poll ``timeout_s``: the time left less :data:`LONG_POLL_HEADROOM_S` (>= 0).

    Raises :class:`SandboxTimeoutError` once the deadline has passed.
    """
    budget = poll_budget(info, deadline, now)
    return max(0.0, min(budget, deadline - now - LONG_POLL_HEADROOM_S))


def poll_pause(deadline: float, now: float, poll_interval_s: float) -> float:
    """The pause between two polls, never past the deadline."""
    return max(0.0, min(poll_interval_s, deadline - now))


def create_body(
    *,
    name: str | None,
    snapshot: str | None,
    resources: Resources | None,
    env: dict[str, str] | None,
    labels: dict[str, str] | None,
    block_network: bool | None,
    auto_stop_minutes: int | None,
    auto_delete_minutes: int | None,
    public: bool | None,
    mounts: Sequence["VolumeMount | Sequence[str]"] | None = None,
    egress_allowlist: Sequence[str] | None = None,
    isolation: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": name,
        "snapshot": snapshot,
        "resources": None if resources is None else resources.to_payload(),
        "env": env,
        "labels": labels,
        "network": None if block_network is None else {"block_all": block_network},
        "auto_stop_minutes": auto_stop_minutes,
        "auto_delete_minutes": auto_delete_minutes,
        "public": public,
        "volumes": None if mounts is None else mounts_payload(mounts),
        "egress_allowlist": None if egress_allowlist is None else list(egress_allowlist),
        "isolation": isolation,
    }
    return {key: value for key, value in body.items() if value is not None}


def mounts_payload(mounts: Sequence["VolumeMount | Sequence[str]"]) -> list[dict[str, Any]]:
    """The ``volumes`` wire list: :func:`sandfort_sdk.volumes.mounts_wire`, the one helper.

    Imported on call: the volumes module imports the request helpers, which import this one.
    """
    from sandfort_sdk.volumes import mounts_wire

    return mounts_wire(mounts)
