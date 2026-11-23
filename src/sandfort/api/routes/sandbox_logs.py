"""``GET /v1/sandboxes/{sandbox_id}/logs``: the sandbox container's logs as server-sent events.

One ``stdout`` / ``stderr`` event per line whose ``id`` is the line's timestamp in unix seconds,
so a client can resume with ``?since=<id>``. Without ``follow`` the stream ends after the tail;
with ``follow`` it stays open and idle periods carry a keepalive comment. Auth, org scoping and
the error envelope match the other sandbox routes: everything that can fail before the first
byte (scope, missing or foreign sandbox, no container) answers with the envelope; a driver
failure mid-stream ends the stream with an ``error`` event. The read is audited once
(``sandbox.logs.read``) when the stream starts, in a unit of work closed before the driver is
called; audit details carry the query, never log content.
"""

import logging
import math
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from pydantic import BeforeValidator
from pydantic_core import PydanticCustomError

from sandfort.api.deps import get_audit_recorder, get_driver, get_uow
from sandfort.api.query_guard import KnownQuery, single_valued
from sandfort.api.sse import DEFAULT_KEEPALIVE_INTERVAL_S, format_event, with_keepalive
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import require_scopes
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.events import ActorType
from sandfort.domain.org import Scope
from sandfort.domain.sandbox import SandboxState
from sandfort.drivers.base import LogEntry, LogsDriver, SandboxDriver
from sandfort.drivers.errors import DriverError, DriverUnsupported
from sandfort.errors import NotFound, no_container_conflict
from sandfort.services.audit import AuditRecorder

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/sandboxes", tags=["sandboxes"])

AUDIT_ACTION = "sandbox.logs.read"
DEFAULT_TAIL = 100
MAX_TAIL = 10_000
KEEPALIVE_INTERVAL_S = DEFAULT_KEEPALIVE_INTERVAL_S
STREAM_FAILED_MESSAGE = "container log stream failed"
# ``since`` must stay below 10000-01-01T00:00:00Z: ``datetime`` ends with year 9999, so a larger
# epoch overflows the conversion. An exclusive bound keeps every value that converts (round 52).
SINCE_LIMIT_S = 253_402_300_800
NOT_FINITE_TYPE = "finite_number"
NOT_FINITE_MESSAGE = "Input should be a finite number of seconds"

_NO_CONTAINER_STATES = frozenset({SandboxState.DESTROYING, SandboxState.DESTROYED})


def _reject_non_finite(value: object) -> object:
    """Refuse NaN and infinities before the bounds read them as out of range (round 54).

    A value that is not a number at all falls through to the usual float parse error.
    """
    if not isinstance(value, str | float):
        return value
    try:
        number = float(value)
    except ValueError:
        return value
    if not math.isfinite(number):
        raise PydanticCustomError(NOT_FINITE_TYPE, NOT_FINITE_MESSAGE)
    return value


# ``Query`` first: its bounds bind to the number (and render as ``minimum``/``exclusiveMaximum``);
# the finite check then wraps the bounded type and runs before them.
Since = Annotated[float | None, Query(ge=0, lt=SINCE_LIMIT_S), BeforeValidator(_reject_non_finite)]
Reader = Annotated[Principal, Depends(require_scopes(Scope.SANDBOXES_READ))]
Uow = Annotated[UnitOfWorkPort, Depends(get_uow)]
Driver = Annotated[SandboxDriver, Depends(get_driver)]
Recorder = Annotated[AuditRecorder, Depends(get_audit_recorder)]
LogsOnce = Annotated[None, Depends(single_valued("follow", "tail", "since"))]


def _logs_driver(driver: SandboxDriver) -> LogsDriver:
    if not isinstance(driver, LogsDriver):
        raise DriverUnsupported(f"the {driver.name} driver does not stream container logs")
    return driver


async def _audited_ref(
    uow: UnitOfWorkPort,
    recorder: AuditRecorder,
    principal: Principal,
    sandbox_id: str,
    details: dict[str, Any],
) -> str:
    """Resolve the sandbox in the caller's org and record the read; return its driver ref."""
    async with uow:
        sandbox = await uow.sandboxes.get(principal.org_id, sandbox_id)
        if sandbox is None:
            raise NotFound(f"sandbox {sandbox_id} not found")
        if sandbox.state in _NO_CONTAINER_STATES or sandbox.driver_ref is None:
            raise no_container_conflict(sandbox.state.value)
        await recorder.record(
            uow,
            org_id=principal.org_id,
            actor_type=ActorType.API_KEY,
            actor_id=principal.key_id,
            action=AUDIT_ACTION,
            target_type="sandbox",
            target_id=sandbox_id,
            details=details,
        )
        await uow.commit()
        return sandbox.driver_ref


def _log_event(entry: LogEntry) -> str:
    seconds = entry.timestamp.timestamp()
    data = {"timestamp": seconds, "stream": entry.stream, "line": entry.line}
    return format_event(data, event=entry.stream, event_id=f"{seconds:.6f}")


async def _log_frames(entries: AsyncIterator[LogEntry], ref: str) -> AsyncIterator[str]:
    try:
        async for entry in entries:
            yield _log_event(entry)
    except DriverError:
        logger.warning("log stream of %s failed", ref, exc_info=True)
        yield format_event({"message": STREAM_FAILED_MESSAGE}, event="error")
    finally:
        aclose = getattr(entries, "aclose", None)
        if aclose is not None:
            await aclose()


@router.get("/{sandbox_id}/logs")
async def stream_sandbox_logs(
    sandbox_id: str,
    principal: Reader,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
    _known: KnownQuery,
    _once: LogsOnce,
    follow: bool = False,
    tail: Annotated[int, Query(ge=0)] = DEFAULT_TAIL,
    since: Since = None,
) -> StreamingResponse:
    logs_driver = _logs_driver(driver)
    lines = min(tail, MAX_TAIL)
    details = {"follow": follow, "tail": lines, "since": since}
    ref = await _audited_ref(uow, recorder, principal, sandbox_id, details)
    await driver.inspect(ref)  # a vanished container answers 404 before the stream starts
    since_at = None if since is None else datetime.fromtimestamp(since, UTC)
    entries = logs_driver.stream_logs(ref, follow=follow, tail=lines, since=since_at)
    frames = with_keepalive(_log_frames(entries, ref), interval_s=KEEPALIVE_INTERVAL_S)
    return StreamingResponse(
        frames,
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
