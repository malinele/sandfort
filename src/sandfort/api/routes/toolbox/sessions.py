"""``/process/sessions``: exec sessions, synchronous and asynchronous commands, logs and kill.

Log events carry exactly one line each (``line`` keeps its ``\\n`` / ``\\r\\n``; ``offset`` is
the byte where it starts). Log follow is a server-sent-event stream (no envelope): one
``stdout`` / ``stderr`` event per line whose ``id`` is the byte offset where the *next* line
starts, so a client reconnecting with ``Last-Event-ID`` (or ``?offset=``) resumes exactly after
the last delivered line, and a final ``exit`` event carrying the exit code. Idle streams emit a
keepalive comment.
"""

import hashlib
from collections.abc import AsyncIterator, Callable
from typing import Annotated, Literal, cast

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from sandfort.api.deps import UOW_FACTORY_ATTR, get_audit_recorder, get_driver
from sandfort.api.envelope import Envelope, ok
from sandfort.api.query_guard import KnownQuery, single_valued
from sandfort.api.routes.toolbox.scope_guard import require_visible_sandbox
from sandfort.api.schemas.toolbox_process import execute_response
from sandfort.api.schemas.toolbox_sessions import (
    CommandStatus,
    LogEvent,
    LogPageResponse,
    SessionCommandRequest,
    SessionCreateRequest,
    SessionExecResponse,
    SessionResponse,
)
from sandfort.api.sse import DEFAULT_KEEPALIVE_INTERVAL_S, format_event, with_keepalive
from sandfort.api.wiring import (
    IDEMPOTENCY_HEADER,
    IdempotencyGuard,
    get_idempotency_service,
    single_idempotency_key,
)
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import require_scopes
from sandfort.clock import SystemClock
from sandfort.db.models.exec import ExecCommandState
from sandfort.db.repositories.ports import ExecCommandRecord, ExecSessionRecord, UnitOfWorkPort
from sandfort.domain.org import Scope
from sandfort.drivers.base import SandboxDriver
from sandfort.errors import InternalError, ValidationFailed
from sandfort.services.audit import AuditRecorder
from sandfort.services.idempotency import MAX_KEY_LENGTH, IdempotencyService
from sandfort.toolbox.command_logs import STDERR, CommandLog, LinePage, LogLine
from sandfort.toolbox.sessions import SessionRuntime, SessionService

router = APIRouter(
    prefix="/v1/sandboxes/{sandbox_id}/toolbox/process/sessions",
    tags=["toolbox"],
    dependencies=[Depends(require_visible_sandbox)],
)

SESSION_RUNTIME_ATTR = "session_runtime"
CREATED = 201
SESSION_KEY_PREFIX = "session:"
KEEPALIVE_INTERVAL_S = DEFAULT_KEEPALIVE_INTERVAL_S
DEFAULT_PAGE_BYTES = 64 * 1024
MAX_PAGE_BYTES = 1024 * 1024
FOLLOW_PAGE_BYTES = 64 * 1024

_CLOCK = SystemClock()

type StopCause = Literal["sandbox_stopped"]


class CommandInfo(CommandStatus):
    """``CommandStatus`` plus ``stop_cause``: ``sandbox_stopped`` when a stop ended the command.

    Such a command reads state ``killed`` with a null ``exit_code``. Optional and additive.
    """

    stop_cause: StopCause | None = None


class SessionExecInfo(SessionExecResponse):
    command: CommandInfo | None = None


class LogPageInfo(LogPageResponse):
    stop_cause: StopCause | None = None


ToolboxUser = Annotated[Principal, Depends(require_scopes(Scope.TOOLBOX))]
Driver = Annotated[SandboxDriver, Depends(get_driver)]
Recorder = Annotated[AuditRecorder, Depends(get_audit_recorder)]


def get_session_service(request: Request, driver: Driver, recorder: Recorder) -> SessionService:
    """Per-request facade over the app-wide runtime (command logs and running tasks)."""
    state = request.app.state
    runtime = getattr(state, SESSION_RUNTIME_ATTR, None)
    if not isinstance(runtime, SessionRuntime):
        runtime = SessionRuntime()
        setattr(state, SESSION_RUNTIME_ATTR, runtime)
    factory = getattr(state, UOW_FACTORY_ATTR, None)
    if factory is None:
        raise InternalError(f"{UOW_FACTORY_ATTR} is not configured")
    return SessionService(
        cast(Callable[[], UnitOfWorkPort], factory), driver, recorder, _CLOCK, runtime
    )


Service = Annotated[SessionService, Depends(get_session_service)]
AsyncOnce = Annotated[None, Depends(single_valued("async"))]
LogsOnce = Annotated[None, Depends(single_valued("offset", "limit"))]
FollowOnce = Annotated[None, Depends(single_valued("offset"))]


def _session_response(record: ExecSessionRecord) -> SessionResponse:
    return SessionResponse(
        id=record.id,
        sandbox_id=record.sandbox_id,
        cwd=record.cwd,
        env=dict(record.env),
        state=record.state,
        created_at=record.created_at,
    )


def _stop_cause(service: SessionService, command_id: str, state: str | None) -> StopCause | None:
    cause = service.stop_cause(command_id, state)
    return "sandbox_stopped" if cause == "sandbox_stopped" else None


def _command_status(record: ExecCommandRecord, stop_cause: StopCause | None = None) -> CommandInfo:
    return CommandInfo(
        id=record.id,
        session_id=record.session_id,
        state=ExecCommandState(record.state),
        exit_code=record.exit_code,
        stdout_bytes=record.stdout_bytes,
        stderr_bytes=record.stderr_bytes,
        created_at=record.created_at,
        finished_at=record.finished_at,
        stop_cause=stop_cause,
    )


def _log_event(line: LogLine) -> LogEvent:
    return LogEvent(
        stream="stderr" if line.stream == STDERR else "stdout",
        offset=line.offset,
        line=line.data.decode("utf-8", errors="replace"),
    )


def _page_state(page: LinePage) -> ExecCommandState:
    if page.finished and page.state is not None:
        return ExecCommandState(page.state)
    return ExecCommandState.RUNNING


def sandbox_scoped_key(sandbox_id: str, key: str) -> str:
    """The slot a session-create key lives in: ``session:``, the sandbox id and a sha256 of the key.

    The same key on two sandboxes is two slots. A key the idempotency service would reject
    (empty, too long) is passed on unchanged so the guard refuses it with its own message.
    """
    if not 0 < len(key) <= MAX_KEY_LENGTH:
        return key
    return f"{SESSION_KEY_PREFIX}{sandbox_id}:{hashlib.sha256(key.encode()).hexdigest()}"


def session_idempotency(
    sandbox_id: str,
    request: Request,
    service: Annotated[IdempotencyService, Depends(get_idempotency_service)],
    idempotency_key: Annotated[
        str | None,
        Header(
            alias=IDEMPOTENCY_HEADER,
            min_length=1,
            max_length=MAX_KEY_LENGTH,
            description="Makes the create safe to retry: the same key and body replays the "
            "first response (the same session); the same key with another body answers 422. "
            "The key belongs to the API key and the sandbox. 1 to 255 characters; an empty or "
            "longer key answers 422 VALIDATION_ERROR.",
        ),
    ] = None,
) -> IdempotencyGuard:
    given = single_idempotency_key(request, idempotency_key)
    key = None if given is None else sandbox_scoped_key(sandbox_id, given)
    return IdempotencyGuard(service, key, request)


SessionIdempotent = Annotated[IdempotencyGuard, Depends(session_idempotency)]


@router.post("", status_code=CREATED, response_model=Envelope[SessionResponse])
async def create_session(
    sandbox_id: str,
    body: SessionCreateRequest,
    principal: ToolboxUser,
    service: Service,
    idempotent: SessionIdempotent,
) -> Envelope[SessionResponse] | JSONResponse:
    """Create an exec session (a persisted cwd and env around single shell commands).

    With an `Idempotency-Key` header the same key and body replays the first response and no
    second session is created; the key is kept for one day. The same key with another body
    answers 422. Replays carry `Idempotent-Replayed: true`. A replay returns the first answer
    even if that session has been deleted since.
    """

    async def create() -> Envelope[SessionResponse]:
        record = await service.create_session(principal, sandbox_id, body.cwd, body.env)
        return ok(_session_response(record))

    return await idempotent.run(principal.org_id, CREATED, create, request_model=body)


@router.get("")
async def list_sessions(
    sandbox_id: str, principal: ToolboxUser, _known: KnownQuery, service: Service
) -> Envelope[list[SessionResponse]]:
    records = await service.list_sessions(principal.org_id, sandbox_id)
    return ok([_session_response(record) for record in records])


@router.get("/{session_id}")
async def get_session(
    sandbox_id: str, session_id: str, principal: ToolboxUser, service: Service
) -> Envelope[SessionResponse]:
    record = await service.get_session(principal.org_id, sandbox_id, session_id)
    return ok(_session_response(record))


@router.delete("/{session_id}")
async def delete_session(
    sandbox_id: str, session_id: str, principal: ToolboxUser, service: Service
) -> Envelope[SessionResponse]:
    """Delete a session: its running commands are killed and the session and its commands are
    removed. Answers the session as it was, with state `closed`. A second delete, or an unknown
    session, answers 404 (like deleting a volume twice). Works on a stopped sandbox.
    """
    record = await service.delete_session(principal, sandbox_id, session_id)
    return ok(_session_response(record))


@router.post(
    "/{session_id}/commands",
    response_description="A synchronous command finished: `mode` is `sync` and `result` has "
    "the output and exit code.",
    responses={
        202: {
            "model": Envelope[SessionExecInfo],
            "description": "The command was started asynchronously (`mode` `async` in the body "
            "or `?async=true`): `mode` is `async`, `command` is its status with state "
            "`running`, and `result` is absent. Read it with the command routes.",
        }
    },
)
async def execute_command(
    sandbox_id: str,
    session_id: str,
    body: SessionCommandRequest,
    response: Response,
    principal: ToolboxUser,
    service: Service,
    _known: KnownQuery,
    _once: AsyncOnce,
    run_async: Annotated[bool, Query(alias="async")] = False,
) -> Envelope[SessionExecInfo]:
    outcome = await service.execute(
        principal,
        sandbox_id,
        session_id,
        body.command,
        run_async=run_async or body.mode == "async",
        timeout_s=body.timeout_s,
    )
    if outcome.command is not None:
        response.status_code = 202
        return ok(
            SessionExecInfo(mode="async", cwd=outcome.cwd, command=_command_status(outcome.command))
        )
    if outcome.result is None:
        raise InternalError("synchronous command produced no result")
    return ok(
        SessionExecInfo(mode="sync", cwd=outcome.cwd, result=execute_response(outcome.result))
    )


@router.get("/{session_id}/commands/{command_id}")
async def get_command(
    sandbox_id: str, session_id: str, command_id: str, principal: ToolboxUser, service: Service
) -> Envelope[CommandInfo]:
    record = await service.get_command(principal.org_id, sandbox_id, session_id, command_id)
    return ok(_command_status(record, _stop_cause(service, record.id, record.state)))


@router.get("/{session_id}/commands/{command_id}/logs")
async def get_command_logs(
    sandbox_id: str,
    session_id: str,
    command_id: str,
    principal: ToolboxUser,
    service: Service,
    _known: KnownQuery,
    _once: LogsOnce,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_BYTES)] = DEFAULT_PAGE_BYTES,
) -> Envelope[LogPageInfo]:
    """One event per line, terminator included; an unterminated tail waits for its line.

    `next_offset` can sit before the log end while the command runs: pass it as `offset` to
    resume exactly after the last line. Lines over 64 KiB or `limit` are cut into pieces.
    """
    record = await service.get_command(principal.org_id, sandbox_id, session_id, command_id)
    page = service.log_for(record).read_lines(offset, limit)
    return ok(
        LogPageInfo(
            events=[_log_event(line) for line in page.lines],
            next_offset=page.next_offset,
            truncated=page.truncated,
            state=_page_state(page),
            exit_code=page.exit_code,
            complete=page.complete,
            stop_cause=_stop_cause(service, record.id, page.state) if page.complete else None,
        )
    )


async def _follow_frames(
    log: CommandLog, offset: int, stop_cause: Callable[[str | None], StopCause | None]
) -> AsyncIterator[str]:
    while True:
        page = log.read_lines(offset, FOLLOW_PAGE_BYTES)
        for line in page.lines:
            event = _log_event(line)
            yield format_event(event.model_dump(), event=event.stream, event_id=str(line.end))
        offset = page.next_offset
        if page.complete:
            final = {
                "exit_code": page.exit_code,
                "state": _page_state(page).value,
                "truncated": page.truncated,
            }
            cause = stop_cause(page.state)
            if cause is not None:
                final["stop_cause"] = cause
            yield format_event(final, event="exit", event_id=str(offset))
            return
        if not page.lines:
            await log.wait_for_change(page.seen_offset)


def _resume_offset(offset: int | None, last_event_id: str | None) -> int:
    if offset is not None:
        return offset
    if last_event_id is None or not last_event_id.strip():
        return 0
    try:
        return max(int(last_event_id), 0)
    except ValueError:
        raise ValidationFailed("Last-Event-ID must be a byte offset") from None


@router.get("/{session_id}/commands/{command_id}/logs/follow")
async def follow_command_logs(
    sandbox_id: str,
    session_id: str,
    command_id: str,
    principal: ToolboxUser,
    service: Service,
    _known: KnownQuery,
    _once: FollowOnce,
    offset: Annotated[int | None, Query(ge=0)] = None,
    last_event_id: Annotated[str | None, Header()] = None,
) -> StreamingResponse:
    record = await service.get_command(principal.org_id, sandbox_id, session_id, command_id)
    start = _resume_offset(offset, last_event_id)
    frames = with_keepalive(
        _follow_frames(
            service.log_for(record),
            start,
            lambda state: _stop_cause(service, record.id, state),
        ),
        interval_s=KEEPALIVE_INTERVAL_S,
    )
    return StreamingResponse(
        frames,
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/{session_id}/commands/{command_id}/kill")
async def kill_command(
    sandbox_id: str, session_id: str, command_id: str, principal: ToolboxUser, service: Service
) -> Envelope[CommandInfo]:
    record = await service.kill(principal, sandbox_id, session_id, command_id)
    return ok(_command_status(record, _stop_cause(service, record.id, record.state)))
