"""``/pty``: interactive terminals bridged over a websocket.

REST (API key, ``toolbox`` scope): create returns the pty id, a single-use connect token and
the websocket url; list, get, resize and close (``DELETE``) work on the persisted rows.

Websocket ``/pty/{pty_id}/connect?token=``: no API key; the token is redeemed exactly once
before any byte moves and a missing, invalid, expired or reused token closes with 4401.
Binary (and text) frames are written to the terminal; terminal output is sent as binary
frames. When the terminal ends the server closes with 4000 + the process exit code (0..255)
when the driver reports it, else normally (1000). When the client goes away
the terminal is torn down: its token is spent, so nobody could reattach. Streams do not use
the response envelope.
"""

import asyncio
import logging
from collections.abc import Callable, Coroutine
from typing import Annotated, Any, cast

import anyio
from fastapi import APIRouter, Depends, Query, Request, WebSocket
from starlette.requests import HTTPConnection
from starlette.websockets import WebSocketState

from sandfort.api.deps import AUDIT_RECORDER_ATTR, DRIVER_ATTR, UOW_FACTORY_ATTR
from sandfort.api.envelope import Envelope, ok
from sandfort.api.query_guard import KnownQuery
from sandfort.api.routes.toolbox.scope_guard import require_visible_sandbox
from sandfort.api.schemas.toolbox_pty import (
    PtyConnectTokenResponse,
    PtyCreateRequest,
    PtyResizeRequest,
    PtyResponse,
)
from sandfort.api.wiring import CONNECT_TOKENS_ATTR, PTY_REGISTRY_ATTR
from sandfort.auth.connect_tokens import ConnectTokenInvalid, ConnectTokenStore
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import require_scopes
from sandfort.clock import SystemClock
from sandfort.db.repositories.ports import PtySessionRecord
from sandfort.domain.org import Scope
from sandfort.drivers.base import SandboxDriver
from sandfort.errors import InternalError
from sandfort.services.audit import AuditRecorder
from sandfort.toolbox.pty import LivePty, PtyRegistry, PtyService, PtyUnitOfWork

logger = logging.getLogger(__name__)

PREFIX = "/v1/sandboxes/{sandbox_id}/toolbox/pty"
# REST routes authenticate with a key and run the label-scope guard. The websocket connect
# route redeems a one-time token instead (no Authorization header), so it is not guarded.
_rest = APIRouter(prefix=PREFIX, tags=["toolbox"], dependencies=[Depends(require_visible_sandbox)])
_ws = APIRouter(prefix=PREFIX, tags=["toolbox"])
router = APIRouter()  # what the toolbox package includes; filled at the end of this module

WS_CLOSE_NORMAL = 1000
WS_CLOSE_UNAUTHORIZED = 4401
PTY_EXIT_CLOSE_BASE = 4000  # close code 4000 + n: the terminal's process exited with code n
MAX_EXIT_CODE = 255
EXIT_CODE_WAIT_S = 1.0  # docker may need a moment to record the exit code of an ended exec
EXIT_CODE_POLL_S = 0.1

_CLOCK = SystemClock()
_DEFAULT_RECORDER = AuditRecorder(_CLOCK)

ToolboxUser = Annotated[Principal, Depends(require_scopes(Scope.TOOLBOX))]


def _state(conn: HTTPConnection, name: str) -> object:
    value = getattr(conn.app.state, name, None)
    if value is None:
        raise InternalError(f"{name} is not configured")
    return value


def get_pty_service(conn: HTTPConnection) -> PtyService:
    """Per-connection facade over the process-wide terminal registry and connect-token store."""
    registry = _state(conn, PTY_REGISTRY_ATTR)
    if not isinstance(registry, PtyRegistry):
        raise InternalError("the pty registry is misconfigured")
    recorder = getattr(conn.app.state, AUDIT_RECORDER_ATTR, None)
    return PtyService(
        cast(Callable[[], PtyUnitOfWork], _state(conn, UOW_FACTORY_ATTR)),
        cast(SandboxDriver, _state(conn, DRIVER_ATTR)),
        recorder if isinstance(recorder, AuditRecorder) else _DEFAULT_RECORDER,
        _CLOCK,
        registry,
        cast(ConnectTokenStore, _state(conn, CONNECT_TOKENS_ATTR)),
    )


Service = Annotated[PtyService, Depends(get_pty_service)]


def _pty_response(record: PtySessionRecord) -> PtyResponse:
    return PtyResponse(
        id=record.id,
        sandbox_id=record.sandbox_id,
        state=record.state,
        rows=record.rows,
        cols=record.cols,
        created_at=record.created_at,
    )


def _websocket_url(request: Request, path: str) -> str:
    base = request.base_url
    scheme = "wss" if base.scheme == "https" else "ws"
    return str(base.replace(scheme=scheme)).rstrip("/") + path


# -- REST -------------------------------------------------------------------------


@_rest.post("", status_code=201)
async def create_pty(
    sandbox_id: str,
    body: PtyCreateRequest,
    request: Request,
    principal: ToolboxUser,
    service: Service,
) -> Envelope[PtyConnectTokenResponse]:
    created = await service.create_pty(
        principal, sandbox_id, rows=body.rows, cols=body.cols, argv=body.argv, env=body.env
    )
    return ok(
        PtyConnectTokenResponse(
            pty_id=created.record.id,
            token=created.token,
            websocket_url=_websocket_url(request, created.websocket_path),
        )
    )


@_rest.get("")
async def list_ptys(
    sandbox_id: str, principal: ToolboxUser, _known: KnownQuery, service: Service
) -> Envelope[list[PtyResponse]]:
    records = await service.list_ptys(principal.org_id, sandbox_id)
    return ok([_pty_response(record) for record in records])


@_rest.get("/{pty_id}")
async def get_pty(
    sandbox_id: str, pty_id: str, principal: ToolboxUser, service: Service
) -> Envelope[PtyResponse]:
    return ok(_pty_response(await service.get_pty(principal.org_id, sandbox_id, pty_id)))


@_rest.post("/{pty_id}/resize")
async def resize_pty(
    sandbox_id: str, pty_id: str, body: PtyResizeRequest, principal: ToolboxUser, service: Service
) -> Envelope[PtyResponse]:
    record = await service.resize(principal, sandbox_id, pty_id, body.rows, body.cols)
    return ok(_pty_response(record))


@_rest.delete("/{pty_id}")
async def close_pty(
    sandbox_id: str, pty_id: str, principal: ToolboxUser, service: Service
) -> Envelope[PtyResponse]:
    return ok(_pty_response(await service.close(principal, sandbox_id, pty_id)))


# -- websocket bridge ---------------------------------------------------------------


@_ws.websocket("/{pty_id}/connect")
async def connect_pty(
    websocket: WebSocket,
    sandbox_id: str,
    pty_id: str,
    token: Annotated[str | None, Query()] = None,
) -> None:
    service = get_pty_service(websocket)
    await websocket.accept()
    try:
        live = await service.connect(token or "", sandbox_id, pty_id)
    except ConnectTokenInvalid:
        await websocket.close(code=WS_CLOSE_UNAUTHORIZED)
        return
    await _bridge(websocket, service, live)


async def _pump_output(websocket: WebSocket, service: PtyService, live: LivePty) -> None:
    while True:
        data = await service.read(live)
        if not data:
            return
        await websocket.send_bytes(data)


async def _pump_input(websocket: WebSocket, service: PtyService, live: LivePty) -> None:
    while True:
        message = await websocket.receive()
        if message["type"] == "websocket.disconnect":
            return
        data = message.get("bytes")
        if data is None:
            data = str(message.get("text") or "").encode()
        if data:
            await service.write(live, bytes(data))


async def _guarded(pump: Coroutine[Any, Any, None], live: LivePty, direction: str) -> None:
    """Run one direction of the bridge; any failure ends the bridge instead of escaping."""
    try:
        await pump
    except Exception:
        logger.info("pty %s %s pump stopped", live.pty_id, direction, exc_info=True)


def _is_open(websocket: WebSocket) -> bool:
    return (
        websocket.client_state == WebSocketState.CONNECTED
        and websocket.application_state == WebSocketState.CONNECTED
    )


async def _terminal_exit_code(service: PtyService, live: LivePty) -> int | None:
    """The ended terminal's exit code; retried briefly, as docker records it a moment late."""
    if not service.reports_exit_codes:
        return None
    deadline = anyio.current_time() + EXIT_CODE_WAIT_S
    while True:
        code = await service.exit_code(live)
        if code is not None or anyio.current_time() >= deadline:
            return code
        await anyio.sleep(EXIT_CODE_POLL_S)


def _close_code(exit_code: int | None) -> int:
    """``4000 + exit_code`` for a known exit code in 0..255, else the normal close code."""
    if exit_code is not None and 0 <= exit_code <= MAX_EXIT_CODE:
        return PTY_EXIT_CLOSE_BASE + exit_code
    return WS_CLOSE_NORMAL


async def _bridge(websocket: WebSocket, service: PtyService, live: LivePty) -> None:
    output = asyncio.create_task(_guarded(_pump_output(websocket, service, live), live, "output"))
    inbound = asyncio.create_task(_guarded(_pump_input(websocket, service, live), live, "input"))
    terminal_ended = False
    exit_code: int | None = None
    try:
        done, _ = await asyncio.wait({output, inbound}, return_when=asyncio.FIRST_COMPLETED)
        terminal_ended = output in done
    finally:
        with anyio.CancelScope(shield=True):  # tear down even when the connection is cancelled
            for task in (output, inbound):
                task.cancel()
            await asyncio.gather(output, inbound, return_exceptions=True)
            try:  # before finish: tearing down drops the driver's handle
                if terminal_ended:
                    exit_code = await _terminal_exit_code(service, live)
            finally:
                await service.finish(live)
    if terminal_ended and _is_open(websocket):
        await websocket.close(code=_close_code(exit_code))


# include_router copies the routes registered so far, so this comes after every decorator.
router.include_router(_rest)
router.include_router(_ws)
