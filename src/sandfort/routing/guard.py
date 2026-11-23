"""Owner-side guard: only a platform node may send the forwarded-hop marker.

``RouteGuardMiddleware`` is installed whenever the routing secret is set. A request without the
``X-Sandfort-Forwarded`` header passes untouched. With the header it must carry a route token
that verifies (signature, expiry, this process's node id, the sandbox id in the path) and the
database must name this node as the sandbox's owner. Any failure answers 503 ``NODE_UNAVAILABLE``
with reason ``rejected`` (token) or ``misrouted`` (owner): deliberately not 401, which clients
read as a bad API key, and never a path around authentication. A verified request is marked in
the ASGI scope (``FORWARDED_SCOPE_KEY``) so the edge middleware never forwards it again, and is
handled locally by the unchanged routes, which authenticate the caller themselves.
"""

import re

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from sandfort.api.errors import REQUEST_ID_ATTR, error_response
from sandfort.clock import Clock, SystemClock
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.node import NodeRoute
from sandfort.errors import NodeUnavailable
from sandfort.routing.forward import FORWARDED_HEADER, ROUTE_TOKEN_HEADER
from sandfort.routing.tokens import InvalidRouteToken, verify_route_token

FORWARDED_SCOPE_KEY = "sandfort.forwarded"
TOOLBOX_PATH = re.compile(r"/v1/sandboxes/([^/]+)/toolbox(?:/.*)?")
REJECTED = "rejected"
MISROUTED = "misrouted"
REJECTED_MESSAGE = "the forwarded request was not accepted by this node"
MISROUTED_MESSAGE = "this node does not own the requested sandbox"
WS_TRY_AGAIN_LATER = 1013


def toolbox_sandbox_id(path: str) -> str | None:
    """The sandbox id of a toolbox path, or ``None`` for any other path."""
    match = TOOLBOX_PATH.fullmatch(path)
    return match.group(1) if match else None


async def lookup_route(
    session_factory: async_sessionmaker[AsyncSession], sandbox_id: str
) -> NodeRoute | None:
    """The owning node of ``sandbox_id`` (a system path, not org scoped), or ``None``."""
    async with UnitOfWork(session_factory) as uow:
        return await uow.nodes.route_for_sandbox(sandbox_id)


async def refuse(scope: Scope, receive: Receive, send: Send, refusal: NodeUnavailable) -> None:
    """Answer a refusal in the standard envelope; a websocket is closed with 1013."""
    if scope["type"] == "websocket":
        await send({"type": "websocket.close", "code": WS_TRY_AGAIN_LATER})
        return
    request_id = scope.get("state", {}).get(REQUEST_ID_ATTR)
    await error_response(refusal, request_id=request_id)(scope, receive, send)


def _refusal(message: str, reason: str, node_id: str) -> NodeUnavailable:
    return NodeUnavailable(message, reason=reason, node_id=node_id)


class RouteGuardMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        settings: Settings,
        session_factory: async_sessionmaker[AsyncSession],
        clock: Clock | None = None,
    ) -> None:
        self.app = app
        self._settings = settings
        self._session_factory = session_factory
        self._clock = clock or SystemClock()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        if FORWARDED_HEADER not in headers:
            await self.app(scope, receive, send)
            return
        refusal = await self._check(scope, headers)
        if refusal is not None:
            await refuse(scope, receive, send, refusal)
            return
        scope[FORWARDED_SCOPE_KEY] = True
        await self.app(scope, receive, send)

    async def _check(self, scope: Scope, headers: Headers) -> NodeUnavailable | None:
        node_id = self._settings.node_id
        sandbox_id = toolbox_sandbox_id(scope["path"])
        token = headers.get(ROUTE_TOKEN_HEADER)
        if sandbox_id is None or token is None:
            return _refusal(REJECTED_MESSAGE, REJECTED, node_id)
        try:
            verify_route_token(
                self._settings.routing_secret,
                token,
                node_id=node_id,
                sandbox_id=sandbox_id,
                now=self._clock.now(),
            )
        except InvalidRouteToken:
            return _refusal(REJECTED_MESSAGE, REJECTED, node_id)
        route = await lookup_route(self._session_factory, sandbox_id)
        if route is None or route.node_id != node_id:
            return _refusal(MISROUTED_MESSAGE, MISROUTED, node_id)
        return None
