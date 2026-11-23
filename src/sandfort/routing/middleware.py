"""Edge-side forwarding middleware: send a toolbox request to the node that owns the sandbox.

``RouteForwardMiddleware`` is installed only when the routing secret is set and matches
``/v1/sandboxes/{id}/toolbox/...``. It passes the request to the local routes when:

- it carries no credential (no ``Authorization`` header; for a websocket no ``token`` query
  value), so an anonymous caller gets the usual 401 and cannot tell a remote sandbox from a
  hosted one;
- the hop marker is already present or the guard verified it (at most one hop);
- the sandbox has no row (the route answers 404) or its owner is this node.

A stale owner or one without an address answers 503 ``NODE_UNAVAILABLE`` (reason ``stale`` or
``no_address``) without a connection. Otherwise the middleware mints a route token and forwards
exactly once. Websockets follow the same ladder for terminal connect paths
(``.../toolbox/pty/{id}/connect``) and are bridged by ``ws_forward``; a refusal closes the
client with 1013 after completing the handshake. Other websocket paths are served locally.
"""

import re
from urllib.parse import parse_qs

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from sandfort.clock import Clock, SystemClock
from sandfort.config import Settings
from sandfort.domain.node import NodeRoute
from sandfort.errors import NodeUnavailable
from sandfort.routing.forward import FORWARDED_HEADER, forward_http
from sandfort.routing.guard import FORWARDED_SCOPE_KEY, lookup_route, refuse, toolbox_sandbox_id
from sandfort.routing.tokens import mint_route_token
from sandfort.routing.ws_forward import close_try_again, forward_websocket
from sandfort.services.node_registry import HEARTBEAT_STALE_AFTER

PTY_CONNECT_PATH = re.compile(r"/v1/sandboxes/[^/]+/toolbox/pty/[^/]+/connect")

STALE = "stale"
NO_ADDRESS = "no_address"
STALE_MESSAGE = "the node that owns this sandbox has stopped reporting"
NO_ADDRESS_MESSAGE = "the node that owns this sandbox advertises no internal address"
TOKEN_QUERY_KEY = "token"


def has_credential(scope: Scope, headers: Headers) -> bool:
    """Whether the caller presented anything for the local handler to authenticate."""
    if scope["type"] == "websocket":
        query = parse_qs(scope.get("query_string", b"").decode("latin-1"))
        return any(query.get(TOKEN_QUERY_KEY, []))
    return bool(headers.get("authorization"))


class RouteForwardMiddleware:
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
        sandbox_id = self._candidate(scope)
        route = await lookup_route(self._session_factory, sandbox_id) if sandbox_id else None
        if sandbox_id is None or route is None or route.node_id == self._settings.node_id:
            await self.app(scope, receive, send)
            return
        refusal = await self._forward(scope, receive, send, sandbox_id, route)
        if refusal is None:
            return
        if scope["type"] == "websocket":
            await close_try_again(receive, send)
        else:
            await refuse(scope, receive, send, refusal)

    def _candidate(self, scope: Scope) -> str | None:
        """The sandbox id when this request may need a hop, else ``None`` (serve locally)."""
        if scope["type"] not in ("http", "websocket"):
            return None
        if scope["type"] == "websocket" and not PTY_CONNECT_PATH.fullmatch(scope["path"]):
            return None
        sandbox_id = toolbox_sandbox_id(scope["path"])
        if sandbox_id is None or scope.get(FORWARDED_SCOPE_KEY):
            return None
        headers = Headers(scope=scope)
        if FORWARDED_HEADER in headers or not has_credential(scope, headers):
            return None
        return sandbox_id

    async def _forward(
        self, scope: Scope, receive: Receive, send: Send, sandbox_id: str, route: NodeRoute
    ) -> NodeUnavailable | None:
        """Forward once; return the refusal to answer when no hop could be made."""
        now = self._clock.now()
        if now - route.last_heartbeat_at > HEARTBEAT_STALE_AFTER:
            return NodeUnavailable(STALE_MESSAGE, reason=STALE, node_id=route.node_id)
        if not route.internal_url:
            return NodeUnavailable(NO_ADDRESS_MESSAGE, reason=NO_ADDRESS, node_id=route.node_id)
        token = mint_route_token(
            self._settings.routing_secret, sandbox_id=sandbox_id, node_id=route.node_id, now=now
        )
        forward = forward_websocket if scope["type"] == "websocket" else forward_http
        try:
            await forward(
                scope,
                receive,
                send,
                route=route,
                token=token,
                timeout_s=self._settings.routing_timeout_s,
            )
        except NodeUnavailable as exc:
            return exc
        return None
