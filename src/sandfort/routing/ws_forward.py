"""Edge-side websocket forwarder: one hop of a terminal connection to the owning node.

``forward_websocket`` dials the owner over ``ws`` (``wss`` for an ``https`` address) at the
same raw path and query, with the forwarded-hop marker and the signed route token, and
copies the client headers the same way the HTTP hop does. The client socket is accepted only
after the upstream handshake succeeded, with the subprotocol the owner chose. Both directions
are then pumped with the shared helpers until either side closes; close codes pass through
the shared sendable-code rule, so the owner's own 4401 for a spent connect token reaches the
client unchanged. A client close closes the upstream connection.

A dial that fails (nothing listening, refused handshake such as a guard rejection, timeout)
raises ``NodeUnavailable`` before the client socket is touched; ``close_try_again`` then
accepts and closes it with 1013 so the client sees a close code instead of a bare handshake
failure. Neither the query (it holds the connect token) nor the route token is logged.
"""

import logging
from functools import partial

import anyio
from starlette.datastructures import Headers
from starlette.types import Receive, Scope, Send
from websockets.asyncio.client import connect
from websockets.exceptions import WebSocketException
from websockets.typing import Subprotocol

from sandfort.domain.node import NodeRoute
from sandfort.errors import NodeUnavailable
from sandfort.proxy.streaming import _client_to_upstream, _until_done, _upstream_to_client
from sandfort.routing.forward import (
    TIMEOUT,
    TIMEOUT_MESSAGE,
    UNREACHABLE,
    UNREACHABLE_MESSAGE,
    _owner_url,
    _request_headers,
)

logger = logging.getLogger(__name__)

WS_TRY_AGAIN_LATER = 1013
WS_MAX_MESSAGE_BYTES = 16 * 1024 * 1024
_SCHEMES = (("https://", "wss://"), ("http://", "ws://"))
# The websockets client writes its own handshake; the rest is the hop's to set.
_NOT_COPIED = frozenset(
    {"sec-websocket-key", "sec-websocket-version", "sec-websocket-extensions"}
    | {"sec-websocket-protocol", "user-agent", "origin", "accept-encoding"}
)


def _dial_url(route: NodeRoute, scope: Scope) -> str:
    url = _owner_url(route, scope)
    for http_scheme, ws_scheme in _SCHEMES:
        if url.startswith(http_scheme):
            return ws_scheme + url.removeprefix(http_scheme)
    return url


async def close_try_again(receive: Receive, send: Send) -> None:
    """Complete the handshake and close with 1013 (a close before accept is a bare 403)."""
    await receive()  # the websocket.connect message
    await send({"type": "websocket.accept"})
    await send({"type": "websocket.close", "code": WS_TRY_AGAIN_LATER})


async def forward_websocket(
    scope: Scope,
    receive: Receive,
    send: Send,
    *,
    route: NodeRoute,
    token: str,
    timeout_s: float,
) -> None:
    """Bridge the client socket to ``route`` once; ``NodeUnavailable`` if no hop was made."""
    offered: list[str] = scope.get("subprotocols") or []
    headers = [(k, v) for k, v in _request_headers(scope, token) if k not in _NOT_COPIED]
    try:
        connection = await connect(
            _dial_url(route, scope),
            additional_headers=headers,
            subprotocols=[Subprotocol(name) for name in offered] or None,
            user_agent_header=Headers(scope=scope).get("user-agent"),
            proxy=None,  # like HTTP: never through the host's proxy settings
            open_timeout=timeout_s,
            max_size=WS_MAX_MESSAGE_BYTES,
        )
    except TimeoutError:
        raise NodeUnavailable(TIMEOUT_MESSAGE, reason=TIMEOUT, node_id=route.node_id) from None
    except (OSError, WebSocketException) as exc:
        logger.warning("forwarded websocket failed: %s", type(exc).__name__)
        raise NodeUnavailable(
            UNREACHABLE_MESSAGE, reason=UNREACHABLE, node_id=route.node_id
        ) from None
    inbound = partial(_client_to_upstream, receive, connection)
    outbound = partial(_upstream_to_client, connection, send)
    try:
        await receive()  # the websocket.connect message
        await send({"type": "websocket.accept", "subprotocol": connection.subprotocol})
        async with anyio.create_task_group() as group:
            group.start_soon(_until_done, group.cancel_scope, inbound)
            group.start_soon(_until_done, group.cancel_scope, outbound)
    finally:
        await connection.close()
