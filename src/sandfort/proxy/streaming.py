"""Streaming helpers shared by the preview proxy and the cross-node toolbox forwarder.

Hop-by-hop header filtering, the request body iterator, the sendable websocket close-code rule
and the two directions of the bidirectional websocket pump.
"""

import contextlib
from collections.abc import AsyncIterator, Awaitable, Callable

import anyio
from starlette.types import Receive, Send
from websockets.asyncio.client import ClientConnection
from websockets.exceptions import ConnectionClosed

WS_NORMAL_CLOSURE = 1000
WS_INTERNAL_ERROR = 1011

HOP_BY_HOP = frozenset(
    {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization"}
    | {"proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"}
)


def _connection_listed(value: str | None) -> set[str]:
    """Header names a ``Connection`` header marks as hop-by-hop."""
    return {name.strip().lower() for name in (value or "").split(",") if name.strip()}


async def _request_body(receive: Receive) -> AsyncIterator[bytes]:
    more_body = True
    while more_body:
        message = await receive()
        if message["type"] == "http.disconnect":
            return
        more_body = bool(message.get("more_body", False))
        body: bytes = message.get("body", b"")
        if body:
            yield body


def _sendable_close_code(code: int | None) -> int:
    """Codes 1005, 1006 and 1015 (and unassigned ones) must never appear in a close frame."""
    if code is None:
        return WS_INTERNAL_ERROR
    allowed = 1000 <= code <= 1003 or 1007 <= code <= 1014 or 3000 <= code < 5000
    return code if allowed else WS_NORMAL_CLOSURE


async def _client_to_upstream(receive: Receive, upstream: ClientConnection) -> None:
    try:
        while True:
            message = await receive()
            if message["type"] == "websocket.disconnect":
                await upstream.close(_sendable_close_code(message.get("code", WS_NORMAL_CLOSURE)))
                return
            if message["type"] == "websocket.receive":
                text = message.get("text")
                await upstream.send(text if text is not None else message.get("bytes") or b"")
    except ConnectionClosed:
        return  # the upstream side ends the bridge and tells the client


async def _upstream_to_client(upstream: ClientConnection, send: Send) -> None:
    try:
        async for data in upstream:
            key = "text" if isinstance(data, str) else "bytes"
            await send({"type": "websocket.send", key: data})
    except ConnectionClosed:
        pass
    except OSError:
        return  # the client went away first; its side closes the upstream
    code = _sendable_close_code(upstream.close_code)
    with contextlib.suppress(OSError):  # the client may be gone by now
        await send({"type": "websocket.close", "code": code})


async def _until_done(cancel: anyio.CancelScope, pump: Callable[[], Awaitable[None]]) -> None:
    """Run one direction of the bridge; when it ends, the other direction is cancelled."""
    try:
        await pump()
    finally:
        cancel.cancel()
