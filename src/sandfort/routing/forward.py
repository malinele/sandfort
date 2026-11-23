"""Edge-side forwarder: one HTTP hop of a toolbox request to the node that owns the sandbox.

``forward_http`` replays the request against the owner's internal address: same method, raw
path and query, body streamed from ``receive`` (never buffered). Headers are copied minus the
hop-by-hop set, ``Host`` and any inbound ``X-Sandfort-*`` header; the hop adds the forwarded
marker, the signed route token and ``X-Forwarded-For``. ``X-Request-Id`` and
``Idempotency-Key`` pass through so one id spans both hops. The answer streams back status,
filtered headers and raw (still encoded) chunks unchanged. A connection failure maps to
``NodeUnavailable`` reason ``unreachable``, a connect, write or pool timeout to ``timeout``.
The read timeout is unbounded: the owner's own limits bound the work. Neither the route token
nor the caller's ``Authorization`` header is logged.
"""

import logging

import httpx
from starlette.types import Receive, Scope, Send

from sandfort.domain.node import NodeRoute
from sandfort.errors import NodeUnavailable
from sandfort.proxy.streaming import HOP_BY_HOP, _connection_listed, _request_body

logger = logging.getLogger(__name__)

FORWARDED_HEADER = "x-sandfort-forwarded"
ROUTE_TOKEN_HEADER = "x-sandfort-route-token"
FORWARDED_VALUE = "1"
INTERNAL_HEADER_PREFIX = "x-sandfort-"
UNREACHABLE = "unreachable"
TIMEOUT = "timeout"
UNREACHABLE_MESSAGE = "the node that owns this sandbox is unreachable"
TIMEOUT_MESSAGE = "the node that owns this sandbox did not answer in time"

# Rebuilt by the hop, never copied from the client.
_REPLACED = frozenset({"host", "x-forwarded-for"})


def _request_headers(scope: Scope, token: str) -> list[tuple[str, str]]:
    raw: list[tuple[bytes, bytes]] = scope.get("headers") or []
    pairs = [(key.decode("latin-1").lower(), value.decode("latin-1")) for key, value in raw]
    listed = _connection_listed(next((v for k, v in pairs if k == "connection"), None))
    skipped = HOP_BY_HOP | _REPLACED | listed
    headers = [
        (key, value)
        for key, value in pairs
        if key not in skipped and not key.startswith(INTERNAL_HEADER_PREFIX)
    ]
    if not any(key == "accept-encoding" for key, _ in headers):
        headers.append(("accept-encoding", "identity"))  # httpx would add its own default
    headers.append((FORWARDED_HEADER, FORWARDED_VALUE))
    headers.append((ROUTE_TOKEN_HEADER, token))
    client = scope.get("client")
    if client:
        headers.append(("x-forwarded-for", str(client[0])))
    return headers


def _has_body(scope: Scope) -> bool:
    """HTTP framing: a request body exists only when a length or a transfer coding is declared."""
    raw: list[tuple[bytes, bytes]] = scope.get("headers") or []
    return any(key.lower() in (b"content-length", b"transfer-encoding") for key, _ in raw)


def _response_headers(response: httpx.Response) -> list[tuple[bytes, bytes]]:
    skipped = HOP_BY_HOP | _connection_listed(response.headers.get("connection"))
    return [
        (key, value)
        for key, value in response.headers.raw
        if key.decode("latin-1").lower() not in skipped
    ]


def _owner_url(route: NodeRoute, scope: Scope) -> str:
    raw_path: bytes = scope.get("raw_path") or str(scope["path"]).encode()
    query: bytes = scope.get("query_string") or b""
    url = route.internal_url.rstrip("/") + raw_path.decode("latin-1")
    return f"{url}?{query.decode('latin-1')}" if query else url


async def forward_http(
    scope: Scope,
    receive: Receive,
    send: Send,
    *,
    route: NodeRoute,
    token: str,
    timeout_s: float,
) -> None:
    """Send the request to ``route`` once and stream the owner's answer back to ``send``."""
    timeout = httpx.Timeout(timeout_s, read=None)
    async with httpx.AsyncClient(timeout=timeout) as client:
        request = client.build_request(
            scope["method"],
            _owner_url(route, scope),
            headers=_request_headers(scope, token),
            content=_request_body(receive) if _has_body(scope) else None,
        )
        try:
            response = await client.send(request, stream=True)
        except httpx.TimeoutException:
            raise NodeUnavailable(TIMEOUT_MESSAGE, reason=TIMEOUT, node_id=route.node_id) from None
        except httpx.TransportError:
            raise NodeUnavailable(
                UNREACHABLE_MESSAGE, reason=UNREACHABLE, node_id=route.node_id
            ) from None
        try:
            await send(
                {
                    "type": "http.response.start",
                    "status": response.status_code,
                    "headers": _response_headers(response),
                }
            )
            async for chunk in response.aiter_raw():
                await send({"type": "http.response.body", "body": chunk, "more_body": True})
            await send({"type": "http.response.body", "body": b""})
        except httpx.TransportError as exc:
            # The status line went out already: the stream is cut short, which the client
            # reads as a failure. Nothing more can be answered.
            logger.warning("forwarded response cut short: %s", type(exc).__name__)
        finally:
            await response.aclose()
