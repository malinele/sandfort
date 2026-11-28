"""Preview proxy ASGI application (separate app, same package).

``Host: <port>-<sandbox-id>.<preview domain>`` routes to that port inside the sandbox. Before
any upstream connection, a foreign host or a stopped sandbox answers 404, and a private sandbox
without a preview token for its org, sandbox and port answers 401. The token is read from the
``TOKEN_HEADER`` request header, else the ``TOKEN_PARAM`` query, else the cookie, and the
header is never forwarded. ``HANDOFF_PATH`` on a preview host is answered by ``handoff``
itself and never reaches the sandbox. HTTP streams through httpx minus hop-by-hop headers,
websockets are bridged with the ``websockets`` client, and upstream failures answer 502. A
valid query token is stripped and set as a cookie (never forwarded). Cookie auth needs
consistent Origin and Sec-Fetch-Site, and upstream cookies lose their Domain.
``GET /terminal`` on a non-preview host serves the terminal.
The token is also cut from every forwarded request header (a Referer, or an edge's X-Url) and
from uvicorn's log lines (``hygiene``). Each request and websocket bridge holds a concurrency
slot (``limits``): above the per-sandbox or the process cap the answer is 503 ``CAPACITY``.
No shared cache may keep an HTTP answer of a private sandbox (``caching``).
The upstream request carries the headers the client sent plus the three ``X-Forwarded-*`` ones
the proxy sets, nothing httpx adds on its own (default headers, cookie jar).
"""

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from functools import partial
from http.cookiejar import CookieJar, DefaultCookiePolicy

import anyio
import httpx
from starlette.types import ASGIApp, Receive, Scope, Send
from websockets.asyncio.client import connect
from websockets.exceptions import WebSocketException
from websockets.typing import Subprotocol

from sandfort.config import Settings
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.drivers.base import EndpointDriver
from sandfort.drivers.errors import DriverError
from sandfort.proxy import handoff, routing, terminal
from sandfort.proxy.answers import _header, _headers, _reject, _Rejected
from sandfort.proxy.caching import answer_cache_headers
from sandfort.proxy.hygiene import CREDENTIAL_HEADERS, install_log_redaction, strip_header_token
from sandfort.proxy.limits import PreviewBusy, PreviewLimits, relay_response_body, send_upstream
from sandfort.proxy.streaming import (
    HOP_BY_HOP,
    _client_to_upstream,
    _connection_listed,
    _request_body,
    _until_done,
    _upstream_to_client,
)
from sandfort.proxy.tokens import (
    TOKEN_HEADER,
    InMemoryPreviewTokenStore,
    PreviewGrant,
    PreviewTokenInvalid,
    PreviewTokenStore,
    authorize_preview,
    fetch_metadata_consistent,
    split_cookie_token,
    split_query_token,
    strip_cookie_domain,
    token_cookie,
)

logger = logging.getLogger(__name__)

type SandboxLookup = Callable[[str], Awaitable[Sandbox | None]]

CONNECT_TIMEOUT_S = 10.0
MAX_KEEPALIVE = 768  # idle upstream connections kept open when the per-sandbox cap is 0
WS_MAX_MESSAGE_BYTES = 16 * 1024 * 1024
BAD_GATEWAY = "BAD_GATEWAY"
NOT_FOUND_MESSAGE = "no running preview is served at this host"
UNREACHABLE_MESSAGE = "the sandbox port is unreachable"

# Never taken from the client: the proxy sets the forwarding headers and rebuilds the cookies,
# and it reads the token header itself.
_REPLACED = frozenset(
    {"host", "cookie", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto"}
    | {"forwarded", "x-forwarded-port", "x-forwarded-scheme", "x-real-ip"}
    | CREDENTIAL_HEADERS
)
# The websockets client performs its own handshake and sends the user agent it is given.
_WS_HANDSHAKE = frozenset(
    {"sec-websocket-key", "sec-websocket-version", "sec-websocket-extensions"}
    | {"sec-websocket-protocol", "user-agent"}
)


@dataclass(frozen=True, slots=True)
class _Upstream:
    host: str
    port: int
    sandbox_id: str  # the slot key of the concurrency caps
    query: bytes  # the client's query string without the preview token
    token_from_query: str | None  # set as a cookie on the response
    token_in_query: bool = False  # the request URL named TOKEN_PARAM, valid or not
    private: bool = False  # a token granted the request: no shared cache may keep the answer


def _cookie_headers(scope: Scope) -> list[str]:
    return [value.decode("latin-1") for key, value in _headers(scope) if key.lower() == b"cookie"]


def _request_headers(scope: Scope, *, websocket: bool = False) -> list[tuple[str, str]]:
    skipped = HOP_BY_HOP | _REPLACED | _connection_listed(_header(scope, b"connection"))
    if websocket:
        skipped |= _WS_HANDSHAKE
    headers = [
        (key.decode("latin-1"), strip_header_token(value.decode("latin-1")))
        for key, value in _headers(scope)
        if key.decode("latin-1").lower() not in skipped
    ]
    _, cookies = split_cookie_token(_cookie_headers(scope))
    if cookies:
        headers.append(("cookie", cookies))
    scheme = "https" if scope.get("scheme") in ("https", "wss") else "http"
    headers.append(("x-forwarded-host", strip_header_token(_header(scope, b"host") or "")))
    headers.append(("x-forwarded-proto", scheme))
    client = scope.get("client")
    if client:
        headers.append(("x-forwarded-for", str(client[0])))
    return headers


def _drop_unsent_defaults(
    request: httpx.Request, client: httpx.AsyncClient, sent: set[str]
) -> None:
    """Remove what httpx added on its own: its default headers and the cookie jar's Cookie.

    ``build_request`` merges ``client.headers`` (Accept, Accept-Encoding, Connection and
    User-Agent in httpx 0.28) and ``client.cookies`` into every request, and the client keeps
    the cookies each response set, whatever the sandbox. ``sent`` holds the lowercase names the
    proxy forwards: a header the client sent stays, one it did not send goes.
    """
    for name in (set(client.headers.keys()) | {"cookie"}) - sent:
        request.headers.pop(name, None)


def _response_headers(response: httpx.Response, cookie: str | None) -> list[tuple[bytes, bytes]]:
    skipped = HOP_BY_HOP | _connection_listed(response.headers.get("connection"))
    headers = [
        (key, strip_cookie_domain(value) if key.lower() == b"set-cookie" else value)
        for key, value in response.headers.raw
        if key.decode("latin-1").lower() not in skipped
    ]
    if cookie is not None:
        headers.append((b"set-cookie", cookie.encode("latin-1")))
    return headers


def _upstream_url(scheme: str, upstream: _Upstream, scope: Scope) -> str:
    host = f"[{upstream.host}]" if ":" in upstream.host else upstream.host
    raw_path: bytes = scope.get("raw_path") or str(scope.get("path") or "/").encode()
    query = "?" + upstream.query.decode("latin-1") if upstream.query else ""
    return f"{scheme}://{host}:{upstream.port}{raw_path.decode('latin-1')}{query}"


def _refusing_cookie_jar() -> CookieJar:
    """A jar that stores nothing: one viewer's cookies never reach another request."""
    return CookieJar(policy=DefaultCookiePolicy(allowed_domains=[]))


class PreviewProxy:
    """The proxy ASGI callable; ``create_proxy_app`` builds it."""

    def __init__(
        self,
        settings: Settings,
        tokens: PreviewTokenStore,
        lookup: SandboxLookup,
        driver: EndpointDriver,
        *,
        http_client: httpx.AsyncClient | None = None,
        on_shutdown: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        self._settings = settings
        self._tokens = tokens
        self._lookup = lookup
        self._driver = driver
        self._owns_client = http_client is None
        keepalive = settings.preview_max_concurrent_per_sandbox or MAX_KEEPALIVE  # 0 = no cap
        self._client = http_client or httpx.AsyncClient(
            cookies=_refusing_cookie_jar(),
            timeout=httpx.Timeout(None, connect=CONNECT_TIMEOUT_S),  # streams may idle long
            limits=httpx.Limits(max_connections=None, max_keepalive_connections=keepalive),
            trust_env=False,  # sandbox traffic never goes through the host's HTTP proxy
        )
        self._on_shutdown = on_shutdown
        self._limits = PreviewLimits.from_settings(settings)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        kind = scope["type"]
        if kind == "lifespan":
            await self._lifespan(receive, send)
            return
        if kind not in ("http", "websocket"):
            return
        if terminal.is_terminal_request(scope, self._settings.preview_domain):
            await terminal.serve_terminal(self._settings, scope, receive, send)
            return
        if kind == "websocket" and (await receive())["type"] != "websocket.connect":
            return
        try:
            if handoff.is_handoff(scope):  # answered by the proxy, nothing reaches the app
                await self._handoff(scope, receive, send)
                return
            upstream = await self._route(scope)
            slot = self._limits.acquire(upstream.sandbox_id)  # before any upstream connection
        except (_Rejected, PreviewBusy) as rejected:
            await _reject(scope, send, rejected)
            return
        with slot:  # freed when the body is sent or the bridge closes, on errors too
            if kind == "http":
                await self._proxy_http(scope, receive, send, upstream)
            else:
                await self._proxy_websocket(scope, receive, send, upstream)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
        if self._on_shutdown is not None:
            await self._on_shutdown()

    async def _lifespan(self, receive: Receive, send: Send) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await self.aclose()
                await send({"type": "lifespan.shutdown.complete"})
                return

    def _target(self, host: str | None) -> routing.PreviewTarget | None:
        hostname = routing.strip_port(host or "").lower()
        _, dot, domain = hostname.partition(".")
        if not dot or domain != self._settings.preview_domain.lower():
            return None  # a foreign host: only the configured preview domain is served
        return routing.parse_preview_host(hostname)

    async def _started(self, scope: Scope) -> tuple[Sandbox, str, int]:
        """The sandbox, its driver ref and the port a preview host names, or the 404."""
        target = self._target(_header(scope, b"host"))
        if target is None or not routing.MIN_PORT <= target.port <= routing.MAX_PORT:
            raise _Rejected(404, "NOT_FOUND", NOT_FOUND_MESSAGE)
        sandbox = await self._lookup(target.sandbox_id)
        if sandbox is None or sandbox.state is not SandboxState.STARTED or not sandbox.driver_ref:
            raise _Rejected(404, "NOT_FOUND", NOT_FOUND_MESSAGE)
        return sandbox, sandbox.driver_ref, target.port

    async def _handoff(self, scope: Scope, receive: Receive, send: Send) -> None:
        sandbox, _, wanted = await self._started(scope)  # the 404 of any preview request
        await handoff.serve(scope, receive, send, partial(self._authorize, sandbox, wanted))

    async def _route(self, scope: Scope) -> _Upstream:
        sandbox, ref, wanted = await self._started(scope)
        query_string: bytes = scope.get("query_string") or b""
        query_token, query = split_query_token(query_string)
        cookie_token, _ = split_cookie_token(_cookie_headers(scope))
        header_token = _header(scope, TOKEN_HEADER.encode()) or None
        direct = header_token or query_token  # precedence: header, query, then the cookie
        grant = await self._authorize(sandbox, wanted, direct or cookie_token)
        if grant is not None and not direct and not fetch_metadata_consistent(_headers(scope)):
            raise _Rejected(401, PreviewTokenInvalid.code, "cross-site preview request refused")
        try:
            host, port = await self._driver.get_endpoint(ref, wanted)
        except DriverError as exc:
            logger.warning("preview endpoint for %s unavailable: %s", sandbox.id, exc.message)
            raise _Rejected(502, BAD_GATEWAY, UNREACHABLE_MESSAGE) from exc
        # Only a query token that earned the grant is kept as a cookie, never the header token.
        granted = query_token if grant is not None and not header_token else None
        return _Upstream(
            host=host,
            port=port,
            sandbox_id=sandbox.id,
            query=query,
            token_from_query=granted,
            token_in_query=query_token is not None,
            private=grant is not None,
        )

    async def _authorize(self, sandbox: Sandbox, port: int, tok: str | None) -> PreviewGrant | None:
        try:
            grant = await authorize_preview(
                self._tokens, sandbox_id=sandbox.id, port=port, public=sandbox.public, token=tok
            )
        except PreviewTokenInvalid as exc:
            raise _Rejected(401, PreviewTokenInvalid.code, exc.message) from exc
        if grant is not None and grant.org_id != sandbox.org_id:
            message = "preview token is not valid for this sandbox"
            raise _Rejected(401, PreviewTokenInvalid.code, message)
        return grant

    async def _proxy_http(
        self, scope: Scope, receive: Receive, send: Send, upstream: _Upstream
    ) -> None:
        has_body = _header(scope, b"content-length") or _header(scope, b"transfer-encoding")
        forwarded = _request_headers(scope)
        request = self._client.build_request(
            str(scope["method"]),
            _upstream_url("http", upstream, scope),
            headers=forwarded,
            content=_request_body(receive) if has_body else None,
        )
        _drop_unsent_defaults(request, self._client, {key.lower() for key, _ in forwarded})
        wait_s = self._limits.header_timeout_s  # 0 = wait for the response headers forever
        try:
            response = await send_upstream(
                self._client, request, receive, timeout_s=wait_s, watch_disconnect=not has_body
            )
        except httpx.HTTPError as exc:
            logger.warning("preview upstream request failed: %s", type(exc).__name__)
            await _reject(scope, send, _Rejected(502, BAD_GATEWAY, UNREACHABLE_MESSAGE))
            return
        if response is None:  # the client left before the sandbox answered
            return
        token, secure = upstream.token_from_query, scope.get("scheme") == "https"
        cookie = None if token is None else token_cookie(token, secure=secure)  # None: malformed
        try:
            sent = _response_headers(response, cookie)
            token_url = upstream.token_in_query  # no-store: the URL still carries the token
            headers = answer_cache_headers(sent, private=upstream.private, token_url=token_url)
            status = response.status_code
            await send({"type": "http.response.start", "status": status, "headers": headers})
            await relay_response_body(response, send, receive)  # stops early on a disconnect
        finally:
            await response.aclose()

    async def _proxy_websocket(
        self, scope: Scope, receive: Receive, send: Send, upstream: _Upstream
    ) -> None:
        offered: list[str] = scope.get("subprotocols") or []
        try:
            connection = await connect(
                _upstream_url("ws", upstream, scope),
                additional_headers=_request_headers(scope, websocket=True),
                subprotocols=[Subprotocol(name) for name in offered] or None,
                user_agent_header=_header(scope, b"user-agent"),
                proxy=None,  # like HTTP: never through the host's proxy settings
                open_timeout=CONNECT_TIMEOUT_S,
                max_size=WS_MAX_MESSAGE_BYTES,
            )
        except (OSError, TimeoutError, WebSocketException) as exc:
            logger.warning("preview upstream websocket failed: %s", type(exc).__name__)
            await _reject(scope, send, _Rejected(502, BAD_GATEWAY, UNREACHABLE_MESSAGE))
            return
        inbound = partial(_client_to_upstream, receive, connection)
        outbound = partial(_upstream_to_client, connection, send)
        try:
            await send({"type": "websocket.accept", "subprotocol": connection.subprotocol})
            async with anyio.create_task_group() as group:
                group.start_soon(_until_done, group.cancel_scope, inbound)
                group.start_soon(_until_done, group.cancel_scope, outbound)
        finally:
            await connection.close()


def create_proxy_app(
    settings: Settings | None = None,
    *,
    tokens: PreviewTokenStore | None = None,
    lookup: SandboxLookup | None = None,
    driver: EndpointDriver | None = None,
    http_client: httpx.AsyncClient | None = None,
    on_shutdown: Callable[[], Awaitable[None]] | None = None,
) -> ASGIApp:
    """Build the proxy app; ``lookup`` and ``driver`` are required, ``tokens`` is the API's store.

    At shutdown only an HTTP client the proxy created is closed, then ``on_shutdown`` runs.
    """
    if lookup is None or driver is None:
        raise NotImplementedError("create_proxy_app needs a lookup and a driver (WP 5.1)")
    install_log_redaction()  # both server paths build the proxy here
    resolved, store = settings or Settings.from_env(), tokens or InMemoryPreviewTokenStore()
    return PreviewProxy(
        resolved, store, lookup, driver, http_client=http_client, on_shutdown=on_shutdown
    )
