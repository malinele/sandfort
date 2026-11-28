"""Round 101 (B32): no httpx default header or cookie jar entry reaches the sandbox app."""

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from tests.test_proxy import LOOPBACK, AsgiWebSocket, EchoApp, World, host_for
from websockets.asyncio.server import ServerConnection, serve

from sandfort.proxy.app import _refusing_cookie_jar, _request_headers

CLIENT_PEER = ("203.0.113.9", 50000)
FORWARDING = ("forwarded", "x-real-ip", "x-forwarded-port", "x-forwarded-scheme")
HTTPX_DEFAULTS = {"accept", "accept-encoding", "connection", "user-agent"}


@pytest.fixture
def world() -> World:
    return World()


@pytest.fixture
def echo() -> EchoApp:
    return EchoApp()


@pytest.fixture
async def upstream(echo: EchoApp) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=echo)) as client:
        yield client


async def raw_call(
    app: Any,
    host: str,
    headers: dict[str, str] | None = None,
    client: tuple[str, int] | None = None,
) -> tuple[int, bytes]:
    """One GET / into ``app`` as raw ASGI messages, so no test client adds headers."""
    scope: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [(b"host", host.encode())]
        + [(key.encode(), value.encode()) for key, value in (headers or {}).items()],
        "server": ("proxy.test", 80),
        "client": client,
    }
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await app(scope, receive, send)
    status: int = sent[0]["status"]
    return status, b"".join(message.get("body", b"") for message in sent[1:])


async def echoed_headers(app: Any, host: str, *args: Any) -> dict[str, str]:
    status, body = await raw_call(app, host, *args)
    assert status == 200, body
    echoed: dict[str, str] = json.loads(body)["headers"]
    return echoed


async def test_client_without_headers_reaches_the_app_with_only_the_proxy_headers(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=True)
    host = host_for(sandbox.id)

    headers = await echoed_headers(world.proxy(upstream), host)

    assert set(headers) == {"host", "x-forwarded-host", "x-forwarded-proto"}
    assert not HTTPX_DEFAULTS & set(headers)


@pytest.mark.parametrize(
    ("sent", "absent"),
    [
        pytest.param(
            {"user-agent": "agent/1.0"},
            ("accept", "accept-encoding", "connection"),
            id="user-agent-only",
        ),
        pytest.param(
            {"accept-encoding": "br"},
            ("accept", "user-agent", "connection"),
            id="accept-encoding-only",
        ),
        pytest.param(
            {"accept": "text/html", "connection": "keep-alive"},
            ("accept-encoding", "user-agent", "connection"),
            id="hop-by-hop-connection-is-never-sent",
        ),
    ],
)
async def test_only_the_defaults_the_client_did_not_send_are_removed(
    world: World, upstream: httpx.AsyncClient, sent: dict[str, str], absent: tuple[str, ...]
) -> None:
    sandbox = await world.add(public=True)
    kept = {name: value for name, value in sent.items() if name != "connection"}

    echoed = await echoed_headers(world.proxy(upstream), host_for(sandbox.id), sent)

    assert {name: echoed.get(name) for name in kept} == kept
    assert not set(absent) & set(echoed)


@pytest.mark.parametrize("name", FORWARDING)
async def test_client_forwarding_header_is_not_forwarded(
    world: World, upstream: httpx.AsyncClient, name: str
) -> None:
    sandbox = await world.add(public=True)
    host = host_for(sandbox.id)

    echoed = await echoed_headers(world.proxy(upstream), host, {name: "6.6.6.6"}, CLIENT_PEER)

    assert name not in echoed


async def test_upstream_cookies_never_reach_the_next_request(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=True)
    host = host_for(sandbox.id)
    proxy = world.proxy(upstream)  # EchoApp answers every request with Set-Cookie a=1 and b=2

    first = await echoed_headers(proxy, host)
    second = await echoed_headers(proxy, host)
    third = await echoed_headers(proxy, host, {"cookie": "theme=dark"})

    assert "cookie" not in first
    assert "cookie" not in second
    assert third["cookie"] == "theme=dark"


@pytest.mark.parametrize("websocket", [False, True])
def test_client_forwarding_headers_are_replaced_by_the_proxys_own(websocket: bool) -> None:
    scope: dict[str, Any] = {
        "headers": [
            (b"host", b"h.test"),
            (b"forwarded", b"for=6.6.6.6"),
            (b"x-real-ip", b"6.6.6.6"),
            (b"x-forwarded-port", b"1"),
            (b"x-forwarded-scheme", b"https"),
            (b"x-forwarded-for", b"6.6.6.6"),
            (b"x-forwarded-host", b"evil.test"),
            (b"x-forwarded-proto", b"https"),
            (b"x-custom", b"kept"),
        ],
        "scheme": "ws",
        "client": CLIENT_PEER,
    }

    headers = _request_headers(scope, websocket=websocket)

    assert headers == [
        ("x-custom", "kept"),
        ("x-forwarded-host", "h.test"),
        ("x-forwarded-proto", "http"),
        ("x-forwarded-for", "203.0.113.9"),
    ]


async def handshake_headers(world: World, headers: dict[str, str]) -> dict[str, str]:
    seen: dict[str, str] = {}

    async def record(connection: ServerConnection) -> None:
        if connection.request is not None:
            seen.update({k.lower(): v for k, v in connection.request.headers.raw_items()})
        async for _ in connection:
            pass

    async with serve(record, LOOPBACK, 0) as server:
        port: int = server.sockets[0].getsockname()[1]
        sandbox = await world.add(public=True, endpoint=(LOOPBACK, port))
        session = AsgiWebSocket(world.proxy(), host_for(sandbox.id), headers=headers)
        await session.connect()
        accepted = await session.next()
        await session.push({"type": "websocket.disconnect", "code": 1000})
        await session.finish()
    assert accepted["type"] == "websocket.accept"
    return seen


async def test_websocket_handshake_adds_no_user_agent_or_encoding(world: World) -> None:
    seen = await handshake_headers(world, {})

    assert "user-agent" not in seen
    assert "accept-encoding" not in seen


async def test_websocket_handshake_drops_client_forwarding_headers(world: World) -> None:
    headers = {
        "user-agent": "agent/1.0",
        "x-custom": "kept",
        "forwarded": "for=6.6.6.6",
        "x-real-ip": "6.6.6.6",
        "x-forwarded-port": "1",
        "x-forwarded-scheme": "https",
        "x-forwarded-for": "6.6.6.6",
    }

    seen = await handshake_headers(world, headers)

    assert seen["user-agent"] == "agent/1.0"
    assert seen["x-custom"] == "kept"
    assert seen["x-forwarded-for"] == LOOPBACK
    for name in FORWARDING:
        assert name not in seen


async def test_default_client_sends_no_httpx_headers_on_the_wire(world: World) -> None:
    captured: list[bytes] = []

    async def answer(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        captured.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(answer, LOOPBACK, 0)
    port: int = server.sockets[0].getsockname()[1]
    async with server:
        sandbox = await world.add(public=True, endpoint=(LOOPBACK, port))
        proxy = world.proxy()
        try:
            status, _ = await raw_call(proxy, host_for(sandbox.id))
        finally:
            await proxy.aclose()
    lines = captured[0].decode("latin-1").split("\r\n")[1:]
    names = {line.partition(":")[0].lower() for line in lines if line}

    assert status == 200
    assert names == {"host", "x-forwarded-host", "x-forwarded-proto"}


def test_refusing_cookie_jar_stores_no_upstream_cookie() -> None:
    cookies = httpx.Cookies(_refusing_cookie_jar())
    request = httpx.Request("GET", "http://10.0.0.5:8080/login")
    response = httpx.Response(200, headers=[("set-cookie", "session=abc; Path=/")], request=request)

    cookies.extract_cookies(response)

    assert len(cookies.jar) == 0


def test_a_default_jar_would_store_the_same_cookie() -> None:
    cookies = httpx.Cookies()
    request = httpx.Request("GET", "http://10.0.0.5:8080/login")
    response = httpx.Response(200, headers=[("set-cookie", "session=abc; Path=/")], request=request)

    cookies.extract_cookies(response)

    assert len(cookies.jar) == 1
