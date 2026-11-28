"""Round 94: no preview token in a forwarded Referer, a referrer policy and no-store."""

from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from tests.test_proxy import (
    LOOPBACK,
    PORT,
    AsgiWebSocket,
    EchoApp,
    World,
    call,
    closed_port,
    error_code,
    host_for,
)

from sandfort.proxy.app import _request_headers
from sandfort.proxy.tokens import COOKIE_NAME, TOKEN_PARAM

TOKEN = "s3cretPreviewTok3n_value-abc"
NO_REFERRER = (b"referrer-policy", b"no-referrer")
STRICT_ORIGIN = "strict-origin"  # not no-referrer: that makes a form POST send Origin null
NO_STORE = (b"cache-control", b"no-store")


class CachingApp:
    """ASGI upstream that answers with its own Cache-Control and Referrer-Policy."""

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        assert scope["type"] == "http"
        headers = [
            (b"content-type", b"text/plain"),
            (b"cache-control", b"max-age=60"),
            (b"referrer-policy", b"origin"),
        ]
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": b"ok"})


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


@pytest.fixture
async def caching() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=CachingApp())) as client:
        yield client


# -- Referer --------------------------------------------------------------------------------


async def test_forwarded_referer_loses_the_token_but_keeps_other_params(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=True)
    host = host_for(sandbox.id)
    headers = {"referer": f"http://{host}/page?keep=1&{TOKEN_PARAM}={TOKEN}&x=2"}

    response = await call(world.proxy(upstream), "GET", host, "/a", headers=headers)

    assert response.json()["headers"]["referer"] == f"http://{host}/page?keep=1&x=2"


async def test_forwarded_referer_with_only_the_token_has_no_question_mark(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=True)
    host = host_for(sandbox.id)
    headers = {"referer": f"http://{host}/page?{TOKEN_PARAM}={TOKEN}"}

    response = await call(world.proxy(upstream), "GET", host, "/a", headers=headers)

    assert response.json()["headers"]["referer"] == f"http://{host}/page"


async def test_referer_without_a_token_is_forwarded_unchanged(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=True)
    referer = "http://other.test/a?b=1"
    headers = {"referer": referer}

    response = await call(world.proxy(upstream), "GET", host_for(sandbox.id), headers=headers)

    assert response.json()["headers"]["referer"] == referer


def test_websocket_handshake_headers_strip_the_referer_token() -> None:
    referer = f"http://h.test/page?keep=1&{TOKEN_PARAM}={TOKEN}"
    scope = {"headers": [(b"host", b"h.test"), (b"referer", referer.encode())], "scheme": "ws"}

    headers = dict(_request_headers(scope, websocket=True))

    assert headers["referer"] == "http://h.test/page?keep=1"


# -- response headers -----------------------------------------------------------------------


async def test_first_token_response_has_no_referrer_and_no_store(
    world: World, caching: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=False)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)

    response = await call(
        world.proxy(caching), "GET", host_for(sandbox.id), f"/p?{TOKEN_PARAM}={token}"
    )

    assert response.status_code == 200, response.text
    assert response.headers.get_list("referrer-policy") == [STRICT_ORIGIN]
    assert response.headers.get_list("cache-control") == ["no-store"]
    assert any(v.startswith(f"{COOKIE_NAME}=") for v in response.headers.get_list("set-cookie"))


async def test_public_sandbox_query_token_also_gets_the_headers(
    world: World, caching: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=True)

    path = f"/?{TOKEN_PARAM}=x"

    response = await call(world.proxy(caching), "GET", host_for(sandbox.id), path)

    assert response.status_code == 200, response.text
    assert response.headers.get_list("referrer-policy") == [STRICT_ORIGIN]
    assert response.headers.get_list("cache-control") == ["no-store"]


async def test_later_cookie_request_keeps_the_app_headers_but_private(
    world: World, caching: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=False)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)
    headers = {"cookie": f"{COOKIE_NAME}={token}"}

    response = await call(world.proxy(caching), "GET", host_for(sandbox.id), headers=headers)

    assert response.status_code == 200, response.text
    assert response.headers.get_list("cache-control") == ["private, max-age=60"]
    assert response.headers.get_list("vary") == ["Cookie, Sandfort-Preview-Token"]
    assert response.headers.get_list("referrer-policy") == ["origin"]


@pytest.mark.parametrize(("origin", "status"), [("same", 200), ("null", 401)])
async def test_cookie_post_needs_the_preview_origin(
    world: World, upstream: httpx.AsyncClient, origin: str, status: int
) -> None:
    sandbox = await world.add(public=False)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)
    host = host_for(sandbox.id)
    headers = {
        "cookie": f"{COOKIE_NAME}={token}",
        "origin": f"http://{host}" if origin == "same" else "null",
        "sec-fetch-site": "same-origin",
    }

    response = await call(world.proxy(upstream), "POST", host, "/form", headers=headers)

    assert response.status_code == status, response.text


async def test_request_without_a_token_gets_no_added_headers(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=True)

    response = await call(world.proxy(upstream), "GET", host_for(sandbox.id), "/p?keep=1")

    assert response.status_code == 200, response.text
    assert "cache-control" not in response.headers
    assert "referrer-policy" not in response.headers


@pytest.mark.parametrize("case", ["unknown_host", "no_token", "bad_token", "no_endpoint"])
async def test_proxy_rejections_carry_no_store_and_no_referrer(
    world: World, upstream: httpx.AsyncClient, echo: EchoApp, case: str
) -> None:
    sandbox = await world.add(public=case == "no_endpoint", endpoint=None)
    host = "nothing.example.test" if case == "unknown_host" else host_for(sandbox.id)
    path = f"/p?{TOKEN_PARAM}=bogus" if case == "bad_token" else "/p"
    expected = {"unknown_host": 404, "no_token": 401, "bad_token": 401, "no_endpoint": 502}

    response = await call(world.proxy(upstream), "GET", host, path)

    assert response.status_code == expected[case]
    assert response.headers.get_list("cache-control") == ["no-store"]
    assert response.headers.get_list("referrer-policy") == ["no-referrer"]
    assert response.headers["content-type"] == "application/json"
    assert echo.calls == 0


async def test_bad_gateway_for_a_token_request_carries_the_headers(world: World) -> None:
    sandbox = await world.add(public=False, endpoint=(LOOPBACK, closed_port()))
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)
    proxy = world.proxy()  # a real httpx client: the connection is actually refused
    try:
        response = await call(proxy, "GET", host_for(sandbox.id), f"/p?{TOKEN_PARAM}={token}")
    finally:
        await proxy.aclose()

    assert response.status_code == 502
    assert error_code(response) == "BAD_GATEWAY"
    assert response.headers.get_list("cache-control") == ["no-store"]
    assert response.headers.get_list("referrer-policy") == ["no-referrer"]


async def test_websocket_http_rejection_carries_the_headers(world: World) -> None:
    sandbox = await world.add(public=False)
    extensions: dict[str, Any] = {"websocket.http.response": {}}
    session = AsgiWebSocket(world.proxy(), host_for(sandbox.id), **extensions)
    await session.connect()

    start = await session.next()
    await session.next()
    await session.finish()

    assert start["type"] == "websocket.http.response.start"
    assert start["status"] == 401
    assert NO_REFERRER in start["headers"]
    assert NO_STORE in start["headers"]
