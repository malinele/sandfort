"""Round 103 (B27 follow-up): no shared cache keeps a proxied answer of a private sandbox.

Whatever carried the grant (the header, the query or the cookie), the answer of a private
sandbox says ``private`` in ``Cache-Control`` and names the token's carriers in ``Vary``. The
query path keeps its ``no-store``, a public sandbox keeps what its app sent, and websocket
upgrades are not touched. The expected values come from the round 103 review decision, not
from running the code.
"""

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from tests.test_proxy import (
    COOKIE_NAME,
    LOOPBACK,
    PORT,
    TOKEN_PARAM,
    AsgiWebSocket,
    EchoApp,
    World,
    call,
    host_for,
)
from websockets.asyncio.server import ServerConnection, serve

from sandfort.proxy.caching import VARY_ON, answer_cache_headers, private_cache_headers
from sandfort.proxy.hygiene import with_token_response_headers
from sandfort.proxy.tokens import TOKEN_HEADER

ROOT = Path(__file__).resolve().parents[1]
VARY_BOTH = "Cookie, Sandfort-Preview-Token"
HTML = (b"content-type", b"text/html")


def values(headers: list[tuple[bytes, bytes]], name: bytes) -> list[bytes]:
    return [value for key, value in headers if key.lower() == name]


# -- the pure rule ------------------------------------------------------------------------


def test_public_and_max_age_become_private_and_max_age() -> None:
    result = private_cache_headers([HTML, (b"Cache-Control", b"public, max-age=600")])

    assert values(result, b"cache-control") == [b"private, max-age=600"]
    assert values(result, b"vary") == [VARY_BOTH.encode()]
    assert values(result, b"content-type") == [b"text/html"]


def test_an_answer_without_cache_control_gets_private() -> None:
    result = private_cache_headers([HTML])

    assert values(result, b"cache-control") == [b"private"]
    assert values(result, b"vary") == [VARY_BOTH.encode()]


def test_only_the_shared_cache_directives_are_dropped_in_any_case() -> None:
    sent = b"Public, S-MaxAge=60, no-cache, max-age=0, must-revalidate, Proxy-Revalidate, immutable"

    result = private_cache_headers([(b"cache-control", sent)])

    assert values(result, b"cache-control") == [
        b"private, no-cache, max-age=0, must-revalidate, immutable"
    ]


def test_a_private_that_names_fields_becomes_a_bare_private() -> None:
    sent = b'private="set-cookie, x-user", max-age=5, no-cache="a, b"'

    result = private_cache_headers([(b"cache-control", sent)])

    assert values(result, b"cache-control") == [b'private, max-age=5, no-cache="a, b"']


def test_cache_control_lines_are_merged_into_one() -> None:
    sent = [(b"Cache-Control", b"max-age=60"), (b"cache-control", b"public, immutable")]

    result = private_cache_headers(sent)

    assert values(result, b"cache-control") == [b"private, max-age=60, immutable"]


def test_vary_gains_the_carriers_it_lacks_without_duplicates() -> None:
    sent = [(b"Vary", b"Accept-Encoding, cookie"), (b"vary", b"Origin")]

    result = private_cache_headers(sent)

    assert values(result, b"vary") == [b"Accept-Encoding, cookie, Origin, Sandfort-Preview-Token"]


def test_vary_star_is_left_as_sent() -> None:
    result = private_cache_headers([(b"Vary", b"*"), (b"cache-control", b"public")])

    assert [(k, v) for k, v in result if k.lower() == b"vary"] == [(b"Vary", b"*")]
    assert values(result, b"cache-control") == [b"private"]


def test_cdn_targeted_cache_headers_are_dropped() -> None:
    sent = [
        HTML,
        (b"CDN-Cache-Control", b"max-age=600"),
        (b"Cloudflare-CDN-Cache-Control", b"max-age=600"),
        (b"Surrogate-Control", b"max-age=600"),
    ]

    result = private_cache_headers(sent)

    assert {key.lower() for key, _ in result} == {b"content-type", b"cache-control", b"vary"}


def test_other_headers_keep_their_order_and_values() -> None:
    sent = [
        HTML,
        (b"set-cookie", b"a=1"),
        (b"cache-control", b"max-age=1"),
        (b"set-cookie", b"b=2"),
    ]

    result = private_cache_headers(sent)

    assert result[:3] == [HTML, (b"set-cookie", b"a=1"), (b"set-cookie", b"b=2")]


def test_the_vary_names_are_the_cookie_and_the_token_header() -> None:
    assert [name.lower() for name in VARY_ON] == ["cookie", TOKEN_HEADER]


def test_answer_rule_a_token_url_gets_no_store() -> None:
    sent = [HTML, (b"cache-control", b"public, max-age=600")]

    for private in (True, False):
        result = answer_cache_headers(sent, private=private, token_url=True)
        assert result == with_token_response_headers(sent)
        assert values(result, b"cache-control") == [b"no-store"]


def test_answer_rule_private_and_public() -> None:
    sent = [HTML, (b"cache-control", b"public, max-age=600")]

    private = answer_cache_headers(sent, private=True, token_url=False)
    public = answer_cache_headers(sent, private=False, token_url=False)

    assert values(private, b"cache-control") == [b"private, max-age=600"]
    assert public == sent


# -- through the proxy --------------------------------------------------------------------


class CachingApp:
    """ASGI upstream that answers with a shared-cache friendly Cache-Control."""

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        assert scope["type"] == "http"
        headers = [HTML, (b"cache-control", b"public, max-age=600")]
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": b"ok"})


@pytest.fixture
def world() -> World:
    return World()


@pytest.fixture
async def caching() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=CachingApp())) as client:
        yield client


@pytest.fixture
async def echo_client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=EchoApp())) as client:
        yield client


@pytest.mark.parametrize("carrier", ["header", "cookie"])
async def test_a_private_answer_is_private_for_the_header_and_the_cookie_grant(
    world: World, caching: httpx.AsyncClient, carrier: str
) -> None:
    sandbox = await world.add(public=False)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)
    name, value = (
        (TOKEN_HEADER, token) if carrier == "header" else ("cookie", f"{COOKIE_NAME}={token}")
    )

    response = await call(world.proxy(caching), "GET", host_for(sandbox.id), headers={name: value})

    assert response.status_code == 200, response.text
    assert response.headers.get_list("cache-control") == ["private, max-age=600"]
    assert response.headers.get_list("vary") == [VARY_BOTH]


async def test_a_private_answer_without_cache_control_gets_private(
    world: World, echo_client: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=False)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)

    response = await call(
        world.proxy(echo_client), "GET", host_for(sandbox.id), headers={TOKEN_HEADER: token}
    )

    assert response.status_code == 200, response.text
    assert response.headers.get_list("cache-control") == ["private"]
    assert response.headers.get_list("vary") == [VARY_BOTH]


async def test_the_query_grant_keeps_no_store(world: World, caching: httpx.AsyncClient) -> None:
    sandbox = await world.add(public=False)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)

    response = await call(
        world.proxy(caching), "GET", host_for(sandbox.id), f"/?{TOKEN_PARAM}={token}"
    )

    assert response.status_code == 200, response.text
    assert response.headers.get_list("cache-control") == ["no-store"]


async def test_a_public_sandbox_answer_passes_unchanged(
    world: World, caching: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=True)

    response = await call(world.proxy(caching), "GET", host_for(sandbox.id))

    assert response.status_code == 200, response.text
    assert response.headers.get_list("cache-control") == ["public, max-age=600"]
    assert "vary" not in response.headers


async def test_a_private_websocket_upgrade_is_not_affected(world: World) -> None:
    async def greet(connection: ServerConnection) -> None:
        await connection.send("welcome")

    async with serve(greet, LOOPBACK, 0) as server:
        upstream_port: int = server.sockets[0].getsockname()[1]
        sandbox = await world.add(public=False, endpoint=(LOOPBACK, upstream_port))
        token = await world.tokens.mint(world.org_id, sandbox.id, PORT)
        session = AsgiWebSocket(world.proxy(), host_for(sandbox.id), headers={TOKEN_HEADER: token})
        await session.connect()

        accepted = await session.next()
        greeting = await session.next()
        await session.push({"type": "websocket.disconnect", "code": 1000})
        await session.finish()

    assert accepted == {"type": "websocket.accept", "subprotocol": None}
    assert greeting == {"type": "websocket.send", "text": "welcome"}


def test_cache_files_stay_small() -> None:
    app = ROOT / "src" / "sandfort" / "proxy" / "app.py"
    for path in (app, ROOT / "src" / "sandfort" / "proxy" / "caching.py", Path(__file__)):
        lines = path.read_text().splitlines()
        assert len(lines) < 400, path
        assert all(len(line) <= 100 for line in lines), path
    assert len(app.read_text().splitlines()) <= 378  # the round 103 size of app.py
