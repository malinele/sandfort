"""Round 99 (B29): no preview token in any forwarded request header (an edge's X-Url too)."""

import json
from collections.abc import AsyncIterator

import httpx
import pytest
from tests.test_proxy import PORT, EchoApp, World, call, host_for

from sandfort.proxy.app import _request_headers
from sandfort.proxy.hygiene import strip_header_token
from sandfort.proxy.tokens import TOKEN_PARAM

TOKEN = "s3cretPreviewTok3n_value-abc"


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


async def test_edge_x_url_loses_the_token_and_keeps_other_params(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=True)
    host = host_for(sandbox.id)
    headers = {"x-url": f"https://{host}/a?keep=1&{TOKEN_PARAM}={TOKEN}&x=2"}

    response = await call(world.proxy(upstream), "GET", host, "/a", headers=headers)

    assert response.json()["headers"]["x-url"] == f"https://{host}/a?keep=1&x=2"


async def test_edge_x_pathname_with_only_the_token_has_no_question_mark(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=True)
    host = host_for(sandbox.id)
    headers = {"x-pathname": f"/a?{TOKEN_PARAM}={TOKEN}"}

    response = await call(world.proxy(upstream), "GET", host, "/a", headers=headers)

    assert response.json()["headers"]["x-pathname"] == "/a"


@pytest.mark.parametrize(
    "name", ["x-original-uri", "x-forwarded-uri", "x-rewrite-url", "x-original-url"]
)
async def test_other_url_headers_lose_the_token(
    world: World, upstream: httpx.AsyncClient, name: str
) -> None:
    sandbox = await world.add(public=True)
    host = host_for(sandbox.id)
    headers = {name: f"/p?{TOKEN_PARAM}={TOKEN}#frag"}

    response = await call(world.proxy(upstream), "GET", host, "/p", headers=headers)

    assert response.json()["headers"][name] == "/p#frag"


async def test_first_private_request_with_edge_headers_reaches_the_app_without_the_token(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=False)
    host = host_for(sandbox.id)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)
    target = f"/p?q=1&{TOKEN_PARAM}={token}"
    headers = {"x-url": f"https://{host}{target}", "x-pathname": target}  # what the edge sets

    response = await call(world.proxy(upstream), "GET", host, target, headers=headers)

    assert response.status_code == 200, response.text
    echoed = response.json()
    assert echoed["query"] == "q=1"
    assert token not in json.dumps(echoed["headers"])
    assert echoed["headers"]["x-url"] == f"https://{host}/p?q=1"
    assert echoed["headers"]["x-pathname"] == "/p?q=1"


async def test_header_without_a_token_is_forwarded_byte_exact(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=True)
    value = "https://h.test/a?b=1&c=%20#f"

    response = await call(
        world.proxy(upstream), "GET", host_for(sandbox.id), headers={"x-url": value}
    )

    assert response.json()["headers"]["x-url"] == value


def test_websocket_handshake_headers_strip_the_token_from_x_url() -> None:
    url = f"https://h.test/p?keep=1&{TOKEN_PARAM}={TOKEN}"
    scope = {"headers": [(b"host", b"h.test"), (b"x-url", url.encode())], "scheme": "ws"}

    headers = dict(_request_headers(scope, websocket=True))

    assert headers["x-url"] == "https://h.test/p?keep=1"


P = TOKEN_PARAM


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(
            f"https://h.test/a?keep=1&{P}={TOKEN}&x=2",
            "https://h.test/a?keep=1&x=2",
            id="between-params",
        ),
        pytest.param(f"/a?{P}={TOKEN}", "/a", id="only-the-token"),
        pytest.param(f"/a?{P}={TOKEN}&x=2", "/a?x=2", id="first-of-several"),
        pytest.param(f"/p?{P}={TOKEN}#frag", "/p#frag", id="fragment-survives"),
        pytest.param(f"/a?x=1#y&{P}={TOKEN}", "/a?x=1#y", id="after-a-hash"),
        pytest.param(
            f"/a?sandfort%5Fpreview%5Ftoken={TOKEN}&b=1", "/a?b=1", id="percent-escaped-upper"
        ),
        pytest.param(f"/a?sandfort%5fpreview%5ftoken={TOKEN}", "/a", id="percent-escaped-lower"),
        pytest.param(f"/a?{P}=one&{P}=two&k=v", "/a?k=v", id="repeated-parameter"),
        pytest.param(
            f"https://a/?x=1, https://b/?{P}={TOKEN}",
            "https://a/?x=1, https://b/",
            id="second-url-in-a-list",
        ),
        pytest.param(
            f"Mozilla (what?) https://h/?{P}={TOKEN}",
            "Mozilla (what?) https://h/",
            id="question-mark-earlier-in-the-value",
        ),
        pytest.param("https://h.test/a?b=1&c=%20#f", "https://h.test/a?b=1&c=%20#f", id="no-token"),
        pytest.param('{"q": "a?b", "n": 1}', '{"q": "a?b", "n": 1}', id="json-without-equals"),
        pytest.param(
            "Mozilla/5.0 (X11; Linux x86_64) what?",
            "Mozilla/5.0 (X11; Linux x86_64) what?",
            id="user-agent",
        ),
    ],
)
def test_strip_header_token_cases(value: str, expected: str) -> None:
    assert strip_header_token(value) == expected


async def test_hash_after_the_query_does_not_hide_the_token_from_the_app(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=True)
    host = host_for(sandbox.id)
    headers = {"x-url": f"https://{host}/a?x=1#y&{TOKEN_PARAM}={TOKEN}"}

    response = await call(world.proxy(upstream), "GET", host, "/a", headers=headers)

    assert response.json()["headers"]["x-url"] == f"https://{host}/a?x=1#y"


def test_strip_header_token_removes_every_copy_however_many() -> None:
    value = "/a?k=v" + f"&{TOKEN_PARAM}=t" * 200

    result = strip_header_token(value)

    assert result == "/a?k=v"
