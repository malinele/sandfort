"""Round 103 (B27): the proxy answers /__sandfort/preview itself and swaps a posted token for
the cookie. Nothing on that path reaches the sandbox app, whatever the method."""

import base64
import hashlib
import re
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from tests.test_proxy import (
    COOKIE_NAME,
    PORT,
    AsgiWebSocket,
    EchoApp,
    World,
    call,
    error_code,
    host_for,
)

from sandfort.domain.sandbox import SandboxState

PATH = "/__sandfort/preview"
PINNED_POLICY = (
    "default-src 'none'; script-src 'sha256-m15pCaJc2RBeO8MOEHm1UVyd6lhsgKNd1nDPnAm4jGc='; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
FORM = "application/x-www-form-urlencoded"


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


def same_origin(host: str) -> dict[str, str]:
    """The headers a browser's same-origin fetch from the handoff page sends."""
    return {"origin": f"https://{host}", "sec-fetch-site": "same-origin", "content-type": FORM}


async def post_token(
    proxy: object, host: str, token: str, headers: dict[str, str] | None = None
) -> httpx.Response:
    sent = same_origin(host) if headers is None else headers
    body = f"sandfort_preview_token={token}"
    return await call(proxy, "POST", host, PATH, content=body, headers=sent)


async def test_get_serves_the_fixed_page_with_its_headers(
    world: World, upstream: httpx.AsyncClient, echo: EchoApp
) -> None:
    sandbox = await world.add(public=False)  # a private sandbox: the page needs no token

    page = await call(world.proxy(upstream), "GET", host_for(sandbox.id), PATH)

    assert page.status_code == 200
    assert page.headers["content-type"] == "text/html; charset=utf-8"
    assert page.headers["cache-control"] == "no-store"
    assert page.headers["referrer-policy"] == "same-origin"
    assert page.headers["x-content-type-options"] == "nosniff"
    assert page.headers["content-security-policy"] == PINNED_POLICY
    assert "set-cookie" not in page.headers
    assert "<noscript><p>JavaScript is needed to open this preview.</p></noscript>" in page.text
    assert echo.calls == 0


async def test_the_policy_hash_is_the_hash_of_the_one_inline_script(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=True)

    page = await call(world.proxy(upstream), "GET", host_for(sandbox.id), PATH)

    [script] = re.findall(r"<script>(.*?)</script>", page.text, re.DOTALL)
    digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
    assert f"script-src 'sha256-{digest}'" in page.headers["content-security-policy"]
    for step in (
        "location.hash",
        "history.replaceState(",
        'fetch("/__sandfort/preview"',
        'method: "POST"',
        'credentials: "same-origin"',
        'redirect: "error"',
        'location.replace("/")',
    ):
        assert step in script, step


async def test_post_sets_the_cookie_and_the_cookie_then_opens_the_app(
    world: World, upstream: httpx.AsyncClient, echo: EchoApp
) -> None:
    sandbox = await world.add(public=False)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)
    host, proxy = host_for(sandbox.id), world.proxy(upstream)

    exchanged = await post_token(proxy, host, token)
    calls_after_exchange = echo.calls
    cookie = {"cookie": f"{COOKIE_NAME}={token}", "sec-fetch-site": "same-origin"}
    opened = await call(proxy, "GET", host, "/", headers=cookie)

    assert exchanged.status_code == 204
    assert exchanged.content == b""
    assert exchanged.headers.get_list("set-cookie") == [
        f"{COOKIE_NAME}={token}; Path=/; Secure; HttpOnly; SameSite=Lax"
    ]
    assert exchanged.headers["cache-control"] == "no-store"
    assert calls_after_exchange == 0
    assert opened.status_code == 200, opened.text
    assert echo.calls == 1


async def test_public_sandbox_answers_204_without_a_cookie(
    world: World, upstream: httpx.AsyncClient, echo: EchoApp
) -> None:
    sandbox = await world.add(public=True)

    exchanged = await post_token(world.proxy(upstream), host_for(sandbox.id), "anything")

    assert exchanged.status_code == 204
    assert "set-cookie" not in exchanged.headers
    assert echo.calls == 0


@pytest.mark.parametrize(
    "headers",
    [
        {"content-type": FORM},  # no Origin at all
        {"content-type": FORM, "sec-fetch-site": "same-origin"},  # still no Origin
        {"origin": "https://evil.example", "content-type": FORM},
        {"origin": "null", "content-type": FORM},
    ],
)
async def test_post_without_the_preview_origin_is_refused(
    world: World, upstream: httpx.AsyncClient, echo: EchoApp, headers: dict[str, str]
) -> None:
    sandbox = await world.add(public=False)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)

    refused = await post_token(world.proxy(upstream), host_for(sandbox.id), token, headers)

    assert refused.status_code == 401
    assert error_code(refused) == "UNAUTHORIZED"
    assert refused.json()["error"]["message"] == "cross-site preview request refused"
    assert "set-cookie" not in refused.headers
    assert echo.calls == 0


async def test_post_with_cross_site_fetch_metadata_is_refused(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=False)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)
    host = host_for(sandbox.id)
    headers = {**same_origin(host), "sec-fetch-site": "cross-site"}

    refused = await post_token(world.proxy(upstream), host, token, headers)

    assert refused.status_code == 401
    assert refused.json()["error"]["message"] == "cross-site preview request refused"
    assert "set-cookie" not in refused.headers


async def test_post_with_a_bad_token_answers_the_401_envelope(
    world: World, upstream: httpx.AsyncClient, echo: EchoApp
) -> None:
    sandbox = await world.add(public=False)
    other_port = await world.tokens.mint(world.org_id, sandbox.id, PORT + 1)
    host, proxy = host_for(sandbox.id), world.proxy(upstream)

    unknown = await post_token(proxy, host, "not-a-minted-token")
    wrong_port = await post_token(proxy, host, other_port)
    missing = await call(proxy, "POST", host, PATH, content=b"", headers=same_origin(host))

    for refused in (unknown, wrong_port, missing):
        assert refused.status_code == 401
        assert error_code(refused) == "UNAUTHORIZED"
        assert refused.headers["cache-control"] == "no-store"
        assert "set-cookie" not in refused.headers
    assert echo.calls == 0


async def test_a_token_of_another_org_is_refused(world: World, upstream: httpx.AsyncClient) -> None:
    sandbox = await world.add(public=False)
    token = await world.tokens.mint("org_other", sandbox.id, PORT)

    refused = await post_token(world.proxy(upstream), host_for(sandbox.id), token)

    assert refused.status_code == 401


async def test_an_oversized_form_is_refused_with_413(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=True)

    refused = await post_token(world.proxy(upstream), host_for(sandbox.id), "a" * 2000)

    assert refused.status_code == 413
    assert error_code(refused) == "PAYLOAD_TOO_LARGE"


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "HEAD"])
async def test_other_methods_answer_405_and_never_reach_the_app(
    world: World, upstream: httpx.AsyncClient, echo: EchoApp, method: str
) -> None:
    sandbox = await world.add(public=True)

    refused = await call(world.proxy(upstream), method, host_for(sandbox.id), PATH)

    assert refused.status_code == 405
    assert refused.headers["allow"] == "GET, POST"
    assert echo.calls == 0


async def test_a_stopped_sandbox_or_a_foreign_host_is_not_found(
    world: World, upstream: httpx.AsyncClient
) -> None:
    stopped = await world.add(public=True, state=SandboxState.STOPPED)
    proxy = world.proxy(upstream)

    page = await call(proxy, "GET", host_for(stopped.id), PATH)
    posted = await post_token(proxy, host_for(stopped.id), "anything")
    foreign = await call(proxy, "GET", "app.example.com", PATH)

    assert [r.status_code for r in (page, posted, foreign)] == [404, 404, 404]


async def test_a_percent_encoded_path_is_answered_by_the_proxy(
    world: World, upstream: httpx.AsyncClient, echo: EchoApp
) -> None:
    sandbox = await world.add(public=True)

    page = await call(world.proxy(upstream), "GET", host_for(sandbox.id), "/__sandfort/%70review")

    assert page.status_code == 200
    assert page.headers["content-security-policy"] == PINNED_POLICY
    assert echo.calls == 0


async def test_a_neighbouring_path_still_reaches_the_app(
    world: World, upstream: httpx.AsyncClient, echo: EchoApp
) -> None:
    sandbox = await world.add(public=True)

    response = await call(world.proxy(upstream), "GET", host_for(sandbox.id), PATH + "/x")

    assert response.status_code == 200
    assert response.json()["path"] == PATH + "/x"
    assert echo.calls == 1


async def test_a_websocket_on_the_path_is_refused_without_an_upstream(world: World) -> None:
    sandbox = await world.add(public=True)
    socket = AsgiWebSocket(world.proxy(), host_for(sandbox.id), PATH)

    await socket.connect()
    first = await socket.next()
    await socket.finish()

    assert first == {"type": "websocket.close", "code": 1008}


def test_b27_files_stay_small() -> None:
    root = Path(__file__).resolve().parents[1]
    paths = [
        root / "src" / "sandfort" / "proxy" / "handoff.py",
        root / "src" / "sandfort" / "proxy" / "answers.py",
        root / "src" / "sandfort" / "proxy" / "app.py",
        Path(__file__),
        Path(__file__).with_name("test_proxy_header_token_b27.py"),
    ]
    for path in paths:
        lines = path.read_text().splitlines()
        assert len(lines) < 400, path
        assert all(len(line) <= 100 for line in lines), path
