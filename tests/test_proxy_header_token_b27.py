"""Round 103 (B27): the Sandfort-Preview-Token request header and the mint's browser_url.

The proxy reads the token from the header first, then the query, then the cookie. The header
is never forwarded and needs no fetch-metadata check. The mint response carries browser_url
only for an https preview origin.
"""

from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import pytest
from tests.test_api_keys import SANDBOX_SCOPES, SANDBOXES, auth, open_world, seed_key
from tests.test_proxy import (
    COOKIE_NAME,
    DOMAIN,
    LOOPBACK,
    PORT,
    SETTINGS,
    TOKEN_PARAM,
    UNUSED_UPSTREAM_PORT,
    EchoApp,
    World,
    call,
    host_for,
)

from sandfort.api.routes.sandbox_preview import PreviewTokenResponse, browser_url, preview_url
from sandfort.api.wiring import sandbox_lookup
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_sandbox_id
from sandfort.proxy.app import _request_headers, create_proxy_app

HEADER = "sandfort-preview-token"
CROSS_SITE = {"origin": "https://evil.example", "sec-fetch-site": "cross-site"}
HTTPS_SETTINGS = replace(SETTINGS, public_preview_url=f"https://{DOMAIN}")


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


async def test_header_token_opens_a_private_sandbox_and_is_not_forwarded(
    world: World, upstream: httpx.AsyncClient, echo: EchoApp
) -> None:
    sandbox = await world.add(public=False)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)
    headers = {"Sandfort-Preview-Token": token, **CROSS_SITE}  # not ambient: no origin check

    response = await call(world.proxy(upstream), "GET", host_for(sandbox.id), "/p", headers=headers)

    assert response.status_code == 200, response.text
    assert HEADER not in response.json()["headers"]
    assert token not in response.text
    assert not any(COOKIE_NAME in value for value in response.headers.get_list("set-cookie"))
    assert echo.calls == 1


async def test_a_bad_header_token_is_refused_even_with_a_good_query_token(
    world: World, upstream: httpx.AsyncClient, echo: EchoApp
) -> None:
    sandbox = await world.add(public=False)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)
    path = f"/p?{TOKEN_PARAM}={token}"

    refused = await call(
        world.proxy(upstream), "GET", host_for(sandbox.id), path, headers={HEADER: "bogus"}
    )

    assert refused.status_code == 401
    assert echo.calls == 0


async def test_a_good_header_token_beats_a_bad_query_token_and_sets_no_cookie(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=False)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)
    path = f"/p?keep=1&{TOKEN_PARAM}=bogus"

    response = await call(
        world.proxy(upstream), "GET", host_for(sandbox.id), path, headers={HEADER: token}
    )

    assert response.status_code == 200, response.text
    assert response.json()["query"] == "keep=1"
    assert not any(COOKIE_NAME in value for value in response.headers.get_list("set-cookie"))
    assert response.headers["referrer-policy"] == "strict-origin"  # the URL still has a token


async def test_a_bad_header_token_beats_a_good_cookie(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=False)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)
    headers = {HEADER: "bogus", "cookie": f"{COOKIE_NAME}={token}"}

    refused = await call(world.proxy(upstream), "GET", host_for(sandbox.id), "/", headers=headers)

    assert refused.status_code == 401


async def test_a_bad_query_token_beats_a_good_cookie(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=False)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)
    path = f"/?{TOKEN_PARAM}=bogus"

    refused = await call(
        world.proxy(upstream),
        "GET",
        host_for(sandbox.id),
        path,
        headers={"cookie": f"{COOKIE_NAME}={token}"},
    )

    assert refused.status_code == 401


async def test_an_empty_header_counts_as_absent(world: World, upstream: httpx.AsyncClient) -> None:
    sandbox = await world.add(public=False)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)
    path = f"/?{TOKEN_PARAM}={token}"

    response = await call(
        world.proxy(upstream), "GET", host_for(sandbox.id), path, headers={HEADER: ""}
    )

    assert response.status_code == 200, response.text
    assert any(COOKIE_NAME in value for value in response.headers.get_list("set-cookie"))


@pytest.mark.parametrize("websocket", [False, True])
def test_the_header_is_dropped_from_forwarded_headers(websocket: bool) -> None:
    scope = {
        "type": "websocket" if websocket else "http",
        "scheme": "http",
        "headers": [(b"host", b"h"), (b"Sandfort-Preview-Token", b"tok"), (b"x-keep", b"1")],
        "client": (LOOPBACK, 50000),
    }

    forwarded = _request_headers(scope, websocket=websocket)

    assert [value for key, value in forwarded if key.lower() == HEADER] == []
    assert ("x-keep", "1") in forwarded


def test_browser_url_is_the_handoff_link_on_an_https_origin_only() -> None:
    sandbox_id = new_sandbox_id()
    host = host_for(sandbox_id)
    with_port = replace(SETTINGS, public_preview_url=f"https://{DOMAIN}:8443")

    https = browser_url(HTTPS_SETTINGS, sandbox_id, PORT, "tok")
    https_port = browser_url(with_port, sandbox_id, PORT, "tok")
    plain = replace(SETTINGS, public_preview_url=f"http://{DOMAIN}")

    assert https == f"https://{host}/__sandfort/preview#sandfort_preview_token=tok"
    assert https_port == f"https://{host}:8443/__sandfort/preview#sandfort_preview_token=tok"
    assert browser_url(SETTINGS, sandbox_id, PORT, "tok") is None
    assert browser_url(plain, sandbox_id, PORT, "tok") is None
    assert preview_url(HTTPS_SETTINGS, sandbox_id, PORT, "tok") == (
        f"https://{host}?sandfort_preview_token=tok"
    )


def test_an_absent_browser_url_is_left_out_of_the_json() -> None:
    expires_at = datetime(2026, 11, 28, tzinfo=UTC)
    bare = PreviewTokenResponse(token="t", url="u", port=PORT, expires_at=expires_at)
    full = PreviewTokenResponse(
        token="t", url="u", browser_url="b", port=PORT, expires_at=expires_at
    )

    assert "browser_url" not in bare.model_dump(mode="json")
    assert full.model_dump(mode="json")["browser_url"] == "b"


@pytest.mark.parametrize("origin", ["", "http"])
async def test_a_plain_http_server_mints_no_browser_url(tmp_path: Path, origin: str) -> None:
    public = f"http://{DOMAIN}" if origin else ""
    async with open_world(tmp_path, public_preview_url=public) as keys:
        headers = auth(await seed_key(keys.app, keys.org_id, SANDBOX_SCOPES))
        created = await keys.client.post(SANDBOXES, json={"public": False}, headers=headers)
        sandbox_id = created.json()["data"]["id"]
        path = f"{SANDBOXES}/{sandbox_id}/preview-tokens"
        minted = await keys.client.post(path, json={"port": PORT}, headers=headers)

    assert minted.status_code == 201, minted.text
    data = minted.json()["data"]
    assert "browser_url" not in data
    assert data["url"].endswith(f"?sandfort_preview_token={data['token']}")


async def test_an_https_server_mints_a_browser_url_the_proxy_hands_off(
    tmp_path: Path, upstream: httpx.AsyncClient, echo: EchoApp
) -> None:
    async with open_world(tmp_path, public_preview_url=f"https://{DOMAIN}") as keys:
        headers = auth(await seed_key(keys.app, keys.org_id, SANDBOX_SCOPES))
        created = await keys.client.post(SANDBOXES, json={"public": False}, headers=headers)
        sandbox_id = created.json()["data"]["id"]
        path = f"{SANDBOXES}/{sandbox_id}/preview-tokens"
        minted = await keys.client.post(path, json={"port": PORT}, headers=headers)
        driver: FakeDriver = keys.app.state.driver
        [info] = [item for item in await driver.list_managed() if item.sandbox_id == sandbox_id]
        driver.register_endpoint(info.ref, LOOPBACK, UNUSED_UPSTREAM_PORT)
        proxy = create_proxy_app(
            keys.app.state.settings,
            tokens=keys.app.state.preview_tokens,
            lookup=sandbox_lookup(keys.app.state.session_factory),
            driver=driver,
            http_client=upstream,
        )
        data = minted.json()["data"]
        link = urlsplit(data["browser_url"])
        host = host_for(sandbox_id)
        page = await call(proxy, "GET", host, link.path)
        name, _, token = link.fragment.partition("=")
        form = {"origin": f"https://{host}", "content-type": "application/x-www-form-urlencoded"}
        exchanged = await call(proxy, "POST", host, link.path, content=link.fragment, headers=form)
        cookie = {"cookie": f"{COOKIE_NAME}={token}"}
        opened = await call(proxy, "GET", host, "/", headers=cookie)

    assert minted.status_code == 201, minted.text
    assert data["browser_url"] == (
        f"https://{host}/__sandfort/preview#sandfort_preview_token={data['token']}"
    )
    assert data["url"] == f"https://{host}?sandfort_preview_token={data['token']}"
    assert (name, token) == ("sandfort_preview_token", data["token"])
    assert page.status_code == 200
    assert exchanged.status_code == 204
    assert opened.status_code == 200, opened.text
    assert echo.calls == 1  # only the last request reached the app
