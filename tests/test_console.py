"""The read-only web console page: served unauthenticated, strict csp, no storage, no assets."""

import re
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from alembic import command
from alembic.config import Config

from sandfort.api.app import create_app
from sandfort.config import Settings

ROOT = Path(__file__).resolve().parents[1]
CONSOLE = "/console"
POLICY_NONCE = re.compile(r"script-src 'nonce-([\w-]+)'")
SCRIPT_NONCE = re.compile(r'<script nonce="([\w-]+)">')


@pytest.fixture
async def client(tmp_path: Path) -> AsyncIterator[httpx.AsyncClient]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'console.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    app = create_app(Settings(driver="fake", database_url=url, api_key_pepper="test-pepper"))
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            yield http
    finally:
        await app.state.engine.dispose()


async def test_page_is_served_with_strict_headers(client: httpx.AsyncClient) -> None:
    response = await client.get(CONSOLE)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    policy = response.headers["content-security-policy"]
    assert "default-src 'none'" in policy
    assert "connect-src 'self'" in policy
    assert POLICY_NONCE.search(policy)
    assert "unsafe-inline" not in policy
    assert "http:" not in policy
    assert "https:" not in policy


async def test_inline_script_carries_the_policy_nonce(client: httpx.AsyncClient) -> None:
    response = await client.get(CONSOLE)

    policy_nonce = POLICY_NONCE.search(response.headers["content-security-policy"])
    script_nonce = SCRIPT_NONCE.search(response.text)
    assert policy_nonce is not None
    assert script_nonce is not None
    assert script_nonce.group(1) == policy_nonce.group(1)


async def test_nonce_differs_between_responses(client: httpx.AsyncClient) -> None:
    first = await client.get(CONSOLE)
    second = await client.get(CONSOLE)

    assert first.headers["content-security-policy"] != second.headers["content-security-policy"]


async def test_page_has_no_external_sources(client: httpx.AsyncClient) -> None:
    html = (await client.get(CONSOLE)).text

    assert not re.search(r"""\b(?:src|href|action)\s*=\s*["']?\s*(?:https?:)?//""", html)
    assert "http://" not in html
    assert "https://" not in html
    assert "<link" not in html
    assert "@import" not in html
    assert not re.search(r"<script[^>]+\bsrc=", html)


async def test_page_never_references_browser_storage(client: httpx.AsyncClient) -> None:
    html = (await client.get(CONSOLE)).text

    assert "localStorage" not in html
    assert "sessionStorage" not in html
    assert "document.cookie" not in html
    assert "indexedDB" not in html
    assert "location.search" not in html


async def test_page_assigns_values_as_text_only(client: httpx.AsyncClient) -> None:
    html = (await client.get(CONSOLE)).text

    assert "textContent" in html
    assert "innerHTML" not in html
    assert "insertAdjacentHTML" not in html


async def test_page_needs_no_authorization_but_data_routes_do(client: httpx.AsyncClient) -> None:
    page = await client.get(CONSOLE)
    sandboxes = await client.get("/v1/sandboxes")
    nodes = await client.get("/v1/nodes")
    audit = await client.get("/v1/audit-events")

    assert page.status_code == 200
    assert sandboxes.status_code == 401
    assert nodes.status_code == 401
    assert audit.status_code == 401


async def test_console_route_is_not_in_the_schema(client: httpx.AsyncClient) -> None:
    schema = (await client.get("/openapi.json")).json()

    assert CONSOLE not in schema["paths"]
