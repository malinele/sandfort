"""Docs pages answer HEAD with the GET status and headers and an empty body."""

from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.docs_pages import SWAGGER_INIT_PATH
from sandfort.config import Settings

PATHS = ["/docs", "/redoc", SWAGGER_INIT_PATH]


@pytest.fixture
async def app() -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    settings = Settings(
        driver="fake", database_url="sqlite+aiosqlite:///:memory:", api_key_pepper="test-pepper"
    )
    application = create_app(settings)
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.mark.parametrize("path", PATHS)
async def test_head_answers_200_with_the_get_content_type_and_no_body(
    client: httpx.AsyncClient, path: str
) -> None:
    got = await client.get(path)
    head = await client.head(path)

    assert got.status_code == 200
    assert head.status_code == 200
    assert head.headers["content-type"] == got.headers["content-type"]
    assert head.content == b""


@pytest.mark.parametrize("path", ["/docs", "/redoc"])
async def test_head_on_a_page_carries_the_get_content_security_policy(
    client: httpx.AsyncClient, path: str
) -> None:
    got = await client.get(path)
    head = await client.head(path)

    assert "content-security-policy" in got.headers
    assert head.headers["content-security-policy"] == got.headers["content-security-policy"]


async def test_head_on_the_bootstrap_script_matches_the_get_headers(
    client: httpx.AsyncClient,
) -> None:
    got = await client.get(SWAGGER_INIT_PATH)
    head = await client.head(SWAGGER_INIT_PATH)

    assert head.headers.get("content-security-policy") == got.headers.get(
        "content-security-policy"
    )
    assert head.headers["cache-control"] == got.headers["cache-control"]
