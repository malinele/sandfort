"""Request body limit: oversized JSON is refused with the 413 envelope, uploads are exempt.

Hermetic: the real application over a migrated temp SQLite database (FakeDriver) with a tiny
configured limit. Requests carry no credentials, so a request that gets past the limit shows
up as the application's own 401, and one that does not shows up as 413.
"""

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from alembic import command
from alembic.config import Config

from sandfort.api.app import create_app
from sandfort.api.middleware.body_limit import BodyLimitMiddleware
from sandfort.config import Settings

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 1024
KEYS = "/v1/api-keys"
UPLOAD = "/v1/sandboxes/sbx_demo/toolbox/fs/upload?path=/work/big.bin"
OVERSIZED = b'{"name": "' + b"x" * (LIMIT * 4) + b'"}'
SMALL = b'{"name": "ok"}'
CHUNK = 256
JSON_HEADERS = {"Content-Type": "application/json"}


@pytest.fixture
async def client(tmp_path: Path) -> AsyncIterator[httpx.AsyncClient]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'body.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(
        driver="fake", database_url=url, api_key_pepper="test-pepper", max_request_body_bytes=LIMIT
    )
    app = create_app(settings)
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            yield http
    finally:
        await app.state.engine.dispose()


async def chunks(body: bytes) -> AsyncIterator[bytes]:
    """Yield ``body`` in small pieces: no Content-Length, so the stream is what gets counted."""
    for start in range(0, len(body), CHUNK):
        yield body[start : start + CHUNK]


def assert_payload_too_large(response: httpx.Response) -> None:
    assert response.status_code == 413
    body = response.json()
    assert body["success"] is False
    assert body["error"]["code"] == "PAYLOAD_TOO_LARGE"
    assert body["error"]["details"] == {"max_bytes": LIMIT}


async def test_an_oversized_json_body_is_refused_by_its_content_length(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post(KEYS, content=OVERSIZED, headers=JSON_HEADERS)

    assert_payload_too_large(response)


async def test_an_oversized_chunked_body_is_cut_off_while_streaming(
    client: httpx.AsyncClient,
) -> None:
    request = client.build_request("POST", KEYS, content=chunks(OVERSIZED), headers=JSON_HEADERS)
    assert "content-length" not in request.headers

    assert_payload_too_large(await client.send(request))


async def test_a_normal_body_reaches_the_application(client: httpx.AsyncClient) -> None:
    response = await client.post(KEYS, content=SMALL, headers=JSON_HEADERS)

    assert response.status_code == 401  # the application's own answer: no credentials


async def test_a_body_exactly_at_the_limit_passes(client: httpx.AsyncClient) -> None:
    response = await client.post(KEYS, content=b" " * LIMIT, headers=JSON_HEADERS)

    assert response.status_code != 413


async def test_the_upload_route_is_exempt_from_the_limit(client: httpx.AsyncClient) -> None:
    declared = await client.put(UPLOAD, content=OVERSIZED)
    chunked = await client.send(client.build_request("PUT", UPLOAD, content=chunks(OVERSIZED)))

    assert declared.status_code != 413  # the application answers (401 here), not the limit
    assert chunked.status_code != 413


def test_the_limit_must_be_positive() -> None:
    with pytest.raises(ValueError):
        BodyLimitMiddleware(lambda *_: None, max_bytes=0)  # type: ignore[arg-type]


def test_the_limit_comes_from_the_environment() -> None:
    settings = Settings.from_env({"SANDFORT_MAX_REQUEST_BODY_BYTES": "4096"})

    assert settings.max_request_body_bytes == 4096
    assert Settings.from_env({}).max_request_body_bytes == 16 * 1024 * 1024
