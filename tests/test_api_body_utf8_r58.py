"""A JSON body with invalid UTF-8 answers the standard 422 shape (round 58).

The request text guard refuses such a body before the framework parser runs, so the answer is
``VALIDATION_ERROR`` with ``details.errors`` (type ``invalid_utf8``, loc ``["body"]``) instead of
the framework's 400 ``HTTP_400``. The message never carries the offending bytes. A valid UTF-8
body is unaffected and a non-JSON upload may carry any bytes.

Through the API on the fake driver and a temp SQLite database; no network and no sockets.
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.text_guard import has_invalid_utf8
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
OK_STATUS = 200
CREATED_STATUS = 201
VALIDATION_STATUS = 422
SCOPES = frozenset({Scope.SANDBOXES_WRITE, Scope.SANDBOXES_READ, Scope.TOOLBOX})

BAD_BODIES = [
    pytest.param(b'{"name": "\xff\xfe"}', id="invalid-start-byte"),
    pytest.param(b'{"name": "\xc3("}', id="bad-continuation"),
    pytest.param(b'{"name": "abc\xe2\x82"}', id="truncated-sequence"),
    pytest.param(b'{"labels": {"k\xff": "v"}}', id="bad-key"),
    pytest.param(b'{"name": "\xc0\xaf"}', id="overlong"),
]


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'utf8_58.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.fixture
async def headers(app: FastAPI) -> dict[str, str]:
    org = Org(id=new_org_id(), name="Utf8", slug="utf8", created_at=NOW)
    generated = generate_api_key(PEPPER)
    key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="utf8",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=SCOPES,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(key)
        await uow.commit()
    return {"Authorization": f"Bearer {generated.key}", "Content-Type": "application/json"}


async def listed(client: httpx.AsyncClient, headers: dict[str, str]) -> list[Any]:
    response = await client.get(SANDBOXES, headers=headers)
    assert response.status_code == OK_STATUS, response.text
    rows: list[Any] = response.json()["data"]
    return rows


@pytest.mark.parametrize("body", BAD_BODIES)
async def test_create_with_invalid_utf8_answers_the_standard_shape(
    client: httpx.AsyncClient, headers: dict[str, str], body: bytes
) -> None:
    response = await client.post(SANDBOXES, content=body, headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    payload: dict[str, Any] = response.json()
    assert payload["success"] is False
    assert payload["error"]["code"] == "VALIDATION_ERROR"
    issues = payload["error"]["details"]["errors"]
    assert [(issue["type"], issue["loc"]) for issue in issues] == [("invalid_utf8", ["body"])]
    assert "\xff" not in response.text and "�" not in response.text
    assert await listed(client, headers) == []


async def test_valid_utf8_body_is_unaffected(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    body = '{"labels": {"naziv": "šđčćž 名前 👨‍👩‍👧"}}'.encode()

    response = await client.post(SANDBOXES, content=body, headers=headers)

    assert response.status_code == CREATED_STATUS, response.text
    assert len(await listed(client, headers)) == 1


async def test_binary_upload_with_a_non_json_type_is_still_accepted(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    created = await client.post(SANDBOXES, json={}, headers=headers)
    assert created.status_code == CREATED_STATUS, created.text
    sandbox_id = created.json()["data"]["id"]
    upload = {"Authorization": headers["Authorization"], "Content-Type": "application/octet-stream"}

    response = await client.put(
        f"{SANDBOXES}/{sandbox_id}/toolbox/fs/upload",
        params={"path": "/tmp/raw.bin"},
        content=b"\xff\xfe\x00\x80binary",
        headers=upload,
    )

    assert response.status_code != VALIDATION_STATUS, response.text


def test_has_invalid_utf8_leaves_other_encodings_and_surrogates_alone() -> None:
    assert has_invalid_utf8(b'{"a": "\xff"}')
    assert not has_invalid_utf8(b'{"a": "ok"}')
    assert not has_invalid_utf8('{"a": "č"}'.encode())
    assert not has_invalid_utf8('{"a": "č"}'.encode("utf-16"))
    assert not has_invalid_utf8(b'{"a": "\xed\xa0\x80"}')  # an encoded surrogate: its own rule
