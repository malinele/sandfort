"""Request inputs a contract tester found under-validated (round 53).

* ``POST .../toolbox/git/clone`` ``depth``: bounded below only; it now has an upper bound
  (``MAX_CLONE_DEPTH``) and an out-of-range value is a validation error naming the field.
* ``PUT .../toolbox/fs/upload``: the tar header takes its size from Content-Length, so a
  ``size_bytes`` query that disagreed with it was silently ignored (200). A mismatch is now
  422 ``UNPROCESSABLE`` naming both sizes, refused before the body is read; nothing is written.

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
from sandfort.api.schemas.toolbox_git import MAX_CLONE_DEPTH, GitCloneRequest
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
NOT_FOUND_STATUS = 404
VALIDATION_STATUS = 422
REPO_URL = "https://example.test/repo.git"
PAYLOAD = b"hello world"


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'limits53.db'}"
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
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as http:
        yield http


@pytest.fixture
async def headers(app: FastAPI) -> dict[str, str]:
    org = Org(id=new_org_id(), name="Limits", slug="limits53", created_at=NOW)
    generated = generate_api_key(PEPPER)
    key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="limits",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset({Scope.SANDBOXES_WRITE, Scope.SANDBOXES_READ, Scope.TOOLBOX}),
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(key)
        await uow.commit()
    return {"Authorization": f"Bearer {generated.key}"}


@pytest.fixture
async def sandbox_id(client: httpx.AsyncClient, headers: dict[str, str]) -> str:
    response = await client.post(SANDBOXES, json={}, headers=headers)
    assert response.status_code == CREATED_STATUS, response.text
    value: str = response.json()["data"]["id"]
    return value


def validation_locations(response: httpx.Response) -> list[list[str]]:
    payload: dict[str, Any] = response.json()
    if payload["success"] or payload["error"]["code"] != "VALIDATION_ERROR":
        return []
    return [issue["loc"] for issue in payload["error"]["details"]["errors"]]


async def clone(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, depth: int
) -> httpx.Response:
    body = {"url": REPO_URL, "path": "/work/repo", "depth": depth}
    return await client.post(
        f"{SANDBOXES}/{sandbox_id}/toolbox/git/clone", json=body, headers=headers
    )


def upload_url(sandbox_id: str) -> str:
    return f"{SANDBOXES}/{sandbox_id}/toolbox/fs/upload"


async def download(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, path: str
) -> httpx.Response:
    return await client.get(
        f"{SANDBOXES}/{sandbox_id}/toolbox/fs/download", params={"path": path}, headers=headers
    )


# --- git clone: depth -------------------------------------------------------------------


@pytest.mark.parametrize("depth", [MAX_CLONE_DEPTH + 1, 2**63, 10**30])
async def test_clone_depth_above_the_bound_answers_422_naming_the_field(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, depth: int
) -> None:
    response = await clone(client, headers, sandbox_id, depth)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert ["body", "depth"] in validation_locations(response)


@pytest.mark.parametrize("depth", [1, 50, MAX_CLONE_DEPTH])
async def test_clone_depth_within_the_bound_passes_validation(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, depth: int
) -> None:
    response = await clone(client, headers, sandbox_id, depth)

    assert ["body", "depth"] not in validation_locations(response), response.text


def test_clone_depth_bound_is_in_the_field_description() -> None:
    description = GitCloneRequest.model_fields["depth"].description or ""

    assert str(MAX_CLONE_DEPTH) in description


# --- fs upload: declared size ----------------------------------------------------------


@pytest.mark.parametrize("declared", [len(PAYLOAD) - 1, len(PAYLOAD) + 1, 0])
async def test_upload_size_bytes_differing_from_the_body_is_422_and_writes_nothing(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, declared: int
) -> None:
    params = {"path": "/work/a.txt", "size_bytes": declared}

    response = await client.put(
        upload_url(sandbox_id), params=params, content=PAYLOAD, headers=headers
    )

    assert response.status_code == VALIDATION_STATUS, response.text
    error = response.json()["error"]
    assert error["code"] == "UNPROCESSABLE"
    assert str(declared) in error["message"]
    assert str(len(PAYLOAD)) in error["message"]
    assert error["details"] == {"declared_bytes": declared, "received_bytes": len(PAYLOAD)}
    missing = await download(client, headers, sandbox_id, "/work/a.txt")
    assert missing.status_code == NOT_FOUND_STATUS, missing.text


async def test_chunked_upload_shorter_than_size_bytes_is_422_and_writes_nothing(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    async def body() -> AsyncIterator[bytes]:
        yield PAYLOAD

    declared = len(PAYLOAD) + 4
    params = {"path": "/work/a.txt", "size_bytes": declared}

    response = await client.put(
        upload_url(sandbox_id), params=params, content=body(), headers=headers
    )

    assert response.status_code == VALIDATION_STATUS, response.text
    error = response.json()["error"]
    assert error["code"] == "UNPROCESSABLE"
    assert str(declared) in error["message"]
    assert str(len(PAYLOAD)) in error["message"]
    missing = await download(client, headers, sandbox_id, "/work/a.txt")
    assert missing.status_code == NOT_FOUND_STATUS, missing.text


async def test_upload_with_a_matching_size_bytes_still_uploads(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    params = {"path": "/work/a.txt", "size_bytes": len(PAYLOAD)}

    response = await client.put(
        upload_url(sandbox_id), params=params, content=PAYLOAD, headers=headers
    )

    assert response.status_code == OK_STATUS, response.text
    assert response.json()["data"] == {"path": "/work/a.txt", "size_bytes": len(PAYLOAD)}
    stored = await download(client, headers, sandbox_id, "/work/a.txt")
    assert stored.content == PAYLOAD


async def test_upload_without_size_bytes_uses_content_length(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    response = await client.put(
        upload_url(sandbox_id), params={"path": "/work/b.txt"}, content=PAYLOAD, headers=headers
    )

    assert response.status_code == OK_STATUS, response.text
    assert response.json()["data"]["size_bytes"] == len(PAYLOAD)
