"""API messages and preview tokens (round 57, contract persona findings).

* The fs download ``max_bytes`` query answers one bound message naming the accepted range
  (1 to the inline read cap) for every out-of-range value: 0, a negative value and a value
  above the cap. Non-digit forms keep the plain-digits parsing message. Error types are the
  ones round 56 pinned (``greater_than_equal``, ``int_parsing``, ``less_than_equal``).
* Minting a preview token on a sandbox that is not started answers the shared 409
  ``no_container`` with ``state`` and the visible ``stop_cause`` in the details, as the
  toolbox does; once the sandbox is started again the mint works.

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
from sandfort.api.schemas.toolbox_fs import MAX_INLINE_READ_BYTES
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
CONFLICT_STATUS = 409
VALIDATION_STATUS = 422
SCOPES = frozenset({Scope.SANDBOXES_WRITE, Scope.SANDBOXES_READ, Scope.TOOLBOX})
FILE_PATH = "/tmp/r57.txt"
FILE_BODY = b"hello world"
PREVIEW_PORT = 3000
BOUND_MESSAGE = f"Input should be an integer from 1 to {MAX_INLINE_READ_BYTES}"
PARSING_MESSAGE = "Input should be a non-negative integer written as plain digits"


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'limits57.db'}"
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
    org = Org(id=new_org_id(), name="Limits", slug="limits", created_at=NOW)
    generated = generate_api_key(PEPPER)
    key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="limits",
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


@pytest.fixture
async def sandbox_id(client: httpx.AsyncClient, headers: dict[str, str]) -> str:
    response = await client.post(SANDBOXES, json={}, headers=headers)
    assert response.status_code == CREATED_STATUS, response.text
    value: str = response.json()["data"]["id"]
    return value


def validation_issues(response: httpx.Response) -> list[dict[str, Any]]:
    assert response.status_code == VALIDATION_STATUS, response.text
    payload: dict[str, Any] = response.json()
    assert payload["success"] is False
    assert payload["error"]["code"] == "VALIDATION_ERROR"
    issues: list[dict[str, Any]] = payload["error"]["details"]["errors"]
    return issues


# --- fs download max_bytes --------------------------------------------------------------------

OUT_OF_RANGE = [
    pytest.param("0", "greater_than_equal", id="zero"),
    pytest.param("-1", "int_parsing", id="minus-one"),
    pytest.param("-0", "int_parsing", id="minus-zero"),
    pytest.param("-5", "int_parsing", id="minus-five"),
    pytest.param(str(MAX_INLINE_READ_BYTES + 1), "less_than_equal", id="cap-plus-one"),
    pytest.param("12345678901234567890", "less_than_equal", id="twenty-digits"),
    pytest.param("9" * 5000, "less_than_equal", id="five-thousand-digits"),
    pytest.param("-" + "9" * 5000, "int_parsing", id="minus-five-thousand-digits"),
]
NOT_DIGITS = ["5.0", "+5", " 5", "5 ", "5e0", "0x5", "-5.0", "--5", "abc", "٥"]


async def write_file(client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str) -> None:
    response = await client.put(
        f"{SANDBOXES}/{sandbox_id}/toolbox/fs/upload",
        params={"path": FILE_PATH},
        content=FILE_BODY,
        headers={**headers, "Content-Type": "application/octet-stream"},
    )
    assert response.status_code == OK_STATUS, response.text


async def download_inline(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, max_bytes: str
) -> httpx.Response:
    return await client.get(
        f"{SANDBOXES}/{sandbox_id}/toolbox/fs/download",
        params={"path": FILE_PATH, "inline": "true", "max_bytes": max_bytes},
        headers=headers,
    )


@pytest.mark.parametrize(("max_bytes", "kind"), OUT_OF_RANGE)
async def test_out_of_range_max_bytes_answers_the_bound_message(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    sandbox_id: str,
    max_bytes: str,
    kind: str,
) -> None:
    response = await download_inline(client, headers, sandbox_id, max_bytes)

    [issue] = validation_issues(response)
    assert issue["loc"] == ["query", "max_bytes"]
    assert issue["type"] == kind
    assert issue["msg"] == BOUND_MESSAGE


@pytest.mark.parametrize("max_bytes", NOT_DIGITS)
async def test_non_digit_max_bytes_keeps_the_parsing_message(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, max_bytes: str
) -> None:
    response = await download_inline(client, headers, sandbox_id, max_bytes)

    [issue] = validation_issues(response)
    assert issue["loc"] == ["query", "max_bytes"]
    assert issue["type"] == "int_parsing"
    assert issue["msg"] == PARSING_MESSAGE


@pytest.mark.parametrize("max_bytes", ["1", "01", str(MAX_INLINE_READ_BYTES)])
async def test_max_bytes_inside_the_range_still_reads(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, max_bytes: str
) -> None:
    await write_file(client, headers, sandbox_id)

    response = await download_inline(client, headers, sandbox_id, max_bytes)

    assert response.status_code == OK_STATUS, response.text
    limit = int(max_bytes)
    data = response.json()["data"]
    assert data["content"] == FILE_BODY[:limit].decode()
    assert data["truncated"] is (limit < len(FILE_BODY))


async def test_download_without_max_bytes_still_reads(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    await write_file(client, headers, sandbox_id)

    response = await client.get(
        f"{SANDBOXES}/{sandbox_id}/toolbox/fs/download",
        params={"path": FILE_PATH, "inline": "true"},
        headers=headers,
    )

    assert response.status_code == OK_STATUS, response.text
    assert response.json()["data"]["content"] == FILE_BODY.decode()


# --- preview token on a sandbox that is not started -------------------------------------------


async def mint(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> httpx.Response:
    path = f"{SANDBOXES}/{sandbox_id}/preview-tokens"
    return await client.post(path, json={"port": PREVIEW_PORT}, headers=headers)


async def lifecycle(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, action: str
) -> None:
    response = await client.post(f"{SANDBOXES}/{sandbox_id}/{action}", headers=headers)
    assert response.status_code == OK_STATUS, response.text


async def test_preview_token_on_a_stopped_sandbox_is_no_container(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    await lifecycle(client, headers, sandbox_id, "stop")

    response = await mint(client, headers, sandbox_id)

    assert response.status_code == CONFLICT_STATUS, response.text
    error = response.json()["error"]
    assert error["code"] == "CONFLICT"
    assert error["message"] == "sandbox has no container instance; start it first"
    assert error["details"] == {
        "reason": "no_container",
        "state": "stopped",
        "stop_cause": "requested",
    }


async def test_preview_token_after_restart_still_mints(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    await lifecycle(client, headers, sandbox_id, "stop")
    await lifecycle(client, headers, sandbox_id, "start")

    response = await mint(client, headers, sandbox_id)

    assert response.status_code == CREATED_STATUS, response.text
    assert response.json()["data"]["port"] == PREVIEW_PORT


async def test_preview_token_on_a_started_sandbox_still_mints(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    response = await mint(client, headers, sandbox_id)

    assert response.status_code == CREATED_STATUS, response.text
    assert response.json()["data"]["token"]
