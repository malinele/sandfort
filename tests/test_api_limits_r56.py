"""Numeric request rules (round 56, persona findings).

* ``true``/``false`` on the session command ``timeout_s``, the code-context run and run/stream
  ``timeout_s`` and the preview-token ``port``/``ttl_seconds`` answer 422 ``number_not_bool``
  naming the field (before, a boolean was read as 1 or refused only by the lower bound).
* The fs download ``max_bytes`` query takes plain decimal digits only (``"5.0"``, ``" 5"``,
  ``"+5"`` are 422 ``int_parsing``) and at most the inline read cap the handler defaults to
  (above it, a 20-digit value included, is 422 ``less_than_equal``).

Each field also has a valid value that still works. Through the API on the fake driver and a
temp SQLite database; no network and no sockets.
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
from sandfort.api.schemas.common import BOOL_NOT_NUMBER_TYPE
from sandfort.api.schemas.toolbox_fs import MAX_INLINE_READ_BYTES
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import Sandbox
from sandfort.drivers.base import ExecResult, SandboxDriver
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.toolbox import code_context_stream, code_contexts

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
OK_STATUS = 200
CREATED_STATUS = 201
VALIDATION_STATUS = 422
CONTEXT_ID = "ctx_0123456789abcdef"
SCOPES = frozenset({Scope.SANDBOXES_WRITE, Scope.SANDBOXES_READ, Scope.TOOLBOX})
BOOLEANS = [pytest.param(True, id="true"), pytest.param(False, id="false")]
FILE_PATH = "/tmp/r56.txt"
FILE_BODY = b"hello world"


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'limits56.db'}"
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


@pytest.fixture
async def session_id(client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str) -> str:
    path = f"{SANDBOXES}/{sandbox_id}/toolbox/process/sessions"
    response = await client.post(path, json={}, headers=headers)
    assert response.status_code == CREATED_STATUS, response.text
    value: str = response.json()["data"]["id"]
    return value


@pytest.fixture
def cell_timeouts(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Stand in for the kernel: every context exists and every cell answers ``5``."""
    seen: list[float] = []

    async def run_in_context(
        driver: SandboxDriver,
        sandbox: Sandbox,
        context_id: str,
        code: str,
        *,
        timeout_s: float,
        cell: int | None = None,
        runner: object = None,
    ) -> code_contexts.ContextRun:
        seen.append(timeout_s)
        return code_contexts.ContextRun(ExecResult(exit_code=0), result="5")

    async def ensure_context(driver: SandboxDriver, sandbox: Sandbox, context_id: str) -> None:
        return None

    monkeypatch.setattr(code_contexts, "run_in_context", run_in_context)
    monkeypatch.setattr(code_context_stream, "ensure_context", ensure_context)
    return seen


def error_kinds(response: httpx.Response) -> list[tuple[str, list[str]]]:
    assert response.status_code == VALIDATION_STATUS, response.text
    payload: dict[str, Any] = response.json()
    assert payload["success"] is False
    assert payload["error"]["code"] == "VALIDATION_ERROR"
    return [(issue["type"], issue["loc"]) for issue in payload["error"]["details"]["errors"]]


# --- session command timeout ------------------------------------------------------------------


def commands_path(sandbox_id: str, session_id: str) -> str:
    return f"{SANDBOXES}/{sandbox_id}/toolbox/process/sessions/{session_id}/commands"


@pytest.mark.parametrize("value", BOOLEANS)
async def test_boolean_session_command_timeout_is_refused(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    sandbox_id: str,
    session_id: str,
    value: bool,
) -> None:
    body = {"command": "true", "timeout_s": value}

    response = await client.post(commands_path(sandbox_id, session_id), json=body, headers=headers)

    assert error_kinds(response) == [(BOOL_NOT_NUMBER_TYPE, ["body", "timeout_s"])]


async def test_numeric_session_command_timeout_still_runs(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, session_id: str
) -> None:
    body = {"command": "true", "timeout_s": 5}

    response = await client.post(commands_path(sandbox_id, session_id), json=body, headers=headers)

    assert response.status_code == OK_STATUS, response.text
    assert response.json()["data"]["mode"] == "sync"


# --- code-context run and run/stream timeout --------------------------------------------------

RUN_SUFFIXES = [pytest.param("run", id="run"), pytest.param("run/stream", id="run-stream")]


def run_path(sandbox_id: str, suffix: str) -> str:
    return f"{SANDBOXES}/{sandbox_id}/toolbox/code-contexts/{CONTEXT_ID}/{suffix}"


@pytest.mark.parametrize("suffix", RUN_SUFFIXES)
@pytest.mark.parametrize("value", BOOLEANS)
async def test_boolean_code_context_timeout_is_refused(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    sandbox_id: str,
    cell_timeouts: list[float],
    suffix: str,
    value: bool,
) -> None:
    body = {"code": "5", "timeout_s": value}

    response = await client.post(run_path(sandbox_id, suffix), json=body, headers=headers)

    assert error_kinds(response) == [(BOOL_NOT_NUMBER_TYPE, ["body", "timeout_s"])]
    assert cell_timeouts == []  # refused before any cell ran


async def test_numeric_code_context_timeout_still_runs(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, cell_timeouts: list[float]
) -> None:
    body = {"code": "5", "timeout_s": 5}

    response = await client.post(run_path(sandbox_id, "run"), json=body, headers=headers)

    assert response.status_code == OK_STATUS, response.text
    assert response.json()["data"]["result"] == "5"
    assert cell_timeouts == [5.0]


async def test_numeric_code_context_stream_timeout_still_streams(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, cell_timeouts: list[float]
) -> None:
    body = {"code": "5", "timeout_s": 5}

    response = await client.post(run_path(sandbox_id, "run/stream"), json=body, headers=headers)

    assert response.status_code == OK_STATUS, response.text
    assert "event: result" in response.text
    assert cell_timeouts == [5.0]


# --- preview token port and ttl_seconds -------------------------------------------------------

PREVIEW_BOOL_CASES = [
    pytest.param({"port": True}, "port", id="port-true"),
    pytest.param({"port": False}, "port", id="port-false"),
    pytest.param({"port": 3000, "ttl_seconds": True}, "ttl_seconds", id="ttl-true"),
    pytest.param({"port": 3000, "ttl_seconds": False}, "ttl_seconds", id="ttl-false"),
]


@pytest.mark.parametrize(("body", "field"), PREVIEW_BOOL_CASES)
async def test_boolean_preview_token_number_is_refused(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    sandbox_id: str,
    body: dict[str, Any],
    field: str,
) -> None:
    path = f"{SANDBOXES}/{sandbox_id}/preview-tokens"

    response = await client.post(path, json=body, headers=headers)

    assert error_kinds(response) == [(BOOL_NOT_NUMBER_TYPE, ["body", field])]


async def test_numeric_preview_token_still_mints(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    path = f"{SANDBOXES}/{sandbox_id}/preview-tokens"

    response = await client.post(path, json={"port": 3000, "ttl_seconds": 120}, headers=headers)

    assert response.status_code == CREATED_STATUS, response.text
    assert response.json()["data"]["port"] == 3000


# --- fs download max_bytes --------------------------------------------------------------------

NOT_PLAIN_DIGITS = ["5.0", " 5", "5 ", "+5", "5e0", "-5", "0x5", "٥"]
ABOVE_CAP = [str(MAX_INLINE_READ_BYTES + 1), "268435457", "12345678901234567890"]


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


@pytest.mark.parametrize("max_bytes", NOT_PLAIN_DIGITS)
async def test_download_max_bytes_must_be_plain_digits(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, max_bytes: str
) -> None:
    response = await download_inline(client, headers, sandbox_id, max_bytes)

    assert error_kinds(response) == [("int_parsing", ["query", "max_bytes"])]


@pytest.mark.parametrize("max_bytes", ABOVE_CAP)
async def test_download_max_bytes_above_the_cap_is_refused(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, max_bytes: str
) -> None:
    response = await download_inline(client, headers, sandbox_id, max_bytes)

    assert error_kinds(response) == [("less_than_equal", ["query", "max_bytes"])]


async def test_download_max_bytes_zero_is_still_below_the_floor(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    response = await download_inline(client, headers, sandbox_id, "0")

    assert error_kinds(response) == [("greater_than_equal", ["query", "max_bytes"])]


async def test_download_with_a_plain_max_bytes_still_reads(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    await write_file(client, headers, sandbox_id)

    response = await download_inline(client, headers, sandbox_id, "5")

    assert response.status_code == OK_STATUS, response.text
    data = response.json()["data"]
    assert data["content"] == FILE_BODY[:5].decode()
    assert data["truncated"] is True


async def test_download_with_max_bytes_at_the_cap_still_reads(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    await write_file(client, headers, sandbox_id)

    response = await download_inline(client, headers, sandbox_id, str(MAX_INLINE_READ_BYTES))

    assert response.status_code == OK_STATUS, response.text
    data = response.json()["data"]
    assert data["content"] == FILE_BODY.decode()
    assert data["truncated"] is False
