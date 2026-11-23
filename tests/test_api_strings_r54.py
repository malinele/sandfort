"""Request text guard on the URL path, and numeric coercion (round 54, second server batch).

* Path: a percent-encoded lone surrogate (``%ED%A0%80``) or an invalid UTF-8 byte sequence
  (``%FF``) in a path segment answered 404 with U+FFFD echoed, and the audit row stored that
  path. The guard now reads the raw path bytes and answers 422 ``VALIDATION_ERROR`` at
  ``["path"]`` before routing, for HTTP and websocket handshakes; nothing is audited. A valid
  non-ASCII segment still routes.
* Booleans: ``true``/``false`` on the exec and code-run ``timeout_s``, the git clone ``depth``,
  the API key ``max_sandboxes`` and the PTY ``rows``/``cols`` answer 422 naming the field;
  the numeric forms accepted before still are.
* Upload ``size_bytes``: plain digits only, at most the upload limit.
* Audit list: a period whose ``to`` is not after ``from`` answers like the export.

Through the API on the fake driver and a temp SQLite database; no network and no sockets.
"""

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from pydantic import BaseModel, ValidationError

from sandfort.api.app import create_app
from sandfort.api.schemas.api_keys import CreateApiKeyRequest
from sandfort.api.schemas.common import BOOL_NOT_NUMBER_TYPE
from sandfort.api.schemas.toolbox_fs import FsDownloadRequest, FsUploadRequest
from sandfort.api.schemas.toolbox_git import GitCloneRequest
from sandfort.api.schemas.toolbox_process import CodeRunRequest, ExecuteRequest
from sandfort.api.schemas.toolbox_pty import PtyCreateRequest, PtyResizeRequest
from sandfort.api.text_guard import (
    NUL_TYPE,
    SURROGATE_TYPE,
    UTF8_TYPE,
    WS_DENIAL_EXTENSION,
    WS_POLICY_VIOLATION,
    Finding,
    path_findings,
)
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
AUDIT_EVENTS = "/v1/audit-events"
OK_STATUS = 200
CREATED_STATUS = 201
NOT_FOUND_STATUS = 404
VALIDATION_STATUS = 422
REPLACEMENT = "�"
BAD_SEGMENTS = [
    ("sbx_%ED%A0%80", SURROGATE_TYPE),  # UTF-8 form of the lone surrogate U+D800
    ("sbx_%ff", UTF8_TYPE),
    ("sbx_%C0%AF", UTF8_TYPE),  # overlong encoding of '/'
    ("sbx_a%E2%82", UTF8_TYPE),  # truncated sequence
]
GOOD_SEGMENTS = ["caf%C3%A9", "%F0%9F%98%80", "%E0%B8%AA%E0%B8%A7"]
TOOLBOX_SCOPES = frozenset(
    {Scope.SANDBOXES_WRITE, Scope.SANDBOXES_READ, Scope.TOOLBOX, Scope.AUDIT_READ}
)


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'strings54.db'}"
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
    org = Org(id=new_org_id(), name="Strings", slug="strings", created_at=NOW)
    generated = generate_api_key(PEPPER)
    key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="strings",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=TOOLBOX_SCOPES | {Scope.API_KEYS_ADMIN},
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


def error_kinds(payload: dict[str, Any]) -> list[tuple[str, list[str]]]:
    assert payload["success"] is False
    assert payload["error"]["code"] == "VALIDATION_ERROR"
    return [(issue["type"], issue["loc"]) for issue in payload["error"]["details"]["errors"]]


async def audit_rows(client: httpx.AsyncClient, headers: dict[str, str]) -> list[Any]:
    response = await client.get(AUDIT_EVENTS, params={"limit": 100}, headers=headers)
    assert response.status_code == OK_STATUS, response.text
    rows: list[Any] = response.json()["data"]
    return rows


# --- path: raw bytes --------------------------------------------------------------------------


def raw_and_decoded(path: str) -> tuple[bytes, str]:
    """The raw path a server receives and the path it decodes (U+FFFD for bad bytes)."""
    return path.encode("ascii"), unquote(path)


@pytest.mark.parametrize(("segment", "kind"), BAD_SEGMENTS)
def test_path_findings_read_the_raw_bytes(segment: str, kind: str) -> None:
    raw, decoded = raw_and_decoded(f"{SANDBOXES}/{segment}")

    assert path_findings(decoded, raw) == [Finding(("path",), kind)]


@pytest.mark.parametrize("segment", GOOD_SEGMENTS)
def test_path_findings_accept_valid_utf8(segment: str) -> None:
    raw, decoded = raw_and_decoded(f"{SANDBOXES}/{segment}")

    assert path_findings(decoded, raw) == []


def test_a_query_string_left_on_the_raw_path_is_not_the_path() -> None:
    assert path_findings(SANDBOXES, f"{SANDBOXES}?q=%FF".encode("ascii")) == []


def test_path_nul_is_still_refused_without_a_raw_path() -> None:
    assert path_findings(f"{SANDBOXES}/a\x00b") == [Finding(("path",), NUL_TYPE)]


@pytest.mark.parametrize(("segment", "kind"), BAD_SEGMENTS)
async def test_bad_path_segment_answers_422_and_leaves_no_audit_row(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, segment: str, kind: str
) -> None:
    before = await audit_rows(client, headers)

    response = await client.post(f"{SANDBOXES}/{segment}/stop", headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert error_kinds(response.json()) == [(kind, ["path"])]
    assert REPLACEMENT not in response.text
    assert before
    assert await audit_rows(client, headers) == before


@pytest.mark.parametrize("segment", GOOD_SEGMENTS)
async def test_valid_non_ascii_path_segment_still_routes(
    client: httpx.AsyncClient, headers: dict[str, str], segment: str
) -> None:
    response = await client.get(f"{SANDBOXES}/{segment}", headers=headers)

    assert response.status_code == NOT_FOUND_STATUS, response.text
    assert response.json()["error"]["code"] == "NOT_FOUND"


async def websocket_handshake(app: FastAPI, path: str, *, denial: bool) -> list[Any]:
    """One websocket handshake straight to the ASGI app, as a server would decode the path."""
    sent: list[Any] = []
    raw, decoded = raw_and_decoded(path)

    async def receive() -> dict[str, Any]:
        return {"type": "websocket.connect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "websocket",
        "asgi": {"version": "3.0"},
        "scheme": "ws",
        "path": decoded,
        "raw_path": raw,
        "root_path": "",
        "query_string": b"token=abc",
        "headers": [],
        "client": ("127.0.0.1", 1),
        "server": ("test", 80),
        "subprotocols": [],
        "extensions": {WS_DENIAL_EXTENSION: {}} if denial else {},
    }
    await app(scope, receive, send)
    return sent


def pty_connect(segment: str) -> str:
    return f"{SANDBOXES}/{segment}/toolbox/pty/pty_1/connect"


@pytest.mark.parametrize(("segment", "kind"), BAD_SEGMENTS)
async def test_websocket_with_a_bad_path_gets_the_422_envelope(
    app: FastAPI,
    client: httpx.AsyncClient,
    headers: dict[str, str],
    sandbox_id: str,
    segment: str,
    kind: str,
) -> None:
    before = await audit_rows(client, headers)

    sent = await websocket_handshake(app, pty_connect(segment), denial=True)

    assert sent[0]["type"] == "websocket.http.response.start"
    assert sent[0]["status"] == VALIDATION_STATUS
    parts = [m.get("body", b"") for m in sent if m["type"] == "websocket.http.response.body"]
    assert error_kinds(json.loads(b"".join(parts))) == [(kind, ["path"])]
    assert await audit_rows(client, headers) == before


@pytest.mark.parametrize(("segment", "kind"), BAD_SEGMENTS)
async def test_websocket_without_the_denial_extension_is_closed(
    app: FastAPI, segment: str, kind: str
) -> None:
    sent = await websocket_handshake(app, pty_connect(segment), denial=False)

    assert sent == [{"type": "websocket.close", "code": WS_POLICY_VIOLATION}]


# --- booleans on numeric request fields -------------------------------------------------------

CLONE_BODY = {"url": "https://git.invalid/r.git", "path": "/r"}
CODE_BODY = {"language": "bash", "code": "1"}
TOOLBOX_BOOL_CASES = [
    ("toolbox/process/execute", {"command": "true", "timeout_s": True}, "timeout_s"),
    ("toolbox/process/code-run", {**CODE_BODY, "timeout_s": False}, "timeout_s"),
    ("toolbox/git/clone", {**CLONE_BODY, "depth": True}, "depth"),
    ("toolbox/pty", {"rows": True}, "rows"),
    ("toolbox/pty", {"cols": False}, "cols"),
    ("toolbox/pty/pty_1/resize", {"rows": True, "cols": 80}, "rows"),
    ("toolbox/pty/pty_1/resize", {"rows": 24, "cols": False}, "cols"),
]


@pytest.mark.parametrize(("suffix", "body", "field"), TOOLBOX_BOOL_CASES)
async def test_boolean_on_a_toolbox_number_answers_422_naming_the_field(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    sandbox_id: str,
    suffix: str,
    body: dict[str, Any],
    field: str,
) -> None:
    response = await client.post(f"{SANDBOXES}/{sandbox_id}/{suffix}", json=body, headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert error_kinds(response.json()) == [(BOOL_NOT_NUMBER_TYPE, ["body", field])]


KEY_BODY = {"name": "capped", "scopes": ["sandboxes:read"], "sandbox_labels": {"team": "a"}}


async def test_boolean_api_key_cap_answers_422_naming_the_field(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    body = {**KEY_BODY, "max_sandboxes": True}

    response = await client.post("/v1/api-keys", json=body, headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert error_kinds(response.json()) == [(BOOL_NOT_NUMBER_TYPE, ["body", "max_sandboxes"])]


async def test_numeric_api_key_cap_still_creates(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    body = {**KEY_BODY, "max_sandboxes": 2}

    response = await client.post("/v1/api-keys", json=body, headers=headers)

    assert response.status_code == CREATED_STATUS, response.text
    assert response.json()["data"]["max_sandboxes"] == 2


async def test_numeric_exec_timeout_still_runs(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    path = f"{SANDBOXES}/{sandbox_id}/toolbox/process/execute"

    response = await client.post(path, json={"command": "true", "timeout_s": 5}, headers=headers)

    assert response.status_code == OK_STATUS, response.text


RESIZE_BODY = {"rows": 24, "cols": 80}
MODEL_CASES: list[tuple[type[BaseModel], dict[str, Any], str]] = [
    (ExecuteRequest, {"command": "true"}, "timeout_s"),
    (CodeRunRequest, {"language": "python", "code": "1"}, "timeout_s"),
    (GitCloneRequest, CLONE_BODY, "depth"),
    (CreateApiKeyRequest, KEY_BODY, "max_sandboxes"),
    (PtyCreateRequest, {}, "rows"),
    (PtyCreateRequest, {}, "cols"),
    (PtyResizeRequest, RESIZE_BODY, "rows"),
    (PtyResizeRequest, RESIZE_BODY, "cols"),
    (FsUploadRequest, {"path": "/f", "size_bytes": 1}, "size_bytes"),
    (FsDownloadRequest, {"path": "/f"}, "max_bytes"),
]


@pytest.mark.parametrize(("model", "base", "field"), MODEL_CASES)
@pytest.mark.parametrize("value", [5, "5", 5.0])
def test_numeric_forms_accepted_before_still_are(
    model: type[BaseModel], base: dict[str, Any], field: str, value: object
) -> None:
    parsed = model.model_validate({**base, field: value})

    assert getattr(parsed, field) == 5


@pytest.mark.parametrize(("model", "base", "field"), MODEL_CASES)
@pytest.mark.parametrize("value", [True, False])
def test_booleans_are_refused_on_every_numeric_field(
    model: type[BaseModel], base: dict[str, Any], field: str, value: bool
) -> None:
    with pytest.raises(ValidationError) as caught:
        model.model_validate({**base, field: value})

    found = [(error["type"], error["loc"]) for error in caught.value.errors()]
    assert found == [(BOOL_NOT_NUMBER_TYPE, (field,))]


# --- upload size_bytes ------------------------------------------------------------------------

BAD_SIZES = ["3.0", " 3", "3 ", "+3", "3e0", "-1", "", "٣"]


async def upload(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, size: str
) -> httpx.Response:
    return await client.put(
        f"{SANDBOXES}/{sandbox_id}/toolbox/fs/upload",
        params={"path": "/tmp/a.txt", "size_bytes": size},
        content=b"abc",
        headers={**headers, "Content-Type": "application/octet-stream"},
    )


@pytest.mark.parametrize("size", BAD_SIZES)
async def test_upload_size_must_be_plain_digits_within_the_limit(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, size: str
) -> None:
    response = await upload(client, headers, sandbox_id, size)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert [loc for _, loc in error_kinds(response.json())] == [["query", "size_bytes"]]


async def test_upload_with_a_plain_size_still_writes(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    response = await upload(client, headers, sandbox_id, "3")

    assert response.status_code == OK_STATUS, response.text
    assert response.json()["data"]["size_bytes"] == len(b"abc")


# --- audit list period ------------------------------------------------------------------------

EMPTY_PERIODS = [
    ("2026-11-10T12:00:00Z", "2026-11-10T12:00:00Z"),
    ("2026-11-10T12:00:00Z", "2026-11-10T11:00:00Z"),
    ("2026-11-10T13:00:00+01:00", "2026-11-10T12:00:00Z"),  # same instant, other offset
]


@pytest.mark.parametrize(("start", "end"), EMPTY_PERIODS)
async def test_audit_list_with_end_not_after_start_answers_like_the_export(
    client: httpx.AsyncClient, headers: dict[str, str], start: str, end: str
) -> None:
    params = {"from": start, "to": end}

    listed = await client.get(AUDIT_EVENTS, params=params, headers=headers)
    exported = await client.get(f"{AUDIT_EVENTS}/export", params=params, headers=headers)

    assert listed.status_code == exported.status_code == VALIDATION_STATUS, listed.text
    assert listed.json()["error"]["code"] == exported.json()["error"]["code"] == "UNPROCESSABLE"


async def test_audit_list_with_an_ordered_period_still_answers_200(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    params = {"from": "2026-11-10T11:00:00Z", "to": "2026-11-10T12:00:00Z"}

    response = await client.get(AUDIT_EVENTS, params=params, headers=headers)

    assert response.status_code == OK_STATUS, response.text
