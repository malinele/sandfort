"""Names a listing shows as blank rows, and a cell's gone line without its newline (round 53).

* ``POST /v1/api-keys`` stored a name made only of invisible format characters (zero-width
  space, bidi controls, tag characters) or holding a control character (ESC, BEL, C1, DEL).
  Such a name now answers 422 ``VALIDATION_ERROR`` naming ``name``; nothing is stored.
* Sandbox create and update stored such a label key; it now answers 422 naming ``labels``.
  Visible keys (any script, emoji with joiners) and every value are accepted as before.
* A code-context run whose sandbox was reset under the cell (the exec ended as a bare kill, no
  death line) got the reset line appended without a newline, unlike a delete or a stop that
  rewords the death line. Every gone line now ends with a newline, streamed and not.

Through the API on the fake driver and a temp SQLite database; no network and no sockets.
"""

from typing import Any

import httpx
import pytest
from fastapi import FastAPI

import test_code_contexts_api as base
from sandfort.api.openapi import OPENAPI_PATH, build_document, render_spec
from sandfort.api.routes.toolbox.code_contexts import CELL_GONE_MESSAGES
from sandfort.api.schemas.text_checks import invisible_text_problem
from sandfort.domain.org import Scope
from sandfort.domain.sandbox import SandboxState
from sandfort.drivers.base import ExecResult
from sandfort.drivers.docker.exec import SANDBOX_DIED_MESSAGE
from test_named_contexts_r35 import RowEdit, sse_events

app = base.app
client = base.client
driver = base.driver
shell = base.shell
org_id = base.org_id
key = base.key
quick_interrupt_wait = base.quick_interrupt_wait

API_KEYS = "/v1/api-keys"
SANDBOXES = "/v1/sandboxes"
CREATED_STATUS = 201
OK_STATUS = 200
VALIDATION_STATUS = 422
ADMIN_SCOPES = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.API_KEYS_ADMIN})

INVISIBLE_ONLY = [
    pytest.param("​", id="zero-width-space"),
    pytest.param("​‌‍﻿", id="zero-width-run"),
    pytest.param("‮⁦⁩", id="bidi-controls"),
    pytest.param("\U000e0041\U000e0062\U000e007f", id="tag-characters"),
    pytest.param("­", id="soft-hyphen"),
]
WITH_CONTROL = [
    pytest.param("ci\x1b[31m", id="esc"),
    pytest.param("ci\x07", id="bel"),
    pytest.param("ci\x85", id="c1-nel"),
    pytest.param("ci\x9b", id="c1-csi"),
    pytest.param("ci\x7f", id="del"),
    pytest.param("ci\tkey", id="tab"),
    pytest.param("ci\nkey", id="newline"),
]
REJECTED = [*INVISIBLE_ONLY, *WITH_CONTROL]
# Round 63: a joiner or zero-width space between visible characters is refused as well (the
# one content rule); a space between visible characters stays fine in a name, not in a label key.
ORDINARY = [
    pytest.param("ci-deploy", id="ascii"),
    pytest.param("ทดสอบ", id="thai"),
    pytest.param("परीक्षण", id="hindi"),
    pytest.param("ключ ci", id="cyrillic-with-space"),
]
LABEL_KEY_ORDINARY = [param for param in ORDINARY if " " not in param.values[0]]


@pytest.fixture
async def admin_key(app: FastAPI, org_id: str) -> str:
    return await base.add_key(app, org_id, ADMIN_SCOPES)


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def error_locations(response: httpx.Response) -> list[list[str]]:
    assert response.status_code == VALIDATION_STATUS, response.text
    payload: dict[str, Any] = response.json()
    assert payload["success"] is False
    assert payload["error"]["code"] == "VALIDATION_ERROR"
    return [issue["loc"] for issue in payload["error"]["details"]["errors"]]


async def key_names(client: httpx.AsyncClient, token: str) -> list[str]:
    response = await client.get(API_KEYS, headers=auth(token))
    assert response.status_code == OK_STATUS, response.text
    return [item["name"] for item in response.json()["data"]]


async def sandbox_count(client: httpx.AsyncClient, token: str) -> int:
    response = await client.get(SANDBOXES, headers=auth(token))
    assert response.status_code == OK_STATUS, response.text
    return len(response.json()["data"])


# --- the shared check -------------------------------------------------------------------


@pytest.mark.parametrize("text", REJECTED)
def test_invisible_or_control_text_has_a_problem(text: str) -> None:
    assert invisible_text_problem(text) is not None


@pytest.mark.parametrize("text", ORDINARY)
def test_ordinary_text_has_no_problem(text: str) -> None:
    assert invisible_text_problem(text) is None


# --- API key names ----------------------------------------------------------------------


@pytest.mark.parametrize("name", REJECTED)
async def test_key_name_invisible_or_with_control_answers_422_and_stores_nothing(
    client: httpx.AsyncClient, admin_key: str, name: str
) -> None:
    before = await key_names(client, admin_key)
    body = {"name": name, "scopes": ["sandboxes:read"]}

    response = await client.post(API_KEYS, json=body, headers=auth(admin_key))

    assert ["body", "name"] in error_locations(response)
    assert await key_names(client, admin_key) == before


@pytest.mark.parametrize("name", ORDINARY)
async def test_key_name_in_any_visible_script_is_still_stored(
    client: httpx.AsyncClient, admin_key: str, name: str
) -> None:
    body = {"name": name, "scopes": ["sandboxes:read"]}

    response = await client.post(API_KEYS, json=body, headers=auth(admin_key))

    assert response.status_code == CREATED_STATUS, response.text
    assert response.json()["data"]["name"] == name
    assert name in await key_names(client, admin_key)


# --- sandbox label keys -----------------------------------------------------------------


@pytest.mark.parametrize("label", REJECTED)
async def test_create_label_key_invisible_or_with_control_answers_422(
    client: httpx.AsyncClient, admin_key: str, label: str
) -> None:
    response = await client.post(SANDBOXES, json={"labels": {label: "x"}}, headers=auth(admin_key))

    assert ["body", "labels"] in error_locations(response)
    assert await sandbox_count(client, admin_key) == 0


@pytest.mark.parametrize("label", REJECTED)
async def test_update_label_key_invisible_or_with_control_answers_422(
    client: httpx.AsyncClient, admin_key: str, label: str
) -> None:
    sandbox_id = await base.create_sandbox(client, admin_key)
    path = f"{SANDBOXES}/{sandbox_id}"

    response = await client.patch(path, json={"labels": {label: "x"}}, headers=auth(admin_key))

    assert ["body", "labels"] in error_locations(response)
    stored = await client.get(path, headers=auth(admin_key))
    assert stored.json()["data"]["labels"] == {}


@pytest.mark.parametrize("label", LABEL_KEY_ORDINARY)
async def test_visible_label_keys_and_any_value_still_work_on_create_and_update(
    client: httpx.AsyncClient, admin_key: str, label: str
) -> None:
    labels = {label: "é", "team": "ทีม"}  # letters of any script are fine in a value

    created = await client.post(SANDBOXES, json={"labels": labels}, headers=auth(admin_key))
    assert created.status_code == CREATED_STATUS, created.text
    assert created.json()["data"]["labels"] == labels

    path = f"{SANDBOXES}/{created.json()['data']['id']}"
    updated = await client.patch(path, json={"labels": {label: "v2"}}, headers=auth(admin_key))
    assert updated.status_code == OK_STATUS, updated.text
    assert updated.json()["data"]["labels"] == {label: "v2"}


async def test_update_without_labels_is_unaffected(
    client: httpx.AsyncClient, admin_key: str
) -> None:
    sandbox_id = await base.create_sandbox(client, admin_key)

    response = await client.patch(
        f"{SANDBOXES}/{sandbox_id}", json={"auto_stop_minutes": 30}, headers=auth(admin_key)
    )

    assert response.status_code == OK_STATUS, response.text


# --- API key label-scope selector -------------------------------------------------------


@pytest.mark.parametrize("label", REJECTED)
async def test_key_label_scope_key_invisible_or_with_control_answers_422_and_stores_nothing(
    client: httpx.AsyncClient, admin_key: str, label: str
) -> None:
    before = await key_names(client, admin_key)
    body = {"name": "scoped", "scopes": ["sandboxes:read"], "sandbox_labels": {label: "x"}}

    response = await client.post(API_KEYS, json=body, headers=auth(admin_key))

    assert ["body", "sandbox_labels"] in error_locations(response)
    assert await key_names(client, admin_key) == before


def validation_messages(response: httpx.Response) -> list[str]:
    assert response.status_code == VALIDATION_STATUS, response.text
    return [issue["msg"] for issue in response.json()["error"]["details"]["errors"]]


async def test_key_label_scope_uses_the_sandbox_label_wording(
    client: httpx.AsyncClient, admin_key: str
) -> None:
    invisible = "​"
    key_body = {"name": "scoped", "scopes": ["sandboxes:read"], "sandbox_labels": {invisible: "x"}}

    key_response = await client.post(API_KEYS, json=key_body, headers=auth(admin_key))
    sandbox_response = await client.post(
        SANDBOXES, json={"labels": {invisible: "x"}}, headers=auth(admin_key)
    )

    assert validation_messages(key_response) == validation_messages(sandbox_response)


@pytest.mark.parametrize("label", LABEL_KEY_ORDINARY)
async def test_key_label_scope_with_a_visible_key_is_still_stored(
    client: httpx.AsyncClient, admin_key: str, label: str
) -> None:
    body = {"name": "scoped", "scopes": ["sandboxes:read"], "sandbox_labels": {label: "x"}}

    response = await client.post(API_KEYS, json=body, headers=auth(admin_key))

    assert response.status_code == CREATED_STATUS, response.text
    assert response.json()["data"]["sandbox_labels"] == {label: "x"}


# --- code-context gone lines ------------------------------------------------------------

GONE_ROWS = [  # (row edit after the cell's exec, the stop reason it gives)
    pytest.param({"state": SandboxState.DESTROYING}, "sandbox_deleted", id="deleted"),
    pytest.param({"driver_ref": "ctr_replaced_by_reset"}, "sandbox_reset", id="reset"),
    pytest.param({"state": SandboxState.STOPPING}, "sandbox_stopped", id="stopped"),
]
CELL_ENDINGS = [  # (what the exec returned)
    pytest.param(ExecResult(exit_code=137, stderr=b"partial\n"), id="bare-kill"),
    pytest.param(ExecResult(exit_code=137, stderr=b"partial"), id="bare-kill-no-newline"),
    pytest.param(
        ExecResult(exit_code=137, stderr=b"partial\n" + SANDBOX_DIED_MESSAGE, sandbox_stopped=True),
        id="death-line",
    ),
]


async def run_cell(
    client: httpx.AsyncClient,
    key: str,
    driver: base.FakeDriver,
    shell: base.SandboxShell,
    edit: RowEdit,
    cell_result: ExecResult,
    *,
    stream: bool,
) -> tuple[str, dict[str, Any]]:
    """Run one cell whose sandbox goes away; the streamed stderr ('' unstreamed) and result."""
    sandbox_id = await base.create_sandbox(client, key)
    context_id = await base.create_context(client, key, sandbox_id)
    shell.cell_result = cell_result
    edit.arm(driver, sandbox_id)
    parts = ("run", "stream") if stream else ("run",)
    response = await client.post(
        base.contexts_path(sandbox_id, context_id, *parts),
        headers=auth(key),
        json={"code": "native()", "timeout_s": 3},
    )
    assert response.status_code == OK_STATUS, response.text
    if not stream:
        data: dict[str, Any] = response.json()["data"]
        return "", data
    events = sse_events(response.text)
    assert events[-1][0] == "result"
    streamed = "".join(item["data"] for name, item in events if name == "stderr")
    return streamed, events[-1][1]


@pytest.mark.parametrize(("changes", "reason"), GONE_ROWS)
@pytest.mark.parametrize("cell_result", CELL_ENDINGS)
@pytest.mark.parametrize("stream", [False, True], ids=["plain", "stream"])
async def test_every_gone_line_ends_with_a_newline(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: base.FakeDriver,
    shell: base.SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
    changes: dict[str, Any],
    reason: str,
    cell_result: ExecResult,
    stream: bool,
) -> None:
    edit = RowEdit(app, org_id, monkeypatch, changes)
    line = CELL_GONE_MESSAGES[reason].decode()

    streamed, result = await run_cell(client, key, driver, shell, edit, cell_result, stream=stream)

    assert result["stop_reason"] == reason
    assert result["stderr"] == f"partial\n{line}\n"
    assert result["stderr"].count(line) == 1
    if stream:
        assert streamed == result["stderr"]


def test_no_cell_gone_line_carries_its_own_newline() -> None:
    """The newline is added once by the route; the error event's message stays a bare line."""
    assert all(not line.endswith(b"\n") for line in CELL_GONE_MESSAGES.values())


# --- published spec ---------------------------------------------------------------------


def test_the_committed_spec_matches_the_application() -> None:
    expected = render_spec(build_document()).encode("utf-8")

    assert OPENAPI_PATH.read_bytes() == expected, (
        f"{OPENAPI_PATH} is stale: regenerate it with `python -m sandfort.api.openapi`"
    )
