"""Lone surrogates and NUL characters in request text (round 53).

A lone UTF-16 surrogate (JSON escape ``\\ud800``) or a NUL in request strings answered 500, and
some were stored (sandbox labels, env, exec cwd, audit details), after which every read of the
row answered 500 as well, because a lone surrogate has no UTF-8 encoding.

* Output: ``SafeJSONResponse`` (the application's default response class) renders a lone
  surrogate as U+FFFD, so rows stored before the fix read back with 200. Ordinary text, and a
  surrogate pair that forms a code point, render byte for byte as before.
* Input: ``TextGuardMiddleware`` answers 422 ``VALIDATION_ERROR`` naming the location for a lone
  surrogate or NUL in the path, a query parameter or a JSON body string or key, before any route
  runs. Exec ``stdin`` may carry NUL. The body walk is bounded by the nesting depth (not the
  element count), a body nested deeper than the cap answers 422, and a websocket handshake with a
  bad path or query is closed with the policy-violation code.
* Streaming: a server-sent event holding a lone surrogate streams it as U+FFFD.

Through the API on the fake driver and a temp SQLite database; no network and no sockets.
"""

import json
import tracemalloc
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import anyio.to_thread
import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from starlette.responses import JSONResponse, StreamingResponse

from sandfort import admin_cli
from sandfort.api import text_guard
from sandfort.api.app import create_app
from sandfort.api.safe_json import REPLACEMENT_CHARACTER, SafeJSONResponse, render_json
from sandfort.api.schemas.text_checks import MAX_LABEL_VALUE_LENGTH
from sandfort.api.sse import format_event, with_keepalive
from sandfort.api.text_guard import (
    DEPTH_TYPE,
    GUARD_LIMITER,
    GUARD_WORKERS,
    MAX_DEPTH,
    NUL_TYPE,
    OFFLOAD_BYTES,
    SURROGATE_TYPE,
    UTF8_TYPE,
    WS_POLICY_VIOLATION,
    Finding,
    body_findings,
    body_findings_async,
    query_findings,
)
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import SystemClock
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import ActorType
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.ids import new_api_key_id, new_org_id, new_sandbox_id
from sandfort.services.audit import AuditRecorder

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
AUDIT_EVENTS = "/v1/audit-events"
OK_STATUS = 200
CREATED_STATUS = 201
VALIDATION_STATUS = 422
TOO_LARGE_STATUS = 413
SMALL_BODY_LIMIT = 2048
BODY_BUDGET_BYTES = 4 * 1024 * 1024
PEAK_BUDGET_BYTES = 20 * 1024 * 1024
LONE = "\ud800"
OLD_NOTE = f"before{LONE}after"
CLEANED_NOTE = f"before{REPLACEMENT_CHARACTER}after"
FAMILY = "\U0001f469\u200d\U0001f469\u200d\U0001f467\u200d\U0001f466"
ORDINARY_TEXT = {
    "thai": "\u0e2a\u0e27\u0e31\u0e2a\u0e14\u0e35 \u0e0a\u0e32\u0e27\u0e42\u0e25\u0e01",
    "hindi": "\u0928\u092e\u0938\u094d\u0924\u0947 \u0926\u0941\u0928\u093f\u092f\u093e",
    "family": FAMILY,
    "accents": "caf\u00e9 \u00fcber",
}


@asynccontextmanager
async def open_app(tmp_path: Path, **overrides: Any) -> AsyncIterator[FastAPI]:
    """The application on the fake driver and a temp SQLite database; ``overrides`` are Settings."""
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'strings53.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(driver="fake", database_url=url, api_key_pepper=PEPPER, **overrides)
    application = create_app(settings)
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    async with open_app(tmp_path) as application:
        yield application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as http:
        yield http


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Strings", slug="strings", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


@pytest.fixture
async def headers(app: FastAPI, org_id: str) -> dict[str, str]:
    generated = generate_api_key(PEPPER)
    key = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="strings",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset(
            {Scope.SANDBOXES_WRITE, Scope.SANDBOXES_READ, Scope.TOOLBOX, Scope.AUDIT_READ}
        ),
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(key)
        await uow.commit()
    return {"Authorization": f"Bearer {generated.key}", "Content-Type": "application/json"}


@pytest.fixture
async def sandbox_id(client: httpx.AsyncClient, headers: dict[str, str]) -> str:
    response = await client.post(SANDBOXES, json={}, headers=headers)
    assert response.status_code == CREATED_STATUS, response.text
    value: str = response.json()["data"]["id"]
    return value


def error_issues(response: httpx.Response) -> list[dict[str, Any]]:
    payload: dict[str, Any] = response.json()
    assert payload["success"] is False
    assert payload["error"]["code"] == "VALIDATION_ERROR"
    issues: list[dict[str, Any]] = payload["error"]["details"]["errors"]
    return issues


def error_locations(response: httpx.Response) -> list[list[str]]:
    return [issue["loc"] for issue in error_issues(response)]


def error_kinds(response: httpx.Response) -> list[tuple[str, list[str]]]:
    return [(issue["type"], issue["loc"]) for issue in error_issues(response)]


async def store_old_sandbox(app: FastAPI, org_id: str, labels: dict[str, str]) -> str:
    """Insert a sandbox below the API, as a row stored before the guard existed."""
    sandbox = Sandbox(
        id=new_sandbox_id(),
        org_id=org_id,
        name="old-row",
        state=SandboxState.STOPPED,
        desired_state=SandboxState.STOPPED,
        image_ref="alpine:3.20",
        driver="fake",
        labels=labels,
        created_at=NOW,
        updated_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.sandboxes.add(sandbox)
        await uow.commit()
    return sandbox.id


# --- tolerant output: rows stored before the guard -------------------------------------


async def test_stored_label_with_a_lone_surrogate_reads_back_on_get(
    app: FastAPI, client: httpx.AsyncClient, headers: dict[str, str], org_id: str
) -> None:
    stored = await store_old_sandbox(app, org_id, {"env": "prod", "note": OLD_NOTE})

    response = await client.get(f"{SANDBOXES}/{stored}", headers=headers)

    assert response.status_code == OK_STATUS, response.text
    assert response.json()["data"]["labels"] == {"env": "prod", "note": CLEANED_NOTE}


async def test_stored_label_with_a_lone_surrogate_is_on_the_labelled_list_after_repair(
    app: FastAPI, client: httpx.AsyncClient, headers: dict[str, str], org_id: str
) -> None:
    """The round-54 guard excludes the unreadable row from labelled lists until it is repaired."""
    stored = await store_old_sandbox(app, org_id, {"env": "prod", "note": OLD_NOTE})
    params = {"label": "env=prod"}

    before = await client.get(SANDBOXES, params=params, headers=headers)
    url = app.state.engine.url.render_as_string(hide_password=False)
    settings = Settings(driver="fake", database_url=url, api_key_pepper=PEPPER)
    repaired = await admin_cli._repair_labels_async(settings, org_id, dry_run=False)
    after = await client.get(SANDBOXES, params=params, headers=headers)

    assert before.status_code == OK_STATUS, before.text
    assert before.json()["data"] == []
    assert repaired == [stored]
    assert after.status_code == OK_STATUS, after.text
    rows = after.json()["data"]
    assert [row["id"] for row in rows] == [stored]
    assert rows[0]["labels"]["note"] == CLEANED_NOTE


async def test_stored_surrogate_does_not_break_reads_of_other_rows(
    app: FastAPI, client: httpx.AsyncClient, headers: dict[str, str], org_id: str, sandbox_id: str
) -> None:
    await store_old_sandbox(app, org_id, {"note": OLD_NOTE})

    response = await client.get(SANDBOXES, headers=headers)

    assert response.status_code == OK_STATUS, response.text
    assert sandbox_id in [row["id"] for row in response.json()["data"]]


async def test_audit_page_with_a_stored_lone_surrogate_reads_back(
    app: FastAPI, client: httpx.AsyncClient, headers: dict[str, str], org_id: str
) -> None:
    async with UnitOfWork(app.state.session_factory) as uow:
        await AuditRecorder(SystemClock()).record(
            uow,
            org_id=org_id,
            actor_type=ActorType.API_KEY,
            actor_id="key_old",
            action="legacy.event",
            details={"note": OLD_NOTE},
        )
        await uow.commit()

    response = await client.get(AUDIT_EVENTS, headers=headers)

    assert response.status_code == OK_STATUS, response.text
    legacy = [event for event in response.json()["data"] if event["action"] == "legacy.event"]
    assert [event["details"]["note"] for event in legacy] == [CLEANED_NOTE]


def test_render_replaces_a_lone_surrogate_in_values_and_keys() -> None:
    rendered = render_json({f"k{LONE}": [f"{LONE}x", "ok"]})

    expected = {f"k{REPLACEMENT_CHARACTER}": [f"{REPLACEMENT_CHARACTER}x", "ok"]}
    assert json.loads(rendered) == expected


def test_render_of_a_paired_surrogate_emoji_is_unchanged() -> None:
    emoji = json.loads('"\\ud83d\\ude00"')  # the pair arrives as one code point
    content = {"emoji": emoji, "family": FAMILY, **ORDINARY_TEXT, "n": [1, 2.5, None, True]}

    assert emoji == "\U0001f600"
    assert render_json(content) == JSONResponse(content).body
    assert SafeJSONResponse(content).body == JSONResponse(content).body
    assert "\U0001f600" in render_json(content).decode("utf-8")


# --- the guard: where a refused text is located ------------------------------------------


@pytest.mark.parametrize(("escape", "kind"), [("\\ud800", SURROGATE_TYPE), ("\\u0000", NUL_TYPE)])
async def test_body_string_value_answers_422_naming_the_location(
    client: httpx.AsyncClient, headers: dict[str, str], escape: str, kind: str
) -> None:
    body = '{"labels": {"note": "a' + escape + 'b"}}'

    response = await client.post(SANDBOXES, content=body, headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert error_kinds(response) == [(kind, ["body", "labels", "note"])]
    assert escape not in response.text


@pytest.mark.parametrize("escape", ["\\ud800", "\\udc00", "\\u0000"])
async def test_body_object_key_answers_422_naming_the_holding_object(
    client: httpx.AsyncClient, headers: dict[str, str], escape: str
) -> None:
    body = '{"labels": {"a' + escape + 'b": "v"}}'

    response = await client.post(SANDBOXES, content=body, headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert error_locations(response) == [["body", "labels"]]


async def test_body_string_inside_a_list_is_located_by_index(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    body = '{"argv": ["echo", "ok", "x\\u0000y"]}'

    response = await client.post(
        f"{SANDBOXES}/{sandbox_id}/toolbox/process/execute", content=body, headers=headers
    )

    assert response.status_code == VALIDATION_STATUS, response.text
    assert error_locations(response) == [["body", "argv", "2"]]


@pytest.mark.parametrize(
    ("value", "kind"),
    [("a%00b", NUL_TYPE), ("%ff", UTF8_TYPE), ("%ed%a0%80", UTF8_TYPE)],
)
async def test_query_parameter_answers_422_naming_the_parameter(
    client: httpx.AsyncClient, headers: dict[str, str], value: str, kind: str
) -> None:
    response = await client.get(f"{SANDBOXES}?label={value}", headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert error_kinds(response) == [(kind, ["query", "label"])]


def test_bad_query_parameter_names_are_named_by_their_encoded_form() -> None:
    findings = query_findings(b"ok=1&a%00b=2&%ff=3&c%ed%a0%80=4")

    assert [(finding.loc, finding.kind) for finding in findings] == [
        (("query", "a%00b"), NUL_TYPE),
        (("query", "%ff"), UTF8_TYPE),
        (("query", "c%ed%a0%80"), UTF8_TYPE),
    ]


async def test_bad_query_parameter_name_answers_422_naming_the_parameter(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    response = await client.get(f"{SANDBOXES}?a%00b=1", headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert error_kinds(response) == [(NUL_TYPE, ["query", "a%00b"])]


async def test_path_segment_with_nul_answers_422_naming_the_path(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    response = await client.get(f"{SANDBOXES}/sbx_a%00b", headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert error_kinds(response) == [(NUL_TYPE, ["path"])]


async def asgi_get(app: FastAPI, path: str, headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
    """One GET straight to the ASGI app, for a path httpx would refuse to build."""
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8", "surrogatepass"),
        "root_path": "",
        "query_string": b"",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": ("127.0.0.1", 1),
        "server": ("test", 80),
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, json.loads(body)


async def test_path_segment_with_a_lone_surrogate_answers_422_naming_the_path(
    app: FastAPI, headers: dict[str, str]
) -> None:
    status, payload = await asgi_get(app, f"{SANDBOXES}/sbx_a{LONE}b", headers)

    assert status == VALIDATION_STATUS
    assert payload["error"]["code"] == "VALIDATION_ERROR"
    assert [issue["loc"] for issue in payload["error"]["details"]["errors"]] == [["path"]]


async def test_refused_request_stores_nothing(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    body = '{"name": "refused-box", "labels": {"note": "a\\ud800b"}}'

    refused = await client.post(SANDBOXES, content=body, headers=headers)
    listed = await client.get(SANDBOXES, headers=headers)
    audit = await client.get(AUDIT_EVENTS, headers=headers)

    assert refused.status_code == VALIDATION_STATUS, refused.text
    assert listed.json()["data"] == []
    assert "refused-box" not in audit.text


async def test_body_that_is_not_json_is_left_to_the_route(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    response = await client.post(SANDBOXES, content='{"labels": \\u0000', headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert response.json()["error"]["message"] == "request body is not valid JSON"


async def test_non_json_body_is_not_inspected(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    upload = {"Authorization": headers["Authorization"], "Content-Type": "application/octet-stream"}

    response = await client.put(
        f"{SANDBOXES}/{sandbox_id}/toolbox/fs/upload",
        params={"path": "/tmp/raw.bin"},
        content=b'{"a": "\\u0000 \\ud800"}\x00\xff',
        headers=upload,
    )

    assert response.status_code != VALIDATION_STATUS, response.text


# --- exec stdin ------------------------------------------------------------------------


async def test_exec_stdin_may_carry_nul(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    body = '{"argv": ["cat"], "stdin": "a\\u0000b"}'

    response = await client.post(
        f"{SANDBOXES}/{sandbox_id}/toolbox/process/execute", content=body, headers=headers
    )

    assert response.status_code == OK_STATUS, response.text
    assert response.json()["data"]["stdout"] == "a\x00b"


async def test_exec_stdin_with_a_lone_surrogate_is_refused(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    body = '{"argv": ["cat"], "stdin": "a\\ud800b"}'

    response = await client.post(
        f"{SANDBOXES}/{sandbox_id}/toolbox/process/execute", content=body, headers=headers
    )

    assert response.status_code == VALIDATION_STATUS, response.text
    assert error_kinds(response) == [(SURROGATE_TYPE, ["body", "stdin"])]


async def test_nul_is_refused_in_the_other_exec_fields(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    body = '{"argv": ["cat"], "cwd": "/tmp\\u0000", "env": {"A": "b\\u0000"}}'

    response = await client.post(
        f"{SANDBOXES}/{sandbox_id}/toolbox/process/execute", content=body, headers=headers
    )

    assert response.status_code == VALIDATION_STATUS, response.text
    assert sorted(error_locations(response)) == [["body", "cwd"], ["body", "env", "A"]]


# --- valid text keeps working ---------------------------------------------------------------


async def test_ordinary_non_ascii_text_round_trips_unchanged(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    created = await client.post(SANDBOXES, json={"labels": ORDINARY_TEXT}, headers=headers)
    assert created.status_code == CREATED_STATUS, created.text
    sandbox = created.json()["data"]

    read = await client.get(f"{SANDBOXES}/{sandbox['id']}", headers=headers)
    listed = await client.get(SANDBOXES, params={"label": f"family={FAMILY}"}, headers=headers)

    assert read.status_code == OK_STATUS, read.text
    assert read.json()["data"]["labels"] == ORDINARY_TEXT
    assert [row["id"] for row in listed.json()["data"]] == [sandbox["id"]]
    assert FAMILY.encode("utf-8") in read.content  # raw UTF-8 on the wire, not escaped


async def test_paired_surrogate_escapes_in_a_body_are_accepted(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    body = '{"argv": ["echo", "\\ud83d\\ude00 \\u0e2a\\u0e27\\u0e31\\u0e2a\\u0e14\\u0e35"]}'

    response = await client.post(
        f"{SANDBOXES}/{sandbox_id}/toolbox/process/execute", content=body, headers=headers
    )

    assert response.status_code == OK_STATUS, response.text
    assert response.json()["data"]["stdout"] == "\U0001f600 \u0e2a\u0e27\u0e31\u0e2a\u0e14\u0e35\n"


# --- the guard: bounded memory, depth cap, off-loop parse -----------------------------------


def nested_arrays(depth: int, leaf: str) -> bytes:
    return ("[" * depth + leaf + "]" * depth).encode()


def peak_bytes(work: Callable[[], object]) -> int:
    """The peak traced allocation while ``work`` runs (the argument bodies exist beforehand)."""
    tracemalloc.start()
    try:
        work()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def test_large_flat_array_with_one_escape_is_walked_within_a_small_memory_budget() -> None:
    count = BODY_BUDGET_BYTES // len(b'"a",')
    body = b"[" + b'"a",' * count + b'"\\ud800"]'
    found: list[Finding] = []

    peak = peak_bytes(lambda: found.extend(body_findings(body)))

    assert [(item.kind, item.loc) for item in found] == [(SURROGATE_TYPE, ("body", str(count)))]
    assert peak < PEAK_BUDGET_BYTES


def test_deeply_nested_array_is_walked_within_a_small_memory_budget() -> None:
    body = nested_arrays(MAX_DEPTH, '"\\ud800"') + b" " * BODY_BUDGET_BYTES
    found: list[Finding] = []

    peak = peak_bytes(lambda: found.extend(body_findings(body)))

    assert [item.kind for item in found] == [SURROGATE_TYPE]
    assert len(found[0].loc) == MAX_DEPTH + 1
    assert peak < PEAK_BUDGET_BYTES


def test_nested_arrays_with_many_elements_per_level_stay_within_the_budget() -> None:
    level = "[" + ",".join(['"a"'] * 4000) + ","
    text = level * (MAX_DEPTH - 1) + '"\\ud800"' + "]" * (MAX_DEPTH - 1)
    body = text.encode()
    found: list[Finding] = []

    peak = peak_bytes(lambda: found.extend(body_findings(body)))

    assert [item.kind for item in found] == [SURROGATE_TYPE]
    assert peak < PEAK_BUDGET_BYTES


@pytest.mark.parametrize("depth", [MAX_DEPTH + 1, 5 * MAX_DEPTH, 200_000])
def test_body_deeper_than_the_cap_is_refused_at_the_body(depth: int) -> None:
    body = nested_arrays(depth, '"\\u0041"')
    found: list[Finding] = []

    peak = peak_bytes(lambda: found.extend(body_findings(body)))

    assert [(item.kind, item.loc) for item in found] == [(DEPTH_TYPE, ("body",))]
    assert peak < PEAK_BUDGET_BYTES


def test_body_nested_exactly_to_the_cap_is_still_walked() -> None:
    assert body_findings(nested_arrays(MAX_DEPTH, '"ok\\u0041"')) == []


async def test_over_deep_body_answers_422_with_the_validation_envelope(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    body = nested_arrays(MAX_DEPTH + 10, '"\\u0041"')

    response = await client.post(SANDBOXES, content=body, headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert error_kinds(response) == [(DEPTH_TYPE, ["body"])]


async def test_body_above_the_offload_size_is_refused_like_a_small_one(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    padding = "a" * (OFFLOAD_BYTES * 2)
    body = '{"labels": {"big": "' + padding + '", "note": "x\\ud800y"}}'

    response = await client.post(SANDBOXES, content=body, headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert error_kinds(response) == [(SURROGATE_TYPE, ["body", "labels", "note"])]


async def test_async_scan_gives_the_sync_result_below_and_above_the_offload_size() -> None:
    small = b'{"a": "\\ud800"}'
    big = b'{"pad": "' + b"a" * (OFFLOAD_BYTES + 1) + b'", "a": "\\ud800"}'

    for body in (small, big):
        assert await body_findings_async(body) == body_findings(body)
        assert [item.loc for item in await body_findings_async(body)] == [("body", "a")]


# --- the guard: byte-level pre-filter and its own thread limiter ----------------------------


def big_body(note: str) -> bytes:
    """A labels body above the offload size whose only escape sits in ``note`` (JSON text)."""
    padding = "a" * (OFFLOAD_BYTES * 4)
    return ('{"labels": {"big": "' + padding + '", "note": "' + note + '"}}').encode()


def big_valid_body(note: str) -> bytes:
    """``big_body`` with every label within the bound: JSON whitespace carries the size."""
    value = "a" * MAX_LABEL_VALUE_LENGTH
    padding = " " * (OFFLOAD_BYTES * 4)
    return ('{"labels": {"big": "' + value + '",' + padding + '"note": "' + note + '"}}').encode()


def count_scans(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    """Record every body the guard hands to its JSON parse."""
    scanned: list[bytes] = []
    real_scan = text_guard._scan

    def counting_scan(body: bytes, nul_allowed_keys: frozenset[str]) -> list[Finding]:
        scanned.append(body)
        return real_scan(body, nul_allowed_keys)

    monkeypatch.setattr(text_guard, "_scan", counting_scan)
    return scanned


@pytest.mark.parametrize(
    "note", ["caf\\u00e9", "\\u0041", "\\u0001", "\\ud7ff", "\\ue000", "a\\\\b"]
)
def test_body_with_only_harmless_escapes_is_not_parsed(note: str) -> None:
    assert text_guard.needs_parse(big_body(note)) is False


@pytest.mark.parametrize(
    "note", ["\\ud800", "\\uDBFF", "\\udc00", "\\uDFFF", "\\u0000", "\\ud83d\\ude00"]
)
def test_body_with_a_nul_or_surrogate_escape_is_parsed(note: str) -> None:
    assert text_guard.needs_parse(big_body(note)) is True


def test_raw_nul_and_utf8_encoded_surrogate_bytes_are_parsed() -> None:
    assert text_guard.needs_parse(b'{"a": "x\x00"}') is True
    assert text_guard.needs_parse(b'{"a": "x\xed\xa0\x80"}') is True
    assert body_findings(b'{"a": "x\xed\xa0\x80"}') == [Finding(("body", "a"), SURROGATE_TYPE)]


async def test_large_body_with_a_harmless_escape_is_parsed_once_and_reaches_the_route(
    client: httpx.AsyncClient, headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    scanned = count_scans(monkeypatch)
    body = big_valid_body("caf\\u00e9")
    assert len(body) > OFFLOAD_BYTES

    response = await client.post(SANDBOXES, content=body, headers=headers)

    assert response.status_code == CREATED_STATUS, response.text
    assert response.json()["data"]["labels"]["note"] == "café"
    assert response.json()["data"]["labels"]["big"] == "a" * MAX_LABEL_VALUE_LENGTH
    assert len(scanned) == 1  # every body is parsed once (repeated keys, integers, depth)


async def test_large_body_with_a_surrogate_escape_is_still_refused(
    client: httpx.AsyncClient, headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    scanned = count_scans(monkeypatch)

    response = await client.post(SANDBOXES, content=big_body("x\\ud800y"), headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert error_kinds(response) == [(SURROGATE_TYPE, ["body", "labels", "note"])]
    assert len(scanned) == 1


async def test_large_body_is_parsed_on_the_guard_limiter_not_the_default_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limiters: list[object] = []
    real_run_sync = anyio.to_thread.run_sync

    async def recording_run_sync(func: Callable[[], Any], *, limiter: Any = None) -> Any:
        limiters.append(limiter)
        return await real_run_sync(func, limiter=limiter)

    monkeypatch.setattr(anyio.to_thread, "run_sync", recording_run_sync)

    found = await body_findings_async(big_body("x\\ud800y"))

    assert [item.kind for item in found] == [SURROGATE_TYPE]
    assert limiters == [GUARD_LIMITER]
    assert GUARD_LIMITER is not anyio.to_thread.current_default_thread_limiter()
    assert GUARD_LIMITER.total_tokens == GUARD_WORKERS


async def test_large_body_with_a_harmless_escape_is_parsed_on_one_guard_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[object] = []
    real_run_sync = anyio.to_thread.run_sync

    async def counting_run_sync(*args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        return await real_run_sync(*args, **kwargs)

    monkeypatch.setattr(anyio.to_thread, "run_sync", counting_run_sync)

    assert await body_findings_async(big_body("caf\\u00e9")) == []
    assert len(calls) == 1


# --- the guard: chunked and over-limit bodies -------------------------------------------------


async def chunked(*parts: bytes) -> AsyncIterator[bytes]:
    for part in parts:
        yield part


async def test_chunked_body_with_a_surrogate_still_answers_422(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    parts = (b'{"labels": {"no', b'te": "a\\ud8', b'00b"}}')

    response = await client.post(SANDBOXES, content=chunked(*parts), headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert error_kinds(response) == [(SURROGATE_TYPE, ["body", "labels", "note"])]


async def test_clean_chunked_body_still_reaches_the_route(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    parts = (b'{"labels": {"no', b'te": "caf\\u00e9"}}')

    response = await client.post(SANDBOXES, content=chunked(*parts), headers=headers)

    assert response.status_code == CREATED_STATUS, response.text
    assert response.json()["data"]["labels"] == {"note": "caf\u00e9"}


async def test_over_limit_declared_body_still_answers_413(tmp_path: Path) -> None:
    async with open_app(tmp_path, max_request_body_bytes=SMALL_BODY_LIMIT) as application:
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            body = '{"labels": {"note": "' + "a" * SMALL_BODY_LIMIT + '\\ud800"}}'

            response = await http.post(
                SANDBOXES, content=body, headers={"Content-Type": "application/json"}
            )

    assert response.status_code == TOO_LARGE_STATUS, response.text
    assert response.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


async def test_over_limit_chunked_body_still_answers_413(tmp_path: Path) -> None:
    async with open_app(tmp_path, max_request_body_bytes=SMALL_BODY_LIMIT) as application:
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            parts = (b'{"labels": {"note": "', b"a" * SMALL_BODY_LIMIT, b'\\ud800"}}')

            response = await http.post(
                SANDBOXES, content=chunked(*parts), headers={"Content-Type": "application/json"}
            )

    assert response.status_code == TOO_LARGE_STATUS, response.text
    assert response.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


# --- SCIM bodies ----------------------------------------------------------------------------------


async def test_scim_json_body_with_a_surrogate_answers_422(tmp_path: Path) -> None:
    async with open_app(tmp_path, scim_enabled=True, session_secret="s" * 40) as application:
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            body = '{"userName": "a\\ud800b@example.com", "emails": []}'

            response = await http.post(
                "/scim/v2/Users", content=body, headers={"Content-Type": "application/scim+json"}
            )

    assert response.status_code == VALIDATION_STATUS, response.text
    assert error_kinds(response) == [(SURROGATE_TYPE, ["body", "userName"])]


# --- exec stdin is exempt only as the top-level field ---------------------------------------


@pytest.mark.parametrize(
    ("body", "where"),
    [
        ('{"argv": ["cat"], "env": {"stdin": "a\\u0000b"}}', ["body", "env", "stdin"]),
        ('{"argv": ["cat"], "extra": {"stdin": "a\\u0000b"}}', ["body", "extra", "stdin"]),
        ('{"argv": ["cat"], "extra": [{"stdin": "a\\u0000b"}]}', ["body", "extra", "0", "stdin"]),
        ('{"argv": ["cat"], "extra": ["a\\u0000b"]}', ["body", "extra", "0"]),
    ],
)
async def test_nested_stdin_key_outside_the_exec_stdin_field_is_still_refused(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, body: str, where: list[str]
) -> None:
    response = await client.post(
        f"{SANDBOXES}/{sandbox_id}/toolbox/process/execute", content=body, headers=headers
    )

    assert response.status_code == VALIDATION_STATUS, response.text
    assert error_kinds(response) == [(NUL_TYPE, where)]


# --- server-sent events ---------------------------------------------------------------------


def test_sse_frame_with_a_lone_surrogate_encodes_with_the_replacement_character() -> None:
    frame = format_event({"line": f"a{LONE}b", "ok": "caf\u00e9"}, event="log", event_id="3")

    assert frame.encode("utf-8").decode("utf-8") == frame
    assert f'"line":"a{REPLACEMENT_CHARACTER}b"' in frame
    assert "caf\u00e9" in frame
    assert frame.startswith("event: log\nid: 3\ndata: ")


def test_sse_frame_of_ordinary_text_is_unchanged() -> None:
    emoji = json.loads('"\\ud83d\\ude00"')

    assert format_event({"line": emoji, "n": 1}) == 'data: {"line":"\U0001f600","n":1}\n\n'


async def test_stored_surrogate_streams_as_the_replacement_character() -> None:
    api = FastAPI()

    async def frames() -> AsyncIterator[str]:
        yield format_event({"message": OLD_NOTE}, event="log", event_id="1")
        yield format_event({"message": "after"}, event="log", event_id="2")

    @api.get("/stream")
    async def stream() -> StreamingResponse:
        return StreamingResponse(with_keepalive(frames()), media_type="text/event-stream")

    transport = httpx.ASGITransport(app=api)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        response = await http.get("/stream")

    assert response.status_code == OK_STATUS
    assert f"before{REPLACEMENT_CHARACTER}after" in response.text
    assert '"message":"after"' in response.text


# --- websockets -----------------------------------------------------------------------------


async def asgi_websocket(
    app: FastAPI, path: str, query_string: bytes = b""
) -> list[dict[str, Any]]:
    """One websocket handshake straight to the ASGI app; returns every message the app sent."""
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "websocket.connect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "websocket",
        "asgi": {"version": "3.0"},
        "scheme": "ws",
        "path": path,
        "raw_path": path.encode("utf-8", "surrogatepass"),
        "root_path": "",
        "query_string": query_string,
        "headers": [],
        "client": ("127.0.0.1", 1),
        "server": ("test", 80),
        "subprotocols": [],
    }
    await app(scope, receive, send)
    return sent


PTY_CONNECT = f"{SANDBOXES}/sbx_1/toolbox/pty/pty_1/connect"


@pytest.mark.parametrize(
    ("path", "query"),
    [
        (f"{SANDBOXES}/sbx_a\x00b/toolbox/pty/pty_1/connect", b""),
        (f"{SANDBOXES}/sbx_a{LONE}b/toolbox/pty/pty_1/connect", b""),
        (PTY_CONNECT, b"token=a%00b"),
        (PTY_CONNECT, b"to%00ken=abc"),
        (PTY_CONNECT, b"token=%ff"),
    ],
)
async def test_websocket_with_a_bad_path_or_query_is_closed_with_the_policy_code(
    app: FastAPI, path: str, query: bytes
) -> None:
    sent = await asgi_websocket(app, path, query)

    assert sent == [{"type": "websocket.close", "code": WS_POLICY_VIOLATION}]
