"""The audit view on the read-only console page: one newest-first request, a protection mark.

Page tests read ``GET /console``, rule tests run the page rules in node, API tests pin premises.
"""

import json
import re
import shutil
import subprocess
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
from sandfort.api.console_assets import PAGE
from sandfort.api.console_audit import (
    AUDIT_RULES_JS,
    PROTECTION_CODES,
    PROTECTION_REFUSAL_ACTION,
    PROTECTION_REFUSAL_REASON,
    PROTECTION_STATUSES,
)
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
AUDIT = "/v1/audit-events"
SCOPES = frozenset({Scope.AUDIT_READ, Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})
CONSOLE = "/console"
Http = httpx.AsyncClient
NOTE_1 = "A successful list, verify or export of audit events writes no audit row."
NOTE_2 = (
    "A request refused after its key was resolved, including a revoked or expired key, "
    "usually leaves a request.denied row, and a create refused by the key sandbox cap, "
    "or a create or start refused for host capacity, leaves a sandbox.create_refused or "
    "sandbox.start_refused row instead, and a repeat of a revoked key refusal, or of a "
    "capacity or key cap refusal, by the same key within 60 seconds leaves no further row."
)
NOTE_3 = (
    "A missing, malformed or unknown key, a key with a wrong secret, a rate limited request "
    "and a request rejected before the key is resolved, such as a body that is not valid "
    "JSON, leave no row."
)
NOTE_4 = (
    "The hash shown after Verify chain is the hash of the newest chain row, "
    "not of each listed row."
)

needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'console_audit.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[Http]:
    async with Http(transport=httpx.ASGITransport(app=app), base_url="http://test") as http:
        yield http


async def add_key(app: FastAPI, org_id: str, labels: dict[str, str] | None) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(), org_id=org_id, name="ci", prefix=generated.prefix,
        secret_hash=generated.secret_hash, scopes=SCOPES, created_at=NOW, sandbox_labels=labels,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


@pytest.fixture
async def unscoped(app: FastAPI, org_id: str) -> str:
    return await add_key(app, org_id, None)


async def get(client: Http, path: str, key: str, **params: Any) -> httpx.Response:
    return await client.get(path, headers={"Authorization": f"Bearer {key}"}, params=params)


@pytest.fixture
async def seeded(client: Http, unscoped: str) -> str:
    headers = {"Authorization": f"Bearer {unscoped}"}
    created = await client.post("/v1/sandboxes", headers=headers, json={"name": "one"})
    assert created.status_code == 201, created.text
    assert (await get(client, "/v1/sandboxes/sbx_missing", unscoped)).status_code == 404
    assert (await client.post("/v1/sandboxes/sbx_missing/stop", headers=headers)).status_code == 404
    return unscoped


async def page(client: Http) -> str:
    return (await client.get(CONSOLE)).text


def inline_script(html: str) -> str:
    match = re.search(r'<script nonce="[\w-]+">(.*?)</script>', html, re.S)
    assert match is not None
    return match.group(1)


def call(function: str, value: Any) -> Any:
    """Run one page rule function in node and return its JSON result."""
    expression = function + "(" + json.dumps(value) + ")"
    source = AUDIT_RULES_JS + "\nconsole.log(JSON.stringify(" + expression + "))"
    args = ["node", "-e", source]
    result = subprocess.run(args, capture_output=True, text=True, timeout=30, check=True)
    return json.loads(result.stdout)


async def test_page_has_audit_table_verify_button_and_result_areas(client: Http) -> None:
    html = await page(client)
    markers = ('id="audit"', 'id="verify-button"', 'id="verify-status"')
    for marker in (*markers, 'id="verify-summary"', 'id="verify-findings"', "Verify chain"):
        assert marker in html


async def test_page_note_states_which_requests_leave_an_audit_row(client: Http) -> None:
    text = " ".join((await page(client)).split())
    for note in (NOTE_1, NOTE_2, NOTE_3, NOTE_4):
        assert note in text
    assert "creates refused by the key sandbox cap" in text
    assert "A refusal because the host is full is not marked" in text
    stale = ("A refused request still leaves", "Successful reads are not audited")
    for sentence in (*stale, "Listing, verifying and exporting audit events writes"):
        assert sentence not in text


async def test_page_requests_one_newest_first_page(client: Http) -> None:
    html = await page(client)
    assert '/v1/audit-events?limit=" + AUDIT_TAIL + "&order=desc' in html
    assert html.count("const AUDIT_TAIL = 20") == 1
    for stale in ("AUDIT_MAX_PAGES", "AUDIT_PAGE_LIMIT", "&cursor="):
        assert stale not in html


async def test_page_verify_runs_only_on_click(client: Http) -> None:
    html = await page(client)
    assert html.count("/v1/audit-events/verify") == 1
    refresh = html[html.index("async function refresh()") : html.index("function schedule()")]
    assert "verify" not in refresh.lower()


async def test_page_does_not_call_the_export(client: Http) -> None:
    assert "/export" not in await page(client)


async def test_page_uses_no_inline_styles_or_handlers(client: Http) -> None:
    html = await page(client)
    assert re.search(r"\sstyle\s*=", html) is None
    for handler in ("onclick=", "onsubmit=", "onload=", "onerror="):
        assert handler not in html


async def test_page_keeps_the_public_route_contract(client: Http) -> None:
    response = await client.get(CONSOLE)
    policy = response.headers["content-security-policy"]
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["cache-control"] == "no-store"
    assert "default-src 'none'" in policy and "connect-src 'self'" in policy
    assert "unsafe-inline" not in policy
    assert CONSOLE not in (await client.get("/openapi.json")).json()["paths"]


async def test_every_script_const_is_declared_once(client: Http) -> None:
    names = re.findall(r"^const (\w+)", inline_script(await page(client)), re.M)
    assert names
    assert len(names) == len(set(names)), names


def test_console_modules_stay_under_400_lines() -> None:
    for name in ("routes/console.py", "console_assets.py", "console_audit.py"):
        lines = (ROOT / "src" / "sandfort" / "api" / name).read_text().splitlines()
        assert len(lines) < 400, name
        assert all(len(line) <= 100 for line in lines), name


def test_protection_constants_match_the_rule() -> None:
    codes = ("FORBIDDEN", "UNAUTHORIZED", "QUOTA_EXCEEDED", "RATE_LIMITED", "EGRESS_DENIED")
    assert PROTECTION_STATUSES == (401, 403, 429)
    assert PROTECTION_CODES == codes
    assert 404 not in PROTECTION_STATUSES and 409 not in PROTECTION_STATUSES
    assert PROTECTION_REFUSAL_ACTION == "sandbox.create_refused"
    assert PROTECTION_REFUSAL_REASON == "key_cap"
    assert "const AUDIT_TAIL = 20" in PAGE


@needs_node
@pytest.mark.parametrize("status", [401, 403, 429])
def test_is_protection_marks_listed_statuses(status: int) -> None:
    assert call("isProtection", {"details": {"status": status, "error_code": "NOT_FOUND"}}) is True


@needs_node
@pytest.mark.parametrize("status", [400, 404, 409, 422, 500, 503])
def test_is_protection_ignores_other_statuses(status: int) -> None:
    assert call("isProtection", {"details": {"status": status, "error_code": "CONFLICT"}}) is False


@needs_node
@pytest.mark.parametrize("code", list(PROTECTION_CODES))
def test_is_protection_marks_listed_error_codes(code: str) -> None:
    assert call("isProtection", {"details": {"status": 400, "error_code": code}}) is True


@needs_node
@pytest.mark.parametrize("code", ["NOT_FOUND", "CONFLICT", "INVALID_STATE", "VALIDATION_ERROR"])
def test_is_protection_ignores_other_error_codes(code: str) -> None:
    assert call("isProtection", {"details": {"status": 409, "error_code": code}}) is False


@needs_node
def test_is_protection_without_details_is_false() -> None:
    for event in ({}, {"details": None}, {"details": {}}):
        assert call("isProtection", event) is False


@needs_node
def test_is_protection_ignores_a_numeric_string_status() -> None:
    assert call("isProtection", {"details": {"status": "403"}}) is False


@needs_node
def test_is_protection_does_not_look_at_outcome() -> None:
    details = {"status": 404, "error_code": "NOT_FOUND"}
    assert call("isProtection", {"outcome": "denied", "details": details}) is False


@needs_node
def test_is_protection_marks_a_key_cap_refusal_row() -> None:
    details = {"reason": "key_cap", "limit": "key_max_sandboxes", "max": 1, "current": 1}
    event = {"action": "sandbox.create_refused", "outcome": "denied", "details": details}
    assert call("isProtection", event) is True


@needs_node
@pytest.mark.parametrize("action", ["sandbox.create_refused", "sandbox.start_refused"])
def test_is_protection_ignores_a_capacity_refusal_row(action: str) -> None:
    requested = {"sandboxes": 1, "vcpus": 1.0, "memory_mib": 512, "disk_gib": 3}
    details = {"reason": "capacity", "host_full": True, "requested": requested}
    event = {"action": action, "outcome": "denied", "details": details}
    assert call("isProtection", event) is False


@needs_node
def test_is_protection_needs_both_action_and_reason_for_the_key_cap_rule() -> None:
    events = (
        {"action": "request.denied", "details": {"reason": "key_cap"}},
        {"action": "sandbox.start_refused", "details": {"reason": "key_cap"}},
        {"action": "sandbox.create_refused", "details": {"reason": "other"}},
    )
    for event in events:
        assert call("isProtection", event) is False


@needs_node
def test_action_label_uses_fixed_labels_then_humanizes() -> None:
    cases = {"request.denied": "Request refused", "request.failed": "Request failed",
             "sandbox.egress_updated": "sandbox egress updated",
             "toolbox.fs.upload": "toolbox fs upload", None: "-"}
    for action, label in cases.items():
        assert call("actionLabel", action) == label


@needs_node
def test_outcome_class_is_whitelisted() -> None:
    known = {"success": "outcome-success", "denied": "outcome-denied", "error": "outcome-error"}
    for outcome, css in known.items():
        assert call("outcomeClass", outcome) == css
    for outcome in ("<script>", "constructor", "__proto__", None):
        assert call("outcomeClass", outcome) == "outcome-unknown"


@needs_node
def test_target_text_joins_type_and_id() -> None:
    assert call("targetText", {"target_type": "sandbox", "target_id": "sbx_1"}) == "sandbox sbx_1"
    assert call("targetText", {"target_id": "sbx_1"}) == "sbx_1"
    assert call("targetText", {}) is None


@needs_node
def test_summary_rows_for_an_ok_chain() -> None:
    result = {"ok": True, "checked": 3, "last_id": "aud_3", "last_hash": "abc",
              "findings": [], "findings_truncated": False}
    assert call("summaryRows", result) == [
        ["ok", "yes"], ["checked", 3], ["newest row id", "aud_3"],
        ["newest row hash", "abc"], ["findings", 0], ["findings truncated", "no"],
    ]


@needs_node
def test_summary_rows_for_a_broken_chain() -> None:
    findings = [{"kind": "hash_mismatch", "event_id": f"aud_{n}", "detail": d}
                for n, d in ((2, "x"), (3, "y"))]
    result: dict[str, Any] = {"ok": False, "checked": 3, "last_id": "aud_3", "last_hash": "abc",
                              "findings": findings, "findings_truncated": True}
    expected = [["ok", "no"], ["checked", 3], ["newest row id", "aud_3"],
                ["newest row hash", "abc"], ["findings", 2], ["findings truncated", "yes"]]
    assert call("summaryRows", result) == expected
    assert call("summaryRows", {**result, "acknowledged_findings": 4}) == [
        *expected, ["acknowledged findings", 4]]
    assert call("summaryRows", {**result, "acknowledged_findings": 0}) == expected


@needs_node
def test_summary_rows_for_an_empty_org() -> None:
    result = {"ok": True, "checked": 0, "first_id": None, "last_id": None, "last_hash": None,
              "findings": [], "findings_truncated": False}
    rows = call("summaryRows", result)
    assert rows[2] == ["newest row id", None]
    assert rows[3] == ["newest row hash", None]


@needs_node
async def test_composed_script_parses(client: Http, tmp_path: Path) -> None:
    path = tmp_path / "console.js"
    path.write_text(inline_script(await page(client)))
    parse = "new Function(require('fs').readFileSync(process.argv[1], 'utf8'))"
    args = ["node", "-e", parse, str(path)]
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


async def newest_first(client: Http, key: str) -> list[dict[str, Any]]:
    response = await get(client, AUDIT, key, limit=20, order="desc")
    rows: list[dict[str, Any]] = response.json()["data"]
    return rows


async def test_list_desc_returns_refusal_rows_with_status_and_error_code(
    client: Http, seeded: str
) -> None:
    rows = await newest_first(client, seeded)
    first, last = rows[0], rows[-1]
    assert (first["action"], first["outcome"]) == ("request.denied", "denied")
    assert first["details"]["path"] == "/v1/sandboxes/sbx_missing/stop"
    assert first["details"]["status"] == 404
    assert first["details"]["error_code"] == "NOT_FOUND"
    assert last["action"] == "sandbox.create"


async def test_list_rows_carry_no_hash_fields(client: Http, seeded: str) -> None:
    rows = await newest_first(client, seeded)
    assert rows
    assert all("hash" not in key for row in rows for key in row)


async def test_verify_names_the_newest_row_and_its_hash(client: Http, seeded: str) -> None:
    rows = await newest_first(client, seeded)
    response = await get(client, f"{AUDIT}/verify", seeded)
    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert data["ok"] is True and data["checked"] == 3
    assert data["last_id"] == rows[0]["id"]
    assert isinstance(data["last_hash"], str) and data["last_hash"]


async def test_list_and_verify_write_no_audit_row(client: Http, seeded: str) -> None:
    before = [row["id"] for row in await newest_first(client, seeded)]
    verify = await get(client, f"{AUDIT}/verify", seeded)
    after = [row["id"] for row in await newest_first(client, seeded)]
    assert verify.status_code == 200, verify.text
    assert len(before) == 3
    assert after == before
