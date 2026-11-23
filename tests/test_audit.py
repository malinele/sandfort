"""Audit trail tests: recorder rows, redaction, listing. FakeDriver, temp SQLite, httpx.

Daemon-free. Rows are read straight from the database through a fresh unit of work, so
the assertions see exactly what was committed.
"""

import hashlib
import json
from collections import Counter
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from sqlalchemy import text

from sandfort.api.app import create_app
from sandfort.api.deps import AUDIT_RECORDER_ATTR
from sandfort.api.errors import DENIED_ACTION
from sandfort.api.routes import audit as audit_routes
from sandfort.api.routes.toolbox import process as process_routes
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import FrozenClock, SystemClock
from sandfort.config import Settings
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import ActorType, AuditEvent, AuditOutcome
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.audit import DIGEST_PREFIX, AuditRecorder, redact_details
from sandfort.services.audit_chain import ChainPolicy, FindingKind, export_line, link_hash
from sandfort.services.audit_chain_head import HEAD_TYPE, SUMMARY_TYPE

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
AUDIT_URL = "/v1/audit-events"
FULL_ACCESS = frozenset(
    {Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX, Scope.AUDIT_READ}
)
SECRET_ENV = "env-secret-value-7f3a"
SECRET_STDIN = "stdin-secret-value-91bc"
SECRET_CODE = "print('code-secret-value-c0de')"
SECRET_CMD = "echo cmd-secret-value-5e1f"
SECRET_FRAGMENTS = (SECRET_ENV, SECRET_STDIN, "code-secret-value-c0de", "cmd-secret-value-5e1f")


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'audit.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(driver="fake", database_url=url, api_key_pepper=PEPPER)
    application = create_app(settings)
    application.include_router(process_routes.router)
    application.include_router(audit_routes.router)
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


async def seed_key(app: FastAPI, org_id: str, scopes: frozenset[Scope]) -> tuple[str, str]:
    """Return ``(raw key, key id)``."""
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=scopes,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key, stored.id


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


@pytest.fixture
async def key_pair(app: FastAPI, org_id: str) -> tuple[str, str]:
    return await seed_key(app, org_id, FULL_ACCESS)


@pytest.fixture
def key(key_pair: tuple[str, str]) -> str:
    return key_pair[0]


async def send(
    client: httpx.AsyncClient, method: str, path: str, key: str, *, status: int, **kwargs: Any
) -> dict[str, Any]:
    response = await client.request(
        method, path, headers={"Authorization": f"Bearer {key}"}, **kwargs
    )
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    return body


async def rows(app: FastAPI, org_id: str) -> list[AuditEvent]:
    async with UnitOfWork(app.state.session_factory) as uow:
        return list(await uow.audit.list(org_id, limit=200))


async def create_sandbox(client: httpx.AsyncClient, key: str, **payload: Any) -> str:
    body = await send(client, "POST", BASE, key, status=201, json=payload)
    sandbox_id: str = body["data"]["id"]
    return sandbox_id


def process_path(sandbox_id: str, action: str) -> str:
    return f"{BASE}/{sandbox_id}/toolbox/process/{action}"


def digest_of(text: str) -> dict[str, Any]:
    raw = text.encode()
    return {"sha256": DIGEST_PREFIX + hashlib.sha256(raw).hexdigest(), "length": len(raw)}


# --- redaction unit tests -----------------------------------------------------------


def test_redact_env_keeps_sorted_key_names_and_count_only() -> None:
    result = redact_details({"env": {"ZED": "z-value", "ALPHA": "a-value"}})

    assert result == {"env": {"keys": ["ALPHA", "ZED"], "value_count": 2}}


@pytest.mark.parametrize("name", ["stdin", "code", "command", "cmd", "token"])
def test_redact_digested_fields_keep_digest_and_byte_length(name: str) -> None:
    result = redact_details({name: "héllo secret"})

    assert result == {name: digest_of("héllo secret")}
    assert result[name]["length"] == len("héllo secret".encode())
    assert "secret" not in json.dumps(result)


def test_redact_args_list_is_digested_not_stored() -> None:
    result = redact_details({"args": ["--password", "hunter2"]})

    assert "hunter2" not in json.dumps(result)
    assert result["args"]["sha256"].startswith(DIGEST_PREFIX)
    assert result["args"]["length"] > 0


def test_redact_passes_scalars_and_recurses_into_nested_dicts() -> None:
    original = {
        "name": "box",
        "public": False,
        "count": 3,
        "nested": {"env": {"A": "secret-a"}, "token": "tok", "note": "kept"},
        "items": [{"cmd": "rm -rf /"}],
    }

    result = redact_details(original)

    assert result["name"] == "box" and result["public"] is False and result["count"] == 3
    assert result["nested"] == {
        "env": {"keys": ["A"], "value_count": 1},
        "token": digest_of("tok"),
        "note": "kept",
    }
    assert result["items"] == [{"cmd": digest_of("rm -rf /")}]
    assert original["nested"]["token"] == "tok"  # input untouched


# --- one row per mutating call ------------------------------------------------------


async def test_each_mutating_call_writes_exactly_one_audit_row(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key_pair: tuple[str, str]
) -> None:
    key, key_id = key_pair
    sandbox_id = await create_sandbox(client, key)
    assert Counter(e.action for e in await rows(app, org_id)) == {"sandbox.create": 1}

    steps: list[tuple[str, str, dict[str, Any]]] = [
        ("POST", f"{BASE}/{sandbox_id}/stop", {}),
        ("POST", f"{BASE}/{sandbox_id}/start", {}),
        ("POST", process_path(sandbox_id, "execute"), {"json": {"argv": ["ls"]}}),
        (
            "POST",
            process_path(sandbox_id, "code-run"),
            {"json": {"language": "python", "code": "print(1)"}},
        ),
        ("DELETE", f"{BASE}/{sandbox_id}", {}),
    ]
    count = len(await rows(app, org_id))
    for method, path, kwargs in steps:
        await send(client, method, path, key, status=200, **kwargs)
        now_count = len(await rows(app, org_id))
        assert now_count == count + 1, f"{method} {path} wrote {now_count - count} rows"
        count = now_count

    events = await rows(app, org_id)
    assert Counter(e.action for e in events) == {
        "sandbox.create": 1,
        "sandbox.stop": 1,
        "sandbox.start": 1,
        "toolbox.process.execute": 1,
        "toolbox.process.code_run": 1,
        "sandbox.delete": 1,
    }
    for event in events:
        assert event.org_id == org_id
        assert event.actor_id == key_id
        assert event.actor_type.value == "api_key"
        assert event.target_id == sandbox_id
        assert event.target_type == "sandbox"


async def test_failed_call_writes_only_a_denied_row(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    await send(client, "POST", f"{BASE}/{sandbox_id}/stop", key, status=200)
    before = len(await rows(app, org_id))
    path = process_path(sandbox_id, "execute")

    await send(client, "POST", path, key, status=409, json={"argv": ["ls"]})

    events = await rows(app, org_id)
    assert len(events) == before + 1
    assert "toolbox.process.execute" not in {e.action for e in events}
    denied = [e for e in events if e.action == DENIED_ACTION]
    assert len(denied) == 1
    assert denied[0].outcome is AuditOutcome.DENIED
    assert denied[0].details["status"] == 409
    assert denied[0].details["path"] == path


# --- authenticated refusals ---------------------------------------------------------


class ExplodingRecorder(AuditRecorder):
    async def record(self, uow: UnitOfWorkPort, **kwargs: Any) -> AuditEvent:
        raise RuntimeError("audit store unavailable")


async def test_missing_scope_refusal_writes_one_denied_row(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    weak_key, weak_key_id = await seed_key(app, org_id, frozenset({Scope.SANDBOXES_READ}))

    body = await send(client, "GET", AUDIT_URL, weak_key, status=403)

    events = await rows(app, org_id)
    assert len(events) == 1
    event = events[0]
    assert event.action == DENIED_ACTION
    assert event.outcome is AuditOutcome.DENIED
    assert event.actor_id == weak_key_id
    assert event.details == {
        "method": "GET",
        "path": AUDIT_URL,
        "status": 403,
        "error_code": body["error"]["code"],
    }
    assert event.user_agent is not None
    assert event.user_agent.startswith("python-httpx")


async def test_successful_call_still_writes_success_row_and_no_denial(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    await create_sandbox(client, key)

    events = await rows(app, org_id)
    assert [(e.action, e.outcome) for e in events] == [("sandbox.create", AuditOutcome.SUCCESS)]


async def test_denial_audit_failure_keeps_the_normal_error_response(
    app: FastAPI,
    client: httpx.AsyncClient,
    org_id: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    weak_key, _ = await seed_key(app, org_id, frozenset({Scope.SANDBOXES_READ}))
    setattr(app.state, AUDIT_RECORDER_ATTR, ExplodingRecorder(SystemClock()))

    body = await send(client, "GET", AUDIT_URL, weak_key, status=403)

    assert body["success"] is False
    assert body["error"]["details"]["missing_scopes"] == ["audit:read"]
    assert await rows(app, org_id) == []
    assert "failed to audit a denied request" in caplog.text


async def test_get_requests_produce_no_audit_row(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    before = len(await rows(app, org_id))

    await send(client, "GET", BASE, key, status=200)
    await send(client, "GET", f"{BASE}/{sandbox_id}", key, status=200)
    await send(client, "GET", AUDIT_URL, key, status=200)

    assert len(await rows(app, org_id)) == before


# --- redaction end to end -----------------------------------------------------------


async def test_secrets_never_reach_audit_details(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key, env={"API_TOKEN": SECRET_ENV, "MODE": "x"})
    await send(
        client,
        "POST",
        process_path(sandbox_id, "execute"),
        key,
        status=200,
        json={"command": SECRET_CMD, "env": {"DB_PASS": SECRET_ENV}, "stdin": SECRET_STDIN},
    )
    await send(
        client,
        "POST",
        process_path(sandbox_id, "code-run"),
        key,
        status=200,
        json={"language": "python", "code": SECRET_CODE, "env": {"K": SECRET_ENV}},
    )

    events = {e.action: e for e in await rows(app, org_id)}
    serialized = json.dumps([e.details for e in events.values()])
    for fragment in SECRET_FRAGMENTS:
        assert fragment not in serialized

    assert events["sandbox.create"].details["env"] == {
        "keys": ["API_TOKEN", "MODE"],
        "value_count": 2,
    }
    execute = events["toolbox.process.execute"].details
    assert execute["env"] == {"keys": ["DB_PASS"], "value_count": 1}
    assert execute["stdin"] == digest_of(SECRET_STDIN)
    assert execute["command"] == digest_of(SECRET_CMD)
    code_run = events["toolbox.process.code_run"].details
    assert code_run["code"] == digest_of(SECRET_CODE)
    assert code_run["language"] == "python"

    listing = await client.get(AUDIT_URL, headers={"Authorization": f"Bearer {key}"})
    for fragment in SECRET_FRAGMENTS:
        assert fragment not in listing.text


# --- listing ------------------------------------------------------------------------


async def test_listing_paginates_without_gaps_or_duplicates(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    await send(client, "POST", f"{BASE}/{sandbox_id}/stop", key, status=200)
    await send(client, "POST", f"{BASE}/{sandbox_id}/start", key, status=200)
    await send(client, "DELETE", f"{BASE}/{sandbox_id}", key, status=200)
    total = len(await rows(app, org_id))
    assert total == 4

    seen: list[str] = []
    cursor: str | None = None
    pages = 0
    while True:
        params: dict[str, Any] = {"limit": 3}
        if cursor is not None:
            params["cursor"] = cursor
        body = await send(client, "GET", AUDIT_URL, key, status=200, params=params)
        assert body["success"] is True
        seen.extend(item["id"] for item in body["data"])
        pages += 1
        cursor = body["meta"]["next_cursor"]
        if cursor is None:
            break

    assert pages == 2
    assert len(seen) == total and len(set(seen)) == total
    assert seen == sorted(seen)


async def test_listing_filters_by_action_and_target(client: httpx.AsyncClient, key: str) -> None:
    first = await create_sandbox(client, key)
    await create_sandbox(client, key)

    by_action = await send(
        client, "GET", AUDIT_URL, key, status=200, params={"action": "sandbox.create"}
    )
    by_target = await send(client, "GET", AUDIT_URL, key, status=200, params={"target_id": first})

    assert len(by_action["data"]) == 2
    assert [item["target_id"] for item in by_target["data"]] == [first]


async def test_listing_requires_audit_read_scope(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    weak_key, _ = await seed_key(app, org_id, frozenset({Scope.SANDBOXES_READ}))

    body = await send(client, "GET", AUDIT_URL, weak_key, status=403)

    assert body["success"] is False
    assert body["error"]["details"]["missing_scopes"] == ["audit:read"]


async def test_listing_is_scoped_to_the_callers_org(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    await create_sandbox(client, key)
    other_org = Org(id=new_org_id(), name="Other", slug="other", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(other_org)
        await uow.commit()
    other_key, _ = await seed_key(app, other_org.id, FULL_ACCESS)

    body = await send(client, "GET", AUDIT_URL, other_key, status=200)

    assert body["data"] == []


# --- export and verify over the API -------------------------------------------------

EXPORT_URL = f"{AUDIT_URL}/export"
VERIFY_URL = f"{AUDIT_URL}/verify"


async def seed_events(app: FastAPI, org_id: str, times: list[datetime]) -> list[str]:
    """Record one chained audit row per instant, in order; return the ids."""
    clock = FrozenClock(NOW)
    recorder = AuditRecorder(clock)
    ids: list[str] = []
    for index, when in enumerate(times):
        clock.set(when)
        async with UnitOfWork(app.state.session_factory) as uow:
            event = await recorder.record(
                uow,
                org_id=org_id,
                actor_type=ActorType.SYSTEM,
                actor_id=None,
                action=f"test.step{index}",
                target_type="thing",
                target_id=f"thing-{index}",
                details={"n": index},
            )
            await uow.commit()
        ids.append(event.id)
    return ids


async def add_other_org(app: FastAPI) -> str:
    other_org = Org(id=new_org_id(), name="Other", slug="other", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(other_org)
        await uow.commit()
    return other_org.id


async def export_raw(client: httpx.AsyncClient, key: str, **params: str) -> str:
    response = await client.get(
        EXPORT_URL, headers={"Authorization": f"Bearer {key}"}, params=params
    )
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/x-ndjson")
    return response.text


def split_export(raw: str, params: dict[str, str]) -> tuple[list[str], dict[str, Any]]:
    """Split an export into its event-row lines and the trailer (the last line, by `type`).

    The trailer is a signed head only for an unfiltered, unbounded export on a server with a
    chain key; any filter or bound, or no chain key, gives a summary.
    """
    lines = raw.splitlines()
    assert lines, "an export always ends with a trailer"
    trailer = json.loads(lines[-1])
    head_expected = ChainPolicy.from_env().key is not None and not params
    assert trailer["type"] == (HEAD_TYPE if head_expected else SUMMARY_TYPE)
    row_lines = lines[:-1]
    assert all("type" not in json.loads(line) for line in row_lines)
    return row_lines, trailer


async def export(client: httpx.AsyncClient, key: str, **params: str) -> list[dict[str, Any]]:
    raw = await export_raw(client, key, **params)
    row_lines, _trailer = split_export(raw, params)
    return [json.loads(line) for line in row_lines]


async def test_export_lines_carry_hashes_that_relink(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    ids = await seed_events(app, org_id, [NOW, NOW, NOW])

    raw = await export_raw(client, key)

    row_lines, _trailer = split_export(raw, {})
    lines = [json.loads(line) for line in row_lines]
    assert [line["id"] for line in lines] == ids
    assert lines[0]["prev_hash"] is None
    for previous, current in zip(lines, lines[1:], strict=False):
        assert current["prev_hash"] == previous["hash"]
    for line in lines:
        fields = {k: v for k, v in line.items() if k not in ("prev_hash", "hash")}
        assert line["hash"] == link_hash(line["prev_hash"], AuditEvent.model_validate(fields))
    async with UnitOfWork(app.state.session_factory) as uow:
        stored = await uow.audit.list_chained(org_id)
    rows_text = "".join(line + "\n" for line in row_lines)
    assert rows_text == "".join(export_line(row) + "\n" for row in stored)  # as audit-export


async def test_export_filters_by_from_inclusive_and_to_exclusive(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    hour = timedelta(hours=1)
    ids = await seed_events(app, org_id, [NOW - 2 * hour, NOW - hour, NOW])
    start, end = (NOW - hour).isoformat(), NOW.isoformat()

    window = await export(client, key, **{"from": start, "to": end})
    tail = await export(client, key, **{"from": start})
    head = await export(client, key, to=start)

    assert [line["id"] for line in window] == [ids[1]]
    assert [line["id"] for line in tail] == ids[1:]
    assert [line["id"] for line in head] == ids[:1]


async def test_export_rejects_to_not_after_from(client: httpx.AsyncClient, key: str) -> None:
    params = {"from": NOW.isoformat(), "to": NOW.isoformat()}

    body = await send(client, "GET", EXPORT_URL, key, status=422, params=params)

    assert body["success"] is False


@pytest.mark.parametrize("url", [EXPORT_URL, VERIFY_URL])
async def test_export_and_verify_require_audit_read_scope(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, url: str
) -> None:
    weak_key, _ = await seed_key(app, org_id, frozenset({Scope.SANDBOXES_READ}))

    body = await send(client, "GET", url, weak_key, status=403)

    assert body["error"]["details"]["missing_scopes"] == ["audit:read"]


async def test_verify_reports_ok_on_an_intact_chain(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    ids = await seed_events(app, org_id, [NOW, NOW, NOW])
    lines = await export(client, key)

    body = await send(client, "GET", VERIFY_URL, key, status=200)

    assert body["success"] is True
    assert body["data"] == {
        "ok": True,
        "checked": 3,
        "first_id": ids[0],
        "last_id": ids[-1],
        "last_hash": lines[-1]["hash"],
        "findings": [],
        "findings_truncated": False,
    }


async def test_verify_flags_a_row_whose_details_were_tampered_with(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    ids = await seed_events(app, org_id, [NOW, NOW, NOW])
    async with app.state.engine.begin() as connection:
        await connection.execute(
            text("UPDATE audit_events SET details = :details WHERE id = :id"),
            {"details": json.dumps({"n": 999}), "id": ids[1]},
        )

    body = await send(client, "GET", VERIFY_URL, key, status=200)

    data = body["data"]
    assert data["ok"] is False and data["checked"] == 3
    assert [(f["kind"], f["event_id"]) for f in data["findings"]] == [
        (FindingKind.HASH_MISMATCH.value, ids[1])
    ]
    assert data["findings_truncated"] is False


async def test_verify_caps_findings_at_100_and_says_so(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    await seed_events(app, org_id, [NOW] * 101)
    async with app.state.engine.begin() as connection:
        await connection.execute(
            text("UPDATE audit_events SET details = :details"), {"details": "{}"}
        )

    body = await send(client, "GET", VERIFY_URL, key, status=200)

    data = body["data"]
    assert data["ok"] is False and data["checked"] == 101
    assert len(data["findings"]) == 100 and data["findings_truncated"] is True


async def test_export_and_verify_never_show_another_orgs_events(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    own_ids = await seed_events(app, org_id, [NOW, NOW])
    other_org = await add_other_org(app)
    other_ids = await seed_events(app, other_org, [NOW])
    other_key, _ = await seed_key(app, other_org, FULL_ACCESS)

    own_lines = await export(client, key)
    other_lines = await export(client, other_key)
    own_verify = await send(client, "GET", VERIFY_URL, key, status=200)
    other_verify = await send(client, "GET", VERIFY_URL, other_key, status=200)

    assert [line["id"] for line in own_lines] == own_ids
    assert [line["id"] for line in other_lines] == other_ids
    assert {line["org_id"] for line in own_lines} == {org_id}
    assert own_verify["data"]["checked"] == 2 and own_verify["data"]["last_id"] == own_ids[-1]
    assert other_verify["data"]["checked"] == 1
    assert other_verify["data"]["first_id"] == other_ids[0]
