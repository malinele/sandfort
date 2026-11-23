"""``audit-reanchor``: acknowledge historical chain breaks so verify can pass again.

A forged break stays in the history and the export; the re-anchor event only moves the
findings at or before its ``acknowledged_through`` row out of ``ok`` and into
``acknowledged_findings``. Sync tests: the admin CLI runs its own event loop.
"""

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from typer.testing import CliRunner

from sandfort import admin_cli
from sandfort.api.app import create_app
from sandfort.api.routes import audit as audit_routes
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import ActorType
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.audit import AuditRecorder
from sandfort.services.audit_chain import REANCHOR_ACTION, FindingKind, link_hash

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
VERIFY_URL = "/v1/audit-events/verify"
FORGED_PREV = "f" * 64
EXIT_MISMATCH = 3
NOTE = "2026-11 incident: forks written before the chain lock"
RUNNER = CliRunner()


@pytest.fixture
def db_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'reanchor.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    monkeypatch.setenv("SANDFORT_DATABASE_URL", url)
    monkeypatch.setenv("SANDFORT_API_KEY_PEPPER", PEPPER)
    return url


def _settings(url: str) -> Settings:
    return Settings(driver="fake", database_url=url, api_key_pepper=PEPPER)


async def _setup_org(url: str) -> tuple[str, str]:
    """An org with an ``audit:read`` key; returns (org id, plaintext key)."""
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset({Scope.AUDIT_READ}),
        created_at=NOW,
    )
    engine = create_engine(_settings(url))
    try:
        async with UnitOfWork(create_session_factory(engine)) as uow:
            await uow.orgs.add(org)
            await uow.api_keys.add(stored)
            await uow.commit()
    finally:
        await engine.dispose()
    return org.id, generated.key


async def _seed(url: str, org_id: str, count: int, start: int) -> list[str]:
    recorder = AuditRecorder(FrozenClock(NOW))
    engine = create_engine(_settings(url))
    ids: list[str] = []
    try:
        for index in range(start, start + count):
            async with UnitOfWork(create_session_factory(engine)) as uow:
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
    finally:
        await engine.dispose()
    return ids


async def _fork_at(url: str, org_id: str, index: int) -> None:
    """Make row ``index`` link to a hash that is not its predecessor's (one broken link)."""
    engine = create_engine(_settings(url))
    try:
        async with UnitOfWork(create_session_factory(engine)) as uow:
            rows = list(await uow.audit.list_chained(org_id, limit=1000))
        prev = FORGED_PREV
        async with engine.begin() as connection:
            for row in rows[index:]:
                entry_hash = link_hash(prev, row.event)
                await connection.execute(
                    text("UPDATE audit_events SET prev_hash = :p, hash = :h WHERE id = :id"),
                    {"p": prev, "h": entry_hash, "id": row.event.id},
                )
                prev = entry_hash
    finally:
        await engine.dispose()


async def _api_verify(url: str, key: str) -> dict[str, Any]:
    app = create_app(_settings(url))
    app.include_router(audit_routes.router)
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            response = await http.get(VERIFY_URL, headers={"Authorization": f"Bearer {key}"})
        assert response.status_code == 200, response.text
        body: dict[str, Any] = response.json()["data"]
        return body
    finally:
        await app.state.engine.dispose()


async def _row_count(url: str, org_id: str) -> int:
    engine = create_engine(_settings(url))
    try:
        async with UnitOfWork(create_session_factory(engine)) as uow:
            return len(await uow.audit.list_chained(org_id, limit=1000))
    finally:
        await engine.dispose()


def seed(url: str, org_id: str, count: int, start: int = 0) -> list[str]:
    return asyncio.run(_seed(url, org_id, count, start))


def fork_at(url: str, org_id: str, index: int) -> None:
    asyncio.run(_fork_at(url, org_id, index))


def verify(url: str, key: str) -> dict[str, Any]:
    return asyncio.run(_api_verify(url, key))


def row_count(url: str, org_id: str) -> int:
    return asyncio.run(_row_count(url, org_id))


def reanchor(org_id: str, note: str = NOTE) -> Any:
    return RUNNER.invoke(admin_cli.app, ["audit-reanchor", "--org", org_id, "--note", note])


def exported(org_id: str) -> list[dict[str, Any]]:
    result = RUNNER.invoke(admin_cli.app, ["audit-export", "--org-id", org_id])
    assert result.exit_code == 0, result.output
    return [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]


def broken_chain(url: str) -> tuple[str, str, list[str]]:
    """An org with 6 rows and two forged links (rows 1 and 3)."""
    org_id, key = asyncio.run(_setup_org(url))
    ids = seed(url, org_id, 6)
    fork_at(url, org_id, 1)
    fork_at(url, org_id, 3)
    return org_id, key, ids


def test_a_forged_break_verifies_not_ok(db_url: str) -> None:
    _, key, ids = broken_chain(db_url)

    data = verify(db_url, key)

    assert data["ok"] is False
    assert [item["event_id"] for item in data["findings"]] == [ids[1], ids[3]]
    assert {item["kind"] for item in data["findings"]} == {FindingKind.LINK_BROKEN.value}
    assert "acknowledged_findings" not in data and "reanchored_by" not in data
    assert RUNNER.invoke(admin_cli.app, ["audit-verify"]).exit_code == EXIT_MISMATCH


def test_after_reanchor_verify_is_ok_with_the_findings_acknowledged(db_url: str) -> None:
    org_id, key, ids = broken_chain(db_url)

    result = reanchor(org_id)

    assert result.exit_code == 0, result.output
    data = verify(db_url, key)
    assert data["ok"] is True and data["findings"] == []
    assert data["acknowledged_findings"] == 2
    assert data["reanchored_by"] == result.stdout.strip()
    assert data["checked"] == len(ids) + 1
    audit_verify = RUNNER.invoke(admin_cli.app, ["audit-verify"])
    assert audit_verify.exit_code == 0, audit_verify.output
    assert "2 acknowledged finding(s)" in audit_verify.stdout


def test_the_event_records_the_acknowledgement_and_every_row_is_kept(db_url: str) -> None:
    org_id, _, ids = broken_chain(db_url)

    result = reanchor(org_id)

    rows = exported(org_id)
    event = rows[-1]
    assert event["action"] == REANCHOR_ACTION and event["id"] == result.stdout.strip()
    assert event["details"] == {"acknowledged_through": ids[3], "findings": 2, "note": NOTE}
    assert event["actor_type"] == ActorType.PLATFORM_ADMIN.value
    assert [row["id"] for row in rows[:-1]] == ids


def test_a_new_break_after_the_reanchor_makes_verify_not_ok_again(db_url: str) -> None:
    org_id, key, ids = broken_chain(db_url)
    anchor_event = reanchor(org_id).stdout.strip()
    later = seed(db_url, org_id, 3, start=100)
    fork_at(db_url, org_id, len(ids) + 2)  # the second row after the re-anchor event

    data = verify(db_url, key)

    assert data["ok"] is False
    assert [item["event_id"] for item in data["findings"]] == [later[1]]
    assert data["acknowledged_findings"] == 2 and data["reanchored_by"] == anchor_event


def test_a_break_in_the_reanchor_event_itself_is_not_acknowledged(db_url: str) -> None:
    org_id, key, ids = broken_chain(db_url)
    anchor_event = reanchor(org_id).stdout.strip()
    fork_at(db_url, org_id, len(ids))  # the re-anchor event links to a forged hash

    data = verify(db_url, key)

    assert data["ok"] is False
    assert [item["event_id"] for item in data["findings"]] == [anchor_event]
    assert data["acknowledged_findings"] == 2


def test_reanchor_with_no_findings_appends_nothing(db_url: str) -> None:
    org_id, key = asyncio.run(_setup_org(db_url))
    seed(db_url, org_id, 4)

    result = reanchor(org_id)

    assert result.exit_code == 0, result.output
    assert "no findings" in result.stdout
    assert row_count(db_url, org_id) == 4
    data = verify(db_url, key)
    assert data["ok"] is True
    assert "acknowledged_findings" not in data and "reanchored_by" not in data


def test_a_second_reanchor_with_nothing_new_appends_nothing(db_url: str) -> None:
    org_id, _, ids = broken_chain(db_url)
    reanchor(org_id)

    result = reanchor(org_id)

    assert result.exit_code == 0 and "no findings" in result.stdout
    assert row_count(db_url, org_id) == len(ids) + 1


def test_the_admin_command_prints_the_event_id(db_url: str) -> None:
    org_id, _, _ = broken_chain(db_url)

    result = reanchor(org_id)

    assert result.exit_code == 0, result.output
    assert result.stdout.strip().startswith("aud_")
    assert len(result.stdout.split()) == 1


def test_an_unknown_org_and_a_blank_note_are_refused(db_url: str) -> None:
    org_id, _, _ = broken_chain(db_url)

    unknown = reanchor("org_missing")
    blank = reanchor(org_id, note="  ")

    assert unknown.exit_code == 1 and "not found" in unknown.output
    assert blank.exit_code == 1 and "note" in blank.output
    assert RUNNER.invoke(admin_cli.app, ["audit-verify"]).exit_code == EXIT_MISMATCH
