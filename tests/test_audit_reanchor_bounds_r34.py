"""Bounds of the re-anchored verify: stored findings are capped, only an admin row anchors.

The verify route looks the latest ``audit.chain_reanchored`` row up before the walk, so
acknowledged findings are only counted and at most ``MAX_FINDINGS`` open ones are stored.
A re-anchor row written by anyone but the platform-admin actor acknowledges nothing.
Sync tests: the admin CLI runs its own event loop.
"""

import asyncio
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
from sandfort.api.schemas.audit import MAX_FINDINGS
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import ActorType, AuditEvent, AuditOutcome
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.audit import AuditRecorder
from sandfort.services.audit_chain import (
    REANCHOR_ACTION,
    ChainVerifier,
    FindingKind,
    reanchor_through,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
VERIFY_URL = "/v1/audit-events/verify"
BAD_HASH = "0" * 64
BROKEN_ROWS = MAX_FINDINGS + 5  # each corrupted hash gives a mismatch and a broken link
RUNNER = CliRunner()


@pytest.fixture
def db_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'bounds.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    monkeypatch.setenv("SANDFORT_DATABASE_URL", url)
    monkeypatch.setenv("SANDFORT_API_KEY_PEPPER", PEPPER)
    return url


def _settings(url: str) -> Settings:
    return Settings(driver="fake", database_url=url, api_key_pepper=PEPPER)


async def _setup_org(url: str) -> tuple[str, str]:
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


async def _record(
    url: str,
    org_id: str,
    count: int,
    start: int = 0,
    *,
    actor_type: ActorType = ActorType.SYSTEM,
    action: str | None = None,
    details: dict[str, Any] | None = None,
) -> list[str]:
    recorder = AuditRecorder(FrozenClock(NOW))
    engine = create_engine(_settings(url))
    ids: list[str] = []
    try:
        for index in range(start, start + count):
            async with UnitOfWork(create_session_factory(engine)) as uow:
                event = await recorder.record(
                    uow,
                    org_id=org_id,
                    actor_type=actor_type,
                    actor_id=None,
                    action=action or f"test.step{index}",
                    target_type="thing",
                    target_id=f"thing-{index}",
                    details=details if details is not None else {"n": index},
                )
                await uow.commit()
            ids.append(event.id)
    finally:
        await engine.dispose()
    return ids


async def _corrupt_hashes(url: str, row_ids: list[str]) -> None:
    """Overwrite the stored hash of each row: a mismatch there and a broken link after it."""
    engine = create_engine(_settings(url))
    try:
        async with engine.begin() as connection:
            for row_id in row_ids:
                await connection.execute(
                    text("UPDATE audit_events SET hash = :h WHERE id = :id"),
                    {"h": BAD_HASH, "id": row_id},
                )
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


def record(url: str, org_id: str, count: int, start: int = 0, **kwargs: Any) -> list[str]:
    return asyncio.run(_record(url, org_id, count, start, **kwargs))


def corrupt(url: str, row_ids: list[str]) -> None:
    asyncio.run(_corrupt_hashes(url, row_ids))


def verify(url: str, key: str) -> dict[str, Any]:
    return asyncio.run(_api_verify(url, key))


def reanchor(org_id: str) -> str:
    result = RUNNER.invoke(
        admin_cli.app, ["audit-reanchor", "--org", org_id, "--note", "bounds test"]
    )
    assert result.exit_code == 0, result.output
    return str(result.stdout.strip())


def test_open_findings_are_stored_up_to_the_cap_and_the_verify_stays_not_ok(
    db_url: str,
) -> None:
    org_id, key = asyncio.run(_setup_org(db_url))
    early = record(db_url, org_id, 6)
    corrupt(db_url, early[1:3])
    event_id = reanchor(org_id)
    later = record(db_url, org_id, BROKEN_ROWS + 1, start=100)
    corrupt(db_url, later[:BROKEN_ROWS])

    data = verify(db_url, key)

    assert data["ok"] is False
    assert len(data["findings"]) == MAX_FINDINGS
    assert data["findings_truncated"] is True
    assert data["reanchored_by"] == event_id
    assert data["acknowledged_findings"] == 4  # two corrupted rows: a mismatch and a link each
    assert early[3] not in {item["event_id"] for item in data["findings"]}


def test_acknowledged_findings_above_the_cap_are_all_counted(db_url: str) -> None:
    org_id, key = asyncio.run(_setup_org(db_url))
    rows = record(db_url, org_id, BROKEN_ROWS + 1)
    corrupt(db_url, rows[:BROKEN_ROWS])
    event_id = reanchor(org_id)

    data = verify(db_url, key)

    assert data["ok"] is True and data["findings"] == []
    assert data["findings_truncated"] is False
    assert data["acknowledged_findings"] == 2 * BROKEN_ROWS > MAX_FINDINGS
    assert data["reanchored_by"] == event_id


def test_a_reanchor_row_written_by_an_api_key_actor_is_ignored(db_url: str) -> None:
    org_id, key = asyncio.run(_setup_org(db_url))
    rows = record(db_url, org_id, 6)
    corrupt(db_url, rows[1:3])
    forged = record(
        db_url,
        org_id,
        1,
        start=100,
        actor_type=ActorType.API_KEY,
        action=REANCHOR_ACTION,
        details={"acknowledged_through": rows[-1]},
    )

    data = verify(db_url, key)

    assert data["ok"] is False
    assert len(data["findings"]) == 4
    assert "acknowledged_findings" not in data and "reanchored_by" not in data
    assert forged[0] not in {item["event_id"] for item in data["findings"]}


def test_only_the_platform_admin_actor_makes_a_reanchor() -> None:
    def event(actor_type: ActorType, outcome: AuditOutcome = AuditOutcome.SUCCESS) -> AuditEvent:
        return AuditEvent(
            id="aud_2",
            org_id="org_1",
            actor_type=actor_type,
            action=REANCHOR_ACTION,
            outcome=outcome,
            details={"acknowledged_through": "aud_1"},
            occurred_at=NOW,
        )

    assert reanchor_through(event(ActorType.PLATFORM_ADMIN)) == "aud_1"
    assert reanchor_through(event(ActorType.API_KEY)) is None
    assert reanchor_through(event(ActorType.SYSTEM)) is None
    assert reanchor_through(event(ActorType.PLATFORM_ADMIN, AuditOutcome.DENIED)) is None


def test_a_bounded_verifier_rejects_a_cap_below_one() -> None:
    with pytest.raises(ValueError, match="max_findings"):
        ChainVerifier(max_findings=0)


def test_the_kinds_reported_are_unchanged(db_url: str) -> None:
    org_id, key = asyncio.run(_setup_org(db_url))
    rows = record(db_url, org_id, 4)
    corrupt(db_url, rows[1:2])

    data = verify(db_url, key)

    assert [item["kind"] for item in data["findings"]] == [
        FindingKind.HASH_MISMATCH.value,
        FindingKind.LINK_BROKEN.value,
    ]
