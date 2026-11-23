"""Persistence tests: migrations, org scoping, optimistic locking, unit of work, audit.

Daemon-free. Migration tests run on the synchronous sqlite driver; tests that
use the async engine skip when ``aiosqlite``/``greenlet`` are not installed.
"""

import sqlite3
from collections.abc import AsyncIterator
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.repositories.ports import IdempotencyRecord
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.db.urls import to_async_url, to_sync_url
from sandfort.domain.events import ActorType, AuditEvent, AuditOutcome
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.errors import Conflict, NotFound
from sandfort.ids import AUDIT, new_api_key_id, new_id, new_org_id, new_sandbox_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
EXPECTED_TABLES = {
    "organizations",
    "api_keys",
    "sandboxes",
    "idempotency_keys",
    "audit_events",
    "exec_sessions",
    "exec_commands",
    "pty_sessions",
    "jobs",
    "snapshots",
    "volumes",
    "quotas",
    "quota_ledger",
    "outbox_events",
    "webhook_endpoints",
    "webhook_deliveries",
    "usage_intervals",
    "usage_rollups",
    "users",
    "org_memberships",
    "nodes",
    "scim_tokens",
}

Factory = async_sessionmaker[AsyncSession]


def alembic_config(db_path: Path) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")
    return config


def table_names(db_path: Path) -> set[str]:
    with closing(sqlite3.connect(db_path)) as connection:
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        return {row[0] for row in rows}


def make_org(slug: str) -> Org:
    return Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)


def make_sandbox(org_id: str, name: str = "dev", labels: dict[str, str] | None = None) -> Sandbox:
    return Sandbox(
        id=new_sandbox_id(),
        org_id=org_id,
        name=name,
        image_ref="python:3.12-slim",
        driver="fake",
        labels=labels or {},
        created_at=NOW,
        updated_at=NOW,
    )


@pytest.fixture
async def factory(tmp_path: Path) -> AsyncIterator[Factory]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    db_path = tmp_path / "sandfort.db"
    command.upgrade(alembic_config(db_path), "head")
    engine = create_engine(Settings(database_url=f"sqlite+aiosqlite:///{db_path}"))
    try:
        yield create_session_factory(engine)
    finally:
        await engine.dispose()


async def commit_all(
    factory: Factory,
    *,
    orgs: tuple[Org, ...] = (),
    sandboxes: tuple[Sandbox, ...] = (),
) -> None:
    async with UnitOfWork(factory) as uow:
        for org in orgs:
            await uow.orgs.add(org)
        for sandbox in sandboxes:
            await uow.sandboxes.add(sandbox)
        await uow.commit()


# --- migrations -----------------------------------------------------------------


def test_upgrade_head_creates_full_schema(tmp_path: Path) -> None:
    db_path = tmp_path / "migrated.db"

    config = alembic_config(db_path)
    command.upgrade(config, "head")

    assert table_names(db_path) == EXPECTED_TABLES | {"alembic_version"}
    with closing(sqlite3.connect(db_path)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchall() == [
            (ScriptDirectory.from_config(config).get_current_head(),)
        ]


def test_downgrade_base_removes_schema(tmp_path: Path) -> None:
    db_path = tmp_path / "migrated.db"
    config = alembic_config(db_path)
    command.upgrade(config, "head")

    command.downgrade(config, "base")

    assert table_names(db_path) == {"alembic_version"}


def test_database_url_switch_maps_between_async_and_sync_drivers() -> None:
    assert to_async_url("sqlite:///x.db").drivername == "sqlite+aiosqlite"
    assert to_async_url("postgresql://u@h/db").drivername == "postgresql+asyncpg"
    assert to_async_url("postgresql+asyncpg://u@h/db").drivername == "postgresql+asyncpg"
    assert to_sync_url("sqlite+aiosqlite:///x.db").drivername == "sqlite"
    assert to_sync_url("postgresql+asyncpg://u@h/db").drivername == "postgresql+psycopg"


# --- org scoping ----------------------------------------------------------------


async def test_sandbox_created_under_org_a_is_invisible_to_org_b(factory: Factory) -> None:
    org_a, org_b = make_org("acme"), make_org("globex")
    sandbox = make_sandbox(org_a.id)
    await commit_all(factory, orgs=(org_a, org_b), sandboxes=(sandbox,))

    async with UnitOfWork(factory) as uow:
        assert await uow.sandboxes.get(org_a.id, sandbox.id) == sandbox
        assert await uow.sandboxes.get(org_b.id, sandbox.id) is None
        assert await uow.sandboxes.get_by_name(org_b.id, sandbox.name) is None
        assert list(await uow.sandboxes.list(org_b.id)) == []
        assert [s.id for s in await uow.sandboxes.list(org_a.id)] == [sandbox.id]
        with pytest.raises(NotFound):
            await uow.sandboxes.update(org_b.id, sandbox, expected_version=1)


async def test_sandbox_name_is_unique_per_org_only(factory: Factory) -> None:
    org_a, org_b = make_org("acme"), make_org("globex")
    await commit_all(
        factory,
        orgs=(org_a, org_b),
        sandboxes=(make_sandbox(org_a.id), make_sandbox(org_b.id)),
    )

    with pytest.raises(Conflict):
        await commit_all(factory, sandboxes=(make_sandbox(org_a.id),))


async def test_errored_sandbox_name_can_be_reused_in_same_org(factory: Factory) -> None:
    org = make_org("acme")
    broken = make_sandbox(org.id)
    await commit_all(factory, orgs=(org,), sandboxes=(broken,))
    async with UnitOfWork(factory) as uow:
        await uow.sandboxes.update(
            org.id,
            broken.model_copy(update={"state": SandboxState.ERROR}),
            expected_version=1,
        )
        await uow.commit()

    replacement = make_sandbox(org.id)
    await commit_all(factory, sandboxes=(replacement,))

    async with UnitOfWork(factory) as uow:
        assert await uow.sandboxes.get(org.id, replacement.id) == replacement


async def test_errored_sandbox_can_enter_destroying_while_live_one_holds_its_name(
    factory: Factory,
) -> None:
    org = make_org("acme")
    errored = make_sandbox(org.id, "x")
    await commit_all(factory, orgs=(org,), sandboxes=(errored,))
    async with UnitOfWork(factory) as uow:
        errored = await uow.sandboxes.update(
            org.id,
            errored.model_copy(update={"state": SandboxState.ERROR}),
            expected_version=errored.version,
        )
        await uow.commit()
    live = make_sandbox(org.id, "x").model_copy(update={"state": SandboxState.STARTED})
    await commit_all(factory, sandboxes=(live,))

    async with UnitOfWork(factory) as uow:
        destroying = await uow.sandboxes.update(
            org.id,
            errored.model_copy(update={"state": SandboxState.DESTROYING}),
            expected_version=errored.version,
        )
        await uow.commit()

    async with UnitOfWork(factory) as uow:
        assert destroying.state is SandboxState.DESTROYING
        assert await uow.sandboxes.get(org.id, live.id) == live


async def test_list_filters_by_state_labels_and_cursor(factory: Factory) -> None:
    org = make_org("acme")
    first = make_sandbox(org.id, "one", {"team": "ml"})
    second = make_sandbox(org.id, "two", {"team": "web"})
    await commit_all(factory, orgs=(org,), sandboxes=(first, second))
    ordered = sorted([first, second], key=lambda s: s.id)

    async with UnitOfWork(factory) as uow:
        by_label = await uow.sandboxes.list(org.id, labels={"team": "ml"})
        assert [s.id for s in by_label] == [first.id]
        by_state = await uow.sandboxes.list(org.id, state=SandboxState.STARTED)
        assert list(by_state) == []
        page = await uow.sandboxes.list(org.id, cursor=ordered[0].id)
        assert [s.id for s in page] == [ordered[1].id]
        assert len(await uow.sandboxes.list(org.id, limit=1)) == 1


async def test_reconciler_listing_spans_orgs_and_skips_destroyed(factory: Factory) -> None:
    org_a, org_b = make_org("acme"), make_org("globex")
    live, gone = make_sandbox(org_a.id), make_sandbox(org_b.id)
    await commit_all(factory, orgs=(org_a, org_b), sandboxes=(live, gone))
    async with UnitOfWork(factory) as uow:
        await uow.sandboxes.update(
            org_b.id,
            gone.model_copy(update={"state": SandboxState.DESTROYED}),
            expected_version=1,
        )
        await uow.commit()

    async with UnitOfWork(factory) as uow:
        assert [s.id for s in await uow.sandboxes.list_for_reconciler()] == [live.id]


# --- optimistic concurrency -----------------------------------------------------


async def test_stale_version_raises_conflict(factory: Factory) -> None:
    org = make_org("acme")
    sandbox = make_sandbox(org.id)
    await commit_all(factory, orgs=(org,), sandboxes=(sandbox,))
    async with UnitOfWork(factory) as uow:
        started = await uow.sandboxes.update(
            org.id,
            sandbox.model_copy(update={"state": SandboxState.STARTED}),
            expected_version=1,
        )
        await uow.commit()
    assert started.version == 2

    async with UnitOfWork(factory) as uow:
        with pytest.raises(Conflict):
            await uow.sandboxes.update(
                org.id,
                sandbox.model_copy(update={"state": SandboxState.STOPPED}),
                expected_version=1,
            )

    async with UnitOfWork(factory) as uow:
        assert await uow.sandboxes.get(org.id, sandbox.id) == started


# --- unit of work ---------------------------------------------------------------


async def test_commit_persists_and_leaves_no_open_transaction(factory: Factory) -> None:
    org = make_org("acme")

    async with UnitOfWork(factory) as uow:
        await uow.orgs.add(org)
        assert uow.in_transaction
        await uow.commit()
        assert not uow.in_transaction

    async with UnitOfWork(factory) as uow:
        assert await uow.orgs.get(org.id) == org
        assert await uow.orgs.get_by_slug("acme") == org


async def test_explicit_rollback_discards_work(factory: Factory) -> None:
    org = make_org("acme")

    async with UnitOfWork(factory) as uow:
        await uow.orgs.add(org)
        await uow.rollback()
        assert await uow.orgs.get(org.id) is None


async def test_leaving_block_without_commit_discards_work(factory: Factory) -> None:
    org = make_org("acme")

    async with UnitOfWork(factory) as uow:
        await uow.orgs.add(org)

    async with UnitOfWork(factory) as uow:
        assert await uow.orgs.get(org.id) is None


async def test_exception_in_block_rolls_back_and_propagates(factory: Factory) -> None:
    org = make_org("acme")

    with pytest.raises(RuntimeError, match="boom"):
        async with UnitOfWork(factory) as uow:
            await uow.orgs.add(org)
            raise RuntimeError("boom")

    async with UnitOfWork(factory) as uow:
        assert await uow.orgs.get(org.id) is None


async def test_duplicate_org_slug_raises_conflict(factory: Factory) -> None:
    await commit_all(factory, orgs=(make_org("acme"),))

    with pytest.raises(Conflict):
        await commit_all(factory, orgs=(make_org("acme"),))


# --- api keys and idempotency ---------------------------------------------------


async def test_api_key_round_trip_revoke_and_touch(factory: Factory) -> None:
    org, other = make_org("acme"), make_org("globex")
    await commit_all(factory, orgs=(org, other))
    key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix="sf_live_abc123",
        secret_hash="hashed",
        scopes=frozenset({Scope.SANDBOXES_READ, Scope.TOOLBOX}),
        created_at=NOW,
    )
    async with UnitOfWork(factory) as uow:
        await uow.api_keys.add(key)
        await uow.commit()

    async with UnitOfWork(factory) as uow:
        assert await uow.api_keys.get_by_prefix("sf_live_abc123") == key
        assert list(await uow.api_keys.list_for_org(org.id)) == [key]
        assert list(await uow.api_keys.list_for_org(other.id)) == []
        assert not await uow.api_keys.revoke(other.id, key.id, NOW)
        assert await uow.api_keys.revoke(org.id, key.id, NOW)
        assert not await uow.api_keys.revoke(org.id, key.id, NOW)
        await uow.api_keys.touch_last_used(key.id, NOW + timedelta(minutes=1))
        stored = await uow.api_keys.get_by_prefix("sf_live_abc123")
        assert stored is not None
        assert stored.revoked_at == NOW
        assert stored.last_used_at == NOW + timedelta(minutes=1)


async def test_idempotency_put_get_conflict_and_purge(factory: Factory) -> None:
    org = make_org("acme")
    await commit_all(factory, orgs=(org,))
    fresh = IdempotencyRecord(
        org_id=org.id,
        key="k-fresh",
        request_hash="h1",
        response_status=201,
        response_body={"id": "sbx_1"},
        expires_at=NOW + timedelta(hours=1),
    )
    stale = IdempotencyRecord(
        org_id=org.id,
        key="k-stale",
        request_hash="h2",
        response_status=201,
        response_body={"id": "sbx_2"},
        expires_at=NOW - timedelta(hours=1),
    )
    async with UnitOfWork(factory) as uow:
        await uow.idempotency.put(fresh)
        await uow.idempotency.put(stale)
        await uow.commit()

    async with UnitOfWork(factory) as uow:
        assert await uow.idempotency.get(org.id, "k-fresh") == fresh
        assert await uow.idempotency.get("org_other", "k-fresh") is None
        with pytest.raises(Conflict):
            await uow.idempotency.put(fresh)

    async with UnitOfWork(factory) as uow:
        assert await uow.idempotency.purge_expired(NOW) == 1
        await uow.commit()
        assert await uow.idempotency.get(org.id, "k-stale") is None
        assert await uow.idempotency.get(org.id, "k-fresh") == fresh


# --- audit ----------------------------------------------------------------------


async def test_audit_event_round_trips_and_is_org_scoped(factory: Factory) -> None:
    org, other = make_org("acme"), make_org("globex")
    await commit_all(factory, orgs=(org, other))
    event = AuditEvent(
        id=new_id(AUDIT),
        org_id=org.id,
        actor_type=ActorType.API_KEY,
        actor_id="key_x",
        action="sandbox.create",
        target_type="sandbox",
        target_id="sbx_x",
        outcome=AuditOutcome.SUCCESS,
        request_id="req-1",
        ip="203.0.113.7",
        user_agent="pytest",
        details={"name": "dev", "env": {"TOKEN": "[redacted]"}},
        occurred_at=NOW,
    )
    async with UnitOfWork(factory) as uow:
        await uow.audit.add(event)
        await uow.commit()

    async with UnitOfWork(factory) as uow:
        assert list(await uow.audit.list(org.id)) == [event]
        assert list(await uow.audit.list(other.id)) == []
        assert list(await uow.audit.list(org.id, action="sandbox.delete")) == []
        assert list(await uow.audit.list(org.id, target_id="sbx_x")) == [event]
        assert list(await uow.audit.list(org.id, since=NOW)) == [event]
        assert list(await uow.audit.list(org.id, since=NOW + timedelta(seconds=1))) == []
        assert list(await uow.audit.list(org.id, until=NOW)) == []
