"""Seed S4 checks: phase-4 interfaces import, quota helpers, outbox publisher, migration 0004."""

import importlib
import sqlite3
from collections.abc import AsyncIterator
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import EventType
from sandfort.domain.org import Org
from sandfort.domain.quota import OrgQuota, Reservation
from sandfort.domain.usage import UsageDimension, UsageInterval
from sandfort.ids import EVENT, has_prefix, new_org_id
from sandfort.services.events import NoOpEventPublisher, OutboxEventPublisher

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PHASE4_TABLES = {
    "quotas",
    "quota_ledger",
    "outbox_events",
    "webhook_endpoints",
    "webhook_deliveries",
    "usage_intervals",
    "usage_rollups",
}
NEW_MODULES = [
    "sandfort.domain.quota",
    "sandfort.domain.usage",
    "sandfort.db.models.quotas",
    "sandfort.db.models.events",
    "sandfort.db.models.webhooks",
    "sandfort.db.models.usage",
    "sandfort.db.repositories.quotas",
    "sandfort.db.repositories.events",
    "sandfort.db.repositories.webhooks",
    "sandfort.db.repositories.usage",
    "sandfort.services.events",
    "sandfort.migrations.versions.r0004_phase4",
]
LIMITS = OrgQuota(max_vcpus=2.0, max_memory_mib=1024, max_disk_gib=10, max_sandboxes=3)

Factory = async_sessionmaker[AsyncSession]


@pytest.mark.parametrize("module", NEW_MODULES)
def test_new_module_imports(module: str) -> None:
    assert importlib.import_module(module) is not None


# --- quota domain ----------------------------------------------------------------


@pytest.mark.parametrize(
    "over",
    [{"vcpus": 2.5}, {"memory_mib": 1025}, {"disk_gib": 11}, {"sandboxes": 4}],
)
def test_reservation_over_any_dimension_does_not_fit(over: dict[str, Any]) -> None:
    assert not Reservation(**over).fits_within(LIMITS)


@pytest.mark.parametrize(
    "at_limit",
    [{"vcpus": 2.0}, {"memory_mib": 1024}, {"disk_gib": 10}, {"sandboxes": 3}],
)
def test_reservation_at_limit_fits(at_limit: dict[str, Any]) -> None:
    assert Reservation(**at_limit).fits_within(LIMITS)


def test_unlimited_quota_fits_any_reservation() -> None:
    huge = Reservation(vcpus=10_000, memory_mib=10**9, disk_gib=10**6, sandboxes=10**6)

    assert huge.fits_within(OrgQuota())


def test_unlimited_dimension_is_ignored_while_others_are_enforced() -> None:
    memory_only = OrgQuota(max_memory_mib=1024)

    assert Reservation(vcpus=500, memory_mib=1024).fits_within(memory_only)
    assert not Reservation(vcpus=500, memory_mib=1025).fits_within(memory_only)


def test_add_sums_every_dimension_without_mutating() -> None:
    first = Reservation(vcpus=0.5, memory_mib=256, disk_gib=1, sandboxes=1)
    second = Reservation(vcpus=1.5, memory_mib=768, disk_gib=9, sandboxes=2)

    total = first.add(second)

    assert total == Reservation(vcpus=2.0, memory_mib=1024, disk_gib=10, sandboxes=3)
    assert total.fits_within(LIMITS)
    assert first == Reservation(vcpus=0.5, memory_mib=256, disk_gib=1, sandboxes=1)


def test_fractional_vcpus_sum_exactly_to_the_limit() -> None:
    total = Reservation()
    for _ in range(10):
        total = total.add(Reservation(vcpus=0.1))

    assert total.vcpus == 1.0
    assert total.fits_within(OrgQuota(max_vcpus=1.0))


def test_quota_rejects_negative_limits() -> None:
    with pytest.raises(ValidationError):
        OrgQuota(max_vcpus=-1)


def test_usage_interval_rejects_end_before_start() -> None:
    with pytest.raises(ValidationError):
        UsageInterval(
            org_id="org_x",
            sandbox_id="sbx_x",
            dimension=UsageDimension.VCPU,
            amount=1.0,
            started_at=NOW,
            ended_at=NOW - timedelta(seconds=1),
        )


# --- outbox publisher and stubs ----------------------------------------------------


def alembic_config(db_path: Path) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")
    return config


@pytest.fixture
async def factory(tmp_path: Path) -> AsyncIterator[Factory]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    db_path = tmp_path / "s4.db"
    command.upgrade(alembic_config(db_path), "head")
    engine = create_engine(Settings(database_url=f"sqlite+aiosqlite:///{db_path}"))
    try:
        yield create_session_factory(engine)
    finally:
        await engine.dispose()


async def add_org(factory: Factory) -> Org:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    async with UnitOfWork(factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org


async def test_outbox_publisher_appends_and_reads_back(factory: Factory) -> None:
    org = await add_org(factory)
    clock = FrozenClock(NOW)
    publisher = OutboxEventPublisher(clock)
    payload = {"sandbox_id": "sbx_x", "state": "started"}

    async with UnitOfWork(factory) as uow:
        await publisher.publish(uow, EventType.SANDBOX_STARTED, org.id, payload)
        await uow.commit()

    async with UnitOfWork(factory) as uow:
        events = await uow.events.list_undispatched(limit=10)

    assert len(events) == 1
    event = events[0]
    assert has_prefix(event.id, EVENT)
    assert event.org_id == org.id
    assert event.event_type == "sandbox.started"
    assert event.payload == payload
    assert event.created_at == NOW
    assert event.dispatched_at is None
    assert event.attempts == 0


async def test_outbox_event_is_discarded_with_the_callers_rollback(factory: Factory) -> None:
    org = await add_org(factory)
    publisher = OutboxEventPublisher(FrozenClock(NOW))

    async with UnitOfWork(factory) as uow:
        await publisher.publish(uow, EventType.SANDBOX_CREATED, org.id, {})

    async with UnitOfWork(factory) as uow:
        assert await uow.events.list_undispatched() == []


async def test_noop_publisher_writes_nothing(factory: Factory) -> None:
    org = await add_org(factory)

    async with UnitOfWork(factory) as uow:
        await NoOpEventPublisher().publish(uow, EventType.SANDBOX_CREATED, org.id, {"a": 1})
        await uow.commit()

    async with UnitOfWork(factory) as uow:
        assert await uow.events.list_undispatched() == []


# --- migration ----------------------------------------------------------------------


def table_names(db_path: Path) -> set[str]:
    with closing(sqlite3.connect(db_path)) as connection:
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        return {row[0] for row in rows}


def test_migration_chain_creates_phase4_tables(tmp_path: Path) -> None:
    db_path = tmp_path / "s4.db"

    config = alembic_config(db_path)
    command.upgrade(config, "head")

    with closing(sqlite3.connect(db_path)) as connection:
        version = connection.execute("SELECT version_num FROM alembic_version").fetchall()
    assert PHASE4_TABLES <= table_names(db_path)
    assert version == [(ScriptDirectory.from_config(config).get_current_head(),)]


def test_downgrade_to_0003_removes_phase4_tables(tmp_path: Path) -> None:
    db_path = tmp_path / "s4.db"
    config = alembic_config(db_path)
    command.upgrade(config, "head")

    command.downgrade(config, "0003")

    tables = table_names(db_path)
    assert not PHASE4_TABLES & tables
    assert {"jobs", "snapshots", "volumes"} <= tables
