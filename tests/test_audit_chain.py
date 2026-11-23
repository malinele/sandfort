"""Audit hash chain tests (WP 5.5): recorder linking, admin verify/export, retention.

Sync tests on purpose: the admin CLI runs its own event loop, so all database work goes
through ``asyncio.run`` helpers. Temp SQLite, no Docker.
"""

import asyncio
import hashlib
import json
import secrets
import uuid
from collections.abc import AsyncIterator, Iterator, Sequence
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool
from typer.testing import CliRunner

from sandfort import admin_cli
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.repositories.audit import SqlAuditRepository
from sandfort.db.repositories.ports import ChainedAuditEvent, OutboxEventRecord
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import ActorType
from sandfort.domain.org import Org
from sandfort.drivers.docker.client import make_client
from sandfort.ids import new_event_id, new_org_id
from sandfort.services.audit import AuditRecorder
from sandfort.services.audit_chain import FindingKind, canonical_row, link_hash, verify_chain
from sandfort.workers.audit_retention import AuditRetention

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
RETENTION_DAYS = 30
EXIT_MISMATCH = 3
RUNNER = CliRunner()


@pytest.fixture
def db_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'chain.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    monkeypatch.setenv("SANDFORT_DATABASE_URL", url)
    return url


@asynccontextmanager
async def open_factory(url: str) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_engine(Settings(database_url=url))
    try:
        yield create_session_factory(engine)
    finally:
        await engine.dispose()


async def _add_org(url: str, slug: str) -> str:
    org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)
    async with open_factory(url) as factory, UnitOfWork(factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


def add_org(url: str, slug: str) -> str:
    return asyncio.run(_add_org(url, slug))


async def _record(url: str, steps: Sequence[tuple[str, datetime]]) -> list[str]:
    """Record one audit row per ``(org id, occurred_at)`` step, in order; return the ids."""
    clock = FrozenClock(NOW)
    recorder = AuditRecorder(clock)
    ids: list[str] = []
    async with open_factory(url) as factory:
        for index, (org_id, when) in enumerate(steps):
            clock.set(when)
            async with UnitOfWork(factory) as uow:
                event = await recorder.record(
                    uow,
                    org_id=org_id,
                    actor_type=ActorType.SYSTEM,
                    actor_id=None,
                    action=f"test.step{index}",
                    target_type="thing",
                    target_id=f"thing-{index}",
                    details={"n": index, "note": "café"},
                )
                await uow.commit()
            ids.append(event.id)
    return ids


def record(url: str, steps: Sequence[tuple[str, datetime]]) -> list[str]:
    return asyncio.run(_record(url, steps))


async def _read(url: str, org_id: str) -> list[ChainedAuditEvent]:
    async with open_factory(url) as factory, UnitOfWork(factory) as uow:
        return list(await uow.audit.list_chained(org_id, limit=500))


def read(url: str, org_id: str) -> list[ChainedAuditEvent]:
    return asyncio.run(_read(url, org_id))


async def _execute(url: str, statement: str, params: dict[str, Any]) -> None:
    engine = create_engine(Settings(database_url=url))
    try:
        async with engine.begin() as connection:
            await connection.execute(text(statement), params)
    finally:
        await engine.dispose()


def corrupt_details(url: str, row_id: str) -> None:
    asyncio.run(
        _execute(
            url,
            "UPDATE audit_events SET details = :details WHERE id = :id",
            {"details": json.dumps({"n": 999}), "id": row_id},
        )
    )


async def _prune(url: str, clock: FrozenClock, days: int) -> dict[str, int]:
    async with open_factory(url) as factory:
        worker = AuditRetention(
            lambda: UnitOfWork(factory), clock, retention_days=days, interval_s=1
        )
        return await worker.prune_once()


def prune(url: str, now: datetime, days: int = RETENTION_DAYS) -> dict[str, int]:
    return asyncio.run(_prune(url, FrozenClock(now), days))


def export_rows(*args: str) -> list[dict[str, Any]]:
    result = RUNNER.invoke(admin_cli.app, ["audit-export", *args])
    assert result.exit_code == 0, result.output
    return [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]


def days_ago(days: int) -> datetime:
    return NOW - timedelta(days=days)


def kinds_and_ids(rows: Sequence[ChainedAuditEvent]) -> list[tuple[FindingKind, str]]:
    return [(finding.kind, finding.row_id) for finding in verify_chain(rows)]


# --- recorder ----------------------------------------------------------------------


def test_recorded_rows_link_to_their_predecessor(db_url: str) -> None:
    org_a, org_b = add_org(db_url, "alpha"), add_org(db_url, "beta")
    steps = [(org, NOW) for _ in range(4) for org in (org_a, org_b)]  # same instant: id ties
    record(db_url, steps)

    for org_id in (org_a, org_b):
        rows = read(db_url, org_id)
        assert len(rows) == 4
        assert [r.event.id for r in rows] == sorted(r.event.id for r in rows)
        assert rows[0].prev_hash is None
        for previous, current in zip(rows, rows[1:], strict=False):
            assert current.prev_hash == previous.entry_hash
        for row in rows:
            payload = (row.prev_hash or "") + canonical_row(row.event)
            expected = hashlib.sha256(payload.encode()).hexdigest()
            assert row.entry_hash == expected == link_hash(row.prev_hash, row.event)
        assert kinds_and_ids(rows) == []


def test_verify_chain_flags_tampered_and_unlinked_rows(db_url: str) -> None:
    org_id = add_org(db_url, "alpha")
    record(db_url, [(org_id, NOW)] * 4)
    rows = read(db_url, org_id)
    forged = rows[1].event.model_copy(update={"action": "forged"})
    tampered = ChainedAuditEvent(forged, rows[1].prev_hash, rows[1].entry_hash)

    assert kinds_and_ids([rows[0], tampered, *rows[2:]]) == [
        (FindingKind.HASH_MISMATCH, rows[1].event.id)
    ]
    assert kinds_and_ids([rows[0], *rows[2:]]) == [(FindingKind.LINK_BROKEN, rows[2].event.id)]


# --- admin verify ------------------------------------------------------------------


def test_audit_verify_reports_ok_on_a_clean_database(db_url: str) -> None:
    org_a, org_b = add_org(db_url, "alpha"), add_org(db_url, "beta")
    record(db_url, [(org_a, NOW), (org_b, NOW), (org_a, NOW), (org_a, NOW)])

    result = RUNNER.invoke(admin_cli.app, ["audit-verify"])

    assert result.exit_code == 0, result.output
    assert "ok: 4 audit rows verified" in result.stdout


def test_audit_verify_exits_3_naming_the_corrupted_row(db_url: str) -> None:
    org_id = add_org(db_url, "alpha")
    ids = record(db_url, [(org_id, NOW)] * 4)
    corrupt_details(db_url, ids[2])

    result = RUNNER.invoke(admin_cli.app, ["audit-verify"])

    assert result.exit_code == EXIT_MISMATCH, result.output
    flagged = [line for line in result.stdout.splitlines() if ids[2] in line]
    assert len(flagged) == 1
    assert FindingKind.HASH_MISMATCH.value in flagged[0]
    assert not any(row_id in result.stdout for row_id in ids if row_id != ids[2])
    assert "ok:" not in result.stdout


# --- retention + export ------------------------------------------------------------


def test_retention_prunes_a_prefix_and_the_rest_still_verifies(db_url: str) -> None:
    org_a, org_b = add_org(db_url, "alpha"), add_org(db_url, "beta")
    ages = (60, 50, 40, 10, 1)
    ids_a = record(db_url, [(org_a, days_ago(age)) for age in ages])
    ids_b = record(db_url, [(org_b, days_ago(2)), (org_b, days_ago(1))])

    pruned = prune(db_url, NOW)

    assert pruned == {org_a: 3}
    verify = RUNNER.invoke(admin_cli.app, ["audit-verify"])
    assert verify.exit_code == 0, verify.output
    assert "ok: 4 audit rows verified" in verify.stdout
    exported_a = export_rows("--org-id", org_a)
    assert [row["id"] for row in exported_a] == ids_a[3:]
    assert [row["id"] for row in export_rows("--org-id", org_b)] == ids_b
    # the new first row still points at the pruned row's hash: verification seeds from it
    assert exported_a[0]["prev_hash"] is not None


def test_retention_never_removes_a_row_newer_than_a_kept_row(db_url: str) -> None:
    org_id = add_org(db_url, "alpha")
    ids = record(db_url, [(org_id, days_ago(60)), (org_id, days_ago(1)), (org_id, days_ago(90))])

    assert prune(db_url, NOW) == {org_id: 1}  # the skewed old third row stays: no gap

    assert [row.event.id for row in read(db_url, org_id)] == ids[1:]
    assert RUNNER.invoke(admin_cli.app, ["audit-verify"]).exit_code == 0


def test_retention_keeps_the_newest_row_and_can_be_disabled(db_url: str) -> None:
    org_id = add_org(db_url, "alpha")
    ids = record(db_url, [(org_id, days_ago(90)), (org_id, days_ago(80))])

    assert prune(db_url, NOW, days=0) == {}
    assert len(read(db_url, org_id)) == 2
    assert prune(db_url, NOW) == {org_id: 1}

    assert [row.event.id for row in read(db_url, org_id)] == ids[1:]
    new_ids = record(db_url, [(org_id, NOW)])  # the chain continues from the kept row
    assert RUNNER.invoke(admin_cli.app, ["audit-verify"]).exit_code == 0
    assert [row.event.id for row in read(db_url, org_id)] == [ids[1], *new_ids]


def test_export_lines_parse_and_carry_the_hash_fields(db_url: str, tmp_path: Path) -> None:
    org_a, org_b = add_org(db_url, "alpha"), add_org(db_url, "beta")
    record(db_url, [(org_a, NOW), (org_b, NOW), (org_a, NOW)])
    target = tmp_path / "audit.ndjson"

    result = RUNNER.invoke(admin_cli.app, ["audit-export", "--output", str(target)])

    assert result.exit_code == 0, result.output
    lines = target.read_text(encoding="utf-8").splitlines()
    parsed = [json.loads(line) for line in lines]
    assert len(parsed) == 3
    for line, obj in zip(lines, parsed, strict=True):
        assert line == json.dumps(obj, sort_keys=True, separators=(",", ":"))
    stored = {r.event.id: r for org in (org_a, org_b) for r in read(db_url, org)}
    for obj in parsed:
        assert len(obj["hash"]) == 64
        assert obj["hash"] == stored[obj["id"]].entry_hash
        assert obj["prev_hash"] == stored[obj["id"]].prev_hash
        assert obj["details"]["note"] == "café"


def test_retention_settings_default_to_disabled() -> None:
    defaults = Settings.from_env({})
    configured = Settings.from_env(
        {"SANDFORT_AUDIT_RETENTION_DAYS": "30", "SANDFORT_AUDIT_RETENTION_INTERVAL_S": "60"}
    )

    assert defaults.audit_retention_days == 0
    assert (configured.audit_retention_days, configured.audit_retention_interval_s) == (30, 60)


# --- chain lock (Postgres: org row FOR NO KEY UPDATE, compatible with FK inserts) ---


class RecordingSession:
    """Stands in for ``AsyncSession``: reports a dialect and records every executed statement.

    Row locks go through ``run_sync`` on a sync session, as in ``sandfort.db.locking``; they
    are recorded in the same ``calls`` list, in execution order.
    """

    def __init__(self, dialect_name: str) -> None:
        self._bind = SimpleNamespace(dialect=SimpleNamespace(name=dialect_name))
        self.calls: list[tuple[str, dict[str, Any] | None]] = []

    def get_bind(self) -> SimpleNamespace:
        return self._bind

    async def run_sync(self, fn: Any, *args: Any) -> Any:
        connection = SimpleNamespace(execute=self._record_sync)
        return fn(SimpleNamespace(connection=lambda: connection), *args)

    def _record_sync(self, statement: Any) -> None:
        # Only the Postgres dialect renders ``FOR NO KEY UPDATE``; the default one drops it.
        sql = str(statement.compile(dialect=postgresql.dialect()))
        self.calls.append((sql, None))

    async def execute(self, statement: Any, params: dict[str, Any] | None = None) -> MagicMock:
        self.calls.append((str(statement), params))
        result = MagicMock()
        result.first.return_value = None  # an org without audit rows has no head
        return result


async def _latest_link_calls(dialect_name: str, org_id: str) -> list[tuple[str, Any]]:
    session = RecordingSession(dialect_name)
    link = await SqlAuditRepository(cast(AsyncSession, session)).latest_link(org_id)
    assert link is None
    return session.calls


def test_latest_link_locks_only_the_org_row_for_no_key_update_on_postgres() -> None:
    calls = asyncio.run(_latest_link_calls("postgresql", "org_01EXAMPLE"))

    assert len(calls) == 2  # one lock statement, then the head query
    (lock_sql, _), (head_sql, _) = calls
    assert "FROM organizations" in lock_sql
    assert lock_sql.rstrip().endswith("FOR NO KEY UPDATE")
    assert "audit_events" in head_sql
    assert "FOR " not in head_sql


def test_latest_link_takes_no_quota_row_and_no_advisory_lock_on_postgres() -> None:
    calls = asyncio.run(_latest_link_calls("postgresql", "org_01EXAMPLE"))

    assert all("quotas" not in sql for sql, _ in calls)
    assert all("pg_advisory" not in sql for sql, _ in calls)
    assert sum("FOR NO KEY UPDATE" in sql for sql, _ in calls) == 1
    assert all("FOR UPDATE" not in sql for sql, _ in calls)


def test_latest_link_takes_no_lock_on_sqlite() -> None:
    calls = asyncio.run(_latest_link_calls("sqlite", "org_01EXAMPLE"))

    assert len(calls) == 1
    assert "FOR " not in calls[0][0]
    assert "pg_advisory" not in calls[0][0]
    assert "audit_events" in calls[0][0]


# Concurrency against a real Postgres. The container helpers live in test_postgres, which is
# imported lazily: its module-level importorskip must not skip this whole file.

PARALLEL_EVENTS = 20
FK_TEST_TIMEOUT_S = 60  # a deadlock would otherwise hang until Postgres detects it
HOLD_BEFORE_COMMIT_S = 0.05  # keeps each transaction open long enough for the others to queue


@pytest.fixture(scope="module")
def postgres_url() -> Iterator[str]:
    pg = pytest.importorskip("test_postgres")
    docker = pytest.importorskip("docker")
    pytest.importorskip("asyncpg")
    pytest.importorskip("greenlet")
    try:
        client = make_client()
        client.ping()
    except Exception as exc:
        pytest.skip(f"no reachable Docker daemon: {exc}")
    try:
        client.images.get(pg.IMAGE)
    except docker.errors.ImageNotFound:
        try:
            client.images.pull(pg.IMAGE)
        except Exception as exc:
            pytest.skip(f"cannot pull {pg.IMAGE}: {exc}")
    password = secrets.token_hex(16)
    container = client.containers.run(
        pg.IMAGE,
        detach=True,
        name=f"sandfort-test-audit-pg-{uuid.uuid4().hex[:10]}",
        environment={
            "POSTGRES_USER": pg.PG_USER,
            "POSTGRES_PASSWORD": password,
            "POSTGRES_DB": pg.PG_DB,
        },
        ports={pg.PG_PORT: ("127.0.0.1", None)},  # ephemeral host port, loopback only
        labels={"suite": "test_audit_chain"},
    )
    try:
        pg.wait_until_ready(container)
        container.reload()
        port = container.ports[pg.PG_PORT][0]["HostPort"]
        yield f"postgresql+asyncpg://{pg.PG_USER}:{password}@127.0.0.1:{port}/{pg.PG_DB}"
    finally:
        with suppress(docker.errors.NotFound):
            container.remove(force=True, v=True)


@pytest.fixture
async def pg_factory(postgres_url: str) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    pg = pytest.importorskip("test_postgres")
    await pg.wait_connectable(postgres_url)
    migrator = create_async_engine(postgres_url, poolclass=NullPool)
    try:
        async with migrator.connect() as connection:
            await connection.run_sync(pg.upgrade_to_head)
            await connection.commit()
    finally:
        await migrator.dispose()
    settings = Settings(
        database_url=postgres_url, database_pool_size=PARALLEL_EVENTS, database_max_overflow=0
    )
    engine = create_engine(settings)
    try:
        yield create_session_factory(engine)
    finally:
        await engine.dispose()


@pytest.mark.docker
async def test_parallel_transactions_keep_one_chain_on_postgres(
    pg_factory: async_sessionmaker[AsyncSession],
) -> None:
    org = Org(id=new_org_id(), name="Chain Lock", slug="chain-lock", created_at=NOW)
    async with UnitOfWork(pg_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    recorder = AuditRecorder(FrozenClock(NOW))

    async def record_one(index: int) -> str:
        async with UnitOfWork(pg_factory) as uow:
            event = await recorder.record(
                uow,
                org_id=org.id,
                actor_type=ActorType.SYSTEM,
                actor_id=None,
                action=f"test.parallel{index}",
            )
            await asyncio.sleep(HOLD_BEFORE_COMMIT_S)  # the lock is held until commit
            await uow.commit()
        return event.id

    ids = await asyncio.gather(*(record_one(i) for i in range(PARALLEL_EVENTS)))

    async with UnitOfWork(pg_factory) as uow:
        rows = list(await uow.audit.list_chained(org.id, limit=500))
    assert len(set(ids)) == PARALLEL_EVENTS
    assert [row.event.id for row in rows] == sorted(ids)
    assert list(verify_chain(rows)) == []
    assert sum(row.prev_hash is None for row in rows) == 1


@pytest.mark.docker
async def test_fk_inserts_then_audit_rows_do_not_deadlock_on_postgres(
    pg_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Each transaction inserts a row with a foreign key to the org (``FOR KEY SHARE`` on the
    org row), then records its audit row. A ``FOR UPDATE`` chain lock would deadlock them."""
    org = Org(id=new_org_id(), name="Fk Lock", slug="fk-lock", created_at=NOW)
    async with UnitOfWork(pg_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    recorder = AuditRecorder(FrozenClock(NOW))

    async def insert_then_record(index: int) -> str:
        async with UnitOfWork(pg_factory) as uow:
            await uow.events.append(  # flushed: the FK insert holds KEY SHARE on the org row
                OutboxEventRecord(
                    id=new_event_id(),
                    org_id=org.id,
                    event_type="test.fk",
                    payload={},
                    created_at=NOW,
                )
            )
            await asyncio.sleep(HOLD_BEFORE_COMMIT_S)  # let every transaction hold KEY SHARE
            event = await recorder.record(
                uow,
                org_id=org.id,
                actor_type=ActorType.SYSTEM,
                actor_id=None,
                action=f"test.fk{index}",
            )
            await uow.commit()
        return event.id

    ids = await asyncio.wait_for(
        asyncio.gather(*(insert_then_record(i) for i in range(PARALLEL_EVENTS))),
        timeout=FK_TEST_TIMEOUT_S,
    )

    async with UnitOfWork(pg_factory) as uow:
        rows = list(await uow.audit.list_chained(org.id, limit=500))
    assert len(set(ids)) == PARALLEL_EVENTS
    assert [row.event.id for row in rows] == sorted(ids)
    assert list(verify_chain(rows)) == []
    assert sum(row.prev_hash is None for row in rows) == 1
