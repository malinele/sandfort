"""Chaos scenarios over the FakeDriver, temp SQLite and a frozen clock: zero orphans.

Each scenario injects one failure (driver create, start or destroy raising, a busy database
inside a job handler, a disk-full archive write), lets the platform recover (one reconcile
pass, a retry, a requeue) and then checks that the driver inventory and the rows agree:
no container without a row, no started or stopped row without its container, and a quota
ledger that matches its recount. The reconciler and the quota recount are the production
ones, never reimplemented here. Sandboxes made over HTTP go through the ASGI client behind
the app factory (route tables are never introspected).
"""

import sqlite3
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from sqlalchemy.exc import OperationalError

from sandfort.api.app import create_app
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.repositories.ports import JobRecord
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.drivers.errors import DriverError
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.quota import QuotaService
from sandfort.services.sandbox_jobs import handle_create
from sandfort.services.sandboxes import CreateSandboxCommand, SandboxService
from sandfort.workers.handlers import HandlerRegistry, JobContext
from sandfort.workers.jobs import SANDBOX_CREATE, JobWakeup
from sandfort.workers.reconciler import Reconciler
from sandfort.workers.runner import JobRunner, RunnerConfig

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
ACTOR = "key_chaos"
GRACE = timedelta(minutes=5)
BACKOFF_BASE_S = 10.0
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
DISK_FULL = "write failed: no space left on device"
LIVE_WITH_CONTAINER = (SandboxState.STARTED, SandboxState.STOPPED)

Wrapped = Callable[..., Awaitable[Any]]


# -- fixtures --------------------------------------------------------------------------------


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'chaos.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(
        driver="fake",
        database_url=url,
        api_key_pepper=PEPPER,
        autostop_enabled=False,
        reconcile_enabled=False,
        gc_enabled=False,
    )
    application = create_app(settings)
    application.state.chaos_settings = settings
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
def driver(app: FastAPI) -> FakeDriver:
    fake = app.state.driver
    assert isinstance(fake, FakeDriver)
    return fake


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock(NOW)


@pytest.fixture
def quota(app: FastAPI, clock: FrozenClock) -> QuotaService:
    return QuotaService(app.state.uow_factory, app.state.chaos_settings, clock)


@pytest.fixture
def service(
    app: FastAPI, driver: FakeDriver, clock: FrozenClock, quota: QuotaService
) -> SandboxService:
    return SandboxService(
        app.state.uow_factory, driver, app.state.chaos_settings, clock, quota=quota
    )


@pytest.fixture
def reconciler(
    app: FastAPI, driver: FakeDriver, clock: FrozenClock, quota: QuotaService
) -> Reconciler:
    return Reconciler(
        app.state.uow_factory,
        driver,
        clock,
        interval_s=1,
        grace_s=GRACE.seconds,
        on_stopped=quota.release,
    )


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Chaos", slug="chaos", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="chaos",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=FULL_ACCESS,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


# -- helpers ---------------------------------------------------------------------------------


def fail_once(original: Wrapped, error: Exception) -> Wrapped:
    """Wrap ``original`` so its first call raises ``error`` and later calls pass through."""
    pending = [error]

    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        if pending:
            raise pending.pop()
        return await original(*args, **kwargs)

    return wrapper


async def live_rows(app: FastAPI) -> Sequence[Sandbox]:
    async with UnitOfWork(app.state.session_factory) as uow:
        return await uow.sandboxes.list_for_reconciler()


async def load(app: FastAPI, org_id: str, sandbox_id: str) -> Sandbox:
    async with UnitOfWork(app.state.session_factory) as uow:
        found = await uow.sandboxes.get(org_id, sandbox_id)
    assert found is not None
    return found


async def only_job(app: FastAPI, org_id: str) -> JobRecord:
    async with UnitOfWork(app.state.session_factory) as uow:
        jobs = await uow.jobs.list_for_org(org_id)  # type: ignore[attr-defined]
    assert len(jobs) == 1
    return jobs[0]  # type: ignore[no-any-return]


async def assert_zero_orphans(
    app: FastAPI, driver: FakeDriver, reconciler: Reconciler, clock: FrozenClock
) -> None:
    """Inventory and rows agree, and reconcile passes past the grace remove nothing."""
    first = await reconciler.reconcile_once()
    clock.advance(GRACE * 2)
    second = await reconciler.reconcile_once()
    assert first.orphans_removed == () and second.orphans_removed == ()
    assert first.errors == 0 and second.errors == 0

    rows = await live_rows(app)
    present = {item.provider_id for item in await driver.list_instances()}
    claimed = {row.driver_ref for row in rows if row.driver_ref is not None}
    assert present <= claimed, f"containers without a row: {sorted(present - claimed)}"
    for row in rows:
        if row.state in LIVE_WITH_CONTAINER:
            assert row.driver_ref in present, f"{row.id} has no container"


async def assert_quota_clean(quota: QuotaService, org_id: str, *, held: int) -> None:
    result = await quota.recount(org_id)
    assert result.consistent
    assert result.ledger.sandboxes == held


# -- driver failures -------------------------------------------------------------------------


async def test_create_that_raises_settles_to_error_and_releases_the_reservation(
    app: FastAPI,
    driver: FakeDriver,
    clock: FrozenClock,
    service: SandboxService,
    quota: QuotaService,
    reconciler: Reconciler,
    org_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(driver, "create", fail_once(driver.create, DriverError("boom")))

    created = await service.create(org_id, ACTOR, CreateSandboxCommand())

    assert created.state is SandboxState.ERROR
    assert created.error_reason is not None and "boom" in created.error_reason
    assert (await load(app, org_id, created.id)).state is SandboxState.ERROR
    await assert_quota_clean(quota, org_id, held=0)
    await assert_zero_orphans(app, driver, reconciler, clock)
    assert await driver.list_instances() == []


async def test_start_that_raises_keeps_the_container_claimed_until_deleted(
    app: FastAPI,
    driver: FakeDriver,
    clock: FrozenClock,
    service: SandboxService,
    quota: QuotaService,
    reconciler: Reconciler,
    org_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(driver, "start", fail_once(driver.start, DriverError("no start")))

    created = await service.create(org_id, ACTOR, CreateSandboxCommand())

    assert created.state is SandboxState.ERROR
    assert created.driver_ref is not None  # the half-made container stays claimed by its row
    await assert_quota_clean(quota, org_id, held=0)
    await assert_zero_orphans(app, driver, reconciler, clock)
    assert len(await driver.list_instances()) == 1

    await service.delete(org_id, ACTOR, created.id)

    await assert_zero_orphans(app, driver, reconciler, clock)
    assert await driver.list_instances() == [] and await live_rows(app) == []
    await assert_quota_clean(quota, org_id, held=0)


async def test_container_lost_mid_flight_is_settled_by_one_reconcile_pass(
    app: FastAPI,
    driver: FakeDriver,
    clock: FrozenClock,
    service: SandboxService,
    quota: QuotaService,
    reconciler: Reconciler,
    org_id: str,
) -> None:
    created = await service.create(org_id, ACTOR, CreateSandboxCommand())
    assert created.state is SandboxState.STARTED and created.driver_ref is not None
    await assert_quota_clean(quota, org_id, held=1)
    driver.kill_instance(created.driver_ref)

    report = await reconciler.reconcile_once()

    assert report.drifted == (created.id,)
    assert (await load(app, org_id, created.id)).state is SandboxState.ERROR
    await assert_quota_clean(quota, org_id, held=0)
    await service.delete(org_id, ACTOR, created.id)
    await assert_zero_orphans(app, driver, reconciler, clock)
    assert await driver.list_instances() == [] and await live_rows(app) == []
    await assert_quota_clean(quota, org_id, held=0)


async def test_delete_that_raises_is_recoverable_and_a_retry_succeeds(
    app: FastAPI,
    driver: FakeDriver,
    clock: FrozenClock,
    service: SandboxService,
    quota: QuotaService,
    reconciler: Reconciler,
    org_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created = await service.create(org_id, ACTOR, CreateSandboxCommand())
    monkeypatch.setattr(driver, "destroy", fail_once(driver.destroy, DriverError("busy")))

    with pytest.raises(DriverError):
        await service.delete(org_id, ACTOR, created.id)

    stuck = await load(app, org_id, created.id)
    assert stuck.state is SandboxState.DESTROYING  # recoverable: the intent is on the row
    await assert_quota_clean(quota, org_id, held=1)
    await assert_zero_orphans(app, driver, reconciler, clock)

    retried = await service.delete(org_id, ACTOR, created.id)

    assert retried.state is SandboxState.DESTROYED
    await assert_quota_clean(quota, org_id, held=0)
    await assert_zero_orphans(app, driver, reconciler, clock)
    assert await driver.list_instances() == [] and await live_rows(app) == []


# -- database failures -----------------------------------------------------------------------


async def test_busy_database_in_a_job_handler_requeues_with_backoff_then_succeeds(
    app: FastAPI,
    driver: FakeDriver,
    clock: FrozenClock,
    quota: QuotaService,
    reconciler: Reconciler,
    org_id: str,
) -> None:
    registry, calls = HandlerRegistry(), [0]

    @registry.register(SANDBOX_CREATE)
    async def flaky_create(payload: Mapping[str, Any], context: JobContext) -> None:
        calls[0] += 1
        if calls[0] == 1:
            busy = sqlite3.OperationalError("database is locked")
            raise OperationalError("UPDATE sandboxes SET state = ?", {}, busy)
        await handle_create(payload, context)

    queued = SandboxService(
        app.state.uow_factory,
        driver,
        app.state.chaos_settings,
        clock,
        use_jobs=True,
        quota=quota,
    )
    runner = JobRunner(
        app.state.uow_factory,
        driver,
        clock,
        registry=registry,
        wakeup=JobWakeup(),
        config=RunnerConfig(backoff_base_s=BACKOFF_BASE_S),
    )
    pending = await queued.create(org_id, ACTOR, CreateSandboxCommand())
    assert pending.state is SandboxState.PENDING

    assert await runner.run_once() is True
    job = await only_job(app, org_id)

    assert (job.state, job.attempts) == ("queued", 1)
    assert job.run_after == NOW + timedelta(seconds=BACKOFF_BASE_S)
    assert job.last_error is not None and "database is locked" in job.last_error
    assert (await load(app, org_id, pending.id)).state is SandboxState.PENDING
    assert await runner.run_once() is False  # still backing off
    await assert_zero_orphans(app, driver, reconciler, clock)  # advances the clock past it

    assert await runner.run_once() is True

    assert (await only_job(app, org_id)).state == "done"
    assert calls[0] == 2
    assert (await load(app, org_id, pending.id)).state is SandboxState.STARTED
    await assert_quota_clean(quota, org_id, held=1)
    await assert_zero_orphans(app, driver, reconciler, clock)


# -- archive failures ------------------------------------------------------------------------


async def put_file(
    client: httpx.AsyncClient, headers: dict[str, str], url: str, path: str, body: bytes
) -> httpx.Response:
    return await client.put(url, headers=headers, params={"path": path}, content=body)


async def test_disk_full_archive_write_is_a_clean_error_and_later_uploads_work(
    app: FastAPI,
    client: httpx.AsyncClient,
    driver: FakeDriver,
    clock: FrozenClock,
    reconciler: Reconciler,
    key: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    headers = {"Authorization": f"Bearer {key}"}
    made = await client.post("/v1/sandboxes", headers=headers, json={})
    assert made.status_code == 201, made.text
    sandbox_id: str = made.json()["data"]["id"]
    base = f"/v1/sandboxes/{sandbox_id}/toolbox/fs"
    full_disk = fail_once(driver.put_archive, DriverError(DISK_FULL))
    monkeypatch.setattr(driver, "put_archive", full_disk)

    failed = await put_file(client, headers, f"{base}/upload", "/work/a.txt", b"one")

    assert failed.status_code == 502, failed.text
    assert failed.json()["success"] is False
    assert failed.json()["error"]["code"] == "DRIVER_ERROR"
    assert "no space left" in failed.json()["error"]["message"]

    again = await put_file(client, headers, f"{base}/upload", "/work/b.txt", b"two")
    assert again.status_code == 200, again.text
    fetched = await client.get(
        f"{base}/download", headers=headers, params={"path": "/work/b.txt"}
    )
    assert fetched.status_code == 200 and fetched.content == b"two"
    await assert_zero_orphans(app, driver, reconciler, clock)
