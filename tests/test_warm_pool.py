"""Warm pool (phase 8): lazy exact-match standbys claimed by repeated identical creates.

FakeDriver, temp SQLite and the real service wiring; daemon-free. Refill jobs are run by hand
(the job runner is not started under the ASGI-less app), so every step is deterministic.
"""

from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.deps import SANDBOX_SERVICE_ATTR
from sandfort.clock import SystemClock
from sandfort.config import Settings
from sandfort.db.repositories.ports import StandbyClaim
from sandfort.db.repositories.sandboxes import SqlSandboxRepository
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import Org
from sandfort.domain.quota import OrgQuota
from sandfort.domain.resources import DEFAULT_DISK_GIB, ResourceSpec
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.drivers.fake import FakeDriver
from sandfort.errors import QuotaExceeded
from sandfort.ids import new_org_id
from sandfort.services.sandboxes import CreateSandboxCommand, SandboxService
from sandfort.services.warm_pool import CLAIM_ACTION, WARM_POOL_REFILL
from sandfort.workers.handlers import JobContext, lookup

ROOT = Path(__file__).resolve().parents[1]
ACTOR = "key_test"
LEASE = timedelta(minutes=1)
SLOT_LIMIT = 2

AppFactory = Callable[[int], FastAPI]


@pytest.fixture
async def make_app(tmp_path: Path) -> AsyncIterator[AppFactory]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    built: list[FastAPI] = []

    def build(size: int) -> FastAPI:
        url = f"sqlite+aiosqlite:///{tmp_path / 'pool.db'}"
        config = Config(str(ROOT / "alembic.ini"))
        config.set_main_option("sqlalchemy.url", url)
        command.upgrade(config, "head")
        settings = Settings(
            driver="fake",
            database_url=url,
            api_key_pepper="test-pepper",
            autostop_enabled=False,
            warm_pool_size=size,
        )
        app = create_app(settings)
        built.append(app)
        return app

    yield build
    for app in built:
        await app.state.engine.dispose()


async def add_org(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=datetime.now(UTC))
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


def service_of(app: FastAPI) -> SandboxService:
    service = getattr(app.state, SANDBOX_SERVICE_ATTR)
    assert isinstance(service, SandboxService)
    return service


def driver_of(app: FastAPI) -> FakeDriver:
    driver = app.state.driver
    assert isinstance(driver, FakeDriver)
    return driver


def claim_terms(name: str) -> StandbyClaim:
    return StandbyClaim(
        name=name,
        labels={},
        public=False,
        auto_stop_minutes=15,
        auto_delete_minutes=-1,
        at=datetime.now(UTC),
    )


async def run_refills(app: FastAPI) -> int:
    """Lease and run every queued refill job the way the job runner would; returns how many."""
    context = JobContext(
        lambda: UnitOfWork(app.state.session_factory), app.state.driver, SystemClock()
    )
    handler = lookup(WARM_POOL_REFILL)
    ran = 0
    while True:
        now = datetime.now(UTC)
        async with UnitOfWork(app.state.session_factory) as uow:
            job = await uow.jobs.lease_next(
                [WARM_POOL_REFILL], now=now, lease_expires_at=now + LEASE
            )
            await uow.commit()
        if job is None:
            return ran
        await handler(job.payload, context)
        async with UnitOfWork(app.state.session_factory) as uow:
            await uow.jobs.complete(job.id, datetime.now(UTC))
            await uow.commit()
        ran += 1


async def standbys(app: FastAPI, org_id: str) -> list[Sandbox]:
    async with UnitOfWork(app.state.session_factory) as uow:
        rows = await uow.sandboxes.list_for_reconciler()  # the system view keeps standbys
    return [row for row in rows if row.org_id == org_id and row.standby]


async def seeded_pool(app: FastAPI, org_id: str) -> tuple[Sandbox, Sandbox]:
    """One ordinary create (seeds the pool) and the standby its refill job builds."""
    first = await service_of(app).create(org_id, ACTOR, CreateSandboxCommand(name="first"))
    assert await run_refills(app) == 1
    (standby,) = await standbys(app, org_id)
    return first, standby


# -- off by default ------------------------------------------------------------------------


def test_pool_size_defaults_to_zero_and_reads_the_environment() -> None:
    assert Settings().warm_pool_size == 0
    assert Settings.from_env({"SANDFORT_WARM_POOL_SIZE": "3"}).warm_pool_size == 3


async def test_size_zero_builds_normally_and_creates_no_standby(make_app: AppFactory) -> None:
    app = make_app(0)
    org_id = await add_org(app)

    created = await service_of(app).create(org_id, ACTOR, CreateSandboxCommand(name="plain"))

    assert created.state is SandboxState.STARTED
    assert created.standby is False
    assert created.spec_hash is None
    assert await standbys(app, org_id) == []
    assert await run_refills(app) == 0
    assert len(await driver_of(app).list_managed()) == 1


# -- claim ---------------------------------------------------------------------------------


async def test_second_identical_create_claims_the_prebuilt_standby(make_app: AppFactory) -> None:
    app = make_app(1)
    org_id = await add_org(app)
    first, standby = await seeded_pool(app, org_id)
    assert first.standby is False
    assert standby.name.startswith("standby-")
    assert standby.state is SandboxState.STARTED
    assert standby.auto_stop_minutes == -1
    built = len(await driver_of(app).list_managed())

    claimed = await service_of(app).create(org_id, ACTOR, CreateSandboxCommand(name="mine"))

    assert claimed.id == standby.id  # the pre-built sandbox, not a new one
    assert claimed.standby is False
    assert claimed.name == "mine"
    assert claimed.state is SandboxState.STARTED
    assert len(await driver_of(app).list_managed()) == built  # nothing was built for the claim
    assert await standbys(app, org_id) == []
    async with UnitOfWork(app.state.session_factory) as uow:
        events = await uow.audit.list(org_id, action=CLAIM_ACTION)
    assert [event.target_id for event in events] == [claimed.id]


async def test_claim_without_a_name_keeps_the_sandbox_id(make_app: AppFactory) -> None:
    app = make_app(1)
    org_id = await add_org(app)
    _, standby = await seeded_pool(app, org_id)

    claimed = await service_of(app).create(org_id, ACTOR, CreateSandboxCommand())

    assert claimed.id == standby.id
    assert claimed.name == standby.id


async def test_claim_enqueues_a_refill_that_restores_the_pool(make_app: AppFactory) -> None:
    app = make_app(1)
    org_id = await add_org(app)
    _, standby = await seeded_pool(app, org_id)
    await service_of(app).create(org_id, ACTOR, CreateSandboxCommand(name="mine"))

    assert await run_refills(app) == 1

    (replacement,) = await standbys(app, org_id)
    assert replacement.id != standby.id


async def test_a_standby_is_claimed_once(make_app: AppFactory) -> None:
    app = make_app(1)
    org_id = await add_org(app)
    _, standby = await seeded_pool(app, org_id)
    assert standby.spec_hash is not None
    async with UnitOfWork(app.state.session_factory) as uow:
        repository = uow.sandboxes
        assert isinstance(repository, SqlSandboxRepository)
        won = await repository.claim_standby(org_id, standby.spec_hash, claim_terms("one"))
        again = await repository.claim_standby(org_id, standby.spec_hash, claim_terms("two"))
        await uow.commit()
    assert won is not None
    assert won.id == standby.id
    assert won.standby is False
    assert again is None


# -- exact match ---------------------------------------------------------------------------


async def test_create_with_env_never_claims(make_app: AppFactory) -> None:
    app = make_app(1)
    org_id = await add_org(app)
    _, standby = await seeded_pool(app, org_id)

    built = await service_of(app).create(
        org_id, ACTOR, CreateSandboxCommand(name="envy", env={"MODE": "test"})
    )

    assert built.id != standby.id
    assert built.standby is False
    assert [row.id for row in await standbys(app, org_id)] == [standby.id]
    assert await run_refills(app) == 0  # an ineligible create does not touch the pool


async def test_different_resource_shape_does_not_claim(make_app: AppFactory) -> None:
    app = make_app(1)
    org_id = await add_org(app)
    _, standby = await seeded_pool(app, org_id)
    larger = ResourceSpec(disk_gib=DEFAULT_DISK_GIB + 1)

    built = await service_of(app).create(
        org_id, ACTOR, CreateSandboxCommand(name="larger", resources=larger)
    )

    assert built.id != standby.id
    assert standby.id in {row.id for row in await standbys(app, org_id)}


# -- visibility and quota ------------------------------------------------------------------


async def test_standbys_are_hidden_from_listings_and_autostop(make_app: AppFactory) -> None:
    app = make_app(1)
    org_id = await add_org(app)
    first, standby = await seeded_pool(app, org_id)

    listed = await service_of(app).list(org_id)
    async with UnitOfWork(app.state.session_factory) as uow:
        repository = uow.sandboxes
        assert isinstance(repository, SqlSandboxRepository)
        candidates = await repository.list_autostop_candidates()
        reconciler_view = await repository.list_for_reconciler()

    assert [sandbox.id for sandbox in listed] == [first.id]
    assert {sandbox.id for sandbox in candidates} == {first.id}
    assert standby.id in {sandbox.id for sandbox in reconciler_view}  # reconciler keeps it
    assert (await service_of(app).get(org_id, standby.id)).standby is True  # still by id


async def test_standbys_reserve_quota(make_app: AppFactory) -> None:
    app = make_app(1)
    org_id = await add_org(app)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.quotas.upsert_limits(
            org_id, OrgQuota(max_sandboxes=SLOT_LIMIT), datetime.now(UTC)
        )
        await uow.commit()
    await seeded_pool(app, org_id)

    async with UnitOfWork(app.state.session_factory) as uow:
        reserved = await uow.quotas.ledger_totals(org_id)
    assert reserved.sandboxes == SLOT_LIMIT  # the ordinary sandbox plus the standby
    with pytest.raises(QuotaExceeded):
        await service_of(app).create(
            org_id, ACTOR, CreateSandboxCommand(name="over", env={"MODE": "test"})
        )

    # A claim needs no new capacity, and a refill with no room leaves the pool smaller.
    claimed = await service_of(app).create(org_id, ACTOR, CreateSandboxCommand(name="mine"))
    assert claimed.standby is False
    assert await run_refills(app) == 1
    assert await standbys(app, org_id) == []
