"""A CREATED container on a row with a recent reset is the reset's new container: deferred.

A reset saves the new container's ref on the row before it starts that container, so in that
window the row already points at the new container and the container is CREATED. The pass must
not mark the row ``error`` then, whatever ref the row holds; missing and exited containers keep
the ref-keyed rule. Real rows go through the ASGI app over the FakeDriver and a temp SQLite
database; the reset events are written with the audit recorder.
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import ActorType, AuditEvent
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.drivers.base import InstanceState
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.audit import AuditRecorder
from sandfort.services.sandbox_reset import SANDBOX_RESET
from sandfort.workers.reconciler import DRIFT_DETECTED, RESET_SETTLE_S, Reconciler

ROOT = Path(__file__).resolve().parents[1]
CREATED_AT = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
GRACE_S = 300
RECENT_AGE = timedelta(seconds=10)  # inside the reset settle window
PAST_WINDOW = timedelta(seconds=RESET_SETTLE_S)
OLD_CONTAINER = "fake-old-container-removed-by-the-reset"
ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'created.db'}"
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
    return FrozenClock(datetime.now(UTC))


@pytest.fixture
def reconciler(app: FastAPI, driver: FakeDriver, clock: FrozenClock) -> Reconciler:
    return Reconciler(app.state.uow_factory, driver, clock, interval_s=1, grace_s=GRACE_S)


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=CREATED_AT)
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
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=ACCESS,
        created_at=CREATED_AT,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


@pytest.fixture
async def sandbox(app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str) -> Sandbox:
    created = await client.post(SANDBOXES, headers={"Authorization": f"Bearer {key}"}, json={})
    assert created.status_code == 201, created.text
    found = await load(app, org_id, created.json()["data"]["id"])
    assert found.state is SandboxState.STARTED and found.driver_ref is not None
    return found


async def load(app: FastAPI, org_id: str, sandbox_id: str) -> Sandbox:
    async with UnitOfWork(app.state.session_factory) as uow:
        found = await uow.sandboxes.get(org_id, sandbox_id)
    assert found is not None
    return found


async def drift_events(app: FastAPI, org_id: str) -> list[AuditEvent]:
    async with UnitOfWork(app.state.session_factory) as uow:
        return list(await uow.audit.list(org_id, action=DRIFT_DETECTED, limit=50))


async def record_reset(
    app: FastAPI, clock: FrozenClock, org_id: str, sandbox_id: str, previous: str
) -> None:
    """Write a ``sandbox.reset`` event that occurred ``RECENT_AGE`` before ``clock``."""
    recorder = AuditRecorder(FrozenClock(clock.now() - RECENT_AGE))
    async with UnitOfWork(app.state.session_factory) as uow:
        await recorder.record(
            uow,
            org_id=org_id,
            actor_type=ActorType.SYSTEM,
            actor_id=None,
            action=SANDBOX_RESET,
            target_type="sandbox",
            target_id=sandbox_id,
            details={"state": "started", "previous_driver_ref": previous},
        )
        await uow.commit()


def make_created(driver: FakeDriver, sandbox: Sandbox) -> None:
    assert sandbox.driver_ref is not None
    driver._set_state(sandbox.driver_ref, InstanceState.CREATED)


async def test_created_container_with_a_recent_reset_is_left_alone(
    app: FastAPI,
    driver: FakeDriver,
    clock: FrozenClock,
    reconciler: Reconciler,
    sandbox: Sandbox,
    org_id: str,
) -> None:
    make_created(driver, sandbox)
    await record_reset(app, clock, org_id, sandbox.id, OLD_CONTAINER)  # names another container

    report = await reconciler.reconcile_once()

    stored = await load(app, org_id, sandbox.id)
    assert report.drifted == () and report.errors == 0
    assert (stored.state, stored.version) == (SandboxState.STARTED, sandbox.version)
    assert await drift_events(app, org_id) == []


async def test_created_container_without_a_recent_reset_is_marked_error(
    app: FastAPI,
    driver: FakeDriver,
    reconciler: Reconciler,
    sandbox: Sandbox,
    org_id: str,
) -> None:
    make_created(driver, sandbox)

    report = await reconciler.reconcile_once()

    stored = await load(app, org_id, sandbox.id)
    assert report.drifted == (sandbox.id,)
    assert stored.state is SandboxState.ERROR
    assert stored.error_reason == "container is created"


async def test_exited_container_on_the_new_ref_is_still_settled_at_once(
    app: FastAPI,
    driver: FakeDriver,
    clock: FrozenClock,
    reconciler: Reconciler,
    sandbox: Sandbox,
    org_id: str,
) -> None:
    assert sandbox.driver_ref is not None
    driver.kill_instance(sandbox.driver_ref, vanish=False)
    await record_reset(app, clock, org_id, sandbox.id, OLD_CONTAINER)

    report = await reconciler.reconcile_once()

    stored = await load(app, org_id, sandbox.id)
    [event] = await drift_events(app, org_id)
    assert report.drifted == (sandbox.id,)
    assert stored.state is SandboxState.STOPPED
    assert event.details["stopped_unexpectedly"] is True


async def test_created_container_is_marked_error_once_the_window_has_passed(
    app: FastAPI,
    driver: FakeDriver,
    clock: FrozenClock,
    reconciler: Reconciler,
    sandbox: Sandbox,
    org_id: str,
) -> None:
    make_created(driver, sandbox)
    await record_reset(app, clock, org_id, sandbox.id, OLD_CONTAINER)
    assert (await reconciler.reconcile_once()).drifted == ()

    clock.advance(PAST_WINDOW)  # the crash between the saved ref and the start
    report = await reconciler.reconcile_once()

    stored = await load(app, org_id, sandbox.id)
    assert report.drifted == (sandbox.id,)
    assert stored.state is SandboxState.ERROR
