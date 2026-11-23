"""Reset deferral keyed on the container ref: a death of the NEW container is settled at once.

A reset audits ``sandbox.reset`` with ``previous_driver_ref`` and then swaps the row's
``driver_ref`` to the new container. The reconciler defers a drift for ``RESET_SETTLE_S`` only
while the row still points at the container being replaced (or the event predates the key, or the
row has no ref). Real resets go through the ASGI app over the FakeDriver and a temp SQLite
database; events that model the mid-reset window are written with the audit recorder.
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

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
from sandfort.workers.reconciler import DRIFT_DETECTED, Reconciler

ROOT = Path(__file__).resolve().parents[1]
CREATED_AT = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
GRACE_S = 300
RECENT_AGE = timedelta(seconds=10)  # inside the 60 s reset settle window
OLD_CONTAINER = "fake-old-container-removed-by-the-reset"  # FakeDriver reuses refs, so staged
ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'deferral.db'}"
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


async def load(app: FastAPI, org_id: str, sandbox_id: str) -> Sandbox:
    async with UnitOfWork(app.state.session_factory) as uow:
        found = await uow.sandboxes.get(org_id, sandbox_id)
    assert found is not None
    return found


async def events_of(app: FastAPI, org_id: str, action: str) -> list[AuditEvent]:
    async with UnitOfWork(app.state.session_factory) as uow:
        return list(await uow.audit.list(org_id, action=action, limit=50))


async def started_sandbox(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> Sandbox:
    headers = {"Authorization": f"Bearer {key}"}
    created = await client.post(SANDBOXES, headers=headers, json={})
    assert created.status_code == 201, created.text
    sandbox = await load(app, org_id, created.json()["data"]["id"])
    assert sandbox.state is SandboxState.STARTED and sandbox.driver_ref is not None
    return sandbox


async def record_reset_event(
    app: FastAPI, clock: FrozenClock, org_id: str, sandbox_id: str, details: dict[str, Any]
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
            details=details,
        )
        await uow.commit()


async def finished_reset(
    app: FastAPI, clock: FrozenClock, org_id: str, sandbox: Sandbox
) -> Sandbox:
    """Stage a reset seconds ago whose old container is gone: the row is on the new one.

    The FakeDriver names a container after the sandbox, so a real reset reuses the ref; the
    event is written with a different ``previous_driver_ref`` to stand for a runtime that hands
    out fresh ids (Docker).
    """
    details = {"state": "started", "previous_driver_ref": OLD_CONTAINER}
    await record_reset_event(app, clock, org_id, sandbox.id, details)
    return sandbox


def break_container(driver: FakeDriver, ref: str, broken: str) -> None:
    if broken == "missing":
        driver.kill_instance(ref)
    elif broken == "created":
        driver._set_state(ref, InstanceState.CREATED)
    else:
        driver.kill_instance(ref, vanish=False)


# -- the audit event ---------------------------------------------------------------------------


async def test_reset_event_carries_the_ref_of_the_container_it_replaces(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    sandbox = await started_sandbox(app, client, org_id, key)
    headers = {"Authorization": f"Bearer {key}"}

    response = await client.post(f"{SANDBOXES}/{sandbox.id}/reset", headers=headers)

    assert response.status_code == 200, response.text
    [event] = await events_of(app, org_id, SANDBOX_RESET)
    assert event.details == {"state": "started", "previous_driver_ref": sandbox.driver_ref}


# -- still pointing at the container being replaced: deferred ----------------------------------


@pytest.mark.parametrize("broken", ["missing", "created", "exited"])
async def test_row_still_on_the_replaced_container_is_deferred_by_the_drift_pass(
    app: FastAPI,
    client: httpx.AsyncClient,
    driver: FakeDriver,
    clock: FrozenClock,
    reconciler: Reconciler,
    broken: str,
    org_id: str,
    key: str,
) -> None:
    sandbox = await started_sandbox(app, client, org_id, key)
    assert sandbox.driver_ref is not None
    break_container(driver, sandbox.driver_ref, broken)
    details = {"state": "started", "previous_driver_ref": sandbox.driver_ref}
    await record_reset_event(app, clock, org_id, sandbox.id, details)

    report = await reconciler.reconcile_once()

    stored = await load(app, org_id, sandbox.id)
    assert report.drifted == () and report.errors == 0
    assert (stored.state, stored.version) == (SandboxState.STARTED, sandbox.version)
    assert await events_of(app, org_id, DRIFT_DETECTED) == []


async def test_mark_stopped_unexpectedly_is_deferred_while_the_row_is_on_the_replaced_one(
    app: FastAPI,
    client: httpx.AsyncClient,
    clock: FrozenClock,
    reconciler: Reconciler,
    org_id: str,
    key: str,
) -> None:
    sandbox = await started_sandbox(app, client, org_id, key)
    details = {"state": "started", "previous_driver_ref": sandbox.driver_ref}
    await record_reset_event(app, clock, org_id, sandbox.id, details)

    marked = await reconciler.mark_stopped_unexpectedly(sandbox)

    stored = await load(app, org_id, sandbox.id)
    assert marked is False
    assert (stored.state, stored.version) == (SandboxState.STARTED, sandbox.version)
    assert await events_of(app, org_id, DRIFT_DETECTED) == []


async def test_old_style_event_without_previous_driver_ref_still_defers(
    app: FastAPI,
    client: httpx.AsyncClient,
    driver: FakeDriver,
    clock: FrozenClock,
    reconciler: Reconciler,
    org_id: str,
    key: str,
) -> None:
    sandbox = await started_sandbox(app, client, org_id, key)
    assert sandbox.driver_ref is not None
    driver.kill_instance(sandbox.driver_ref, vanish=False)
    await record_reset_event(app, clock, org_id, sandbox.id, {"state": "started"})

    report = await reconciler.reconcile_once()
    marked = await reconciler.mark_stopped_unexpectedly(sandbox)

    assert report.drifted == () and marked is False
    assert (await load(app, org_id, sandbox.id)).state is SandboxState.STARTED


async def test_row_without_a_driver_ref_is_deferred(
    app: FastAPI,
    client: httpx.AsyncClient,
    clock: FrozenClock,
    reconciler: Reconciler,
    org_id: str,
    key: str,
) -> None:
    sandbox = await started_sandbox(app, client, org_id, key)
    details = {"state": "started", "previous_driver_ref": "fake-sf-some-other-container"}
    await record_reset_event(app, clock, org_id, sandbox.id, details)
    no_ref = sandbox.model_copy(update={"driver_ref": None})

    assert await reconciler.mark_stopped_unexpectedly(no_ref) is False

    assert (await load(app, org_id, sandbox.id)).state is SandboxState.STARTED


# -- already on the new container: settled at once ---------------------------------------------


@pytest.mark.parametrize(
    ("broken", "settled_state"),
    [
        ("missing", SandboxState.ERROR),
        ("exited", SandboxState.STOPPED),
    ],
)
async def test_death_of_the_new_container_is_settled_by_the_next_pass(
    app: FastAPI,
    client: httpx.AsyncClient,
    driver: FakeDriver,
    clock: FrozenClock,
    reconciler: Reconciler,
    broken: str,
    settled_state: SandboxState,
    org_id: str,
    key: str,
) -> None:
    sandbox = await started_sandbox(app, client, org_id, key)
    after = await finished_reset(app, clock, org_id, sandbox)
    assert after.driver_ref is not None
    break_container(driver, after.driver_ref, broken)  # the reset is seconds old

    report = await reconciler.reconcile_once()

    stored = await load(app, org_id, sandbox.id)
    assert report.drifted == (sandbox.id,)
    assert stored.state is settled_state
    if settled_state is SandboxState.STOPPED:
        assert stored.desired_state is SandboxState.STOPPED
        [event] = await events_of(app, org_id, DRIFT_DETECTED)
        assert event.details["stopped_unexpectedly"] is True
        assert event.details["driver_ref"] == after.driver_ref


async def test_mark_stopped_unexpectedly_settles_the_new_container_at_once(
    app: FastAPI,
    client: httpx.AsyncClient,
    clock: FrozenClock,
    reconciler: Reconciler,
    org_id: str,
    key: str,
) -> None:
    sandbox = await started_sandbox(app, client, org_id, key)
    after = await finished_reset(app, clock, org_id, sandbox)

    marked = await reconciler.mark_stopped_unexpectedly(after)

    stored = await load(app, org_id, sandbox.id)
    assert marked is True
    assert stored.state is SandboxState.STOPPED
    assert stored.error_reason is not None and "stopped unexpectedly" in stored.error_reason


async def test_event_with_a_null_previous_ref_does_not_shield_a_row_that_has_a_ref(
    app: FastAPI,
    client: httpx.AsyncClient,
    clock: FrozenClock,
    reconciler: Reconciler,
    org_id: str,
    key: str,
) -> None:
    sandbox = await started_sandbox(app, client, org_id, key)
    details: dict[str, Any] = {"state": "started", "previous_driver_ref": None}
    await record_reset_event(app, clock, org_id, sandbox.id, details)

    assert await reconciler.mark_stopped_unexpectedly(sandbox) is True

    assert (await load(app, org_id, sandbox.id)).state is SandboxState.STOPPED
