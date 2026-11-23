"""Reconciler and garbage collector over the FakeDriver, temp SQLite and a frozen clock.

Drift is staged by killing a fake container behind the platform's back; orphans by planting a
labelled container no row knows. Sandboxes and volumes are made through the ASGI client behind
the app factory (route tables are never introspected). The grace tracker, the reconciler and
the collector all read the one FrozenClock, so grace periods are crossed by advancing it.
"""

import asyncio
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.wiring import GC_ATTR, RECONCILER_ATTR
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import ActorType, AuditEvent
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.domain.snapshot import Snapshot, SnapshotState
from sandfort.drivers.base import InstanceState
from sandfort.drivers.errors import DriverError
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id, new_sandbox_id, new_snapshot_id
from sandfort.services.audit import AuditRecorder
from sandfort.services.sandbox_reset import SANDBOX_RESET
from sandfort.services.snapshots import snapshot_image_reference
from sandfort.workers.gc import IMAGE_REMOVED, VOLUME_REMOVED, GarbageCollector
from sandfort.workers.reconciler import (
    DRIFT_DETECTED,
    ORPHAN_REMOVED,
    RESET_SETTLE_S,
    SANDBOX_RESET_ACTION,
    Reconciler,
)

ROOT = Path(__file__).resolve().parents[1]
CREATED_AT = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
GRACE = timedelta(minutes=5)
SETTLED = timedelta(seconds=RESET_SETTLE_S * 2)  # a row this old is past the reset settle window
STOPPED_UNEXPECTEDLY = (
    "the sandbox stopped unexpectedly (its process tree exited, for example after exceeding "
    "its memory or process limit); start it again"
)
FULL_ACCESS = frozenset(
    {Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.VOLUMES_READ, Scope.VOLUMES_WRITE}
)


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'reconciler.db'}"
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
    return Reconciler(app.state.uow_factory, driver, clock, interval_s=1, grace_s=GRACE.seconds)


@pytest.fixture
def collector(app: FastAPI, driver: FakeDriver, clock: FrozenClock) -> GarbageCollector:
    return GarbageCollector(
        app.state.uow_factory,
        app.state.session_factory,
        driver,
        clock,
        interval_s=1,
        grace_s=GRACE.seconds,
    )


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
        scopes=FULL_ACCESS,
        created_at=CREATED_AT,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def post(client: httpx.AsyncClient, path: str, key: str, **body: Any) -> str:
    response = await client.post(path, headers=auth(key), json=body)
    assert response.status_code == 201, response.text
    created_id: str = response.json()["data"]["id"]
    return created_id


async def load(app: FastAPI, org_id: str, sandbox_id: str) -> Sandbox:
    async with UnitOfWork(app.state.session_factory) as uow:
        found = await uow.sandboxes.get(org_id, sandbox_id)
    assert found is not None
    return found


async def audit_events(app: FastAPI, org_id: str) -> list[AuditEvent]:
    async with UnitOfWork(app.state.session_factory) as uow:
        return list(await uow.audit.list(org_id, limit=200))


async def audit_actions(app: FastAPI, org_id: str) -> list[str]:
    return [event.action for event in await audit_events(app, org_id)]


async def started_sandbox(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> Sandbox:
    sandbox = await load(app, org_id, await post(client, "/v1/sandboxes", key))
    assert sandbox.state is SandboxState.STARTED
    assert sandbox.driver_ref is not None
    return sandbox


async def instance_refs(driver: FakeDriver) -> list[str]:
    return [item.provider_id for item in await driver.list_instances()]


# -- drift -----------------------------------------------------------------------------------


async def test_killed_container_marks_the_row_error_with_an_audit_event(
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
    driver.kill_instance(sandbox.driver_ref)
    clock.advance(SETTLED)

    report = await reconciler.reconcile_once()

    stored = await load(app, org_id, sandbox.id)
    assert report.drifted == (sandbox.id,)
    assert stored.state is SandboxState.ERROR
    assert stored.error_reason is not None and "missing" in stored.error_reason
    assert DRIFT_DETECTED in await audit_actions(app, org_id)


async def test_exited_container_of_a_started_row_becomes_stopped_and_restartable(
    app: FastAPI,
    client: httpx.AsyncClient,
    driver: FakeDriver,
    clock: FrozenClock,
    org_id: str,
    key: str,
) -> None:
    stopped_hook: list[tuple[str, str]] = []

    async def on_stopped(org: str, sandbox_id: str) -> None:
        stopped_hook.append((org, sandbox_id))

    reconciler = Reconciler(
        app.state.uow_factory,
        driver,
        clock,
        interval_s=1,
        grace_s=GRACE.seconds,
        on_stopped=on_stopped,
    )
    sandbox = await started_sandbox(app, client, org_id, key)
    assert sandbox.driver_ref is not None
    driver.kill_instance(sandbox.driver_ref, vanish=False)

    report = await reconciler.reconcile_once()

    stored = await load(app, org_id, sandbox.id)
    assert report.drifted == (sandbox.id,)
    assert stored.state is SandboxState.STOPPED
    assert stored.desired_state is SandboxState.STOPPED
    assert stored.error_reason == STOPPED_UNEXPECTEDLY
    [event] = [item for item in await audit_events(app, org_id) if item.action == DRIFT_DETECTED]
    assert event.actor_type is ActorType.SYSTEM
    assert event.target_id == sandbox.id
    assert event.details["stopped_unexpectedly"] is True
    assert event.details["driver_ref"] == sandbox.driver_ref
    assert stopped_hook == [(org_id, sandbox.id)]

    restarted = await client.post(f"/v1/sandboxes/{sandbox.id}/start", headers=auth(key))

    assert restarted.status_code == 200, restarted.text
    after_start = await load(app, org_id, sandbox.id)
    assert after_start.state is SandboxState.STARTED
    assert after_start.error_reason is None
    assert (await reconciler.reconcile_once()).drifted == ()


async def test_mark_stopped_unexpectedly_moves_a_started_row_to_stopped_with_the_reason(
    app: FastAPI,
    client: httpx.AsyncClient,
    driver: FakeDriver,
    clock: FrozenClock,
    org_id: str,
    key: str,
) -> None:
    stopped_hook: list[tuple[str, str]] = []

    async def on_stopped(org: str, sandbox_id: str) -> None:
        stopped_hook.append((org, sandbox_id))

    reconciler = Reconciler(
        app.state.uow_factory,
        driver,
        clock,
        interval_s=1,
        grace_s=GRACE.seconds,
        on_stopped=on_stopped,
    )
    sandbox = await started_sandbox(app, client, org_id, key)

    marked = await reconciler.mark_stopped_unexpectedly(sandbox)

    stored = await load(app, org_id, sandbox.id)
    assert marked is True
    assert stored.state is SandboxState.STOPPED
    assert stored.desired_state is SandboxState.STOPPED
    assert stored.error_reason == STOPPED_UNEXPECTEDLY
    [event] = [item for item in await audit_events(app, org_id) if item.action == DRIFT_DETECTED]
    assert event.actor_type is ActorType.SYSTEM
    assert event.details["stopped_unexpectedly"] is True
    assert stopped_hook == [(org_id, sandbox.id)]


async def test_mark_stopped_unexpectedly_returns_false_for_a_row_that_is_no_longer_started(
    app: FastAPI,
    client: httpx.AsyncClient,
    reconciler: Reconciler,
    org_id: str,
    key: str,
) -> None:
    sandbox = await started_sandbox(app, client, org_id, key)
    assert await reconciler.mark_stopped_unexpectedly(sandbox) is True

    again = await reconciler.mark_stopped_unexpectedly(sandbox)  # the stale row says started

    assert again is False
    assert (await load(app, org_id, sandbox.id)).state is SandboxState.STOPPED
    drift_events = [e for e in await audit_events(app, org_id) if e.action == DRIFT_DETECTED]
    assert len(drift_events) == 1


async def test_mark_stopped_unexpectedly_returns_false_when_the_driver_ref_changed(
    app: FastAPI,
    client: httpx.AsyncClient,
    reconciler: Reconciler,
    org_id: str,
    key: str,
) -> None:
    sandbox = await started_sandbox(app, client, org_id, key)
    seen_before_reset = sandbox.model_copy(update={"driver_ref": "fake-sf-replaced-meanwhile"})

    marked = await reconciler.mark_stopped_unexpectedly(seen_before_reset)

    stored = await load(app, org_id, sandbox.id)
    assert marked is False
    assert stored.state is SandboxState.STARTED
    assert stored.version == sandbox.version  # nothing was written
    assert DRIFT_DETECTED not in await audit_actions(app, org_id)


async def record_reset_event(
    app: FastAPI, clock: FrozenClock, org_id: str, sandbox_id: str, *, age_s: float
) -> None:
    """Write a ``sandbox.reset`` audit event that occurred ``age_s`` seconds before ``clock``."""
    recorder = AuditRecorder(FrozenClock(clock.now() - timedelta(seconds=age_s)))
    async with UnitOfWork(app.state.session_factory) as uow:
        await recorder.record(
            uow,
            org_id=org_id,
            actor_type=ActorType.SYSTEM,
            actor_id=None,
            action=SANDBOX_RESET,
            target_type="sandbox",
            target_id=sandbox_id,
            details={},
        )
        await uow.commit()


def break_container(driver: FakeDriver, provider_id: str, broken: str) -> None:
    if broken == "missing":
        driver.kill_instance(provider_id)
    elif broken == "created":
        driver._set_state(provider_id, InstanceState.CREATED)
    else:
        driver.kill_instance(provider_id, vanish=False)


def test_the_reset_action_matches_the_service_constant() -> None:
    assert SANDBOX_RESET_ACTION == SANDBOX_RESET


@pytest.mark.parametrize("broken", ["missing", "created"])
async def test_fresh_row_without_a_reset_event_is_settled_to_error_at_once(
    app: FastAPI,
    client: httpx.AsyncClient,
    driver: FakeDriver,
    reconciler: Reconciler,
    broken: str,
    org_id: str,
    key: str,
) -> None:
    sandbox = await started_sandbox(app, client, org_id, key)
    assert sandbox.driver_ref is not None
    break_container(driver, sandbox.driver_ref, broken)

    report = await reconciler.reconcile_once()  # the row was written moments ago

    assert report.drifted == (sandbox.id,)
    assert (await load(app, org_id, sandbox.id)).state is SandboxState.ERROR


@pytest.mark.parametrize("broken", ["missing", "created", "exited"])
async def test_row_with_a_reset_event_ten_seconds_ago_is_skipped(
    app: FastAPI,
    client: httpx.AsyncClient,
    driver: FakeDriver,
    clock: FrozenClock,
    reconciler: Reconciler,
    caplog: pytest.LogCaptureFixture,
    broken: str,
    org_id: str,
    key: str,
) -> None:
    sandbox = await started_sandbox(app, client, org_id, key)
    assert sandbox.driver_ref is not None
    break_container(driver, sandbox.driver_ref, broken)
    await record_reset_event(app, clock, org_id, sandbox.id, age_s=10)

    with caplog.at_level("INFO", logger="sandfort.workers.reconciler"):
        report = await reconciler.reconcile_once()

    skipped = await load(app, org_id, sandbox.id)
    assert report.drifted == () and report.errors == 0
    assert (skipped.state, skipped.version) == (SandboxState.STARTED, sandbox.version)
    assert any(
        sandbox.id in record.getMessage() and record.levelname == "INFO"
        for record in caplog.records
    )
    assert DRIFT_DETECTED not in await audit_actions(app, org_id)


@pytest.mark.parametrize(
    ("broken", "settled_state"),
    [
        ("missing", SandboxState.ERROR),
        ("created", SandboxState.ERROR),
        ("exited", SandboxState.STOPPED),
    ],
)
async def test_row_with_a_reset_event_120_seconds_ago_is_settled(
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
    assert sandbox.driver_ref is not None
    break_container(driver, sandbox.driver_ref, broken)
    await record_reset_event(app, clock, org_id, sandbox.id, age_s=120)

    report = await reconciler.reconcile_once()

    assert report.drifted == (sandbox.id,)
    assert (await load(app, org_id, sandbox.id)).state is settled_state


async def test_reset_event_of_another_sandbox_does_not_shield_the_row(
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
    driver.kill_instance(sandbox.driver_ref)
    await record_reset_event(app, clock, org_id, new_sandbox_id(), age_s=10)

    report = await reconciler.reconcile_once()

    assert report.drifted == (sandbox.id,)


async def test_exited_container_skipped_during_a_reset_is_settled_after_the_window(
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
    break_container(driver, sandbox.driver_ref, "exited")
    await record_reset_event(app, clock, org_id, sandbox.id, age_s=10)
    assert (await reconciler.reconcile_once()).drifted == ()

    clock.advance(SETTLED)  # a crash right after the reset: the first pass after the window
    report = await reconciler.reconcile_once()

    assert report.drifted == (sandbox.id,)
    assert (await load(app, org_id, sandbox.id)).state is SandboxState.STOPPED


async def test_mark_stopped_unexpectedly_is_deferred_by_a_reset_event_ten_seconds_ago(
    app: FastAPI,
    client: httpx.AsyncClient,
    clock: FrozenClock,
    reconciler: Reconciler,
    caplog: pytest.LogCaptureFixture,
    org_id: str,
    key: str,
) -> None:
    sandbox = await started_sandbox(app, client, org_id, key)
    await record_reset_event(app, clock, org_id, sandbox.id, age_s=10)

    with caplog.at_level("INFO", logger="sandfort.workers.reconciler"):
        marked = await reconciler.mark_stopped_unexpectedly(sandbox)

    stored = await load(app, org_id, sandbox.id)
    assert marked is False
    assert (stored.state, stored.version) == (SandboxState.STARTED, sandbox.version)
    assert DRIFT_DETECTED not in await audit_actions(app, org_id)
    assert any(
        sandbox.id in record.getMessage() and record.levelname == "INFO"
        for record in caplog.records
    )


async def test_mark_stopped_unexpectedly_settles_with_a_reset_event_120_seconds_ago(
    app: FastAPI,
    client: httpx.AsyncClient,
    clock: FrozenClock,
    reconciler: Reconciler,
    org_id: str,
    key: str,
) -> None:
    sandbox = await started_sandbox(app, client, org_id, key)
    await record_reset_event(app, clock, org_id, sandbox.id, age_s=120)

    marked = await reconciler.mark_stopped_unexpectedly(sandbox)

    assert marked is True
    assert (await load(app, org_id, sandbox.id)).state is SandboxState.STOPPED


async def test_created_never_started_container_of_a_started_row_is_an_error(
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
    driver._set_state(sandbox.driver_ref, InstanceState.CREATED)
    clock.advance(SETTLED)

    report = await reconciler.reconcile_once()

    stored = await load(app, org_id, sandbox.id)
    assert report.drifted == (sandbox.id,)
    assert stored.state is SandboxState.ERROR
    assert stored.error_reason == "container is created"
    [event] = [item for item in await audit_events(app, org_id) if item.action == DRIFT_DETECTED]
    assert "stopped_unexpectedly" not in event.details


async def test_healthy_and_stopped_sandboxes_are_left_alone(
    app: FastAPI,
    client: httpx.AsyncClient,
    driver: FakeDriver,
    clock: FrozenClock,
    reconciler: Reconciler,
    org_id: str,
    key: str,
) -> None:
    healthy = await started_sandbox(app, client, org_id, key)
    stopped = await started_sandbox(app, client, org_id, key)
    stop = await client.post(f"/v1/sandboxes/{stopped.id}/stop", headers=auth(key))
    assert stop.status_code == 200, stop.text

    first = await reconciler.reconcile_once()
    clock.advance(GRACE * 2)
    second = await reconciler.reconcile_once()

    assert first == second
    assert (first.drifted, first.orphans_removed, first.errors) == ((), (), 0)
    assert (await load(app, org_id, healthy.id)).state is SandboxState.STARTED
    assert (await load(app, org_id, stopped.id)).state is SandboxState.STOPPED
    assert len(await instance_refs(driver)) == 2


async def test_unreadable_inventory_does_not_read_as_drift(
    app: FastAPI,
    client: httpx.AsyncClient,
    driver: FakeDriver,
    reconciler: Reconciler,
    monkeypatch: pytest.MonkeyPatch,
    org_id: str,
    key: str,
) -> None:
    sandbox = await started_sandbox(app, client, org_id, key)

    async def broken() -> Any:
        raise DriverError("daemon unreachable")

    monkeypatch.setattr(driver, "list_instances", broken)

    report = await reconciler.reconcile_once()

    assert report.errors == 1 and report.drifted == ()
    assert (await load(app, org_id, sandbox.id)).state is SandboxState.STARTED


# -- orphans ---------------------------------------------------------------------------------


async def test_planted_container_is_removed_only_after_the_grace_period(
    app: FastAPI,
    driver: FakeDriver,
    clock: FrozenClock,
    reconciler: Reconciler,
    org_id: str,
) -> None:
    ref = driver.plant_instance(new_sandbox_id(), org_id)

    first = await reconciler.reconcile_once()  # first sighting starts the clock
    clock.advance(GRACE - timedelta(minutes=1))
    inside = await reconciler.reconcile_once()
    still_there = await instance_refs(driver)
    clock.advance(timedelta(minutes=1, seconds=1))
    after = await reconciler.reconcile_once()

    assert first.orphans_removed == () and inside.orphans_removed == ()
    assert still_there == [ref]
    assert after.orphans_removed == (ref,)
    assert await instance_refs(driver) == []
    assert ORPHAN_REMOVED in await audit_actions(app, org_id)


async def test_orphan_with_an_unknown_org_is_removed_without_an_audit_row(
    app: FastAPI,
    driver: FakeDriver,
    clock: FrozenClock,
    reconciler: Reconciler,
    org_id: str,
) -> None:
    ref = driver.plant_instance(new_sandbox_id(), new_org_id())
    await reconciler.reconcile_once()
    clock.advance(GRACE)

    report = await reconciler.reconcile_once()

    assert report.orphans_removed == (ref,) and report.errors == 0
    assert await instance_refs(driver) == []
    assert await audit_actions(app, org_id) == []


async def test_failing_audit_recorder_does_not_break_the_pass(
    app: FastAPI,
    driver: FakeDriver,
    clock: FrozenClock,
    reconciler: Reconciler,
    monkeypatch: pytest.MonkeyPatch,
    org_id: str,
) -> None:
    calls: list[int] = []

    async def failing(*args: Any, **kwargs: Any) -> None:
        calls.append(1)
        raise RuntimeError("audit storage down")

    monkeypatch.setattr(reconciler._audit, "record", failing)
    ref = driver.plant_instance(new_sandbox_id(), org_id)
    await reconciler.reconcile_once()
    clock.advance(GRACE)

    report = await reconciler.reconcile_once()

    assert calls == [1]
    assert report.orphans_removed == (ref,) and report.errors == 0
    assert await instance_refs(driver) == []


async def test_second_pass_changes_nothing(
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
    driver.kill_instance(sandbox.driver_ref)
    driver.plant_instance(new_sandbox_id(), org_id)
    await reconciler.reconcile_once()
    clock.advance(GRACE)
    first = await reconciler.reconcile_once()
    after_first = await audit_actions(app, org_id)
    row_after_first = await load(app, org_id, sandbox.id)

    second = await reconciler.reconcile_once()

    assert len(first.orphans_removed) == 1
    assert second.drifted == () and second.orphans_removed == () and second.errors == 0
    assert await audit_actions(app, org_id) == after_first
    assert await load(app, org_id, sandbox.id) == row_after_first
    assert after_first.count(DRIFT_DETECTED) == 1
    assert after_first.count(ORPHAN_REMOVED) == 1


async def test_driver_error_on_one_item_does_not_end_the_pass(
    app: FastAPI,
    client: httpx.AsyncClient,
    driver: FakeDriver,
    clock: FrozenClock,
    reconciler: Reconciler,
    monkeypatch: pytest.MonkeyPatch,
    org_id: str,
    key: str,
) -> None:
    sandbox = await started_sandbox(app, client, org_id, key)
    assert sandbox.driver_ref is not None
    driver.kill_instance(sandbox.driver_ref)
    bad = driver.plant_instance(new_sandbox_id(), org_id)
    good = driver.plant_instance(new_sandbox_id(), org_id)
    original = driver.destroy

    async def flaky(ref: str, *, remove_volumes: bool = True) -> None:
        if ref == bad:
            raise DriverError("cannot remove", ref=ref)
        await original(ref, remove_volumes=remove_volumes)

    monkeypatch.setattr(driver, "destroy", flaky)
    await reconciler.reconcile_once()
    clock.advance(GRACE)

    report = await reconciler.reconcile_once()

    assert report.errors == 1
    assert report.orphans_removed == (good,)
    assert await instance_refs(driver) == [bad]
    assert (await load(app, org_id, sandbox.id)).state is SandboxState.ERROR


async def test_container_claimed_by_a_row_is_never_an_orphan(
    app: FastAPI,
    client: httpx.AsyncClient,
    driver: FakeDriver,
    clock: FrozenClock,
    reconciler: Reconciler,
    org_id: str,
    key: str,
) -> None:
    sandbox = await started_sandbox(app, client, org_id, key)

    await reconciler.reconcile_once()
    clock.advance(GRACE * 3)
    report = await reconciler.reconcile_once()

    assert report.orphans_removed == ()
    assert await instance_refs(driver) == [sandbox.driver_ref]


# -- garbage collection ----------------------------------------------------------------------


async def seed_snapshot(app: FastAPI, driver: FakeDriver, org_id: str) -> Snapshot:
    """A ready snapshot row with its image on the driver and an audit trail like the service's."""
    snapshot_id = new_snapshot_id()
    snapshot = Snapshot(
        id=snapshot_id,
        org_id=org_id,
        name=f"snap-{snapshot_id}",
        image_ref=snapshot_image_reference(snapshot_id),
        digest="sha256:abc",
        layer_count=1,
        state=SnapshotState.READY,
        created_at=CREATED_AT,
    )
    await driver.build_image(snapshot.image_ref, b"context")
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.snapshots.add(snapshot)
        await AuditRecorder(FrozenClock(CREATED_AT)).record(
            uow,
            org_id=org_id,
            actor_type=ActorType.API_KEY,
            actor_id=None,
            action="snapshot.create",
            target_type="snapshot",
            target_id=snapshot_id,
        )
        await uow.commit()
    return snapshot


async def image_refs(driver: FakeDriver) -> list[str]:
    return [item.ref for item in await driver.list_images()]


async def test_gc_removes_the_image_of_a_deleted_snapshot_after_the_grace_period(
    app: FastAPI,
    driver: FakeDriver,
    clock: FrozenClock,
    collector: GarbageCollector,
    org_id: str,
) -> None:
    kept = await seed_snapshot(app, driver, org_id)
    deleted = await seed_snapshot(app, driver, org_id)
    async with UnitOfWork(app.state.session_factory) as uow:
        assert await uow.snapshots.delete(org_id, deleted.id)
        await uow.commit()

    first = await collector.collect_once()
    clock.advance(GRACE - timedelta(seconds=1))
    inside = await collector.collect_once()
    still_there = await image_refs(driver)
    clock.advance(timedelta(seconds=1))
    after = await collector.collect_once()

    assert first.images_removed == () and inside.images_removed == ()
    assert sorted(still_there) == sorted([kept.image_ref, deleted.image_ref])
    assert after.images_removed == (deleted.image_ref,)
    assert await image_refs(driver) == [kept.image_ref]
    assert IMAGE_REMOVED in await audit_actions(app, org_id)


async def test_gc_never_touches_images_without_the_platform_tag(
    driver: FakeDriver, clock: FrozenClock, collector: GarbageCollector
) -> None:
    await driver.pull_image("alpine:3.20")

    await collector.collect_once()
    clock.advance(GRACE * 2)
    report = await collector.collect_once()

    assert report.images_removed == ()
    assert (await driver.inspect_image("alpine:3.20")).ref == "alpine:3.20"


async def test_gc_removes_an_unreferenced_volume_only_after_the_grace_period(
    app: FastAPI,
    client: httpx.AsyncClient,
    driver: FakeDriver,
    clock: FrozenClock,
    collector: GarbageCollector,
    org_id: str,
    key: str,
) -> None:
    orphaned_id = await post(client, "/v1/volumes", key, name="orphaned")
    kept_id = await post(client, "/v1/volumes", key, name="kept")
    await driver.create_volume("scratch", labels={})  # not the platform's: never collected
    async with UnitOfWork(app.state.session_factory) as uow:
        assert await uow.volumes.delete(org_id, orphaned_id)
        await uow.commit()

    first = await collector.collect_once()
    clock.advance(GRACE - timedelta(seconds=1))
    inside = await collector.collect_once()
    before = sorted(item.name for item in await driver.list_volumes())
    clock.advance(timedelta(seconds=1))
    after = await collector.collect_once()

    remaining = sorted(item.name for item in await driver.list_volumes())
    assert first.volumes_removed == () and inside.volumes_removed == ()
    assert len(before) == 3
    assert len(after.volumes_removed) == 1
    assert after.volumes_removed[0].endswith(orphaned_id.lower())
    assert any(name.endswith(kept_id.lower()) for name in remaining)
    assert "scratch" in remaining and len(remaining) == 2
    assert VOLUME_REMOVED in await audit_actions(app, org_id)


async def test_gc_error_on_one_volume_does_not_end_the_pass(
    app: FastAPI,
    client: httpx.AsyncClient,
    driver: FakeDriver,
    clock: FrozenClock,
    collector: GarbageCollector,
    monkeypatch: pytest.MonkeyPatch,
    org_id: str,
    key: str,
) -> None:
    first_id = await post(client, "/v1/volumes", key, name="first")
    second_id = await post(client, "/v1/volumes", key, name="second")
    async with UnitOfWork(app.state.session_factory) as uow:
        assert await uow.volumes.delete(org_id, first_id)
        assert await uow.volumes.delete(org_id, second_id)
        await uow.commit()
    original = driver.remove_volume

    async def flaky(ref: str) -> None:
        if ref.endswith(first_id.lower()):
            raise DriverError("cannot remove", ref=ref)
        await original(ref)

    monkeypatch.setattr(driver, "remove_volume", flaky)
    await collector.collect_once()
    clock.advance(GRACE)

    report = await collector.collect_once()

    assert report.errors == 1
    assert len(report.volumes_removed) == 1
    assert report.volumes_removed[0].endswith(second_id.lower())


# -- loops -----------------------------------------------------------------------------------


async def test_loops_start_run_a_startup_pass_and_stop_cleanly(app: FastAPI) -> None:
    reconciler: Reconciler = getattr(app.state, RECONCILER_ATTR)
    collector: GarbageCollector = getattr(app.state, GC_ATTR)

    reconciler.start()
    collector.start()
    await asyncio.sleep(0.05)
    running = (reconciler.running, collector.running)
    await reconciler.stop()
    await collector.stop()

    assert running == (True, True)
    assert (reconciler.running, collector.running) == (False, False)


async def wait_for(condition: Callable[[], bool], timeout_s: float = 2.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout_s
    while not condition():
        assert asyncio.get_running_loop().time() < deadline, "condition not reached in time"
        await asyncio.sleep(0.01)


def count_passes(driver: FakeDriver, monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """One entry per reconcile pass (each pass reads the driver inventory exactly once)."""
    passes: list[int] = []
    original = driver.list_instances

    async def counting() -> Any:
        passes.append(1)
        return await original()

    monkeypatch.setattr(driver, "list_instances", counting)
    return passes


async def test_kick_wakes_the_running_loop_before_the_interval(
    app: FastAPI, driver: FakeDriver, clock: FrozenClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    passes = count_passes(driver, monkeypatch)
    slow = Reconciler(app.state.uow_factory, driver, clock, interval_s=3600, grace_s=1)
    slow.start()
    try:
        await wait_for(lambda: len(passes) == 1)  # the startup pass

        slow.kick()

        await wait_for(lambda: len(passes) == 2)
    finally:
        await slow.stop()


async def test_repeated_kicks_before_the_pass_runs_collapse_into_one_pass(
    app: FastAPI, driver: FakeDriver, clock: FrozenClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    passes = count_passes(driver, monkeypatch)
    slow = Reconciler(app.state.uow_factory, driver, clock, interval_s=3600, grace_s=1)
    slow.start()
    try:
        await wait_for(lambda: len(passes) == 1)

        for _ in range(5):
            slow.kick()
        await wait_for(lambda: len(passes) == 2)
        await asyncio.sleep(0.2)  # a leftover wake-up would show as a third pass

        assert len(passes) == 2
    finally:
        await slow.stop()


async def test_kick_without_a_running_loop_does_nothing(
    app: FastAPI, driver: FakeDriver, clock: FrozenClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    passes = count_passes(driver, monkeypatch)
    idle = Reconciler(app.state.uow_factory, driver, clock, interval_s=3600, grace_s=1)

    idle.kick()
    await asyncio.sleep(0.05)
    idle.start()  # the stale kick must not add a pass to the startup one
    try:
        await wait_for(lambda: len(passes) == 1)
        await asyncio.sleep(0.2)

        assert len(passes) == 1
    finally:
        await idle.stop()
