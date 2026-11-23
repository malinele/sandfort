"""A stopped sandbox records why it stopped in ``stop_cause`` (round 54).

FakeDriver, temp SQLite migrated to head, httpx over ASGI. The cause is written by the
write that starts the stop (the service intent, the idle scanner, the reconciler's drift
settle), kept by ``drive_stop`` and by a reset, and cleared by a successful start.
"""

import sqlite3
import sys
from collections.abc import AsyncIterator
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi import FastAPI  # noqa: E402

from sandfort.api.wiring import ACTIVITY_TRACKER_ATTR  # noqa: E402
from sandfort.clock import FrozenClock  # noqa: E402
from sandfort.db.unit_of_work import UnitOfWork  # noqa: E402
from sandfort.domain.org import Scope  # noqa: E402
from sandfort.domain.sandbox import (  # noqa: E402
    STOP_CAUSE_AUTO_STOP,
    STOP_CAUSE_CONTAINER_EXITED,
    STOP_CAUSE_OOM_KILLED,
    STOP_CAUSE_REQUESTED,
    STOP_CAUSE_UNKNOWN,
    STOP_CAUSES,
    Sandbox,
    SandboxState,
    visible_stop_cause,
    visible_stopped_at,
)
from sandfort.drivers.fake import FakeDriver  # noqa: E402
from sandfort.services.activity import ActivityTracker  # noqa: E402
from sandfort.services.sandbox_jobs import AuditNote, Lifecycle  # noqa: E402
from sandfort.workers.autostop import AUTO_STOPPED, AutoStopScanner  # noqa: E402
from sandfort.workers.reconciler import DRIFT_DETECTED, Reconciler  # noqa: E402
from test_api_sandboxes import BASE, add_org, migrated_app, seed_key, send  # noqa: E402

READ_WRITE = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})
MINUTE = timedelta(minutes=1)
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    async with migrated_app(tmp_path) as application:
        yield application


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
async def org_id(app: FastAPI) -> str:
    return await add_org(app, "stopcause")


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id, READ_WRITE)


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock(datetime.now(UTC))


async def create(client: httpx.AsyncClient, key: str, **payload: Any) -> str:
    body = await send(client, "POST", BASE, key, status=201, json=payload)
    sandbox_id: str = body["data"]["id"]
    return sandbox_id


async def load(app: FastAPI, org_id: str, sandbox_id: str) -> Sandbox:
    async with UnitOfWork(app.state.session_factory) as uow:
        found = await uow.sandboxes.get(org_id, sandbox_id)
    assert found is not None
    return found


async def audit_details(app: FastAPI, org_id: str, action: str) -> list[dict[str, Any]]:
    async with UnitOfWork(app.state.session_factory) as uow:
        events = await uow.audit.list(org_id, action=action, limit=50)
    return [event.details for event in events]


def reconciler_for(app: FastAPI, driver: FakeDriver, clock: FrozenClock) -> Reconciler:
    return Reconciler(app.state.uow_factory, driver, clock, interval_s=1, grace_s=300)


def scanner_for(app: FastAPI, driver: FakeDriver, clock: FrozenClock) -> AutoStopScanner:
    tracker = ActivityTracker(clock)
    setattr(app.state, ACTIVITY_TRACKER_ATTR, tracker)
    return AutoStopScanner(app.state.uow_factory, driver, clock, tracker, interval_s=1)


async def stop(client: httpx.AsyncClient, key: str, sandbox_id: str, status: int = 200) -> None:
    await send(client, "POST", f"{BASE}/{sandbox_id}/stop", key, status=status)


async def start(client: httpx.AsyncClient, key: str, sandbox_id: str) -> None:
    await send(client, "POST", f"{BASE}/{sandbox_id}/start", key, status=200)


async def kill_exited(app: FastAPI, driver: FakeDriver, org_id: str, sandbox_id: str) -> Sandbox:
    sandbox = await load(app, org_id, sandbox_id)
    assert sandbox.driver_ref is not None
    driver.kill_instance(sandbox.driver_ref, vanish=False)
    return sandbox


# -- write paths -----------------------------------------------------------------------------


async def test_a_manual_stop_stores_requested(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    sandbox_id = await create(client, key)
    assert (await load(app, org_id, sandbox_id)).stop_cause is None

    await stop(client, key, sandbox_id)

    stored = await load(app, org_id, sandbox_id)
    assert stored.state is SandboxState.STOPPED
    assert stored.stop_cause == STOP_CAUSE_REQUESTED


async def test_an_auto_stop_pass_stores_auto_stop(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    clock: FrozenClock,
) -> None:
    sandbox_id = await create(client, key, auto_stop_minutes=1)
    scanner = scanner_for(app, driver, clock)

    clock.advance(2 * MINUTE)
    await scanner.scan_once()

    stored = await load(app, org_id, sandbox_id)
    assert stored.state is SandboxState.STOPPED
    assert stored.stop_cause == STOP_CAUSE_AUTO_STOP


async def test_a_reconcile_pass_stores_container_exited(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    clock: FrozenClock,
) -> None:
    sandbox_id = await create(client, key)
    await kill_exited(app, driver, org_id, sandbox_id)

    report = await reconciler_for(app, driver, clock).reconcile_once()

    stored = await load(app, org_id, sandbox_id)
    assert report.drifted == (sandbox_id,)
    assert stored.state is SandboxState.STOPPED
    assert stored.stop_cause == STOP_CAUSE_CONTAINER_EXITED


async def test_mark_stopped_unexpectedly_stores_container_exited(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    clock: FrozenClock,
) -> None:
    sandbox_id = await create(client, key)
    row = await kill_exited(app, driver, org_id, sandbox_id)

    settled = await reconciler_for(app, driver, clock).mark_stopped_unexpectedly(row)

    stored = await load(app, org_id, sandbox_id)
    assert settled is True
    assert stored.state is SandboxState.STOPPED
    assert stored.stop_cause == STOP_CAUSE_CONTAINER_EXITED


async def test_a_missing_container_is_an_error_and_stores_no_stop_cause(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    clock: FrozenClock,
) -> None:
    sandbox_id = await create(client, key)
    row = await load(app, org_id, sandbox_id)
    assert row.driver_ref is not None
    driver.kill_instance(row.driver_ref)  # vanishes

    await reconciler_for(app, driver, clock).reconcile_once()

    stored = await load(app, org_id, sandbox_id)
    assert stored.state is SandboxState.ERROR
    assert stored.stop_cause is None


# -- start, repeat stops, reset --------------------------------------------------------------


@pytest.mark.parametrize("how", ["manual", "auto", "exited"])
async def test_a_start_clears_the_cause(
    how: str,
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    clock: FrozenClock,
) -> None:
    sandbox_id = await create(client, key, auto_stop_minutes=1)
    if how == "manual":
        await stop(client, key, sandbox_id)
    elif how == "auto":
        scanner = scanner_for(app, driver, clock)
        clock.advance(2 * MINUTE)
        await scanner.scan_once()
    else:
        await kill_exited(app, driver, org_id, sandbox_id)
        await reconciler_for(app, driver, clock).reconcile_once()
    assert (await load(app, org_id, sandbox_id)).stop_cause is not None

    await start(client, key, sandbox_id)

    stored = await load(app, org_id, sandbox_id)
    assert stored.state is SandboxState.STARTED
    assert stored.stop_cause is None


async def test_a_manual_stop_after_an_auto_stop_intent_leaves_auto_stop(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    clock: FrozenClock,
) -> None:
    sandbox_id = await create(client, key)
    core = Lifecycle(app.state.uow_factory, driver, clock)
    await core.transition(
        org_id,
        sandbox_id,
        SandboxState.STOPPING,
        desired_state=SandboxState.STOPPED,
        audit=AuditNote(None, AUTO_STOPPED),
        stop_cause=STOP_CAUSE_AUTO_STOP,
    )

    await stop(client, key, sandbox_id, status=409)  # stopping -> stopping is not an edge

    assert (await load(app, org_id, sandbox_id)).stop_cause == STOP_CAUSE_AUTO_STOP
    stopped = await core.drive_stop(org_id, sandbox_id)  # the step keeps the intent's cause
    assert stopped.state is SandboxState.STOPPED
    assert (await load(app, org_id, sandbox_id)).stop_cause == STOP_CAUSE_AUTO_STOP


async def test_a_stop_of_a_row_the_reconciler_stopped_keeps_container_exited(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    clock: FrozenClock,
) -> None:
    sandbox_id = await create(client, key)
    await kill_exited(app, driver, org_id, sandbox_id)
    await reconciler_for(app, driver, clock).reconcile_once()
    before = await load(app, org_id, sandbox_id)

    await stop(client, key, sandbox_id)  # already stopped: a no-op

    after = await load(app, org_id, sandbox_id)
    assert after.stop_cause == STOP_CAUSE_CONTAINER_EXITED
    assert after.version == before.version


async def test_a_reset_of_a_stopped_sandbox_keeps_its_cause(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    sandbox_id = await create(client, key)
    await stop(client, key, sandbox_id)

    await send(client, "POST", f"{BASE}/{sandbox_id}/reset", key, status=200)

    stored = await load(app, org_id, sandbox_id)
    assert stored.state is SandboxState.STOPPED
    assert stored.stop_cause == STOP_CAUSE_REQUESTED


# -- audit details ---------------------------------------------------------------------------


async def test_the_audit_details_carry_the_stop_cause(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    clock: FrozenClock,
) -> None:
    manual = await create(client, key, auto_stop_minutes=-1)
    await stop(client, key, manual)
    await create(client, key, auto_stop_minutes=1)
    scanner = scanner_for(app, driver, clock)
    clock.advance(2 * MINUTE)
    await scanner.scan_once()
    exited = await create(client, key, auto_stop_minutes=-1)
    await kill_exited(app, driver, org_id, exited)
    await reconciler_for(app, driver, clock).reconcile_once()

    [requested] = await audit_details(app, org_id, "sandbox.stop")
    [auto] = await audit_details(app, org_id, AUTO_STOPPED)
    [drift] = await audit_details(app, org_id, DRIFT_DETECTED)

    assert requested == {"stop_cause": STOP_CAUSE_REQUESTED}
    assert auto["stop_cause"] == STOP_CAUSE_AUTO_STOP
    assert auto["auto_stop_minutes"] == 1
    assert drift["stop_cause"] == STOP_CAUSE_CONTAINER_EXITED
    assert drift["stopped_unexpectedly"] is True


# -- domain helpers --------------------------------------------------------------------------


def sandbox_in(state: SandboxState, **extra: Any) -> Sandbox:
    return Sandbox(
        id="sbx_x",
        org_id="org_x",
        name="x",
        state=state,
        image_ref="alpine",
        driver="fake",
        created_at=NOW,
        updated_at=NOW,
        **extra,
    )


def test_the_causes_are_the_five_documented_values() -> None:
    assert STOP_CAUSES == (
        "requested",
        "auto_stop",
        "container_exited",
        "oom_killed",
        "unknown",
    )
    assert STOP_CAUSE_OOM_KILLED == "oom_killed"
    assert STOP_CAUSE_UNKNOWN == "unknown"


@pytest.mark.parametrize("state", [SandboxState.STOPPING, SandboxState.STOPPED])
def test_a_stopping_or_stopped_row_shows_its_cause_or_unknown(state: SandboxState) -> None:
    assert visible_stop_cause(sandbox_in(state, stop_cause=STOP_CAUSE_AUTO_STOP)) == "auto_stop"
    assert visible_stop_cause(sandbox_in(state)) == STOP_CAUSE_UNKNOWN


@pytest.mark.parametrize(
    "state",
    [s for s in SandboxState if s not in (SandboxState.STOPPING, SandboxState.STOPPED)],
)
def test_every_other_state_shows_no_cause(state: SandboxState) -> None:
    assert visible_stop_cause(sandbox_in(state)) is None
    assert visible_stop_cause(sandbox_in(state, stop_cause=STOP_CAUSE_REQUESTED)) is None


def test_stopped_at_is_visible_only_when_stopped() -> None:
    for state in SandboxState:
        shown = visible_stopped_at(sandbox_in(state, stopped_at=NOW))
        assert shown == (NOW if state is SandboxState.STOPPED else None)
    assert visible_stopped_at(sandbox_in(SandboxState.STOPPED)) is None


# -- migration -------------------------------------------------------------------------------


def column_names(db_path: Path) -> set[str]:
    with closing(sqlite3.connect(db_path)) as connection:
        rows = connection.execute("PRAGMA table_info(sandboxes)").fetchall()
    return {row[1] for row in rows}


def test_the_migration_adds_and_drops_the_column(tmp_path: Path) -> None:
    pytest.importorskip("aiosqlite")
    db_path = tmp_path / "migrate.db"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")

    command.upgrade(config, "0019")
    assert "stop_cause" not in column_names(db_path)
    command.upgrade(config, "0020")
    assert "stop_cause" in column_names(db_path)
    command.downgrade(config, "0019")
    assert "stop_cause" not in column_names(db_path)
    assert {"error_code", "snapshot"} <= column_names(db_path)
