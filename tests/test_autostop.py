"""Auto-stop / auto-delete: activity tracker, toolbox touch and the idle scanner.

FakeDriver, temp SQLite and the ASGI client behind the app factory (route tables are never
introspected). The tracker and scanner share one FrozenClock, built after the sandboxes are
created so the rows' real-clock ``last_activity_at`` never lies ahead of it; the tracker is
swapped onto ``app.state`` so the toolbox dependency feeds the same instance the scanner reads.
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
from sandfort.api.wiring import ACTIVITY_TRACKER_ATTR
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.activity import DEBOUNCE_S, ActivityTracker
from sandfort.workers.autostop import AUTO_DELETED, AUTO_STOPPED, AutoStopScanner

ROOT = Path(__file__).resolve().parents[1]
CREATED_AT = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
MINUTE = timedelta(minutes=1)


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'autostop.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(
        driver="fake", database_url=url, api_key_pepper=PEPPER, autostop_enabled=False
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


async def create_sandbox(client: httpx.AsyncClient, key: str, **body: Any) -> str:
    response = await client.post(BASE, headers=auth(key), json=body)
    assert response.status_code == 201, response.text
    sandbox_id: str = response.json()["data"]["id"]
    return sandbox_id


async def load(app: FastAPI, org_id: str, sandbox_id: str) -> Sandbox:
    async with UnitOfWork(app.state.session_factory) as uow:
        found = await uow.sandboxes.get(org_id, sandbox_id)
    assert found is not None
    return found


async def audit_actions(app: FastAPI, org_id: str) -> list[str]:
    async with UnitOfWork(app.state.session_factory) as uow:
        events = await uow.audit.list(org_id, limit=200)
    return [event.action for event in events]


def wire(app: FastAPI, driver: FakeDriver) -> tuple[FrozenClock, AutoStopScanner]:
    """A frozen clock shared by a fresh tracker (installed on the app) and a scanner."""
    clock = FrozenClock(datetime.now(UTC))
    tracker = ActivityTracker(clock)
    setattr(app.state, ACTIVITY_TRACKER_ATTR, tracker)
    scanner = AutoStopScanner(app.state.uow_factory, driver, clock, tracker, interval_s=1)
    return clock, scanner


async def toolbox_call(client: httpx.AsyncClient, key: str, sandbox_id: str) -> httpx.Response:
    return await client.get(f"{BASE}/{sandbox_id}/toolbox/process/sessions", headers=auth(key))


# -- tracker unit tests ----------------------------------------------------------------------


def test_untouched_sandbox_reports_the_construction_baseline() -> None:
    clock = FrozenClock(CREATED_AT)
    tracker = ActivityTracker(clock)

    clock.advance(timedelta(hours=3))

    assert tracker.last_activity("sbx_unknown") == CREATED_AT


def test_touch_is_debounced_within_the_window() -> None:
    clock = FrozenClock(CREATED_AT)
    tracker = ActivityTracker(clock)
    window = timedelta(seconds=DEBOUNCE_S)

    first = tracker.touch("sbx_a")
    clock.advance(window / 2)
    rapid = [tracker.touch("sbx_a") for _ in range(50)]
    unchanged = tracker.last_activity("sbx_a")
    clock.advance(window)
    after_window = tracker.touch("sbx_a")

    assert first is True
    assert rapid == [False] * 50
    assert unchanged == CREATED_AT
    assert after_window is True
    assert tracker.last_activity("sbx_a") == clock.now()


def test_debounce_is_per_sandbox() -> None:
    clock = FrozenClock(CREATED_AT)
    tracker = ActivityTracker(clock)

    tracker.touch("sbx_a")

    assert tracker.touch("sbx_b") is True


# -- scanner ---------------------------------------------------------------------------------


async def test_idle_sandbox_is_stopped_after_auto_stop_minutes(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, org_id: str, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key, auto_stop_minutes=15)
    clock, scanner = wire(app, driver)

    clock.advance(14 * MINUTE)
    await scanner.scan_once()
    still_running = await load(app, org_id, sandbox_id)
    clock.advance(2 * MINUTE)
    await scanner.scan_once()
    stopped = await load(app, org_id, sandbox_id)

    assert still_running.state is SandboxState.STARTED
    assert stopped.state is SandboxState.STOPPED
    assert AUTO_STOPPED in await audit_actions(app, org_id)


async def test_toolbox_call_resets_the_idle_timer(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, org_id: str, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key, auto_stop_minutes=15)
    clock, scanner = wire(app, driver)

    clock.advance(10 * MINUTE)
    response = await toolbox_call(client, key, sandbox_id)
    clock.advance(10 * MINUTE)  # 20 minutes since creation, 10 since the call
    await scanner.scan_once()
    after_call = await load(app, org_id, sandbox_id)
    clock.advance(6 * MINUTE)  # 16 minutes since the call
    await scanner.scan_once()
    after_idle = await load(app, org_id, sandbox_id)

    assert response.status_code == 200, response.text
    assert after_call.state is SandboxState.STARTED
    assert after_idle.state is SandboxState.STOPPED


async def test_unauthenticated_toolbox_call_does_not_reset_the_timer(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, org_id: str, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key, auto_stop_minutes=15)
    clock, scanner = wire(app, driver)

    clock.advance(10 * MINUTE)
    response = await client.get(f"{BASE}/{sandbox_id}/toolbox/process/sessions")
    clock.advance(6 * MINUTE)
    await scanner.scan_once()

    assert response.status_code == 401
    assert (await load(app, org_id, sandbox_id)).state is SandboxState.STOPPED


async def test_disabled_auto_stop_is_never_stopped(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, org_id: str, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key, auto_stop_minutes=-1)
    clock, scanner = wire(app, driver)

    clock.advance(timedelta(days=2))
    await scanner.scan_once()

    assert (await load(app, org_id, sandbox_id)).state is SandboxState.STARTED


async def test_auto_delete_zero_deletes_on_stop_in_the_same_pass(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, org_id: str, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key, auto_stop_minutes=15, auto_delete_minutes=0)
    clock, scanner = wire(app, driver)

    clock.advance(16 * MINUTE)
    await scanner.scan_once()

    assert (await load(app, org_id, sandbox_id)).state is SandboxState.DESTROYED
    actions = await audit_actions(app, org_id)
    assert AUTO_STOPPED in actions
    assert AUTO_DELETED in actions


async def test_manually_stopped_sandbox_with_auto_delete_zero_is_deleted(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, org_id: str, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key, auto_delete_minutes=0)
    stop = await client.post(f"{BASE}/{sandbox_id}/stop", headers=auth(key))
    _, scanner = wire(app, driver)

    await scanner.scan_once()

    assert stop.status_code == 200, stop.text
    assert (await load(app, org_id, sandbox_id)).state is SandboxState.DESTROYED


async def test_auto_delete_unset_keeps_the_stopped_sandbox(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, org_id: str, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key, auto_stop_minutes=15)
    clock, scanner = wire(app, driver)

    clock.advance(16 * MINUTE)
    await scanner.scan_once()

    assert (await load(app, org_id, sandbox_id)).state is SandboxState.STOPPED
    assert AUTO_DELETED not in await audit_actions(app, org_id)


async def stop_manually(client: httpx.AsyncClient, key: str, sandbox_id: str) -> None:
    stop = await client.post(f"{BASE}/{sandbox_id}/stop", headers=auth(key))
    assert stop.status_code == 200, stop.text


async def test_positive_auto_delete_deletes_once_stopped_long_enough(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, org_id: str, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key, auto_delete_minutes=3)
    await stop_manually(client, key, sandbox_id)
    clock, scanner = wire(app, driver)

    clock.advance(4 * MINUTE)
    await scanner.scan_once()

    assert (await load(app, org_id, sandbox_id)).state is SandboxState.DESTROYED
    assert AUTO_DELETED in await audit_actions(app, org_id)


async def test_positive_auto_delete_keeps_a_recently_stopped_sandbox(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, org_id: str, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key, auto_delete_minutes=10)
    await stop_manually(client, key, sandbox_id)
    clock, scanner = wire(app, driver)

    clock.advance(5 * MINUTE)
    await scanner.scan_once()

    assert (await load(app, org_id, sandbox_id)).state is SandboxState.STOPPED
    assert AUTO_DELETED not in await audit_actions(app, org_id)


async def test_negative_auto_delete_never_deletes_a_stopped_sandbox(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, org_id: str, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key, auto_delete_minutes=-1)
    await stop_manually(client, key, sandbox_id)
    clock, scanner = wire(app, driver)

    clock.advance(24 * 60 * MINUTE)
    await scanner.scan_once()

    assert (await load(app, org_id, sandbox_id)).state is SandboxState.STOPPED
    assert AUTO_DELETED not in await audit_actions(app, org_id)


async def test_positive_auto_delete_skips_a_stopped_sandbox_without_stopped_at(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, org_id: str, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key, auto_delete_minutes=3)
    await stop_manually(client, key, sandbox_id)
    stopped = await load(app, org_id, sandbox_id)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.sandboxes.update(
            org_id,
            stopped.model_copy(update={"stopped_at": None}),
            expected_version=stopped.version,
        )
        await uow.commit()
    clock, scanner = wire(app, driver)

    clock.advance(60 * MINUTE)
    await scanner.scan_once()

    assert (await load(app, org_id, sandbox_id)).state is SandboxState.STOPPED
    assert AUTO_DELETED not in await audit_actions(app, org_id)


async def test_driver_failure_on_one_sandbox_does_not_block_the_next(
    app: FastAPI,
    client: httpx.AsyncClient,
    driver: FakeDriver,
    org_id: str,
    key: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = await create_sandbox(client, key, auto_stop_minutes=15)
    second = await create_sandbox(client, key, auto_stop_minutes=15)
    clock, scanner = wire(app, driver)
    poisoned = (await load(app, org_id, first)).driver_ref
    real_stop = driver.stop

    async def flaky_stop(ref: str, *, timeout_s: float = 10.0) -> None:
        if ref == poisoned:
            raise RuntimeError("daemon went away")
        await real_stop(ref, timeout_s=timeout_s)

    monkeypatch.setattr(driver, "stop", flaky_stop)

    clock.advance(16 * MINUTE)
    await scanner.scan_once()

    assert (await load(app, org_id, second)).state is SandboxState.STOPPED
    assert (await load(app, org_id, first)).state is not SandboxState.STOPPED


async def test_scanner_loop_starts_and_stops_cleanly(app: FastAPI, driver: FakeDriver) -> None:
    _, scanner = wire(app, driver)

    scanner.start()
    assert scanner.running
    await scanner.stop()

    assert not scanner.running
