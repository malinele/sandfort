"""A failed sandbox carries a machine-readable ``error_code`` next to ``error_reason``.

FakeDriver, temp SQLite migrated to head, httpx over ASGI. Driver failures are staged by
replacing one driver method; drift by killing a fake container behind the platform's back.
The code comes from the exception type or the drift kind, never from the message text.
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
from sandfort_sdk._create_cleanup import is_ready  # noqa: E402
from sandfort_sdk.exceptions import SandboxFailedError  # noqa: E402
from sandfort_sdk.models import SandboxInfo  # noqa: E402

from sandfort.api.schemas.sandboxes import SandboxResponse, sandbox_response  # noqa: E402
from sandfort.clock import FrozenClock  # noqa: E402
from sandfort.db.unit_of_work import UnitOfWork  # noqa: E402
from sandfort.domain.events import EventType  # noqa: E402
from sandfort.domain.org import Scope  # noqa: E402
from sandfort.domain.sandbox import (  # noqa: E402
    ERROR_CODES,
    ERROR_CONTAINER_EXITED,
    ERROR_CONTAINER_MISSING,
    ERROR_IMAGE_NOT_FOUND,
    ERROR_INTERNAL,
    ERROR_RESET_FAILED,
    ERROR_START_FAILED,
    ERROR_TIMEOUT,
    Sandbox,
    SandboxState,
)
from sandfort.drivers.base import InstanceInfo, InstanceState, SandboxSpec  # noqa: E402
from sandfort.drivers.errors import (  # noqa: E402
    DriverConflict,
    DriverError,
    DriverNotFound,
    DriverTimeout,
)
from sandfort.drivers.fake import FakeDriver  # noqa: E402
from sandfort.services.events import OutboxEventPublisher, with_sandbox_events  # noqa: E402
from sandfort.services.sandbox_jobs import driver_error_code  # noqa: E402
from sandfort.workers.reconciler import RESET_SETTLE_S, Reconciler  # noqa: E402
from test_api_sandboxes import BASE, add_org, migrated_app, seed_key, send  # noqa: E402

MISSING_IMAGE = "registry.example/ghost:1"
SETTLED = timedelta(seconds=RESET_SETTLE_S * 2)
READ_WRITE = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})


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
    return await add_org(app, "errcode")


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id, READ_WRITE)


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock(datetime.now(UTC))


async def create(client: httpx.AsyncClient, key: str, **payload: Any) -> dict[str, Any]:
    body = await send(client, "POST", BASE, key, status=201, json=payload)
    data: dict[str, Any] = body["data"]
    return data


async def fetch(client: httpx.AsyncClient, key: str, sandbox_id: str) -> dict[str, Any]:
    body = await send(client, "GET", f"{BASE}/{sandbox_id}", key, status=200)
    data: dict[str, Any] = body["data"]
    return data


async def load(app: FastAPI, org_id: str, sandbox_id: str) -> Sandbox:
    async with UnitOfWork(app.state.session_factory) as uow:
        found = await uow.sandboxes.get(org_id, sandbox_id)
    assert found is not None
    return found


def fail_create(driver: FakeDriver, monkeypatch: pytest.MonkeyPatch, exc: DriverError) -> None:
    async def failing_create(spec: SandboxSpec) -> InstanceInfo:
        raise exc

    monkeypatch.setattr(driver, "create", failing_create)


# -- job failure recording -------------------------------------------------------------------


async def test_an_unknown_image_gives_image_not_found_and_keeps_the_reason(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def missing_image(spec: SandboxSpec) -> InstanceInfo:
        raise DriverNotFound(f"no such image or snapshot: {spec.image}", ref=spec.image)

    monkeypatch.setattr(driver, "create", missing_image)

    created = await create(client, key, snapshot=MISSING_IMAGE)

    assert created["state"] == "error"
    assert created["error_reason"] == f"no such image or snapshot: {MISSING_IMAGE}"
    assert created["error_code"] == ERROR_IMAGE_NOT_FOUND
    stored = await load(app, org_id, created["id"])
    assert stored.error_code == ERROR_IMAGE_NOT_FOUND
    assert (await fetch(client, key, created["id"]))["error_code"] == ERROR_IMAGE_NOT_FOUND


async def test_a_not_found_on_another_object_is_start_failed_not_image_not_found(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, monkeypatch: pytest.MonkeyPatch
) -> None:
    fail_create(driver, monkeypatch, DriverNotFound("volume 'v' does not exist", ref="v"))

    created = await create(client, key)

    assert created["state"] == "error"
    assert created["error_code"] == ERROR_START_FAILED


async def test_a_driver_timeout_gives_timeout(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, monkeypatch: pytest.MonkeyPatch
) -> None:
    fail_create(driver, monkeypatch, DriverTimeout("create timed out after 30s"))

    created = await create(client, key)

    assert created["state"] == "error"
    assert created["error_reason"] == "create timed out after 30s"
    assert created["error_code"] == ERROR_TIMEOUT


async def test_any_other_create_error_gives_start_failed(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, monkeypatch: pytest.MonkeyPatch
) -> None:
    fail_create(driver, monkeypatch, DriverError("no capacity left on the node"))

    created = await create(client, key)

    assert created["error_reason"] == "no capacity left on the node"
    assert created["error_code"] == ERROR_START_FAILED


async def test_a_stop_failure_falls_back_to_internal(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, monkeypatch: pytest.MonkeyPatch
) -> None:
    sandbox_id = (await create(client, key))["id"]

    async def refuse(ref: str, *, timeout_s: float = 10.0) -> None:
        raise DriverConflict("daemon refused", ref=ref)

    monkeypatch.setattr(driver, "stop", refuse)
    failed = await send(client, "POST", f"{BASE}/{sandbox_id}/stop", key, status=200)

    assert failed["data"]["state"] == "error"
    assert failed["data"]["error_reason"] == "daemon refused"
    assert failed["data"]["error_code"] == ERROR_INTERNAL


def test_the_code_comes_from_the_type_never_the_message() -> None:
    worded_like_an_image = DriverError("no such image or snapshot: x", ref="x")
    timeout = DriverTimeout("no such image or snapshot: x", ref="x")

    code = driver_error_code(worded_like_an_image, fallback=ERROR_START_FAILED, image="x")
    assert code == ERROR_START_FAILED
    assert driver_error_code(timeout, fallback=ERROR_START_FAILED, image="x") == ERROR_TIMEOUT
    assert {ERROR_IMAGE_NOT_FOUND, ERROR_TIMEOUT, ERROR_INTERNAL} <= set(ERROR_CODES)


# -- reset -----------------------------------------------------------------------------------


async def test_a_reset_failure_gives_reset_failed(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox_id = (await create(client, key))["id"]
    fail_create(driver, monkeypatch, DriverError("no capacity left on the node"))

    await send(client, "POST", f"{BASE}/{sandbox_id}/reset", key, status=502)

    stored = await load(app, org_id, sandbox_id)
    assert stored.state is SandboxState.ERROR
    assert stored.error_reason == "no capacity left on the node"
    assert stored.error_code == ERROR_RESET_FAILED


# -- reconciler drift ------------------------------------------------------------------------


def reconciler_for(app: FastAPI, driver: FakeDriver, clock: FrozenClock) -> Reconciler:
    evented = with_sandbox_events(app.state.uow_factory, OutboxEventPublisher(clock))
    return Reconciler(evented, driver, clock, interval_s=1, grace_s=300)


async def started(app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str) -> Sandbox:
    sandbox = await load(app, org_id, (await create(client, key))["id"])
    assert sandbox.state is SandboxState.STARTED
    assert sandbox.driver_ref is not None
    return sandbox


async def test_a_missing_container_gives_container_missing(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    clock: FrozenClock,
) -> None:
    sandbox = await started(app, client, key, org_id)
    assert sandbox.driver_ref is not None
    driver.kill_instance(sandbox.driver_ref)
    clock.advance(SETTLED)

    report = await reconciler_for(app, driver, clock).reconcile_once()

    stored = await load(app, org_id, sandbox.id)
    assert report.drifted == (sandbox.id,)
    assert stored.state is SandboxState.ERROR
    assert stored.error_code == ERROR_CONTAINER_MISSING
    assert (await fetch(client, key, sandbox.id))["error_code"] == ERROR_CONTAINER_MISSING


async def test_a_never_started_container_gives_container_missing(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    clock: FrozenClock,
) -> None:
    sandbox = await started(app, client, key, org_id)
    assert sandbox.driver_ref is not None
    driver.kill_instance(sandbox.driver_ref)
    driver.plant_instance(sandbox.id, org_id, state=InstanceState.CREATED)
    clock.advance(SETTLED)

    await reconciler_for(app, driver, clock).reconcile_once()

    stored = await load(app, org_id, sandbox.id)
    assert stored.state is SandboxState.ERROR
    assert stored.error_reason == "container is created"  # the never-started drift kind
    assert stored.error_code == ERROR_CONTAINER_MISSING


async def test_an_exited_container_gives_container_exited_and_a_restart_clears_both(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    clock: FrozenClock,
) -> None:
    sandbox = await started(app, client, key, org_id)
    assert sandbox.driver_ref is not None
    driver.kill_instance(sandbox.driver_ref, vanish=False)

    await reconciler_for(app, driver, clock).reconcile_once()

    stored = await load(app, org_id, sandbox.id)
    assert stored.state is SandboxState.STOPPED
    assert stored.error_reason is not None
    assert stored.error_code == ERROR_CONTAINER_EXITED
    async with UnitOfWork(app.state.session_factory) as uow:
        events = await uow.events.list_undispatched(limit=50)
    [stopped] = [item for item in events if item.event_type == EventType.SANDBOX_STOPPED.value]
    assert stopped.payload["reason"] == stored.error_reason
    assert stopped.payload["error_code"] == ERROR_CONTAINER_EXITED

    restarted = await send(client, "POST", f"{BASE}/{sandbox.id}/start", key, status=200)

    assert restarted["data"]["state"] == "started"
    assert restarted["data"]["error_reason"] is None
    assert restarted["data"]["error_code"] is None
    after = await load(app, org_id, sandbox.id)
    assert (after.error_reason, after.error_code) == (None, None)


# -- response and SDK ------------------------------------------------------------------------


def test_the_response_carries_the_code_and_documents_the_values() -> None:
    now = datetime.now(UTC)
    sandbox = Sandbox(
        id="sbx_x",
        org_id="org_x",
        name="x",
        state=SandboxState.ERROR,
        image_ref="alpine:3.20",
        driver="fake",
        error_reason="create timed out",
        error_code=ERROR_TIMEOUT,
        created_at=now,
        updated_at=now,
    )

    assert sandbox_response(sandbox).error_code == ERROR_TIMEOUT
    description = SandboxResponse.model_fields["error_code"].description or ""
    assert all(code in description for code in ERROR_CODES)


def sdk_payload(**extra: Any) -> dict[str, Any]:
    return {"id": "sbx_x", "name": "x", "state": "error", **extra}


def test_the_sdk_model_parses_the_code_and_tolerates_older_servers() -> None:
    info = SandboxInfo.from_payload(
        sdk_payload(error_reason="no such image or snapshot: x", error_code="image_not_found")
    )

    assert info.error_code == "image_not_found"
    assert SandboxInfo.from_payload(sdk_payload()).error_code is None


def test_sandbox_failed_error_carries_the_code() -> None:
    info = SandboxInfo.from_payload(sdk_payload(error_reason="timed out", error_code="timeout"))

    with pytest.raises(SandboxFailedError) as caught:
        is_ready(info)

    assert caught.value.error_code == "timeout"
    assert caught.value.error_reason == "timed out"
    assert caught.value.as_deleted().error_code == "timeout"


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

    command.upgrade(config, "0017")
    assert "error_code" not in column_names(db_path)
    command.upgrade(config, "0018")
    assert "error_code" in column_names(db_path)
    command.downgrade(config, "0017")
    assert "error_code" not in column_names(db_path)
    assert {"error_reason", "snapshot"} <= column_names(db_path)
