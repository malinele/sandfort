"""Resets inside the settle window: deferral holds for any recent reset, and an exec cut short
by a reset says so before the row points at the new container.

* The reconciler reads every ``sandbox.reset`` event of the window, not only the last one. With
  7 resets in the window, the event naming the row's container is the newest, and the ones read
  before it name older containers.
* A reset updates ``driver_ref`` only after creating the new container, so an exec it kills ends
  while the row still has the old ref. The route finds the reset in the audit log.
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
from sandfort.api.routes.toolbox import process as process_routes
from sandfort.api.schemas.toolbox_process import (
    STOP_REASON_SANDBOX_RESET,
    STOP_REASON_SANDBOX_STOPPED,
)
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import ActorType
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.drivers.base import ExecRequest, ExecResult
from sandfort.drivers.docker.exec import SANDBOX_DIED_MESSAGE
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.audit import AuditRecorder
from sandfort.services.sandbox_reset import SANDBOX_RESET
from sandfort.workers.reconciler import RESET_SETTLE_S, Reconciler

ROOT = Path(__file__).resolve().parents[1]
CREATED_AT = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
GRACE_S = 300
RESETS = 7  # more than the 5 events the reconciler used to read
RESET_LINE = "the sandbox was reset while running this command"
OOM_TEXT = "a resource limit was hit"
ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'race.db'}"
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
    application.include_router(process_routes.router)
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


async def started_sandbox(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> Sandbox:
    created = await client.post(SANDBOXES, headers={"Authorization": f"Bearer {key}"}, json={})
    assert created.status_code == 201, created.text
    async with UnitOfWork(app.state.session_factory) as uow:
        found = await uow.sandboxes.get(org_id, created.json()["data"]["id"])
    assert found is not None
    assert found.state is SandboxState.STARTED and found.driver_ref is not None
    return found


async def record_reset(
    app: FastAPI, at: datetime, org_id: str, sandbox_id: str, previous: str
) -> None:
    """Write a ``sandbox.reset`` event stamped ``at`` whose container ref is ``previous``."""
    recorder = AuditRecorder(FrozenClock(at))
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


async def record_resets(
    app: FastAPI, clock: FrozenClock, org_id: str, sandbox_id: str, previous: list[str]
) -> None:
    """Write one event per ref, oldest first, all inside the settle window."""
    for index, ref in enumerate(previous):
        at = clock.now() - timedelta(seconds=len(previous) - index)
        await record_reset(app, at, org_id, sandbox_id, ref)


async def state_of(app: FastAPI, org_id: str, sandbox_id: str) -> SandboxState:
    async with UnitOfWork(app.state.session_factory) as uow:
        row = await uow.sandboxes.get(org_id, sandbox_id)
    assert row is not None
    return row.state


def older_refs() -> list[str]:
    return [f"fake-older-container-{index}" for index in range(RESETS - 1)]


# -- reconciler: every event in the window counts ----------------------------------------------


async def test_row_on_the_container_the_newest_of_seven_resets_removes_is_deferred(
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
    refs = [*older_refs(), sandbox.driver_ref]  # the newest reset removes the row's container
    await record_resets(app, clock, org_id, sandbox.id, refs)
    driver.kill_instance(sandbox.driver_ref, vanish=False)

    report = await reconciler.reconcile_once()
    marked = await reconciler.mark_stopped_unexpectedly(sandbox)

    assert report.drifted == () and report.errors == 0
    assert marked is False
    assert await state_of(app, org_id, sandbox.id) is SandboxState.STARTED


async def test_row_on_the_new_container_is_settled_after_seven_resets(
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
    refs = [*older_refs(), "fake-container-the-last-reset-removed"]  # none is the row's ref
    await record_resets(app, clock, org_id, sandbox.id, refs)
    driver.kill_instance(sandbox.driver_ref, vanish=False)

    report = await reconciler.reconcile_once()

    assert report.drifted == (sandbox.id,)
    assert await state_of(app, org_id, sandbox.id) is SandboxState.STOPPED


async def test_mark_stopped_unexpectedly_settles_the_new_container_after_seven_resets(
    app: FastAPI,
    client: httpx.AsyncClient,
    clock: FrozenClock,
    reconciler: Reconciler,
    org_id: str,
    key: str,
) -> None:
    sandbox = await started_sandbox(app, client, org_id, key)
    refs = [*older_refs(), "fake-container-the-last-reset-removed"]
    await record_resets(app, clock, org_id, sandbox.id, refs)

    marked = await reconciler.mark_stopped_unexpectedly(sandbox)

    assert marked is True
    assert await state_of(app, org_id, sandbox.id) is SandboxState.STOPPED


# -- route: an exec cut short by a reset, the row not yet on the new container ------------------


def die_while_row_is_unchanged(driver: FakeDriver, monkeypatch: pytest.MonkeyPatch) -> None:
    """The user's command dies as the Docker driver reports, the row left untouched."""
    original = driver.exec

    async def exec_(ref: str, request: ExecRequest) -> ExecResult:
        if request.argv[-1] != "stress":
            return await original(ref, request)
        return ExecResult(
            exit_code=137, stdout=b"partial", stderr=SANDBOX_DIED_MESSAGE, sandbox_stopped=True
        )

    monkeypatch.setattr(driver, "exec", exec_)


async def execute_stress(client: httpx.AsyncClient, key: str, sandbox_id: str) -> dict[str, Any]:
    response = await client.post(
        f"{SANDBOXES}/{sandbox_id}/toolbox/process/execute",
        headers={"Authorization": f"Bearer {key}"},
        json={"command": "stress"},
    )
    assert response.status_code == 200, response.text
    data: dict[str, Any] = response.json()["data"]
    assert (data["exit_code"], data["sandbox_stopped"]) == (137, True)
    return data


async def test_exec_killed_by_a_reset_before_the_row_moves_reports_sandbox_reset(
    app: FastAPI,
    client: httpx.AsyncClient,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
    org_id: str,
    key: str,
) -> None:
    sandbox = await started_sandbox(app, client, org_id, key)
    assert sandbox.driver_ref is not None
    await record_reset(app, datetime.now(UTC), org_id, sandbox.id, sandbox.driver_ref)
    die_while_row_is_unchanged(driver, monkeypatch)

    data = await execute_stress(client, key, sandbox.id)

    assert data["stop_reason"] == STOP_REASON_SANDBOX_RESET
    assert data["stderr"] == RESET_LINE
    assert OOM_TEXT not in data["stderr"]
    assert await state_of(app, org_id, sandbox.id) is SandboxState.STARTED


async def test_a_reset_of_another_container_does_not_explain_the_death(
    app: FastAPI,
    client: httpx.AsyncClient,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
    org_id: str,
    key: str,
) -> None:
    sandbox = await started_sandbox(app, client, org_id, key)
    await record_reset(app, datetime.now(UTC), org_id, sandbox.id, "fake-some-other-container")
    die_while_row_is_unchanged(driver, monkeypatch)

    data = await execute_stress(client, key, sandbox.id)

    assert data["stop_reason"] == STOP_REASON_SANDBOX_STOPPED
    assert data["stderr"] == SANDBOX_DIED_MESSAGE.decode()


async def test_a_reset_older_than_the_settle_window_does_not_explain_the_death(
    app: FastAPI,
    client: httpx.AsyncClient,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
    org_id: str,
    key: str,
) -> None:
    sandbox = await started_sandbox(app, client, org_id, key)
    assert sandbox.driver_ref is not None
    long_ago = datetime.now(UTC) - timedelta(seconds=RESET_SETTLE_S * 3)
    await record_reset(app, long_ago, org_id, sandbox.id, sandbox.driver_ref)
    die_while_row_is_unchanged(driver, monkeypatch)

    data = await execute_stress(client, key, sandbox.id)

    assert data["stop_reason"] == STOP_REASON_SANDBOX_STOPPED
    assert data["stderr"] == SANDBOX_DIED_MESSAGE.decode()
