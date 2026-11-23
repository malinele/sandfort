"""A failed sandbox create or start leaves a ``sandbox.failed`` audit row (round 36).

FakeDriver, temp SQLite migrated to head, httpx over ASGI. The row carries outcome ``error``
and ``{phase, error_code, error_reason}``; it is written in the unit of work that moves the
sandbox to ``error``, so both land or neither does.
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import ActorType, AuditEvent, AuditOutcome
from sandfort.domain.org import Scope
from sandfort.domain.sandbox import ERROR_IMAGE_NOT_FOUND, ERROR_START_FAILED, Sandbox, SandboxState
from sandfort.drivers.base import InstanceInfo, SandboxSpec
from sandfort.drivers.errors import DriverError, DriverNotFound
from sandfort.drivers.fake import FakeDriver
from sandfort.services.audit import AuditRecorder
from sandfort.services.sandbox_jobs import SANDBOX_FAILED
from sandfort.services.sandboxes import CreateSandboxCommand, SandboxService
from sandfort.workers.jobs import JobWakeup
from sandfort.workers.reconciler import DRIFT_DETECTED, Reconciler
from sandfort.workers.runner import JobRunner
from test_api_sandboxes import BASE, PEPPER, add_org, migrated_app, seed_key, send
from test_reconciler import GRACE, SETTLED

MISSING_IMAGE = "registry.example/ghost:1"
WORKER_ACTOR = "key_workerpath"
READ_WRITE = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    async with migrated_app(tmp_path) as application:
        yield application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.fixture
def driver(app: FastAPI) -> FakeDriver:
    fake = app.state.driver
    assert isinstance(fake, FakeDriver)
    return fake


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    return await add_org(app, "failedaudit")


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id, READ_WRITE)


def stage_missing_image(driver: FakeDriver, monkeypatch: pytest.MonkeyPatch) -> None:
    async def missing_image(spec: SandboxSpec) -> InstanceInfo:
        raise DriverNotFound(f"no such image or snapshot: {spec.image}", ref=spec.image)

    monkeypatch.setattr(driver, "create", missing_image)


async def audit_rows(
    app: FastAPI, org_id: str, *, outcome: AuditOutcome | None = None
) -> list[AuditEvent]:
    """The org's audit rows through the repository the audit list endpoint reads."""
    async with UnitOfWork(app.state.session_factory) as uow:
        rows = await uow.audit.list(org_id, outcome=outcome, limit=100)
    return list(rows)


async def load(app: FastAPI, org_id: str, sandbox_id: str) -> Sandbox:
    async with UnitOfWork(app.state.session_factory) as uow:
        found = await uow.sandboxes.get(org_id, sandbox_id)
    assert found is not None
    return found


async def test_a_create_failing_with_image_not_found_leaves_an_error_audit_row(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stage_missing_image(driver, monkeypatch)

    body = await send(client, "POST", BASE, key, status=201, json={"snapshot": MISSING_IMAGE})

    sandbox_id = body["data"]["id"]
    failed = await audit_rows(app, org_id, outcome=AuditOutcome.ERROR)
    assert [r.action for r in failed] == [SANDBOX_FAILED]
    row = failed[0]
    stored = await load(app, org_id, sandbox_id)
    assert stored.state is SandboxState.ERROR
    assert row.outcome is AuditOutcome.ERROR
    assert row.target_type == "sandbox"
    assert row.target_id == sandbox_id
    created = [r for r in await audit_rows(app, org_id) if r.action == "sandbox.create"]
    assert created[0].actor_id is not None
    assert row.actor_type is ActorType.API_KEY  # the inline drive finds the requester
    assert row.actor_id == created[0].actor_id
    assert row.details["phase"] == "create"
    assert row.details["error_code"] == ERROR_IMAGE_NOT_FOUND
    assert row.details["error_reason"] == stored.error_reason


async def test_a_failed_start_leaves_a_start_phase_row(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = await send(client, "POST", BASE, key, status=201, json={"snapshot": "alpine:3.20"})
    sandbox_id = body["data"]["id"]
    await send(client, "POST", f"{BASE}/{sandbox_id}/stop", key, status=200)

    async def failing_start(ref: str) -> None:
        raise DriverError("the container could not be started")

    monkeypatch.setattr(driver, "start", failing_start)
    await send(client, "POST", f"{BASE}/{sandbox_id}/start", key, status=200)

    failed = await audit_rows(app, org_id, outcome=AuditOutcome.ERROR)
    assert [r.action for r in failed] == [SANDBOX_FAILED]
    assert failed[0].details["phase"] == "start"
    assert failed[0].details["error_code"] == ERROR_START_FAILED
    assert (await load(app, org_id, sandbox_id)).state is SandboxState.ERROR


async def test_a_successful_create_writes_no_failed_row(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    await send(client, "POST", BASE, key, status=201, json={"snapshot": "alpine:3.20"})

    rows = await audit_rows(app, org_id)
    assert rows
    assert SANDBOX_FAILED not in [r.action for r in rows]
    assert await audit_rows(app, org_id, outcome=AuditOutcome.ERROR) == []


async def test_a_failing_audit_write_leaves_neither_the_error_state_nor_the_row(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stage_missing_image(driver, monkeypatch)
    original = AuditRecorder.record

    async def record(self: AuditRecorder, uow: Any, **kwargs: Any) -> AuditEvent:
        if kwargs["action"] == SANDBOX_FAILED:
            raise RuntimeError("audit store unavailable")
        return await original(self, uow, **kwargs)

    monkeypatch.setattr(AuditRecorder, "record", record)

    response = await client.post(
        BASE, headers={"Authorization": f"Bearer {key}"}, json={"snapshot": MISSING_IMAGE}
    )

    assert response.status_code == 500
    rows = await audit_rows(app, org_id)
    assert SANDBOX_FAILED not in [r.action for r in rows]
    created = [r for r in rows if r.action == "sandbox.create"]
    assert len(created) == 1
    assert created[0].target_id is not None
    stored = await load(app, org_id, created[0].target_id)
    assert stored.state is SandboxState.CREATING  # not error: the move rolled back with the row


async def test_a_create_failing_on_the_worker_path_records_the_job_actor(
    app: FastAPI,
    org_id: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = FrozenClock(datetime.now(UTC))
    uow_factory: Any = app.state.uow_factory
    settings = Settings(driver="fake", api_key_pepper=PEPPER)
    service = SandboxService(uow_factory, driver, settings, clock, use_jobs=True)
    stage_missing_image(driver, monkeypatch)
    command = CreateSandboxCommand(snapshot=MISSING_IMAGE)
    queued = await service.create(org_id, WORKER_ACTOR, command)
    assert queued.state is SandboxState.PENDING  # nothing ran yet: the job is only queued

    runner = JobRunner(uow_factory, driver, clock, wakeup=JobWakeup())
    assert await runner.run_once() is True

    failed = await audit_rows(app, org_id, outcome=AuditOutcome.ERROR)
    assert [r.action for r in failed] == [SANDBOX_FAILED]
    assert failed[0].target_id == queued.id
    assert failed[0].actor_type is ActorType.API_KEY
    assert failed[0].actor_id == WORKER_ACTOR
    assert (await load(app, org_id, queued.id)).state is SandboxState.ERROR


async def test_a_failed_start_row_names_the_key_that_asked_for_the_start(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = await send(client, "POST", BASE, key, status=201, json={"snapshot": "alpine:3.20"})
    sandbox_id = body["data"]["id"]
    await send(client, "POST", f"{BASE}/{sandbox_id}/stop", key, status=200)

    async def failing_start(ref: str) -> None:
        raise DriverError("the container could not be started")

    monkeypatch.setattr(driver, "start", failing_start)
    await send(client, "POST", f"{BASE}/{sandbox_id}/start", key, status=200)

    [started] = [r for r in await audit_rows(app, org_id) if r.action == "sandbox.start"]
    [failed] = await audit_rows(app, org_id, outcome=AuditOutcome.ERROR)
    assert started.actor_id is not None
    assert failed.actor_type is ActorType.API_KEY
    assert failed.actor_id == started.actor_id


async def test_the_reconciler_drift_row_has_outcome_error_and_the_filter_finds_it(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
) -> None:
    body = await send(client, "POST", BASE, key, status=201, json={"snapshot": "alpine:3.20"})
    sandbox = await load(app, org_id, body["data"]["id"])
    assert sandbox.driver_ref is not None
    driver.kill_instance(sandbox.driver_ref, vanish=False)  # the container exited under it
    clock = FrozenClock(datetime.now(UTC))
    clock.advance(SETTLED)
    uow_factory: Any = app.state.uow_factory
    reconciler = Reconciler(uow_factory, driver, clock, interval_s=1, grace_s=GRACE.seconds)

    report = await reconciler.reconcile_once()

    assert report.drifted == (sandbox.id,)
    [drift] = [r for r in await audit_rows(app, org_id) if r.action == DRIFT_DETECTED]
    assert drift.outcome is AuditOutcome.ERROR
    assert drift.actor_type is ActorType.SYSTEM
    assert [r.id for r in await audit_rows(app, org_id, outcome=AuditOutcome.ERROR)] == [drift.id]
    reader = await seed_key(app, org_id, frozenset({Scope.AUDIT_READ}))
    listed = await send(
        client, "GET", "/v1/audit-events", reader, status=200, params={"outcome": "error"}
    )
    assert [e["action"] for e in listed["data"]] == [DRIFT_DETECTED]
