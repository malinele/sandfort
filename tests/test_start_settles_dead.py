"""``POST /start`` on a ``started`` row whose container already died starts it for real.

After a fork bomb the container is dead while the row still says ``started`` for a few
seconds. The start route inspects the instance once; a dead one has its row marked stopped
through the reconciler (``sandbox.drift_detected``) and the normal start then runs. A live
container stays a no-op, and a failing check leaves the start answering as before.
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import Sandbox
from sandfort.drivers.base import InstanceInfo, InstanceState
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.workers.reconciler import Reconciler

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})
DRIFT_ACTION = "sandbox.drift_detected"
START_ACTION = "sandbox.start"


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'start_dead.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(driver="fake", database_url=url, api_key_pepper=PEPPER)
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
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
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
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


@pytest.fixture
def starts(driver: FakeDriver, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every ``driver.start`` call made after the fixture is set up (the create's included)."""
    seen: list[str] = []
    original = driver.start

    async def start(ref: str) -> None:
        seen.append(ref)
        await original(ref)

    monkeypatch.setattr(driver, "start", start)
    return seen


async def send(
    client: httpx.AsyncClient, method: str, path: str, key: str, **kwargs: Any
) -> dict[str, Any]:
    response = await client.request(
        method, path, headers={"Authorization": f"Bearer {key}"}, **kwargs
    )
    assert response.status_code < 300, response.text
    data: dict[str, Any] = response.json()["data"]
    return data


async def create_started(client: httpx.AsyncClient, key: str) -> dict[str, Any]:
    data = await send(client, "POST", BASE, key, json={})
    assert data["state"] == "started"
    return data


async def actions(app: FastAPI, org_id: str, sandbox_id: str, action: str) -> int:
    async with UnitOfWork(app.state.session_factory) as uow:
        events = await uow.audit.list(org_id, action=action, target_id=sandbox_id)
    return len(events)


async def driver_ref(app: FastAPI, org_id: str, sandbox_id: str) -> str:
    async with UnitOfWork(app.state.session_factory) as uow:
        row = await uow.sandboxes.get(org_id, sandbox_id)
    assert row is not None and row.driver_ref is not None
    return row.driver_ref


async def test_start_on_a_started_row_with_a_dead_container_starts_it_for_real(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    starts: list[str],
) -> None:
    sandbox_id = (await create_started(client, key))["id"]
    ref = await driver_ref(app, org_id, sandbox_id)
    driver.kill_instance(ref, vanish=False)  # the fork bomb took it down; row still started
    starts_before = await actions(app, org_id, sandbox_id, START_ACTION)
    calls_before = len(starts)

    data = await send(client, "POST", f"{BASE}/{sandbox_id}/start", key)

    assert data["state"] == "started"
    assert starts[calls_before:] == [ref]
    assert (await driver.inspect(ref)).state is InstanceState.RUNNING
    assert await actions(app, org_id, sandbox_id, DRIFT_ACTION) == 1
    assert await actions(app, org_id, sandbox_id, START_ACTION) == starts_before + 1


async def test_start_on_a_started_row_with_a_vanished_container_settles_it(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
) -> None:
    sandbox_id = (await create_started(client, key))["id"]
    ref = await driver_ref(app, org_id, sandbox_id)
    driver.kill_instance(ref)  # removed behind the platform's back

    await send(client, "POST", f"{BASE}/{sandbox_id}/start", key)

    assert await actions(app, org_id, sandbox_id, DRIFT_ACTION) == 1


async def test_start_on_a_started_row_with_a_paused_container_leaves_it_started(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    starts: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created = await create_started(client, key)
    sandbox_id = created["id"]
    ref = await driver_ref(app, org_id, sandbox_id)
    await driver.pause(ref)  # a snapshot commit pauses the container
    settled: list[str] = []

    async def spy(self: Reconciler, sandbox: Sandbox) -> bool:
        settled.append(sandbox.id)
        return True

    monkeypatch.setattr(Reconciler, "mark_stopped_unexpectedly", spy)
    calls_before = len(starts)

    data = await send(client, "POST", f"{BASE}/{sandbox_id}/start", key)

    assert data["state"] == "started"
    assert settled == []
    assert starts[calls_before:] == []
    assert await actions(app, org_id, sandbox_id, DRIFT_ACTION) == 0


async def test_start_on_a_started_row_with_a_live_container_stays_a_no_op(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    starts: list[str],
) -> None:
    created = await create_started(client, key)
    sandbox_id = created["id"]
    starts_before = await actions(app, org_id, sandbox_id, START_ACTION)
    calls_before = len(starts)

    data = await send(client, "POST", f"{BASE}/{sandbox_id}/start", key)

    assert data["state"] == "started"
    assert data == created
    assert starts[calls_before:] == []
    assert await actions(app, org_id, sandbox_id, DRIFT_ACTION) == 0
    assert await actions(app, org_id, sandbox_id, START_ACTION) == starts_before


async def test_a_failing_dead_container_check_answers_like_today(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    starts: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox_id = (await create_started(client, key))["id"]

    async def broken_inspect(ref: str) -> InstanceInfo:
        raise RuntimeError("docker daemon unreachable")

    monkeypatch.setattr(driver, "inspect", broken_inspect)
    calls_before = len(starts)

    data = await send(client, "POST", f"{BASE}/{sandbox_id}/start", key)

    assert data["state"] == "started"
    assert starts[calls_before:] == []
    assert await actions(app, org_id, sandbox_id, DRIFT_ACTION) == 0


async def test_start_of_an_unknown_sandbox_still_answers_404(
    client: httpx.AsyncClient, key: str
) -> None:
    response = await client.post(
        f"{BASE}/sbx_missing/start", headers={"Authorization": f"Bearer {key}"}
    )

    assert response.status_code == 404
