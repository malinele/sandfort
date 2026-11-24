"""A sandbox that dies after an exec that returned normally is settled by a short probe.

A background fork bomb lets ``exec`` answer exit 0 and kills the container a moment later. The
row would read ``started`` until the next exec or the 30 s reconciler pass. On the ``gvisor`` and
``microvm`` tiers the exec route now schedules one probe task per sandbox that inspects the
instance after ``PROBE_DELAYS_S`` and settles a dead one through the reconciler.
"""

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api import death_probe
from sandfort.api.app import create_app
from sandfort.api.death_probe import DEATH_PROBES_ATTR, DeathProbes, schedule_death_probe
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.isolation import isolation_labels
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.workers.reconciler import Reconciler

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
DRIFT_ACTION = "sandbox.drift_detected"
TINY_DELAYS_S = (0.05, 0.1, 0.2)
LONG_DELAYS_S = (30.0, 60.0, 90.0)
WAIT_S = 5.0
POLL_S = 0.02
QUIET_S = 0.5  # longer than the last tiny delay: a second settle would have happened by now
PROBED_TIERS = ["gvisor", "microvm"]


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'death_probe.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(driver="fake", database_url=url, api_key_pepper=PEPPER)
    application = create_app(settings)
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture(autouse=True)
async def no_probe_outlives_its_test(app: FastAPI) -> AsyncIterator[None]:
    """Cancel and await every probe task so none is destroyed while pending."""
    yield
    registry = getattr(app.state, DEATH_PROBES_ATTR, None)
    if isinstance(registry, DeathProbes):
        await registry.cancel_all()
    leftovers = [
        task.get_name()
        for task in asyncio.all_tasks()
        if task.get_name().startswith("death-probe-") and not task.done()
    ]
    assert leftovers == []


@pytest.fixture
def tiny_delays(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(death_probe, "PROBE_DELAYS_S", TINY_DELAYS_S)


@pytest.fixture
def long_delays(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(death_probe, "PROBE_DELAYS_S", LONG_DELAYS_S)


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


async def create_started(client: httpx.AsyncClient, key: str) -> str:
    response = await client.post(BASE, headers={"Authorization": f"Bearer {key}"}, json={})
    assert response.status_code < 300, response.text
    data: dict[str, Any] = response.json()["data"]
    assert data["state"] == "started"
    sandbox_id: str = data["id"]
    return sandbox_id


async def set_tier(app: FastAPI, org_id: str, sandbox_id: str, tier: str) -> None:
    async with UnitOfWork(app.state.session_factory) as uow:
        row = await uow.sandboxes.get(org_id, sandbox_id)
        assert row is not None
        changed = row.model_copy(update={"labels": {**row.labels, **isolation_labels(tier)}})
        await uow.sandboxes.update(org_id, changed, expected_version=row.version)
        await uow.commit()


async def tiered_sandbox(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str, tier: str
) -> str:
    sandbox_id = await create_started(client, key)
    await set_tier(app, org_id, sandbox_id, tier)
    return sandbox_id


async def run_exec(client: httpx.AsyncClient, key: str, sandbox_id: str) -> None:
    response = await client.post(
        f"{BASE}/{sandbox_id}/toolbox/process/execute",
        headers={"Authorization": f"Bearer {key}"},
        json={"command": "echo hi"},
    )
    assert response.status_code == 200, response.text


async def row_of(app: FastAPI, org_id: str, sandbox_id: str) -> Sandbox:
    async with UnitOfWork(app.state.session_factory) as uow:
        row = await uow.sandboxes.get(org_id, sandbox_id)
    assert row is not None
    return row


async def drift_rows(app: FastAPI, org_id: str, sandbox_id: str) -> int:
    async with UnitOfWork(app.state.session_factory) as uow:
        events = await uow.audit.list(org_id, action=DRIFT_ACTION, target_id=sandbox_id)
    return len(events)


async def driver_ref(app: FastAPI, org_id: str, sandbox_id: str) -> str:
    row = await row_of(app, org_id, sandbox_id)
    assert row.driver_ref is not None
    return row.driver_ref


def registry_of(app: FastAPI) -> DeathProbes | None:
    registry = getattr(app.state, DEATH_PROBES_ATTR, None)
    return registry if isinstance(registry, DeathProbes) else None


def pending_probes(app: FastAPI) -> frozenset[str]:
    registry = registry_of(app)
    return frozenset() if registry is None else registry.pending()


async def wait_until(check: Callable[[], Awaitable[bool]]) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + WAIT_S
    while not await check():
        assert loop.time() < deadline, "the condition was not reached in time"
        await asyncio.sleep(POLL_S)


@pytest.mark.usefixtures("tiny_delays")
@pytest.mark.parametrize("tier", PROBED_TIERS)
async def test_a_death_after_an_exit_zero_exec_settles_the_row(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    tier: str,
) -> None:
    sandbox_id = await tiered_sandbox(app, client, key, org_id, tier)
    ref = await driver_ref(app, org_id, sandbox_id)

    await run_exec(client, key, sandbox_id)
    driver.kill_instance(ref, vanish=False)  # the background fork bomb took it down

    async def settled() -> bool:
        return (await row_of(app, org_id, sandbox_id)).state is SandboxState.STOPPED

    await wait_until(settled)
    row = await row_of(app, org_id, sandbox_id)
    assert row.stop_cause == "container_exited"
    await asyncio.sleep(QUIET_S)
    assert await drift_rows(app, org_id, sandbox_id) == 1
    assert pending_probes(app) == frozenset()


@pytest.mark.usefixtures("tiny_delays")
async def test_a_live_container_stays_started_and_the_probe_ends(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    sandbox_id = await tiered_sandbox(app, client, key, org_id, "gvisor")

    await run_exec(client, key, sandbox_id)
    assert pending_probes(app) == frozenset({sandbox_id})

    async def ended() -> bool:
        return pending_probes(app) == frozenset()

    await wait_until(ended)
    row = await row_of(app, org_id, sandbox_id)
    assert row.state is SandboxState.STARTED
    assert await drift_rows(app, org_id, sandbox_id) == 0


@pytest.mark.usefixtures("long_delays")
async def test_the_container_tier_schedules_no_probe(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    sandbox_id = await tiered_sandbox(app, client, key, org_id, "container")

    await run_exec(client, key, sandbox_id)

    assert pending_probes(app) == frozenset()


@pytest.mark.usefixtures("long_delays")
async def test_a_second_exec_extends_the_pending_probe_instead_of_adding_one(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    sandbox_id = await tiered_sandbox(app, client, key, org_id, "microvm")

    await run_exec(client, key, sandbox_id)
    registry = registry_of(app)
    assert registry is not None
    first_task = registry.task_of(sandbox_id)
    first_exec = registry.last_exec_of(sandbox_id)
    await run_exec(client, key, sandbox_id)

    assert registry.pending() == frozenset({sandbox_id})
    assert first_task is not None and registry.task_of(sandbox_id) is first_task
    assert first_exec is not None
    second_exec = registry.last_exec_of(sandbox_id)
    assert second_exec is not None and second_exec > first_exec


@pytest.mark.usefixtures("tiny_delays")
async def test_a_declined_settle_ends_the_probe_quietly(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox_id = await tiered_sandbox(app, client, key, org_id, "gvisor")
    ref = await driver_ref(app, org_id, sandbox_id)
    marked: list[str] = []

    async def declined(self: Reconciler, sandbox: Sandbox) -> bool:
        marked.append(sandbox.id)
        return False

    monkeypatch.setattr(Reconciler, "mark_stopped_unexpectedly", declined)

    await run_exec(client, key, sandbox_id)
    driver.kill_instance(ref, vanish=False)

    async def ended() -> bool:
        return pending_probes(app) == frozenset()

    await wait_until(ended)
    await asyncio.sleep(QUIET_S)
    assert marked == [sandbox_id]  # asked once, never again
    assert (await row_of(app, org_id, sandbox_id)).state is SandboxState.STARTED
    assert await drift_rows(app, org_id, sandbox_id) == 0


@pytest.mark.usefixtures("tiny_delays")
async def test_a_failing_settle_is_swallowed_and_the_probe_ends(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox_id = await tiered_sandbox(app, client, key, org_id, "gvisor")
    ref = await driver_ref(app, org_id, sandbox_id)

    async def broken(self: Reconciler, sandbox: Sandbox) -> bool:
        raise RuntimeError("database unreachable")

    monkeypatch.setattr(Reconciler, "mark_stopped_unexpectedly", broken)

    await run_exec(client, key, sandbox_id)
    driver.kill_instance(ref, vanish=False)

    async def ended() -> bool:
        return pending_probes(app) == frozenset()

    await wait_until(ended)
    assert (await row_of(app, org_id, sandbox_id)).state is SandboxState.STARTED


@pytest.mark.usefixtures("long_delays")
async def test_cancelling_all_probes_leaves_no_task_behind(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    sandbox_id = await tiered_sandbox(app, client, key, org_id, "gvisor")
    await run_exec(client, key, sandbox_id)
    registry = registry_of(app)
    assert registry is not None
    task = registry.task_of(sandbox_id)
    assert task is not None

    await registry.cancel_all()

    assert task.done()
    assert registry.pending() == frozenset()
    assert registry.task_of(sandbox_id) is None


@pytest.mark.usefixtures("long_delays")
async def test_scheduling_never_raises_for_a_bare_sandbox_or_a_bare_request(
    app: FastAPI, driver: FakeDriver
) -> None:
    bare_sandbox: Any = SimpleNamespace(id="sbx_bare", driver_ref=None)
    gvisor_without_ref: Any = SimpleNamespace(
        id="sbx_noref", driver_ref=None, labels=isolation_labels("gvisor")
    )
    gvisor: Any = SimpleNamespace(
        id="sbx_gv", driver_ref="ref-1", labels=isolation_labels("gvisor")
    )
    real_request: Any = SimpleNamespace(app=app)
    no_state_request: Any = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))
    no_app_request: Any = object()

    schedule_death_probe(real_request, driver, bare_sandbox)
    schedule_death_probe(real_request, driver, gvisor_without_ref)
    schedule_death_probe(no_state_request, driver, gvisor)
    schedule_death_probe(no_app_request, driver, gvisor)
    schedule_death_probe(no_app_request, driver, None)  # type: ignore[arg-type]

    assert pending_probes(app) == frozenset()
    assert not hasattr(no_state_request.app.state, DEATH_PROBES_ATTR)
