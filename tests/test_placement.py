"""Placement and node affinity: pick_node, job leasing per node, node-scoped worker queries."""

from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.models.jobs import JobRow
from sandfort.db.models.sandboxes import SandboxRow
from sandfort.db.repositories.ports import JobRecord, UnitOfWorkPort
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.node import Node, NodeState
from sandfort.domain.org import Org
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import JOB, new_id, new_org_id, new_sandbox_id
from sandfort.services.node_registry import HEARTBEAT_STALE_AFTER, pick_node
from sandfort.services.sandboxes import CreateSandboxCommand, SandboxService
from sandfort.workers.handlers import HandlerRegistry, JobContext
from sandfort.workers.runner import JobRunner

ROOT = Path(__file__).resolve().parents[1]
START = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
ACTOR = "key_test"
KIND = "placement.test"
LOCAL = "node-local"

Factory = async_sessionmaker[AsyncSession]


@pytest.fixture
async def factory(tmp_path: Path) -> AsyncIterator[Factory]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'placement.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    engine = create_engine(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))
    try:
        yield create_session_factory(engine)
    finally:
        await engine.dispose()


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock(START)


async def add_org(factory: Factory) -> str:
    org = Org(id=new_org_id(), name="acme", slug="acme", created_at=START)
    async with UnitOfWork(factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def beat(
    factory: Factory,
    node_id: str,
    at: datetime,
    *,
    max_sandboxes: int = 0,
    state: NodeState = NodeState.ACTIVE,
) -> None:
    node = Node(
        id=node_id,
        name=node_id,
        max_sandboxes=max_sandboxes,
        state=state,
        last_heartbeat_at=at,
    )
    async with UnitOfWork(factory) as uow:
        await uow.nodes.upsert_heartbeat(node)
        await uow.commit()


async def add_started(factory: Factory, org_id: str, node_id: str, count: int) -> list[str]:
    ids: list[str] = []
    async with UnitOfWork(factory) as uow:
        for index in range(count):
            sandbox = Sandbox(
                id=new_sandbox_id(),
                org_id=org_id,
                name=f"{node_id}-{index}",
                image_ref="python:3.12-slim",
                driver="fake",
                state=SandboxState.STARTED,
                desired_state=SandboxState.STARTED,
                created_at=START,
                updated_at=START,
            )
            await uow.sandboxes.add(sandbox)
            await uow.nodes.assign_sandbox(sandbox.id, node_id)
            ids.append(sandbox.id)
        await uow.commit()
    return ids


async def picked(factory: Factory, clock: FrozenClock) -> str:
    async with UnitOfWork(factory) as uow:
        return await pick_node(uow, clock, LOCAL)


async def create_sandbox(factory: Factory, clock: FrozenClock, org_id: str) -> str:
    def uow_factory() -> UnitOfWorkPort:
        return UnitOfWork(factory)

    settings = Settings(driver="fake", api_key_pepper=PEPPER, node_id=LOCAL)
    service = SandboxService(uow_factory, FakeDriver(clock), settings, clock, use_jobs=True)
    return (await service.create(org_id, ACTOR, CreateSandboxCommand())).id


async def stamped_nodes(factory: Factory, sandbox_id: str) -> tuple[str | None, list[str]]:
    async with factory() as session:
        sandbox_node = await session.scalar(
            select(SandboxRow.node_id).where(SandboxRow.id == sandbox_id)
        )
        job_nodes = list((await session.execute(select(JobRow.node_id))).scalars())
    return sandbox_node, job_nodes


# --- pick_node ----------------------------------------------------------------------


async def test_empty_registry_places_on_the_local_node(
    factory: Factory, clock: FrozenClock
) -> None:
    org_id = await add_org(factory)

    sandbox_id = await create_sandbox(factory, clock, org_id)

    assert await stamped_nodes(factory, sandbox_id) == (LOCAL, [LOCAL])
    assert await picked(factory, clock) == LOCAL


async def test_create_lands_on_the_least_loaded_node_and_its_job_follows(
    factory: Factory, clock: FrozenClock
) -> None:
    org_id = await add_org(factory)
    await beat(factory, "node-a", START)
    await beat(factory, "node-b", START)
    await add_started(factory, org_id, "node-a", 2)
    await add_started(factory, org_id, "node-b", 1)

    sandbox_id = await create_sandbox(factory, clock, org_id)

    assert await stamped_nodes(factory, sandbox_id) == ("node-b", ["node-b"])


async def test_a_node_at_capacity_is_skipped(factory: Factory, clock: FrozenClock) -> None:
    org_id = await add_org(factory)
    await beat(factory, "node-a", START, max_sandboxes=1)
    await beat(factory, "node-b", START)
    await add_started(factory, org_id, "node-a", 1)
    await add_started(factory, org_id, "node-b", 3)

    assert await picked(factory, clock) == "node-b"  # a is emptier but full


async def test_zero_capacity_means_unlimited(factory: Factory, clock: FrozenClock) -> None:
    org_id = await add_org(factory)
    await beat(factory, "node-a", START, max_sandboxes=0)
    await add_started(factory, org_id, "node-a", 4)

    assert await picked(factory, clock) == "node-a"


async def test_stale_and_draining_nodes_are_never_picked(
    factory: Factory, clock: FrozenClock
) -> None:
    await beat(factory, "node-stale", START - HEARTBEAT_STALE_AFTER - timedelta(seconds=1))
    await beat(factory, "node-draining", START, state=NodeState.DRAINING)

    assert await picked(factory, clock) == LOCAL  # nobody qualifies: fall back, never fail

    await beat(factory, "node-fresh", START)
    assert await picked(factory, clock) == "node-fresh"


async def test_all_nodes_full_falls_back_to_the_local_node(
    factory: Factory, clock: FrozenClock
) -> None:
    org_id = await add_org(factory)
    await beat(factory, "node-a", START, max_sandboxes=1)
    await add_started(factory, org_id, "node-a", 1)

    assert await picked(factory, clock) == LOCAL


# --- job affinity -------------------------------------------------------------------


async def enqueue_for(factory: Factory, org_id: str, node_id: str) -> str:
    job = JobRecord(
        id=new_id(JOB),
        org_id=org_id,
        kind=KIND,
        payload={},
        state="queued",
        attempts=0,
        run_after=START,
        lease_expires_at=None,
        last_error=None,
        created_at=START,
        updated_at=START,
    )
    async with UnitOfWork(factory) as uow:
        await uow.jobs.enqueue(job)
        await uow.nodes.assign_job(job.id, node_id)
        await uow.commit()
    return job.id


async def test_a_job_is_leased_only_by_the_runner_of_its_node(
    factory: Factory, clock: FrozenClock
) -> None:
    org_id = await add_org(factory)
    job_id = await enqueue_for(factory, org_id, "node-a")
    ran: list[Mapping[str, Any]] = []
    registry = HandlerRegistry()

    @registry.register(KIND)
    async def handler(payload: Mapping[str, Any], context: JobContext) -> None:
        ran.append(payload)

    def runner(node_id: str) -> JobRunner:
        return JobRunner(
            lambda: UnitOfWork(factory),
            FakeDriver(clock),
            clock,
            registry=registry,
            node_id=node_id,
        )

    assert await runner("node-b").run_once() is False
    assert ran == []
    assert await runner("node-a").run_once() is True
    assert len(ran) == 1
    async with factory() as session:
        state = await session.scalar(select(JobRow.state).where(JobRow.id == job_id))
    assert state == "done"


# --- node-scoped worker queries -------------------------------------------------------


async def test_autostop_candidates_are_scoped_to_the_node(factory: Factory) -> None:
    org_id = await add_org(factory)
    mine = await add_started(factory, org_id, "node-a", 2)
    await add_started(factory, org_id, "node-b", 1)

    async with UnitOfWork(factory) as uow:
        repository: Any = uow.sandboxes
        scoped = await repository.list_autostop_candidates("node-a")
        everything = await repository.list_autostop_candidates()
        on_node = await repository.list_for_node("node-a")

    assert sorted(s.id for s in scoped) == sorted(mine)
    assert sorted(s.id for s in on_node) == sorted(mine)
    assert len(everything) == 3
