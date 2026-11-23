"""Node registry: heartbeat upsert, listing with counts and staleness, node stamping."""

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

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
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.node import DEFAULT_NODE_ID, NodeState
from sandfort.domain.org import Org
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_org_id, new_sandbox_id
from sandfort.services.node_registry import HEARTBEAT_STALE_AFTER, NodeRegistry
from sandfort.services.sandboxes import CreateSandboxCommand, SandboxService

ROOT = Path(__file__).resolve().parents[1]
START = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
ACTOR = "key_test"

Factory = async_sessionmaker[AsyncSession]


@pytest.fixture
async def factory(tmp_path: Path) -> AsyncIterator[Factory]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'nodes.db'}"
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
    org_id = new_org_id()
    org = Org(id=org_id, name="acme", slug=f"acme-{org_id}".lower(), created_at=START)
    async with UnitOfWork(factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


def registry(
    factory: Factory,
    clock: FrozenClock,
    node_id: str = "node-a",
    max_sandboxes: int = 0,
    internal_url: str = "",
) -> NodeRegistry:
    return NodeRegistry(
        lambda: UnitOfWork(factory),
        clock,
        node_id=node_id,
        max_sandboxes=max_sandboxes,
        interval_s=1,
        internal_url=internal_url,
    )


def job_service(factory: Factory, clock: FrozenClock, settings: Settings) -> SandboxService:
    def uow_factory() -> UnitOfWorkPort:
        return UnitOfWork(factory)

    return SandboxService(uow_factory, FakeDriver(clock), settings, clock, use_jobs=True)


async def sandbox_and_job_nodes(factory: Factory, sandbox_id: str) -> tuple[str, list[str]]:
    async with factory() as session:
        sandbox_node = await session.scalar(
            select(SandboxRow.node_id).where(SandboxRow.id == sandbox_id)
        )
        job_nodes = list((await session.execute(select(JobRow.node_id))).scalars())
    assert sandbox_node is not None
    return sandbox_node, job_nodes


# --- configuration --------------------------------------------------------------


def test_settings_default_to_the_local_node() -> None:
    defaults = Settings.from_env({})
    configured = Settings.from_env(
        {"SANDFORT_NODE_ID": "node-b", "SANDFORT_NODE_MAX_SANDBOXES": "12"}
    )

    assert (defaults.node_id, defaults.node_max_sandboxes) == (DEFAULT_NODE_ID, 0)
    assert DEFAULT_NODE_ID == "local"
    assert (configured.node_id, configured.node_max_sandboxes) == ("node-b", 12)


# --- heartbeat and listing -------------------------------------------------------


async def test_heartbeat_creates_then_refreshes_the_row(
    factory: Factory, clock: FrozenClock
) -> None:
    await registry(factory, clock, max_sandboxes=5).heartbeat()
    clock.advance(timedelta(seconds=30))
    await registry(factory, clock, max_sandboxes=8).heartbeat()

    listed = await registry(factory, clock).list_nodes()

    assert len(listed) == 1
    node = listed[0].node
    assert (node.id, node.max_sandboxes, node.state) == ("node-a", 8, NodeState.ACTIVE)
    assert node.last_heartbeat_at == START + timedelta(seconds=30)


async def test_heartbeat_stores_the_configured_address(
    factory: Factory, clock: FrozenClock
) -> None:
    await registry(factory, clock, internal_url="http://10.0.0.5:8000").heartbeat()

    listed = await registry(factory, clock).list_nodes()

    assert [status.node.internal_url for status in listed] == ["http://10.0.0.5:8000"]


async def test_a_later_heartbeat_overwrites_the_address(
    factory: Factory, clock: FrozenClock
) -> None:
    await registry(factory, clock, internal_url="http://10.0.0.5:8000").heartbeat()
    clock.advance(timedelta(seconds=15))
    await registry(factory, clock, internal_url="http://10.0.0.9:9000").heartbeat()

    listed = await registry(factory, clock).list_nodes()

    assert [status.node.internal_url for status in listed] == ["http://10.0.0.9:9000"]


async def test_default_address_stays_empty(factory: Factory, clock: FrozenClock) -> None:
    await registry(factory, clock).heartbeat()
    clock.advance(timedelta(seconds=15))
    await registry(factory, clock).heartbeat()

    listed = await registry(factory, clock).list_nodes()

    assert [status.node.internal_url for status in listed] == [""]


async def test_listing_reports_running_counts_and_staleness(
    factory: Factory, clock: FrozenClock
) -> None:
    org_id = await add_org(factory)
    await registry(factory, clock, "node-a").heartbeat()
    clock.advance(HEARTBEAT_STALE_AFTER + timedelta(seconds=1))
    await registry(factory, clock, "node-b").heartbeat()
    async with UnitOfWork(factory) as uow:
        for index, state in enumerate(
            (SandboxState.STARTED, SandboxState.STARTED, SandboxState.STOPPED)
        ):
            sandbox = Sandbox(
                id=new_sandbox_id(),
                org_id=org_id,
                name=f"sbx-{index}",
                image_ref="python:3.12-slim",
                driver="fake",
                state=state,
                desired_state=state,
                created_at=START,
                updated_at=START,
            )
            await uow.sandboxes.add(sandbox)
            await uow.nodes.assign_sandbox(sandbox.id, "node-a")
        await uow.commit()

    by_id = {status.node.id: status for status in await registry(factory, clock).list_nodes()}

    assert (by_id["node-a"].running_sandboxes, by_id["node-a"].stale) == (2, True)
    assert (by_id["node-b"].running_sandboxes, by_id["node-b"].stale) == (0, False)


async def seed_sandboxes(
    factory: Factory,
    org_id: str,
    node_id: str,
    state: SandboxState,
    count: int,
    standby: bool = False,
) -> None:
    async with UnitOfWork(factory) as uow:
        for _ in range(count):
            sandbox = Sandbox(
                id=new_sandbox_id(),
                org_id=org_id,
                name=f"sbx-{new_sandbox_id()}",
                image_ref="python:3.12-slim",
                driver="fake",
                state=state,
                desired_state=state,
                created_at=START,
                updated_at=START,
                standby=standby,
            )
            await uow.sandboxes.add(sandbox)
            await uow.nodes.assign_sandbox(sandbox.id, node_id)
        await uow.commit()


async def test_per_org_counts_sum_to_the_host_wide_counts(factory: Factory) -> None:
    first = await add_org(factory)
    second = await add_org(factory)
    await seed_sandboxes(factory, first, "node-a", SandboxState.STARTED, 2)
    await seed_sandboxes(factory, first, "node-b", SandboxState.STARTED, 1)
    await seed_sandboxes(factory, first, "node-a", SandboxState.STOPPED, 4)
    await seed_sandboxes(factory, second, "node-a", SandboxState.STARTED, 3)
    await seed_sandboxes(factory, second, "node-b", SandboxState.STARTED, 2, standby=True)
    await seed_sandboxes(factory, second, "node-b", SandboxState.DESTROYED, 1)

    async with UnitOfWork(factory) as uow:
        host_wide = dict(await uow.nodes.running_counts())
        per_org = [dict(await uow.nodes.running_counts(org)) for org in (first, second)]

    summed: dict[str, int] = {}
    for counts in per_org:
        for node_id, count in counts.items():
            summed[node_id] = summed.get(node_id, 0) + count
    assert host_wide == {"node-a": 5, "node-b": 3}
    assert summed == host_wide


async def test_another_orgs_sandboxes_do_not_count(factory: Factory) -> None:
    mine = await add_org(factory)
    theirs = await add_org(factory)
    await seed_sandboxes(factory, mine, "node-a", SandboxState.STARTED, 1)
    await seed_sandboxes(factory, theirs, "node-a", SandboxState.STARTED, 5)
    await seed_sandboxes(factory, theirs, "node-b", SandboxState.STARTED, 2)
    idle = await add_org(factory)

    async with UnitOfWork(factory) as uow:
        counts = dict(await uow.nodes.running_counts(mine))
        empty = dict(await uow.nodes.running_counts(idle))

    assert counts == {"node-a": 1}
    assert empty == {}


# --- stamping ---------------------------------------------------------------------


async def test_new_sandboxes_and_jobs_carry_the_configured_node_id(
    factory: Factory, clock: FrozenClock
) -> None:
    org_id = await add_org(factory)
    settings = Settings(driver="fake", api_key_pepper=PEPPER, node_id="node-b")

    sandbox = await job_service(factory, clock, settings).create(
        org_id, ACTOR, CreateSandboxCommand()
    )

    sandbox_node, job_nodes = await sandbox_and_job_nodes(factory, sandbox.id)
    assert sandbox_node == "node-b"
    assert job_nodes == ["node-b"]


async def test_default_configuration_stamps_local_everywhere(
    factory: Factory, clock: FrozenClock
) -> None:
    org_id = await add_org(factory)
    settings = Settings(driver="fake", api_key_pepper=PEPPER)

    sandbox = await job_service(factory, clock, settings).create(
        org_id, ACTOR, CreateSandboxCommand()
    )

    sandbox_node, job_nodes = await sandbox_and_job_nodes(factory, sandbox.id)
    assert sandbox_node == "local"
    assert job_nodes == ["local"]
