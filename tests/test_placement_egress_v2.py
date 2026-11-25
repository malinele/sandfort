"""Egress v2 round 5 placement (case J2): egress readiness on nodes and ``require_egress``."""

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sandfort.api.wiring import node_egress_ready
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.node import Node, NodeState
from sandfort.domain.org import Org
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.errors import Conflict
from sandfort.ids import new_org_id, new_sandbox_id
from sandfort.services.node_registry import HEARTBEAT_STALE_AFTER, NodeRegistry, pick_node

ROOT = Path(__file__).resolve().parents[1]
START = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
LOCAL = "node-local"
REMOTE = "node-remote"
REFUSAL = "no node can run egress-allowlisted sandboxes"

Factory = async_sessionmaker[AsyncSession]


def alembic_config(url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    return config


@pytest.fixture
async def factory(tmp_path: Path) -> AsyncIterator[Factory]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'placement-egress.db'}"
    command.upgrade(alembic_config(url), "head")
    engine = create_engine(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))
    try:
        yield create_session_factory(engine)
    finally:
        await engine.dispose()


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock(START)


async def beat(
    factory: Factory,
    node_id: str,
    at: datetime,
    *,
    egress_ready: bool,
    max_sandboxes: int = 0,
    state: NodeState = NodeState.ACTIVE,
) -> None:
    node = Node(
        id=node_id,
        name=node_id,
        max_sandboxes=max_sandboxes,
        state=state,
        last_heartbeat_at=at,
        egress_ready=egress_ready,
    )
    async with UnitOfWork(factory) as uow:
        await uow.nodes.upsert_heartbeat(node)
        await uow.commit()


async def pick(factory: Factory, clock: FrozenClock, *, require_egress: bool) -> str:
    async with UnitOfWork(factory) as uow:
        return await pick_node(uow, clock, LOCAL, require_egress=require_egress)


async def refused(factory: Factory, clock: FrozenClock) -> Conflict:
    with pytest.raises(Conflict) as caught:
        await pick(factory, clock, require_egress=True)
    return caught.value


async def add_started(factory: Factory, node_id: str, count: int) -> None:
    org = Org(id=new_org_id(), name="acme", slug="acme", created_at=START)
    async with UnitOfWork(factory) as uow:
        await uow.orgs.add(org)
        for index in range(count):
            sandbox = Sandbox(
                id=new_sandbox_id(),
                org_id=org.id,
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
        await uow.commit()


def registry(factory: Factory, clock: FrozenClock, *, egress_ready: bool) -> NodeRegistry:
    return NodeRegistry(
        lambda: UnitOfWork(factory),
        clock,
        node_id=REMOTE,
        max_sandboxes=0,
        interval_s=1,
        egress_ready=egress_ready,
    )


# --- pick_node(require_egress) -------------------------------------------------------


async def test_empty_registry_refuses_an_egress_create_instead_of_choosing_local(
    factory: Factory, clock: FrozenClock
) -> None:
    failure = await refused(factory, clock)

    assert failure.status == 409
    assert str(failure) == REFUSAL
    assert await pick(factory, clock, require_egress=False) == LOCAL


async def test_no_ready_node_refuses_and_never_falls_back_to_local(
    factory: Factory, clock: FrozenClock
) -> None:
    await beat(factory, LOCAL, START, egress_ready=False)
    await beat(factory, REMOTE, START, egress_ready=False)

    failure = await refused(factory, clock)

    assert str(failure) == REFUSAL
    assert await pick(factory, clock, require_egress=False) in {LOCAL, REMOTE}


async def test_a_ready_remote_node_wins_over_a_not_ready_local_node(
    factory: Factory, clock: FrozenClock
) -> None:
    await beat(factory, LOCAL, START, egress_ready=False)
    await beat(factory, REMOTE, START, egress_ready=True)
    await add_started(factory, REMOTE, 3)

    assert await pick(factory, clock, require_egress=True) == REMOTE


async def test_a_ready_local_node_qualifies(factory: Factory, clock: FrozenClock) -> None:
    await beat(factory, LOCAL, START, egress_ready=True)

    assert await pick(factory, clock, require_egress=True) == LOCAL


async def test_the_least_loaded_ready_node_is_chosen(factory: Factory, clock: FrozenClock) -> None:
    await beat(factory, LOCAL, START, egress_ready=True)
    await beat(factory, REMOTE, START, egress_ready=True)
    await add_started(factory, LOCAL, 2)

    assert await pick(factory, clock, require_egress=True) == REMOTE


async def test_stale_draining_and_full_ready_nodes_are_refused_not_replaced_by_local(
    factory: Factory, clock: FrozenClock
) -> None:
    await beat(
        factory, "stale", START - HEARTBEAT_STALE_AFTER - timedelta(seconds=1), egress_ready=True
    )
    await beat(factory, "draining", START, egress_ready=True, state=NodeState.DRAINING)
    await beat(factory, "full", START, egress_ready=True, max_sandboxes=1)
    await beat(factory, LOCAL, START, egress_ready=False)
    await add_started(factory, "full", 1)

    assert str(await refused(factory, clock)) == REFUSAL


async def test_a_node_whose_heartbeat_stops_fails_closed(
    factory: Factory, clock: FrozenClock
) -> None:
    await beat(factory, REMOTE, START, egress_ready=True)
    assert await pick(factory, clock, require_egress=True) == REMOTE

    clock.advance(HEARTBEAT_STALE_AFTER + timedelta(seconds=1))

    assert str(await refused(factory, clock)) == REFUSAL


async def advance_heartbeat_like_old_code(factory: Factory, node_id: str, at: datetime) -> None:
    """A pre-round-5 worker: moves ``last_heartbeat_at``, never touches the egress columns."""
    async with factory() as session:
        await session.execute(
            sa.text("UPDATE nodes SET last_heartbeat_at = :at WHERE id = :id"),
            {"at": at, "id": node_id},
        )
        await session.commit()


async def test_an_old_code_heartbeat_leaves_a_stale_ready_flag_that_fails_closed(
    factory: Factory, clock: FrozenClock
) -> None:
    await beat(factory, REMOTE, START, egress_ready=True)
    assert await pick(factory, clock, require_egress=True) == REMOTE

    clock.advance(timedelta(seconds=30))
    await advance_heartbeat_like_old_code(factory, REMOTE, clock.now())

    async with UnitOfWork(factory) as uow:
        (stored,) = await uow.nodes.list_nodes()
    assert stored.egress_ready is True  # the flag survived the rollback, the beat did not renew it
    assert str(await refused(factory, clock)) == REFUSAL
    assert await pick(factory, clock, require_egress=False) == REMOTE


async def test_a_new_code_heartbeat_after_an_old_one_makes_the_node_ready_again(
    factory: Factory, clock: FrozenClock
) -> None:
    await beat(factory, REMOTE, START, egress_ready=True)
    clock.advance(timedelta(seconds=30))
    await advance_heartbeat_like_old_code(factory, REMOTE, clock.now())
    await beat(factory, REMOTE, clock.now() + timedelta(seconds=30), egress_ready=True)

    assert await pick(factory, clock, require_egress=True) == REMOTE


async def test_the_heartbeat_stores_the_ready_time_equal_to_the_beat(factory: Factory) -> None:
    await beat(factory, REMOTE, START, egress_ready=True)
    await beat(factory, LOCAL, START, egress_ready=False)

    async with UnitOfWork(factory) as uow:
        stored = {node.id: node for node in await uow.nodes.list_nodes()}
    assert stored[REMOTE].egress_ready_at == stored[REMOTE].last_heartbeat_at == START
    assert stored[LOCAL].egress_ready_at is None


# --- the heartbeat stores the flag ---------------------------------------------------


async def test_the_heartbeat_stores_egress_ready_and_a_flip_fails_closed(
    factory: Factory, clock: FrozenClock
) -> None:
    ready = await registry(factory, clock, egress_ready=True).heartbeat()
    assert ready.egress_ready is True
    assert await pick(factory, clock, require_egress=True) == REMOTE

    await registry(factory, clock, egress_ready=False).heartbeat()

    async with UnitOfWork(factory) as uow:
        stored = {node.id: node for node in await uow.nodes.list_nodes()}
    assert stored[REMOTE].egress_ready is False
    assert str(await refused(factory, clock)) == REFUSAL


async def test_a_node_is_not_egress_ready_by_default() -> None:
    node = Node(id="n", name="n", last_heartbeat_at=START)

    assert node.egress_ready is False


# --- what the heartbeat flag is derived from -----------------------------------------


@pytest.mark.parametrize(
    ("address", "secret", "policy_url", "expected"),
    [
        ("proxy:3128", "s", "http://api:8000/policy", True),
        ("", "s", "http://api:8000/policy", False),
        ("proxy:3128", "", "http://api:8000/policy", False),
        ("proxy:3128", "s", "", False),
        ("proxy:3128", "s", "   ", False),
    ],
)
def test_node_egress_ready_needs_proxy_secret_and_policy_url(
    address: str, secret: str, policy_url: str, expected: bool
) -> None:
    settings = Settings(
        driver="fake",
        api_key_pepper=PEPPER,
        egress_proxy_address=address,
        egress_secret=secret,
    )
    environ = {"SANDFORT_EGRESS_POLICY_URL": policy_url}

    assert node_egress_ready(settings, environ) is expected


def test_node_egress_ready_is_false_without_a_policy_url_variable() -> None:
    settings = Settings(
        driver="fake",
        api_key_pepper=PEPPER,
        egress_proxy_address="proxy:3128",
        egress_secret="s",
    )

    assert node_egress_ready(settings, {}) is False


# --- migration r0028 -----------------------------------------------------------------


def column_names(url: str) -> dict[str, sa.engine.interfaces.ReflectedColumn]:
    engine = sa.create_engine(url.replace("+aiosqlite", ""))
    try:
        return {col["name"]: col for col in sa.inspect(engine).get_columns("nodes")}
    finally:
        engine.dispose()


def test_migration_0028_adds_and_drops_egress_ready_with_default_false(tmp_path: Path) -> None:
    pytest.importorskip("aiosqlite")
    url = f"sqlite+aiosqlite:///{tmp_path / 'm0028.db'}"
    config = alembic_config(url)

    command.upgrade(config, "0027")
    assert "egress_ready" not in column_names(url)
    sync = sa.create_engine(url.replace("+aiosqlite", ""))
    with sync.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO nodes (id, name, max_sandboxes, state, last_heartbeat_at,"
                " internal_url, created_at, updated_at) VALUES ('old', 'old', 0, 'active',"
                " '2026-11-01 12:00:00', '', '2026-11-01 12:00:00', '2026-11-01 12:00:00')"
            )
        )
    sync.dispose()

    command.upgrade(config, "0028")
    columns = column_names(url)
    assert columns["egress_ready"]["nullable"] is False
    sync = sa.create_engine(url.replace("+aiosqlite", ""))
    with sync.connect() as conn:
        value = conn.execute(sa.text("SELECT egress_ready FROM nodes WHERE id = 'old'")).scalar()
    sync.dispose()
    assert not value

    assert columns["egress_ready_at"]["nullable"] is True
    sync = sa.create_engine(url.replace("+aiosqlite", ""))
    with sync.connect() as conn:
        ready_at = conn.execute(
            sa.text("SELECT egress_ready_at FROM nodes WHERE id = 'old'")
        ).scalar()
    sync.dispose()
    assert ready_at is None  # an existing row never counts as ready until a new-code beat

    command.downgrade(config, "0027")
    assert "egress_ready" not in column_names(url)
    assert "egress_ready_at" not in column_names(url)
