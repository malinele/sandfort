"""Node address: migration 0009 and the sandbox-to-node route lookup."""

import sqlite3
from collections.abc import AsyncIterator
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.repositories.nodes import SqlNodeRepository
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.node import Node, NodeRoute, NodeState
from sandfort.domain.org import Org
from sandfort.domain.sandbox import Sandbox
from sandfort.ids import new_org_id, new_sandbox_id

ROOT = Path(__file__).resolve().parents[1]
START = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)

Factory = async_sessionmaker[AsyncSession]


def alembic_config(db_path: Path) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")
    return config


def node_column_names(db_path: Path) -> set[str]:
    with closing(sqlite3.connect(db_path)) as connection:
        rows = connection.execute("PRAGMA table_info(nodes)").fetchall()
    return {row[1] for row in rows}


def make_node(
    node_id: str,
    url: str,
    beat: datetime = START,
    state: NodeState = NodeState.ACTIVE,
) -> Node:
    return Node(id=node_id, name=node_id, state=state, last_heartbeat_at=beat, internal_url=url)


@pytest.fixture
async def factory(tmp_path: Path) -> AsyncIterator[Factory]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    db_path = tmp_path / "routes.db"
    command.upgrade(alembic_config(db_path), "head")
    engine = create_engine(Settings(database_url=f"sqlite+aiosqlite:///{db_path}"))
    try:
        yield create_session_factory(engine)
    finally:
        await engine.dispose()


async def place_sandbox(factory: Factory, node_id: str) -> str:
    org = Org(id=new_org_id(), name="acme", slug="acme", created_at=START)
    sandbox = Sandbox(
        id=new_sandbox_id(),
        org_id=org.id,
        name="dev",
        image_ref="python:3.12-slim",
        driver="fake",
        created_at=START,
        updated_at=START,
    )
    async with UnitOfWork(factory) as uow:
        await uow.orgs.add(org)
        await uow.sandboxes.add(sandbox)
        await uow.nodes.assign_sandbox(sandbox.id, node_id)
        await uow.commit()
    return sandbox.id


async def heartbeat(factory: Factory, node: Node) -> None:
    async with factory() as session:
        await SqlNodeRepository(session).upsert_heartbeat(node)
        await session.commit()


async def route(factory: Factory, sandbox_id: str) -> NodeRoute | None:
    async with factory() as session:
        return await SqlNodeRepository(session).route_for_sandbox(sandbox_id)


# --- migration ------------------------------------------------------------------


def test_upgrade_adds_internal_url_and_downgrade_removes_it(tmp_path: Path) -> None:
    db_path = tmp_path / "migrated.db"
    config = alembic_config(db_path)

    command.upgrade(config, "0009")
    upgraded = node_column_names(db_path)
    command.downgrade(config, "0008")
    downgraded = node_column_names(db_path)

    assert "internal_url" in upgraded
    assert "internal_url" not in downgraded
    with closing(sqlite3.connect(db_path)) as connection:
        version = connection.execute("SELECT version_num FROM alembic_version").fetchall()
    assert version == [("0008",)]


# --- route lookup ---------------------------------------------------------------


async def test_route_is_the_owning_nodes_address(factory: Factory) -> None:
    await heartbeat(factory, make_node("node-a", "http://10.0.0.1:8000"))
    await heartbeat(factory, make_node("node-b", "http://10.0.0.2:8000"))
    sandbox_id = await place_sandbox(factory, "node-b")

    found = await route(factory, sandbox_id)

    assert found is not None
    assert (found.node_id, found.internal_url) == ("node-b", "http://10.0.0.2:8000")


async def test_route_is_none_for_an_unknown_sandbox(factory: Factory) -> None:
    await heartbeat(factory, make_node("node-a", "http://10.0.0.1:8000"))

    assert await route(factory, new_sandbox_id()) is None


async def test_route_reflects_a_heartbeat_that_changes_the_address(factory: Factory) -> None:
    await heartbeat(factory, make_node("node-a", "http://10.0.0.1:8000"))
    sandbox_id = await place_sandbox(factory, "node-a")

    await heartbeat(factory, make_node("node-a", "http://10.0.0.9:9000"))

    found = await route(factory, sandbox_id)
    assert found is not None
    assert found.internal_url == "http://10.0.0.9:9000"


async def test_route_carries_state_and_heartbeat_for_staleness_checks(factory: Factory) -> None:
    beat = START + timedelta(seconds=45)
    await heartbeat(factory, make_node("node-a", "", beat, NodeState.DRAINING))
    sandbox_id = await place_sandbox(factory, "node-a")

    found = await route(factory, sandbox_id)

    assert found is not None
    assert (found.state, found.last_heartbeat_at, found.internal_url) == (
        NodeState.DRAINING,
        beat,
        "",
    )
