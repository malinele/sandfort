"""WP 5.3 Postgres profile against a real daemon: migrations, optimistic locking, quota burst.

A module fixture runs ``postgres:16-alpine`` with a random password on an ephemeral loopback
port (skipped when no Docker daemon is reachable). Migrations run on the asyncpg connection
through alembic's ``EnvironmentContext``: ``env.py`` would open a psycopg engine, which the
dev environment does not install. The burst drives the API (fake compute driver) over the
ASGI client, so the quota ``FOR UPDATE`` path is exercised under real concurrency.
"""

import asyncio
import contextlib
import secrets
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from typing import Any

import pytest
from alembic.config import Config
from alembic.runtime.environment import EnvironmentContext
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, inspect, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from sandfort.api.app import create_app
from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.sandbox import SandboxState
from sandfort.drivers.docker.client import make_client
from sandfort.drivers.fake import FakeDriver
from sandfort.errors import Conflict
from test_db import EXPECTED_TABLES, ROOT, make_org, make_sandbox
from test_quota import (
    ADMIN,
    CONCURRENT_CREATES,
    PEPPER,
    VCPU_LIMIT,
    add_org,
    create,
    reserved,
    seed_key,
    serve,
    set_limits,
)

pytestmark = pytest.mark.docker

docker = pytest.importorskip("docker")
pytest.importorskip("asyncpg")
pytest.importorskip("greenlet")

IMAGE = "postgres:16-alpine"
PG_USER = "sandfort"
PG_DB = "sandfort"
PG_PORT = "5432/tcp"
READY_TIMEOUT_S = 60.0
POLL_INTERVAL_S = 0.5

Factory = async_sessionmaker[AsyncSession]


@pytest.fixture(scope="module")
def client() -> Any:
    try:
        docker_client = make_client()
        docker_client.ping()
    except Exception as exc:
        pytest.skip(f"no reachable Docker daemon: {exc}")
    try:
        docker_client.images.get(IMAGE)
    except docker.errors.ImageNotFound:
        try:
            docker_client.images.pull(IMAGE)
        except Exception as exc:
            pytest.skip(f"cannot pull {IMAGE}: {exc}")
    return docker_client


def wait_until_ready(container: Any) -> None:
    """Poll ``pg_isready`` over TCP: the image's init-time server listens on no TCP port."""
    probe = ["pg_isready", "-h", "127.0.0.1", "-U", PG_USER, "-d", PG_DB]
    deadline = time.monotonic() + READY_TIMEOUT_S
    while time.monotonic() < deadline:
        container.reload()
        if container.status not in ("created", "running"):
            logs = container.logs(tail=50).decode(errors="replace")
            pytest.fail(f"postgres container is {container.status}:\n{logs}")
        if container.status == "running" and container.exec_run(probe).exit_code == 0:
            return
        time.sleep(POLL_INTERVAL_S)
    pytest.fail(f"postgres not ready within {READY_TIMEOUT_S}s")


@pytest.fixture(scope="module")
def postgres_url(client: Any) -> Iterator[str]:
    password = secrets.token_hex(16)
    container = client.containers.run(
        IMAGE,
        detach=True,
        name=f"sandfort-test-pg-{uuid.uuid4().hex[:10]}",
        environment={
            "POSTGRES_USER": PG_USER,
            "POSTGRES_PASSWORD": password,
            "POSTGRES_DB": PG_DB,
        },
        ports={PG_PORT: ("127.0.0.1", None)},  # ephemeral host port, loopback only
        labels={"suite": "test_postgres"},
    )
    try:
        wait_until_ready(container)
        container.reload()
        host_port = container.ports[PG_PORT][0]["HostPort"]
        yield f"postgresql+asyncpg://{PG_USER}:{password}@127.0.0.1:{host_port}/{PG_DB}"
    finally:
        with contextlib.suppress(docker.errors.NotFound):
            container.remove(force=True, v=True)


def alembic_config() -> Config:
    return Config(str(ROOT / "alembic.ini"))


def upgrade_to_head(connection: Connection) -> None:
    """``alembic upgrade head`` over ``connection`` (what ``command.upgrade`` does via env.py)."""
    config = alembic_config()
    script = ScriptDirectory.from_config(config)

    def upgrade(revision: Any, _context: Any) -> Any:
        return script._upgrade_revs("head", revision)

    with EnvironmentContext(config, script, fn=upgrade, destination_rev="head") as environment:
        environment.configure(connection=connection)
        with environment.begin_transaction():
            environment.run_migrations()


async def wait_connectable(url: str) -> None:
    """The published port can lag the server it forwards to; retry until a query answers."""
    engine = create_async_engine(url, poolclass=NullPool)
    deadline = time.monotonic() + READY_TIMEOUT_S
    try:
        while True:
            try:
                async with engine.connect() as connection:
                    await connection.execute(text("SELECT 1"))
                return
            except (OSError, DBAPIError):
                if time.monotonic() > deadline:
                    raise
                await asyncio.sleep(POLL_INTERVAL_S)
    finally:
        await engine.dispose()


@pytest.fixture
async def database_url(postgres_url: str) -> str:
    """The module database migrated to head (a no-op after the first test)."""
    await wait_connectable(postgres_url)
    engine = create_async_engine(postgres_url, poolclass=NullPool)
    try:
        async with engine.connect() as connection:
            await connection.run_sync(upgrade_to_head)
            await connection.commit()
    finally:
        await engine.dispose()
    return postgres_url


@pytest.fixture
async def factory(database_url: str) -> AsyncIterator[Factory]:
    engine = create_engine(Settings(database_url=database_url))
    try:
        yield create_session_factory(engine)
    finally:
        await engine.dispose()


def table_names(connection: Connection) -> set[str]:
    return set(inspect(connection).get_table_names())


# --- migrations -----------------------------------------------------------------


async def test_upgrade_head_creates_full_schema_on_postgres(database_url: str) -> None:
    head = ScriptDirectory.from_config(alembic_config()).get_current_head()
    engine = create_async_engine(database_url, poolclass=NullPool)
    try:
        async with engine.connect() as connection:
            result = await connection.execute(text("SELECT version_num FROM alembic_version"))
            versions = list(result.scalars().all())
            tables = await connection.run_sync(table_names)
    finally:
        await engine.dispose()

    assert head is not None
    assert versions == [head]
    assert tables == EXPECTED_TABLES | {"alembic_version"}


# --- optimistic concurrency -----------------------------------------------------


async def test_stale_version_raises_conflict_on_postgres(factory: Factory) -> None:
    org = make_org("pg-optimistic")
    sandbox = make_sandbox(org.id)
    async with UnitOfWork(factory) as uow:
        await uow.orgs.add(org)
        await uow.sandboxes.add(sandbox)
        await uow.commit()
    async with UnitOfWork(factory) as uow:
        started = await uow.sandboxes.update(
            org.id,
            sandbox.model_copy(update={"state": SandboxState.STARTED}),
            expected_version=1,
        )
        await uow.commit()
    assert started.version == 2

    async with UnitOfWork(factory) as uow:
        with pytest.raises(Conflict):
            await uow.sandboxes.update(
                org.id,
                sandbox.model_copy(update={"state": SandboxState.STOPPED}),
                expected_version=1,
            )

    async with UnitOfWork(factory) as uow:
        assert await uow.sandboxes.get(org.id, sandbox.id) == started


# --- quota burst ----------------------------------------------------------------


async def test_fifty_concurrent_creates_admit_exactly_the_quota_on_postgres(
    database_url: str,
) -> None:
    app = create_app(Settings(driver="fake", database_url=database_url, api_key_pepper=PEPPER))
    async with serve(app) as client:
        key = await seed_key(app, await add_org(app, "pg-burst"), ADMIN, platform=True)
        await set_limits(client, key, max_vcpus=VCPU_LIMIT)

        responses = await asyncio.gather(
            *(create(client, key) for _ in range(CONCURRENT_CREATES))
        )

        failures = [r.text for r in responses if r.status_code not in (201, 429)]
        assert failures == []
        admitted = [r for r in responses if r.status_code == 201]
        refused = [r for r in responses if r.status_code == 429]
        assert len(admitted) == VCPU_LIMIT
        assert len(refused) == CONCURRENT_CREATES - VCPU_LIMIT
        assert {r.json()["error"]["code"] for r in refused} == {"QUOTA_EXCEEDED"}
        driver = app.state.driver
        assert isinstance(driver, FakeDriver)
        assert len(await driver.list_managed()) == VCPU_LIMIT
        held = await reserved(client, key)
        assert held["vcpus"] == VCPU_LIMIT
        assert held["sandboxes"] == VCPU_LIMIT
