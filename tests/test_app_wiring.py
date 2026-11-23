"""App-factory wiring: every router is reachable over HTTP (status codes only)."""

from pathlib import Path
from typing import Protocol

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app, create_worker_app
from sandfort.api.wiring import (
    AUTOSTOP_SCANNER_ATTR,
    GC_ATTR,
    JOB_RUNNER_ATTR,
    METERING_ATTR,
    RECONCILER_ATTR,
    WEBHOOK_DISPATCHER_ATTR,
)
from sandfort.config import Settings

ROOT = Path(__file__).resolve().parents[1]
PROCESS_EXECUTE = "/v1/sandboxes/sbx_00000000000000000000000000/toolbox/process/execute"


async def test_all_routers_are_wired_and_require_auth(tmp_path: Path) -> None:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'wiring.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(driver="fake", database_url=url, api_key_pepper="test-pepper")
    app = create_app(settings)
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            audit = await client.get("/v1/audit-events")
            execute = await client.post(PROCESS_EXECUTE, json={})
            sandboxes = await client.get("/v1/sandboxes")
            members = await client.get("/v1/org/members")
            nodes = await client.get("/v1/nodes")
    finally:
        await app.state.engine.dispose()

    assert audit.status_code == 401
    assert execute.status_code == 401
    assert sandboxes.status_code == 401
    assert members.status_code == 401
    assert nodes.status_code == 401


class _Running(Protocol):
    @property
    def running(self) -> bool: ...


WORKER_ATTRS = (
    JOB_RUNNER_ATTR,
    AUTOSTOP_SCANNER_ATTR,
    RECONCILER_ATTR,
    GC_ATTR,
    WEBHOOK_DISPATCHER_ATTR,
    METERING_ATTR,
)


def _migrated_settings(tmp_path: Path, role: str) -> Settings:
    url = f"sqlite+aiosqlite:///{tmp_path / 'roles.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    return Settings(driver="fake", database_url=url, api_key_pepper="test-pepper", role=role)


def _running_flags(app: FastAPI) -> list[bool]:
    workers: list[_Running] = [getattr(app.state, attr) for attr in WORKER_ATTRS]
    return [worker.running for worker in workers]


async def test_api_role_lifespan_starts_no_background_worker(tmp_path: Path) -> None:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    app = create_app(_migrated_settings(tmp_path, "api"))

    async with app.router.lifespan_context(app):
        during = _running_flags(app)

    assert during == [False] * len(WORKER_ATTRS)


async def test_all_role_lifespan_starts_background_workers(tmp_path: Path) -> None:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    app = create_app(_migrated_settings(tmp_path, "all"))

    async with app.router.lifespan_context(app):
        during = _running_flags(app)
    after = _running_flags(app)

    assert all(during)
    assert not any(after)


async def test_worker_role_serves_health_and_runs_workers_during_lifespan(
    tmp_path: Path,
) -> None:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    app = create_worker_app(_migrated_settings(tmp_path, "worker"))

    async with app.router.lifespan_context(app):
        during = _running_flags(app)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            health = await client.get("/healthz")
            business = await client.get("/v1/sandboxes")
    after = _running_flags(app)

    assert health.status_code == 200
    assert business.status_code == 404
    assert all(during)
    assert not any(after)
