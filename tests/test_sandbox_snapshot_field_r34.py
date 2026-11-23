"""A sandbox records what it was created from (snapshot id or image reference).

FakeDriver, temp SQLite database migrated to head. A snapshot name is stored as its ``snp_`` id,
an image reference as given, and a create with no snapshot leaves the field null.
"""

import sqlite3
from collections.abc import AsyncIterator
from contextlib import closing
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import Scope
from sandfort.services.sandboxes import SNAPSHOT_ID_PREFIX
from test_api_sandboxes import BASE, ROOT, add_org, migrated_app, seed_key, send
from test_api_snapshots import FULL_TIERS, snapshot_of

SNAPSHOT_NAME = "snap"  # the name ``snapshot_of`` gives its snapshot
IMAGE_REFERENCE = "python:3.12"
SCOPES = frozenset(
    {Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.SNAPSHOTS_READ, Scope.SNAPSHOTS_WRITE}
)


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    async with migrated_app(tmp_path, isolation_runtimes=FULL_TIERS) as application:
        yield application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    return await add_org(app, "snapfield")


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id, SCOPES)


async def create(client: httpx.AsyncClient, key: str, **payload: Any) -> dict[str, Any]:
    body = await send(client, "POST", BASE, key, status=201, json=payload)
    data: dict[str, Any] = body["data"]
    return data


async def fetch(client: httpx.AsyncClient, key: str, sandbox_id: str) -> dict[str, Any]:
    body = await send(client, "GET", f"{BASE}/{sandbox_id}", key, status=200)
    data: dict[str, Any] = body["data"]
    return data


async def stored_snapshot(app: FastAPI, org_id: str, sandbox_id: str) -> str | None:
    async with UnitOfWork(app.state.session_factory) as uow:
        sandbox = await uow.sandboxes.get(org_id, sandbox_id)
    assert sandbox is not None
    return sandbox.snapshot


async def test_create_by_snapshot_name_records_the_snapshot_id(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    source = await create(client, key)
    snapshot = await snapshot_of(app, client, key, source["id"])
    assert snapshot["name"] == SNAPSHOT_NAME

    created = await create(client, key, snapshot=SNAPSHOT_NAME)

    assert created["snapshot"] == snapshot["id"]
    assert snapshot["id"].startswith(SNAPSHOT_ID_PREFIX)
    assert await stored_snapshot(app, org_id, created["id"]) == snapshot["id"]
    assert (await fetch(client, key, created["id"]))["snapshot"] == snapshot["id"]


async def test_create_by_snapshot_id_records_the_same_id(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    source = await create(client, key)
    snapshot = await snapshot_of(app, client, key, source["id"])

    created = await create(client, key, snapshot=snapshot["id"])

    assert created["snapshot"] == snapshot["id"]
    assert (await fetch(client, key, created["id"]))["snapshot"] == snapshot["id"]


async def test_create_by_image_reference_records_the_reference(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    created = await create(client, key, snapshot=IMAGE_REFERENCE)

    assert created["snapshot"] == IMAGE_REFERENCE
    assert await stored_snapshot(app, org_id, created["id"]) == IMAGE_REFERENCE
    assert (await fetch(client, key, created["id"]))["snapshot"] == IMAGE_REFERENCE


async def test_create_without_a_snapshot_answers_null(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    created = await create(client, key)

    assert created["snapshot"] is None
    assert await stored_snapshot(app, org_id, created["id"]) is None
    assert (await fetch(client, key, created["id"]))["snapshot"] is None


def column_names(db_path: Path) -> set[str]:
    with closing(sqlite3.connect(db_path)) as connection:
        rows = connection.execute("PRAGMA table_info(sandboxes)").fetchall()
    return {row[1] for row in rows}


def test_the_migration_adds_and_drops_the_column(tmp_path: Path) -> None:
    pytest.importorskip("aiosqlite")
    db_path = tmp_path / "migrate.db"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")

    command.upgrade(config, "0016")
    assert "snapshot" not in column_names(db_path)
    command.upgrade(config, "0017")
    assert "snapshot" in column_names(db_path)
    command.downgrade(config, "0016")
    assert "snapshot" not in column_names(db_path)
    assert "egress_allowlist" in column_names(db_path)
