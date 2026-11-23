"""Audit events are org-wide, so a label-scoped key cannot read them.

Through the API on the fake driver and a temp SQLite database: list, export and verify answer
403 to a label-scoped key that holds ``audit:read``, and still answer 200 to an unscoped one.
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
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
AUDIT = "/v1/audit-events"
REFUSAL = "audit events are org-wide; use an API key without sandbox labels"
SCOPES = frozenset({Scope.AUDIT_READ, Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})
READ_PATHS = (AUDIT, f"{AUDIT}/export", f"{AUDIT}/verify")


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'audit_scope.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


async def add_org(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def add_key(app: FastAPI, org_id: str, labels: dict[str, str] | None) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=SCOPES,
        created_at=NOW,
        sandbox_labels=labels,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    return await add_org(app)


@pytest.fixture
async def unscoped(app: FastAPI, org_id: str) -> str:
    return await add_key(app, org_id, None)


@pytest.fixture
async def scoped(app: FastAPI, org_id: str) -> str:
    return await add_key(app, org_id, {"team": "a"})


async def get(client: httpx.AsyncClient, path: str, key: str, **params: Any) -> httpx.Response:
    return await client.get(path, headers={"Authorization": f"Bearer {key}"}, params=params)


async def create_sandbox(client: httpx.AsyncClient, key: str, name: str) -> None:
    response = await client.post(
        "/v1/sandboxes",
        headers={"Authorization": f"Bearer {key}"},
        json={"name": name},
    )
    assert response.status_code == 201, response.text


@pytest.mark.parametrize("path", READ_PATHS)
async def test_label_scoped_key_with_audit_read_is_forbidden(
    client: httpx.AsyncClient, scoped: str, path: str
) -> None:
    response = await get(client, path, scoped)

    assert response.status_code == 403, response.text
    body = response.json()
    assert body["success"] is False
    assert body["error"]["message"] == REFUSAL


@pytest.mark.parametrize("path", READ_PATHS)
async def test_unscoped_key_still_reads_audit_events(
    client: httpx.AsyncClient, unscoped: str, path: str
) -> None:
    response = await get(client, path, unscoped)

    assert response.status_code == 200, response.text


async def test_list_with_order_desc_returns_newest_first(
    client: httpx.AsyncClient, unscoped: str
) -> None:
    await create_sandbox(client, unscoped, "first")
    await create_sandbox(client, unscoped, "second")

    asc = (await get(client, AUDIT, unscoped, order="asc")).json()["data"]
    desc = (await get(client, AUDIT, unscoped, order="desc")).json()["data"]

    assert len(asc) >= 2
    assert [event["id"] for event in desc] == [event["id"] for event in reversed(asc)]
