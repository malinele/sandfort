"""An unknown scope in API key create is a 422 that names it and lists the valid scopes."""

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
PEPPER = "test-pepper"
KEYS = "/v1/api-keys"


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'scope.db'}"
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
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as http:
        yield http


@pytest.fixture
async def admin_key(app: FastAPI) -> str:
    now = datetime.now(UTC)
    org = Org(id=new_org_id(), name="School", slug="school", created_at=now)
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="admin",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset(Scope),
        created_at=now,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


async def create(client: httpx.AsyncClient, key: str, scopes: list[Any]) -> httpx.Response:
    return await client.post(
        KEYS,
        json={"name": "child", "scopes": scopes},
        headers={"Authorization": f"Bearer {key}"},
    )


async def test_unknown_scope_is_named_and_the_valid_scopes_are_listed(
    client: httpx.AsyncClient, admin_key: str
) -> None:
    response = await create(client, admin_key, ["sandboxes:read", "sandboxes:admin"])

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert "unknown scope 'sandboxes:admin'" in error["message"]
    for scope in Scope:
        assert scope.value in error["message"]
    assert "body.scopes.0" not in error["message"]
    assert "body.scopes.1" not in error["message"]


async def test_a_valid_scope_list_is_still_accepted(
    client: httpx.AsyncClient, admin_key: str
) -> None:
    response = await create(client, admin_key, ["sandboxes:read", "toolbox:use"])

    assert response.status_code == 201
    assert response.json()["data"]["scopes"] == ["sandboxes:read", "toolbox:use"]


async def test_an_empty_scope_list_is_still_a_422(
    client: httpx.AsyncClient, admin_key: str
) -> None:
    response = await create(client, admin_key, [])

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
