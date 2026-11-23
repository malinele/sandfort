"""``GET /v1/nodes`` shows host-wide load, so it is only for keys without sandbox labels."""

from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.routes.nodes import NODES_LABEL_SCOPED_MESSAGE
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.repositories.nodes import SqlNodeRepository
from sandfort.db.repositories.sandboxes import SqlSandboxRepository
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
NODES = "/v1/nodes"


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'nodes.db'}"
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


async def add_key(app: FastAPI, labels: dict[str, str] | None) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset({Scope.ORG_READ}),
        created_at=NOW,
        sandbox_labels=labels,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


async def test_an_org_wide_org_read_key_sees_the_nodes(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    key = await add_key(app, None)

    response = await client.get(NODES, headers={"Authorization": f"Bearer {key}"})

    assert response.status_code == 200, response.text
    assert response.json()["success"] is True


async def test_the_listing_makes_one_grouped_count_call_and_no_sandbox_listing(
    app: FastAPI, client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = await add_key(app, None)
    count_calls: list[str | None] = []
    list_calls: list[object] = []
    real_counts = SqlNodeRepository.running_counts
    real_list = SqlSandboxRepository.list

    async def spy_counts(
        self: SqlNodeRepository, org_id: str | None = None
    ) -> Mapping[str, int]:
        count_calls.append(org_id)
        return await real_counts(self, org_id)

    async def spy_list(self: SqlSandboxRepository, *args: Any, **kwargs: Any) -> Any:
        list_calls.append(args)
        return await real_list(self, *args, **kwargs)

    monkeypatch.setattr(SqlNodeRepository, "running_counts", spy_counts)
    monkeypatch.setattr(SqlSandboxRepository, "list", spy_list)

    response = await client.get(NODES, headers={"Authorization": f"Bearer {key}"})

    assert response.status_code == 200, response.text
    # NodeRegistry.list_nodes() still makes its own host-wide call (org_id None); the route
    # itself makes exactly one per-org call and never lists sandboxes.
    assert len([org_id for org_id in count_calls if org_id is not None]) == 1
    assert list_calls == []


async def test_a_label_scoped_org_read_key_gets_403_forbidden(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    key = await add_key(app, {"team": "a"})

    response = await client.get(NODES, headers={"Authorization": f"Bearer {key}"})

    assert response.status_code == 403
    error = response.json()["error"]
    assert error["code"] == "FORBIDDEN"
    assert error["message"] == NODES_LABEL_SCOPED_MESSAGE
    assert "without sandbox labels" in error["message"]
