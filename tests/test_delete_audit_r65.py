"""Round 65: the ``sandbox.delete`` audit row carries the sandbox's name and user labels.

So a delete can be attributed to a student or a run without joining the create row. Platform
labels (the reserved mount record) stay out, as they do from the create row's ``labels``.
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
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
AUDIT = "/v1/audit-events"
SCOPES = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.AUDIT_READ})


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'delete.db'}"
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
async def key(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="School", slug="school", created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="seed",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=SCOPES,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


def bearer(secret: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {secret}"}


async def audit_rows(client: httpx.AsyncClient, secret: str, action: str) -> list[dict[str, Any]]:
    response = await client.get(AUDIT, headers=bearer(secret), params={"action": action})
    assert response.status_code == 200, response.text
    rows: list[dict[str, Any]] = response.json()["data"]
    return rows


async def test_delete_row_carries_the_name_and_labels(client: httpx.AsyncClient, key: str) -> None:
    labels = {"student": "ada", "run": "7"}
    created = await client.post(
        SANDBOXES, headers=bearer(key), json={"name": "ada-lab", "labels": labels}
    )
    assert created.status_code == 201, created.text
    sandbox_id = created.json()["data"]["id"]

    deleted = await client.delete(f"{SANDBOXES}/{sandbox_id}", headers=bearer(key))

    assert deleted.status_code == 200, deleted.text
    [row] = await audit_rows(client, key, "sandbox.delete")
    assert row["target_id"] == sandbox_id
    assert row["details"]["name"] == "ada-lab"
    assert row["details"]["labels"] == labels
    [create_row] = await audit_rows(client, key, "sandbox.create")
    assert create_row["details"]["name"] == row["details"]["name"]
    assert create_row["details"]["labels"] == row["details"]["labels"]


async def test_delete_row_has_empty_labels_for_an_unlabelled_sandbox(
    client: httpx.AsyncClient, key: str
) -> None:
    created = await client.post(SANDBOXES, headers=bearer(key), json={})
    sandbox_id = created.json()["data"]["id"]

    await client.delete(f"{SANDBOXES}/{sandbox_id}", headers=bearer(key))

    [row] = await audit_rows(client, key, "sandbox.delete")
    assert row["details"]["labels"] == {}
