"""A key minted by another key never outlives it, and revoking a key revokes its children.

Through the API on the fake driver and a temp SQLite database. A creator that expires bounds
the child's ``expires_at`` (422 naming the bound); ``created_by`` records the creator, and
revoking the creator with ``cascade=true`` revokes its live descendants (children and
grandchildren) with it; without the flag they stay alive (see ``test_api_key_cascade_r58``).
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
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
SANDBOXES = "/v1/sandboxes"
SCOPES = frozenset({Scope.SANDBOXES_READ, Scope.API_KEYS_ADMIN})
DAY = timedelta(days=1)


def _now() -> datetime:
    return datetime.now(UTC)


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'expiry.db'}"
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
async def org_id(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="School", slug="school", created_at=_now())
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def seed_key(
    app: FastAPI, org_id: str, expires_at: datetime | None, name: str = "seed"
) -> tuple[str, str]:
    """Store a key straight in the database; returns (key id, plaintext key)."""
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name=name,
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=SCOPES,
        expires_at=expires_at,
        created_at=_now(),
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return stored.id, generated.key


def bearer(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def mint(client: httpx.AsyncClient, caller: str, **extra: Any) -> httpx.Response:
    body: dict[str, Any] = {"name": "child", "scopes": [s.value for s in SCOPES]}
    for name, value in extra.items():
        body[name] = value.isoformat() if isinstance(value, datetime) else value
    return await client.post(KEYS, json=body, headers=bearer(caller))


async def listing(client: httpx.AsyncClient, caller: str) -> dict[str, dict[str, Any]]:
    response = await client.get(KEYS, headers=bearer(caller))
    return {item["id"]: item for item in response.json()["data"]}


# --- the expiry bound ----------------------------------------------------------------


async def test_a_child_may_not_expire_after_its_creator(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    bound = _now() + DAY
    _, creator = await seed_key(app, org_id, bound)

    response = await mint(client, creator, expires_at=bound + DAY)

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "UNPROCESSABLE"
    assert "creating key's expiry" in error["message"]
    assert "max_expires_at" in error["details"]


async def test_a_child_without_expiry_is_refused_under_an_expiring_creator(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    _, creator = await seed_key(app, org_id, _now() + DAY)

    response = await mint(client, creator)

    assert response.status_code == 422
    assert "creating key's expiry" in response.text


async def test_a_child_at_or_before_the_creator_expiry_is_accepted(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    bound = _now() + DAY
    _, creator = await seed_key(app, org_id, bound)

    sooner = await mint(client, creator, expires_at=bound - timedelta(hours=1))

    assert sooner.status_code == 201


async def test_a_creator_without_expiry_leaves_the_child_unbounded(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    _, creator = await seed_key(app, org_id, None)

    unbounded = await mint(client, creator)
    far = await mint(client, creator, expires_at=_now() + 400 * DAY)

    assert unbounded.status_code == 201
    assert far.status_code == 201


async def test_the_child_records_its_creator(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    creator_id, creator = await seed_key(app, org_id, None)
    child_id = (await mint(client, creator)).json()["data"]["id"]

    async with UnitOfWork(app.state.session_factory) as uow:
        stored = {key.id: key for key in await uow.api_keys.list_for_org(org_id)}

    assert stored[child_id].created_by == creator_id


# --- the revoke cascade --------------------------------------------------------------


async def test_revoking_the_creator_with_cascade_revokes_children_and_grandchildren(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    root_id, root = await seed_key(app, org_id, None, "root")
    _, admin = await seed_key(app, org_id, None, "admin")
    child = (await mint(client, root)).json()["data"]
    grandchild = (await mint(client, child["key"])).json()["data"]
    sibling = (await mint(client, admin)).json()["data"]

    revoked = await client.delete(f"{KEYS}/{root_id}?cascade=true", headers=bearer(admin))
    after = await listing(client, admin)

    assert revoked.status_code == 200
    assert after[child["id"]]["revoked_at"] is not None
    assert after[grandchild["id"]]["revoked_at"] is not None
    assert after[sibling["id"]]["revoked_at"] is None
    assert (await client.get(SANDBOXES, headers=bearer(child["key"]))).status_code == 401
    assert (await client.get(SANDBOXES, headers=bearer(grandchild["key"]))).status_code == 401


async def test_revoking_a_child_leaves_its_creator_alive(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    _, creator = await seed_key(app, org_id, None)
    child = (await mint(client, creator)).json()["data"]

    revoked = await client.delete(f"{KEYS}/{child['id']}", headers=bearer(creator))

    assert revoked.status_code == 200
    assert (await client.get(KEYS, headers=bearer(creator))).status_code == 200
