"""Revoking an API key cascades to its descendants only when the request says so (round 58).

Through the API on the fake driver and a temp SQLite database. ``DELETE /v1/api-keys/{id}``
takes ``cascade`` (query or body, default false). Without it only the key is revoked and the
response lists its live ``dependants``; with it they are revoked and listed. The key's audit
event records the dependant count and the flag, and the cascade also runs for a key that was
already revoked so its leftover children can be cleaned up.
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
from sandfort.domain.events import AuditEvent
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.api_key_admin import KEY_REVOKED

ROOT = Path(__file__).resolve().parents[1]
PEPPER = "test-pepper"
KEYS = "/v1/api-keys"
SANDBOXES = "/v1/sandboxes"
SCOPES = [Scope.SANDBOXES_READ.value, Scope.API_KEYS_ADMIN.value]


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'cascade.db'}"
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
    org = Org(id=new_org_id(), name="School", slug="school", created_at=datetime.now(UTC))
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


@pytest.fixture
async def root(app: FastAPI, org_id: str) -> tuple[str, str]:
    """A seeded admin key with no creator; returns (key id, plaintext key)."""
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="root",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset(Scope(value) for value in SCOPES),
        created_at=datetime.now(UTC),
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return stored.id, generated.key


def bearer(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def mint(client: httpx.AsyncClient, caller: str, name: str = "child") -> dict[str, Any]:
    body = {"name": name, "scopes": SCOPES}
    response = await client.post(KEYS, json=body, headers=bearer(caller))
    assert response.status_code == 201
    data: dict[str, Any] = response.json()["data"]
    return data


async def revoke(
    client: httpx.AsyncClient, caller: str, key_id: str, cascade: bool | None = None
) -> httpx.Response:
    suffix = "" if cascade is None else f"?cascade={str(cascade).lower()}"
    return await client.delete(f"{KEYS}/{key_id}{suffix}", headers=bearer(caller))


async def revoked_ids(client: httpx.AsyncClient, caller: str) -> set[str]:
    response = await client.get(KEYS, headers=bearer(caller))
    return {row["id"] for row in response.json()["data"] if row["revoked_at"] is not None}


async def revoke_events(app: FastAPI, org_id: str) -> list[AuditEvent]:
    async with UnitOfWork(app.state.session_factory) as uow:
        rows = await uow.audit.list(org_id, limit=200)
    return [row for row in rows if row.action == KEY_REVOKED]


async def test_rotation_keeps_the_new_key_and_its_children_alive_by_default(
    client: httpx.AsyncClient, root: tuple[str, str]
) -> None:
    old_id, old_key = root
    new = await mint(client, old_key, "new-admin")
    grandchild = await mint(client, new["key"], "worker")

    response = await revoke(client, new["key"], old_id)

    data = response.json()["data"]
    assert response.status_code == 200
    assert data["status"] == "revoked"
    assert data["cascade"] is False
    assert {row["id"] for row in data["dependants"]} == {new["id"], grandchild["id"]}
    assert all(row["revoked_at"] is None for row in data["dependants"])
    assert (await client.get(SANDBOXES, headers=bearer(old_key))).status_code == 401
    assert (await client.get(SANDBOXES, headers=bearer(new["key"]))).status_code == 200
    assert (await client.get(SANDBOXES, headers=bearer(grandchild["key"]))).status_code == 200
    assert await revoked_ids(client, new["key"]) == {old_id}


async def test_cascade_revokes_descendants_only(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, root: tuple[str, str]
) -> None:
    root_id, root_key = root
    middle = await mint(client, root_key, "middle")
    sibling = await mint(client, root_key, "sibling")
    child = await mint(client, middle["key"], "child")
    grandchild = await mint(client, child["key"], "grandchild")

    response = await revoke(client, root_key, middle["id"], cascade=True)

    data = response.json()["data"]
    revoked = await revoked_ids(client, root_key)
    assert response.status_code == 200
    assert data["cascade"] is True
    assert {row["id"] for row in data["dependants"]} == {child["id"], grandchild["id"]}
    assert all(row["revoked_at"] is not None for row in data["dependants"])
    assert revoked == {middle["id"], child["id"], grandchild["id"]}
    assert root_id not in revoked
    assert sibling["id"] not in revoked
    assert (await client.get(SANDBOXES, headers=bearer(grandchild["key"]))).status_code == 401
    assert (await client.get(SANDBOXES, headers=bearer(sibling["key"]))).status_code == 200
    events = {event.target_id: event for event in await revoke_events(app, org_id)}
    assert events[middle["id"]].details["cascade"] is True
    assert events[middle["id"]].details["dependants"] == 2
    assert events[child["id"]].details["cascade_from"] == middle["id"]


async def test_audit_event_records_the_count_and_the_flag_without_cascade(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, root: tuple[str, str]
) -> None:
    _, root_key = root
    middle = await mint(client, root_key, "middle")
    await mint(client, middle["key"], "child")

    await revoke(client, root_key, middle["id"])

    (event,) = await revoke_events(app, org_id)
    assert event.target_id == middle["id"]
    assert event.details["cascade"] is False
    assert event.details["dependants"] == 1


async def test_cascade_cleans_the_children_of_an_already_revoked_parent(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, root: tuple[str, str]
) -> None:
    _, root_key = root
    parent = await mint(client, root_key, "parent")
    child = await mint(client, parent["key"], "child")
    await revoke(client, root_key, parent["id"])
    assert child["id"] not in await revoked_ids(client, root_key)
    assert len(await revoke_events(app, org_id)) == 1

    plain = await revoke(client, root_key, parent["id"])
    cleaned = await revoke(client, root_key, parent["id"], cascade=True)

    assert plain.status_code == 200
    assert [row["id"] for row in plain.json()["data"]["dependants"]] == [child["id"]]
    assert cleaned.status_code == 200
    assert [row["id"] for row in cleaned.json()["data"]["dependants"]] == [child["id"]]
    assert await revoked_ids(client, root_key) == {parent["id"], child["id"]}
    assert (await client.get(SANDBOXES, headers=bearer(child["key"]))).status_code == 401
    assert len(await revoke_events(app, org_id)) == 2
    again = await revoke(client, root_key, parent["id"], cascade=True)
    assert again.json()["data"]["dependants"] == []
    assert len(await revoke_events(app, org_id)) == 2


async def test_cascade_may_be_sent_in_the_json_body(
    client: httpx.AsyncClient, root: tuple[str, str]
) -> None:
    _, root_key = root
    parent = await mint(client, root_key, "parent")
    child = await mint(client, parent["key"], "child")

    response = await client.request(
        "DELETE", f"{KEYS}/{parent['id']}", json={"cascade": True}, headers=bearer(root_key)
    )

    assert response.status_code == 200
    assert response.json()["data"]["cascade"] is True
    assert child["id"] in await revoked_ids(client, root_key)


async def test_a_non_boolean_cascade_in_the_body_is_rejected(
    client: httpx.AsyncClient, root: tuple[str, str]
) -> None:
    _, root_key = root
    parent = await mint(client, root_key, "parent")

    response = await client.request(
        "DELETE", f"{KEYS}/{parent['id']}", json={"cascade": "yes"}, headers=bearer(root_key)
    )

    assert response.status_code == 422
    assert parent["id"] not in await revoked_ids(client, root_key)
