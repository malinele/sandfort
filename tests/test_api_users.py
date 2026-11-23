"""Enterprise user administration: ``/v1/org/members`` over the RBAC foundation.

FakeDriver, a temp SQLite database and the ASGI client; daemon-free. Routes are exercised
over HTTP; storage is checked through a fresh unit of work.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.errors import DENIED_ACTION
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import AuditEvent, AuditOutcome
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.user import OrgRole
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
MEMBERS = "/v1/org/members"
# Granting a role needs every scope it maps to, so the org admin key holds the full catalog.
ADMIN_SCOPES = frozenset(Scope)
KEY_ADMIN_SCOPES = frozenset({Scope.API_KEYS_ADMIN})
READ_SCOPES = frozenset({Scope.ORG_READ, Scope.SANDBOXES_READ})
SANDBOX_SCOPES = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})


@dataclass
class World:
    app: FastAPI
    client: httpx.AsyncClient
    org_id: str
    admin_key: str


@asynccontextmanager
async def open_world(tmp_path: Path) -> AsyncIterator[World]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'users.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(driver="fake", database_url=url, api_key_pepper=PEPPER)
    app = create_app(settings)
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            org_id = await add_org(app, "acme")
            admin_key = await seed_key(app, org_id, ADMIN_SCOPES)
            yield World(app, http, org_id, admin_key)
    finally:
        await app.state.engine.dispose()


@pytest.fixture
async def world(tmp_path: Path) -> AsyncIterator[World]:
    async with open_world(tmp_path) as opened:
        yield opened


async def add_org(app: FastAPI, slug: str) -> str:
    org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=T0)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def seed_key(app: FastAPI, org_id: str, scopes: frozenset[Scope]) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="seed",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=scopes,
        created_at=T0,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


async def audit_rows(app: FastAPI, org_id: str) -> list[AuditEvent]:
    async with UnitOfWork(app.state.session_factory) as uow:
        return list(await uow.audit.list(org_id, limit=200))


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def create_member(
    world: World,
    email: str,
    *,
    role: str = OrgRole.DEVELOPER.value,
    caller: str | None = None,
    display_name: str = "Ada Lovelace",
) -> httpx.Response:
    body: dict[str, Any] = {"email": email, "display_name": display_name, "role": role}
    return await world.client.post(MEMBERS, json=body, headers=auth(caller or world.admin_key))


def member_path(user_id: str) -> str:
    return f"{MEMBERS}/{user_id}"


async def change_role(
    world: World, user_id: str, role: str, *, caller: str | None = None
) -> httpx.Response:
    return await world.client.patch(
        member_path(user_id), json={"role": role}, headers=auth(caller or world.admin_key)
    )


async def remove_member(
    world: World, user_id: str, *, caller: str | None = None
) -> httpx.Response:
    return await world.client.delete(
        member_path(user_id), headers=auth(caller or world.admin_key)
    )


async def member_id(world: World, email: str, role: str = OrgRole.DEVELOPER.value) -> str:
    response = await create_member(world, email, role=role)
    assert response.status_code == 201
    user_id: str = response.json()["data"]["user_id"]
    return user_id


async def stored_role(world: World, user_id: str) -> OrgRole | None:
    async with UnitOfWork(world.app.state.session_factory) as uow:
        membership = await uow.memberships.get(user_id, world.org_id)
    return None if membership is None else membership.role


# --- create ------------------------------------------------------------------------------


async def test_creating_a_member_stores_user_and_membership(world: World) -> None:
    response = await create_member(world, "  Ada@Example.COM ", role=OrgRole.ADMIN.value)

    assert response.status_code == 201
    data = response.json()["data"]
    assert data["email"] == "ada@example.com"
    assert data["display_name"] == "Ada Lovelace"
    assert data["role"] == OrgRole.ADMIN.value
    assert data["user_id"].startswith("usr_")
    assert data["disabled_at"] is None
    async with UnitOfWork(world.app.state.session_factory) as uow:
        user = await uow.users.get_by_email("ada@example.com")
        membership = await uow.memberships.get(data["user_id"], world.org_id)
    assert user is not None
    assert user.id == data["user_id"]
    assert membership is not None
    assert membership.role is OrgRole.ADMIN


async def test_creating_a_member_is_audited(world: World) -> None:
    data = (await create_member(world, "grace@example.com")).json()["data"]

    rows = [row for row in await audit_rows(world.app, world.org_id) if row.target_type == "user"]

    actions = [row.action for row in rows]
    assert actions.count("user.created") == 1
    assert actions.count("membership.added") == 1
    assert all(row.target_id == data["user_id"] for row in rows)
    added = next(row for row in rows if row.action == "membership.added")
    assert added.details["role"] == OrgRole.DEVELOPER.value


async def test_an_existing_user_is_reused_in_another_org(world: World) -> None:
    other_org = await add_org(world.app, "globex")
    other_admin = await seed_key(world.app, other_org, ADMIN_SCOPES)
    first = (await create_member(world, "linus@example.com")).json()["data"]

    second = await create_member(
        world, "LINUS@example.com", role=OrgRole.VIEWER.value, caller=other_admin
    )

    assert second.status_code == 201
    assert second.json()["data"]["user_id"] == first["user_id"]
    assert second.json()["data"]["role"] == OrgRole.VIEWER.value
    other_rows = await audit_rows(world.app, other_org)
    assert [row.action for row in other_rows if row.target_type == "user"] == [
        "membership.added"
    ]


async def test_a_duplicate_membership_is_a_conflict(world: World) -> None:
    first = await create_member(world, "ken@example.com")

    second = await create_member(world, "Ken@Example.com", role=OrgRole.ADMIN.value)

    assert first.status_code == 201
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "CONFLICT"
    listed = await world.client.get(MEMBERS, headers=auth(world.admin_key))
    assert len(listed.json()["data"]) == 1


async def test_an_invalid_role_is_a_validation_error(world: World) -> None:
    response = await create_member(world, "eve@example.com", role="owner")

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    listed = await world.client.get(MEMBERS, headers=auth(world.admin_key))
    assert listed.json()["data"] == []


# --- list --------------------------------------------------------------------------------


async def test_listing_returns_the_created_members(world: World) -> None:
    await create_member(world, "a@example.com", role=OrgRole.ADMIN.value)
    await create_member(world, "b@example.com", role=OrgRole.VIEWER.value)

    response = await world.client.get(MEMBERS, headers=auth(world.admin_key))

    assert response.status_code == 200
    roles = {item["email"]: item["role"] for item in response.json()["data"]}
    assert roles == {
        "a@example.com": OrgRole.ADMIN.value,
        "b@example.com": OrgRole.VIEWER.value,
    }


async def test_listing_is_org_scoped(world: World) -> None:
    other_org = await add_org(world.app, "initech")
    other_reader = await seed_key(world.app, other_org, READ_SCOPES)
    await create_member(world, "a@example.com")

    response = await world.client.get(MEMBERS, headers=auth(other_reader))

    assert response.status_code == 200
    assert response.json()["data"] == []


# --- change role -------------------------------------------------------------------------


async def test_changing_a_role_persists_and_returns_it(world: World) -> None:
    user_id = await member_id(world, "ada@example.com")

    response = await change_role(world, user_id, OrgRole.VIEWER.value)

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["user_id"] == user_id
    assert data["email"] == "ada@example.com"
    assert data["role"] == OrgRole.VIEWER.value
    assert await stored_role(world, user_id) is OrgRole.VIEWER
    listed = await world.client.get(MEMBERS, headers=auth(world.admin_key))
    assert [item["role"] for item in listed.json()["data"]] == [OrgRole.VIEWER.value]


async def test_changing_a_role_is_audited(world: World) -> None:
    user_id = await member_id(world, "ada@example.com")

    await change_role(world, user_id, OrgRole.ADMIN.value)

    rows = await audit_rows(world.app, world.org_id)
    changed = [row for row in rows if row.action == "membership.role_changed"]
    assert len(changed) == 1
    assert changed[0].target_type == "user"
    assert changed[0].target_id == user_id
    assert changed[0].details["from_role"] == OrgRole.DEVELOPER.value
    assert changed[0].details["role"] == OrgRole.ADMIN.value


async def test_changing_to_the_same_role_is_a_no_op(world: World) -> None:
    user_id = await member_id(world, "ada@example.com", OrgRole.VIEWER.value)
    before = len(await audit_rows(world.app, world.org_id))

    response = await change_role(world, user_id, OrgRole.VIEWER.value)

    assert response.status_code == 200
    assert response.json()["data"]["role"] == OrgRole.VIEWER.value
    assert len(await audit_rows(world.app, world.org_id)) == before


async def test_an_invalid_new_role_is_a_validation_error(world: World) -> None:
    user_id = await member_id(world, "ada@example.com")

    response = await change_role(world, user_id, "owner")

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert await stored_role(world, user_id) is OrgRole.DEVELOPER


# --- remove ------------------------------------------------------------------------------


async def test_removing_a_member_omits_them_from_the_listing(world: World) -> None:
    removed_id = await member_id(world, "a@example.com")
    await member_id(world, "b@example.com")

    response = await remove_member(world, removed_id)

    assert response.status_code == 204
    assert response.content == b""
    listed = await world.client.get(MEMBERS, headers=auth(world.admin_key))
    assert [item["email"] for item in listed.json()["data"]] == ["b@example.com"]
    assert await stored_role(world, removed_id) is None
    async with UnitOfWork(world.app.state.session_factory) as uow:
        assert await uow.users.get(removed_id) is not None


async def test_removing_a_member_is_audited(world: World) -> None:
    user_id = await member_id(world, "a@example.com", OrgRole.VIEWER.value)

    await remove_member(world, user_id)

    rows = await audit_rows(world.app, world.org_id)
    removed = [row for row in rows if row.action == "membership.removed"]
    assert len(removed) == 1
    assert removed[0].target_id == user_id
    assert removed[0].details["role"] == OrgRole.VIEWER.value


async def test_a_removed_member_can_be_added_again(world: World) -> None:
    user_id = await member_id(world, "a@example.com")
    await remove_member(world, user_id)

    again = await create_member(world, "a@example.com", role=OrgRole.VIEWER.value)

    assert again.status_code == 201
    assert again.json()["data"]["user_id"] == user_id
    assert await stored_role(world, user_id) is OrgRole.VIEWER


# --- unknown members ---------------------------------------------------------------------


async def test_changing_an_unknown_member_is_not_found(world: World) -> None:
    response = await change_role(world, "usr_unknown", OrgRole.VIEWER.value)

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"


async def test_removing_an_unknown_member_is_not_found(world: World) -> None:
    response = await remove_member(world, "usr_unknown")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"


async def test_a_member_of_another_org_is_not_found(world: World) -> None:
    other_org = await add_org(world.app, "globex")
    other_admin = await seed_key(world.app, other_org, ADMIN_SCOPES)
    user_id = await member_id(world, "a@example.com")

    changed = await change_role(world, user_id, OrgRole.VIEWER.value, caller=other_admin)
    removed = await remove_member(world, user_id, caller=other_admin)

    assert changed.status_code == 404
    assert removed.status_code == 404
    assert await stored_role(world, user_id) is OrgRole.DEVELOPER


# --- last admin --------------------------------------------------------------------------


async def test_the_last_admin_cannot_be_demoted(world: World) -> None:
    admin_id = await member_id(world, "root@example.com", OrgRole.ADMIN.value)
    before = len(await audit_rows(world.app, world.org_id))

    response = await change_role(world, admin_id, OrgRole.DEVELOPER.value)

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "INVALID_STATE"
    assert await stored_role(world, admin_id) is OrgRole.ADMIN
    rows = await audit_rows(world.app, world.org_id)
    assert len(rows) == before + 1
    assert rows[-1].action == DENIED_ACTION
    assert rows[-1].outcome is AuditOutcome.DENIED


async def test_the_last_admin_cannot_be_removed(world: World) -> None:
    admin_id = await member_id(world, "root@example.com", OrgRole.ADMIN.value)
    await member_id(world, "dev@example.com")
    before = len(await audit_rows(world.app, world.org_id))

    response = await remove_member(world, admin_id)

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "INVALID_STATE"
    assert await stored_role(world, admin_id) is OrgRole.ADMIN
    rows = await audit_rows(world.app, world.org_id)
    assert len(rows) == before + 1
    assert rows[-1].action == DENIED_ACTION
    assert rows[-1].outcome is AuditOutcome.DENIED


async def test_an_admin_can_be_demoted_or_removed_while_another_remains(world: World) -> None:
    first = await member_id(world, "first@example.com", OrgRole.ADMIN.value)
    second = await member_id(world, "second@example.com", OrgRole.ADMIN.value)

    demoted = await change_role(world, first, OrgRole.VIEWER.value)
    blocked = await remove_member(world, second)

    assert demoted.status_code == 200
    assert blocked.status_code == 409
    assert await stored_role(world, first) is OrgRole.VIEWER
    assert await stored_role(world, second) is OrgRole.ADMIN
    removed = await remove_member(world, first)
    assert removed.status_code == 204


# --- scopes ------------------------------------------------------------------------------


async def test_a_key_without_the_admin_scope_cannot_create(world: World) -> None:
    reader = await seed_key(world.app, world.org_id, READ_SCOPES)

    response = await create_member(world, "mallory@example.com", caller=reader)

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


async def test_a_key_without_the_admin_scope_cannot_change_a_role(world: World) -> None:
    user_id = await member_id(world, "a@example.com")
    reader = await seed_key(world.app, world.org_id, READ_SCOPES)

    response = await change_role(world, user_id, OrgRole.ADMIN.value, caller=reader)

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"
    assert await stored_role(world, user_id) is OrgRole.DEVELOPER


async def test_a_key_without_the_admin_scope_cannot_remove(world: World) -> None:
    user_id = await member_id(world, "a@example.com")
    reader = await seed_key(world.app, world.org_id, READ_SCOPES)

    response = await remove_member(world, user_id, caller=reader)

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"
    assert await stored_role(world, user_id) is OrgRole.DEVELOPER


async def test_a_key_admin_only_key_cannot_create_an_admin_member(world: World) -> None:
    key_admin = await seed_key(world.app, world.org_id, KEY_ADMIN_SCOPES)
    before = len(await audit_rows(world.app, world.org_id))

    response = await create_member(
        world, "mallory@example.com", role=OrgRole.ADMIN.value, caller=key_admin
    )

    assert response.status_code == 403
    error = response.json()["error"]
    assert error["code"] == "FORBIDDEN"
    assert Scope.AUDIT_READ.value in error["details"]["excess_scopes"]
    assert Scope.API_KEYS_ADMIN.value not in error["details"]["excess_scopes"]
    listed = await world.client.get(MEMBERS, headers=auth(world.admin_key))
    assert listed.json()["data"] == []
    rows = await audit_rows(world.app, world.org_id)
    assert len(rows) == before + 1
    assert rows[-1].action == DENIED_ACTION
    assert rows[-1].outcome is AuditOutcome.DENIED


async def test_a_key_admin_only_key_cannot_make_a_member_admin(world: World) -> None:
    user_id = await member_id(world, "a@example.com")
    key_admin = await seed_key(world.app, world.org_id, KEY_ADMIN_SCOPES)
    before = len(await audit_rows(world.app, world.org_id))

    response = await change_role(world, user_id, OrgRole.ADMIN.value, caller=key_admin)

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"
    assert await stored_role(world, user_id) is OrgRole.DEVELOPER
    rows = await audit_rows(world.app, world.org_id)
    assert len(rows) == before + 1
    assert rows[-1].action == DENIED_ACTION
    assert rows[-1].outcome is AuditOutcome.DENIED


async def test_a_full_scope_key_can_create_and_promote_an_admin(world: World) -> None:
    full = await seed_key(world.app, world.org_id, frozenset(Scope))
    user_id = await member_id(world, "a@example.com")

    created = await create_member(
        world, "root@example.com", role=OrgRole.ADMIN.value, caller=full
    )
    promoted = await change_role(world, user_id, OrgRole.ADMIN.value, caller=full)

    assert created.status_code == 201
    assert created.json()["data"]["role"] == OrgRole.ADMIN.value
    assert promoted.status_code == 200
    assert await stored_role(world, user_id) is OrgRole.ADMIN


async def test_a_read_only_key_can_list(world: World) -> None:
    await create_member(world, "a@example.com")
    reader = await seed_key(world.app, world.org_id, READ_SCOPES)

    response = await world.client.get(MEMBERS, headers=auth(reader))

    assert response.status_code == 200
    assert [item["email"] for item in response.json()["data"]] == ["a@example.com"]


async def test_a_key_without_org_read_cannot_list(world: World) -> None:
    sandboxes_key = await seed_key(world.app, world.org_id, SANDBOX_SCOPES)

    response = await world.client.get(MEMBERS, headers=auth(sandboxes_key))

    assert response.status_code == 403


async def test_member_routes_require_authentication(world: World) -> None:
    listed = await world.client.get(MEMBERS)
    body = {"email": "x@example.com", "display_name": "X", "role": "viewer"}
    created = await world.client.post(MEMBERS, json=body)
    changed = await world.client.patch(member_path("usr_x"), json={"role": "viewer"})
    removed = await world.client.delete(member_path("usr_x"))

    assert listed.status_code == 401
    assert created.status_code == 401
    assert changed.status_code == 401
    assert removed.status_code == 401
