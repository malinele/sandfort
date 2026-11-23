"""SCIM ``/scim/v2`` Users routes over HTTP (phase 10, slice 9).

FakeDriver, a temp SQLite database and the ASGI client; daemon-free. Every request carries a SCIM
token minted through ``/v1/org/scim-tokens`` and an ``application/scim+json`` body: create, get,
filter hit and miss, paging, replace, the three PATCH shapes, deactivation and delete. The world
and request helpers here are shared with ``test_scim_auth.py`` and ``test_scim_openapi.py``.
"""

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
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
from sandfort.domain.user import OrgRole
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SESSION_SECRET = "scim-session-secret-for-the-tests-0123"
SCIM_TYPE = "application/scim+json"
SCIM = "/scim/v2"
USERS = f"{SCIM}/Users"
TOKENS = "/v1/org/scim-tokens"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ROLES_PRIMARY = 'roles[primary eq "True"].value'


@dataclass(frozen=True)
class World:
    app: FastAPI
    client: httpx.AsyncClient
    org_id: str
    admin_key: str
    token: str  # a SCIM token with max_role admin; empty when SCIM is off
    token_id: str


@asynccontextmanager
async def open_world(tmp_path: Path, *, scim_enabled: bool = True) -> AsyncIterator[World]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'scim_api.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(
        driver="fake",
        database_url=url,
        api_key_pepper=PEPPER,
        session_secret=SESSION_SECRET,
        scim_enabled=scim_enabled,
    )
    app = create_app(settings)
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            org_id = await add_org(app, "acme")
            world = World(app, http, org_id, await seed_key(app, org_id), "", "")
            if scim_enabled:
                minted = await mint_token(world, OrgRole.ADMIN)
                world = replace(world, token=minted["token"], token_id=minted["id"])
            yield world
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


async def seed_key(app: FastAPI, org_id: str) -> str:
    """An API key holding every scope (an org admin key, not a member)."""
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="seed",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset(Scope),
        created_at=T0,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


def bearer(credential: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {credential}"}


async def mint_token(
    world: World, max_role: OrgRole, *, name: str = "okta", admin_key: str | None = None
) -> dict[str, Any]:
    """Mint a SCIM token through the management route; ``token`` and ``id`` are in the result."""
    body = {"name": name, "max_role": max_role.value}
    headers = bearer(admin_key or world.admin_key)
    response = await world.client.post(TOKENS, json=body, headers=headers)
    assert response.status_code == 201
    data: dict[str, Any] = response.json()["data"]
    return data


async def send(
    world: World,
    method: str,
    path: str,
    body: object = None,
    *,
    token: str | None = None,
    content_type: str = SCIM_TYPE,
    params: dict[str, Any] | None = None,
) -> httpx.Response:
    """A SCIM request with the world's token; a ``str`` body is sent as is (malformed JSON)."""
    headers = bearer(world.token if token is None else token)
    content: str | None = None
    if body is not None:
        headers["Content-Type"] = content_type
        content = body if isinstance(body, str) else json.dumps(body)
    return await world.client.request(
        method, path, content=content, headers=headers, params=params
    )


def role_of(name: str) -> list[dict[str, Any]]:
    return [{"value": name, "primary": True}]


def user_body(email: str, *, role: str | None = None, **extra: Any) -> dict[str, Any]:
    """A create or replace body; ``extra`` adds SCIM attributes such as ``externalId``."""
    body: dict[str, Any] = {
        "schemas": [USER_SCHEMA],
        "userName": email,
        "emails": [{"value": email, "type": "work", "primary": True}],
        "active": True,
        **extra,
    }
    return body if role is None else {**body, "roles": role_of(role)}


def patch(*operations: dict[str, Any]) -> dict[str, Any]:
    return {"schemas": [PATCH_SCHEMA], "Operations": list(operations)}


def user_path(user_id: str) -> str:
    return f"{USERS}/{user_id}"


async def create(world: World, email: str, **kwargs: Any) -> dict[str, Any]:
    response = await send(world, "POST", USERS, user_body(email, **kwargs))
    assert response.status_code == 201
    resource: dict[str, Any] = response.json()
    return resource


def assert_scim_error(response: httpx.Response, status: int, scim_type: str | None = None) -> None:
    assert response.status_code == status
    assert response.headers["content-type"] == SCIM_TYPE
    body = response.json()
    assert body["schemas"] == [ERROR_SCHEMA]
    assert body["status"] == str(status)
    assert body.get("scimType") == scim_type
    assert isinstance(body["detail"], str)


# --- create, get and list -----------------------------------------------------------------


async def test_create_answers_201_with_the_resource_and_its_location(world: World) -> None:
    body = user_body("Ada@Example.com", role="developer", externalId="okta-1", displayName="Ada")

    response = await send(world, "POST", USERS, body)
    defaulted = await create(world, "bob@example.com")

    assert response.status_code == 201
    assert response.headers["content-type"] == SCIM_TYPE
    resource = response.json()
    assert resource["schemas"] == [USER_SCHEMA]
    assert resource["id"].startswith("usr_")
    assert (resource["userName"], resource["displayName"]) == ("ada@example.com", "Ada")
    assert (resource["externalId"], resource["active"]) == ("okta-1", True)
    assert resource["roles"] == role_of("developer")
    assert resource["meta"]["location"] == f"http://test{user_path(resource['id'])}"
    assert response.headers["location"] == resource["meta"]["location"]
    assert defaulted["roles"] == role_of("viewer")  # no role on create: scim_default_role


async def test_get_returns_the_member_and_an_unknown_id_is_404(world: World) -> None:
    created = await create(world, "ada@example.com", role="developer", externalId="e1")

    found = await send(world, "GET", user_path(created["id"]))
    missing = await send(world, "GET", user_path("usr_missing"))

    assert found.status_code == 200
    assert found.headers["content-type"] == SCIM_TYPE
    for key in ("id", "userName", "roles", "externalId", "active"):
        assert found.json()[key] == created[key]
    assert_scim_error(missing, 404)


async def test_a_filter_hit_a_miss_and_an_unsupported_filter(world: World) -> None:
    created = await create(world, "ada@example.com")
    await create(world, "bob@example.com")

    hit = await send(world, "GET", USERS, params={"filter": 'userName eq "ADA@example.com"'})
    miss = await send(world, "GET", USERS, params={"filter": 'userName eq "eve@example.com"'})
    refused = await send(world, "GET", USERS, params={"filter": 'externalId eq "x"'})

    assert hit.status_code == 200
    assert hit.headers["content-type"] == SCIM_TYPE
    assert hit.json()["schemas"] == [LIST_SCHEMA]
    assert hit.json()["totalResults"] == 1
    assert [item["id"] for item in hit.json()["Resources"]] == [created["id"]]
    assert miss.status_code == 200
    assert (miss.json()["totalResults"], miss.json()["Resources"]) == (0, [])
    assert_scim_error(refused, 400, "invalidFilter")


async def test_start_index_and_count_page_the_member_list(world: World) -> None:
    for name in ("ada", "bob", "cyd"):
        await create(world, f"{name}@example.com")
    everyone = (await send(world, "GET", USERS)).json()
    ids = [item["id"] for item in everyone["Resources"]]

    page = (await send(world, "GET", USERS, params={"startIndex": 2, "count": 1})).json()
    counted = (await send(world, "GET", USERS, params={"count": 0})).json()
    past_end = (await send(world, "GET", USERS, params={"startIndex": 9})).json()

    assert (everyone["totalResults"], len(ids)) == (3, 3)
    assert (page["startIndex"], page["itemsPerPage"], page["totalResults"]) == (2, 1, 3)
    assert [item["id"] for item in page["Resources"]] == ids[1:2]
    assert (counted["totalResults"], counted["Resources"]) == (3, [])
    assert past_end["Resources"] == []


# --- replace and PATCH --------------------------------------------------------------------


async def test_replace_sets_given_values_and_keeps_omitted_ones(world: World) -> None:
    created = await create(world, "ada@example.com", role="developer", externalId="e1")
    path = user_path(created["id"])
    changed_body = user_body("ada@example.com", role="viewer", externalId="e2")

    kept = await send(world, "PUT", path, user_body("ada@example.com"))
    changed = await send(world, "PUT", path, changed_body)

    assert kept.status_code == 200
    assert kept.headers["content-type"] == SCIM_TYPE
    assert (kept.json()["roles"], kept.json()["externalId"]) == (role_of("developer"), "e1")
    assert (changed.json()["roles"], changed.json()["externalId"]) == (role_of("viewer"), "e2")


async def test_patch_active_false_in_the_okta_and_entra_forms(world: World) -> None:
    okta = await create(world, "ada@example.com")
    entra = await create(world, "bob@example.com")
    by_value = patch({"op": "replace", "value": {"active": False}})
    by_path = patch({"op": "Replace", "path": "active", "value": "False"})

    first = await send(world, "PATCH", user_path(okta["id"]), by_value)
    second = await send(world, "PATCH", user_path(entra["id"]), by_path)

    for response, created in ((first, okta), (second, entra)):
        assert response.status_code == 200
        assert response.headers["content-type"] == SCIM_TYPE
        assert response.json()["id"] == created["id"]
        assert response.json()["active"] is False
        assert (await send(world, "GET", user_path(created["id"]))).status_code == 404


async def test_patch_replaces_and_removes_the_external_id(world: World) -> None:
    created = await create(world, "ada@example.com", externalId="e1")
    path = user_path(created["id"])
    by_path = {"op": "replace", "path": "externalId", "value": "e2"}
    by_value = {"op": "replace", "value": {"externalId": "e3", "displayName": "ada"}}

    first = await send(world, "PATCH", path, patch(by_path))
    second = await send(world, "PATCH", path, patch(by_value))  # an unchanged name is a no-op
    removed = await send(world, "PATCH", path, patch({"op": "remove", "path": "externalId"}))

    assert first.json()["externalId"] == "e2"
    assert second.json()["externalId"] == "e3"
    assert removed.status_code == 200
    assert "externalId" not in removed.json()


async def test_patch_sets_the_role_by_list_and_by_primary_path(world: World) -> None:
    created = await create(world, "ada@example.com", role="developer")
    path = user_path(created["id"])
    by_list = {"op": "add", "path": "roles", "value": role_of("viewer")}
    by_primary = {"op": "replace", "path": ROLES_PRIMARY, "value": "admin"}

    listed = await send(world, "PATCH", path, patch(by_list))
    primary = await send(world, "PATCH", path, patch(by_primary))

    assert listed.status_code == 200
    assert listed.json()["roles"] == role_of("viewer")
    assert primary.json()["roles"] == role_of("admin")


# --- deactivation and delete --------------------------------------------------------------


async def test_replace_deactivates_until_a_create_reuses_the_id(world: World) -> None:
    created = await create(world, "ada@example.com", role="developer", externalId="e1")
    path = user_path(created["id"])
    deactivate = patch({"op": "replace", "path": "active", "value": False})

    first = await send(world, "PUT", path, user_body("ada@example.com", active=False))
    gone = await send(world, "GET", path)
    again = await send(world, "PATCH", path, deactivate)
    revived = await create(world, "ada@example.com")

    assert first.status_code == 200
    assert first.headers["content-type"] == SCIM_TYPE
    assert first.json()["active"] is False
    assert_scim_error(gone, 404)
    assert_scim_error(again, 404)
    assert revived["id"] == created["id"]
    assert revived["roles"] == role_of("viewer")
    assert "externalId" not in revived


async def test_delete_removes_the_membership(world: World) -> None:
    created = await create(world, "ada@example.com")
    path = user_path(created["id"])

    deleted = await send(world, "DELETE", path)
    again = await send(world, "DELETE", path)

    assert deleted.status_code == 204
    assert deleted.content == b""
    assert (await send(world, "GET", path)).status_code == 404
    assert_scim_error(again, 404)
