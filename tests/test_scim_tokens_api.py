"""SCIM token management routes and the SCIM authenticator (phase 10, slice 8).

FakeDriver, a temp SQLite database and the ASGI client; daemon-free. With ``scim_enabled`` off
the routes are absent; with it on an org admin mints, lists and revokes tokens. No response
carries a hash. ``auth/scim.py`` refuses unknown, wrong-secret, revoked and non-SCIM credentials.
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
from sandfort.auth.api_keys import generate_api_key, parse_prefix
from sandfort.auth.scim import SCIM_AUTH_STATE_ATTR, ScimAuthenticator
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import AuditEvent
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.scim import ScimToken
from sandfort.domain.user import OrgRole, role_scopes
from sandfort.errors import Unauthorized
from sandfort.ids import SCIM_TOKEN, has_prefix, new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
TOKENS = "/v1/org/scim-tokens"
ADMIN_SCOPES = frozenset(Scope)
DEVELOPER_SCOPES = role_scopes(OrgRole.DEVELOPER)
KEY_ADMIN_ONLY = frozenset({Scope.API_KEYS_ADMIN})
HASH_MARKER = "v1$"
MAX_ACTIVE = 5


@dataclass
class World:
    app: FastAPI
    client: httpx.AsyncClient
    org_id: str
    admin_key: str


@asynccontextmanager
async def open_world(tmp_path: Path, *, scim_enabled: bool) -> AsyncIterator[World]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'scim_tokens_api.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(
        driver="fake", database_url=url, api_key_pepper=PEPPER, scim_enabled=scim_enabled
    )
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
    async with open_world(tmp_path, scim_enabled=True) as opened:
        yield opened


@pytest.fixture
async def off_world(tmp_path: Path) -> AsyncIterator[World]:
    async with open_world(tmp_path, scim_enabled=False) as opened:
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


async def token_audit_rows(world: World) -> list[AuditEvent]:
    async with UnitOfWork(world.app.state.session_factory) as uow:
        rows = await uow.audit.list(world.org_id, limit=200)
    return [row for row in rows if row.target_type == "scim_token"]


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def authenticator(world: World) -> ScimAuthenticator:
    value = getattr(world.app.state, SCIM_AUTH_STATE_ATTR)
    assert isinstance(value, ScimAuthenticator)
    return value


async def mint(
    world: World,
    *,
    name: str = "okta",
    max_role: OrgRole = OrgRole.DEVELOPER,
    caller: str | None = None,
) -> httpx.Response:
    body: dict[str, Any] = {"name": name, "max_role": max_role.value}
    return await world.client.post(TOKENS, json=body, headers=auth(caller or world.admin_key))


async def minted(world: World, **kwargs: Any) -> dict[str, Any]:
    response = await mint(world, **kwargs)
    assert response.status_code == 201
    data: dict[str, Any] = response.json()["data"]
    return data


async def stored_tokens(world: World, org_id: str | None = None) -> list[ScimToken]:
    async with UnitOfWork(world.app.state.session_factory) as uow:
        return list(await uow.scim_tokens.list_for_org(org_id or world.org_id))


def revoke_path(token_id: str) -> str:
    return f"{TOKENS}/{token_id}"


# --- the setting gates the routes ---------------------------------------------------------


async def test_routes_are_absent_when_scim_is_off(off_world: World) -> None:
    headers = auth(off_world.admin_key)

    created = await off_world.client.post(
        TOKENS, json={"name": "okta", "max_role": "viewer"}, headers=headers
    )
    listed = await off_world.client.get(TOKENS, headers=headers)
    revoked = await off_world.client.delete(revoke_path("stk_missing"), headers=headers)

    assert created.status_code == 404
    assert listed.status_code == 404
    assert revoked.status_code == 404
    assert await stored_tokens(off_world) == []


async def test_authenticator_is_wired_even_when_scim_is_off(off_world: World) -> None:
    with pytest.raises(Unauthorized):
        await authenticator(off_world).authenticate(
            "Bearer " + generate_api_key(PEPPER, env="scim").key
        )


# --- mint ---------------------------------------------------------------------------------


async def test_an_admin_mints_a_token_shown_once(world: World) -> None:
    response = await mint(world, name="  Okta prod ", max_role=OrgRole.DEVELOPER)

    assert response.status_code == 201
    body = response.json()
    assert body["success"] is True
    data = body["data"]
    assert data["token"].startswith("sf_scim_")
    assert parse_prefix(data["token"]) == data["prefix"]
    assert has_prefix(data["id"], SCIM_TOKEN)
    assert data["name"] == "Okta prod"
    assert data["max_role"] == OrgRole.DEVELOPER.value
    assert data["last_used_at"] is None
    assert data["revoked_at"] is None
    assert data["created_by"] is not None


async def test_the_mint_response_never_contains_a_hash(world: World) -> None:
    response = await mint(world)

    stored = await stored_tokens(world)
    assert len(stored) == 1
    assert stored[0].secret_hash not in response.text
    assert HASH_MARKER not in response.text
    assert "secret_hash" not in response.json()["data"]


async def test_only_a_hash_is_stored_never_the_token(world: World) -> None:
    data = await minted(world)

    stored = await stored_tokens(world)
    assert stored[0].secret_hash.startswith(HASH_MARKER)
    assert data["token"] not in stored[0].secret_hash
    assert stored[0].prefix == data["prefix"]


async def test_minting_is_audited_without_the_token(world: World) -> None:
    data = await minted(world, name="entra")

    rows = await token_audit_rows(world)

    assert [row.action for row in rows] == ["scim_token.created"]
    assert rows[0].target_id == data["id"]
    assert rows[0].details["name"] == "entra"
    assert rows[0].details["prefix"] == data["prefix"]
    assert data["token"] not in str(rows[0].details)
    assert HASH_MARKER not in str(rows[0].details)


async def test_a_minter_lacking_the_role_scopes_gets_403(world: World) -> None:
    limited = await seed_key(world.app, world.org_id, KEY_ADMIN_ONLY)

    response = await mint(world, max_role=OrgRole.DEVELOPER, caller=limited)

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"
    assert await stored_tokens(world) == []


async def test_the_sixth_active_token_is_refused(world: World) -> None:
    for index in range(MAX_ACTIVE):
        assert (await mint(world, name=f"t{index}")).status_code == 201

    response = await mint(world, name="one-too-many")

    assert response.status_code == 409
    assert len(await stored_tokens(world)) == MAX_ACTIVE


async def test_a_bad_role_or_empty_name_is_a_client_error(world: World) -> None:
    headers = auth(world.admin_key)

    bad_role = await world.client.post(
        TOKENS, json={"name": "x", "max_role": "root"}, headers=headers
    )
    no_name = await world.client.post(
        TOKENS, json={"name": "", "max_role": "viewer"}, headers=headers
    )

    assert 400 <= bad_role.status_code < 500
    assert 400 <= no_name.status_code < 500
    assert await stored_tokens(world) == []


# --- list ---------------------------------------------------------------------------------


async def test_listing_returns_metadata_without_token_or_hash(world: World) -> None:
    first = await minted(world, name="one", max_role=OrgRole.VIEWER)
    second = await minted(world, name="two", max_role=OrgRole.ADMIN)

    response = await world.client.get(TOKENS, headers=auth(world.admin_key))

    assert response.status_code == 200
    data = response.json()["data"]
    assert {item["id"] for item in data} == {first["id"], second["id"]}
    for item in data:
        assert "token" not in item
        assert "secret_hash" not in item
    assert first["token"] not in response.text
    assert second["token"] not in response.text
    assert HASH_MARKER not in response.text
    by_id = {item["id"]: item for item in data}
    assert by_id[first["id"]]["max_role"] == OrgRole.VIEWER.value
    assert by_id[second["id"]]["prefix"] == second["prefix"]


async def test_listing_is_limited_to_the_callers_org(world: World) -> None:
    other_org = await add_org(world.app, "globex")
    other_admin = await seed_key(world.app, other_org, ADMIN_SCOPES)
    await minted(world, name="mine")
    foreign = await minted(world, name="theirs", caller=other_admin)

    response = await world.client.get(TOKENS, headers=auth(world.admin_key))

    ids = [item["id"] for item in response.json()["data"]]
    assert foreign["id"] not in ids
    assert len(ids) == 1


# --- revoke -------------------------------------------------------------------------------


async def test_an_admin_revokes_a_token(world: World) -> None:
    data = await minted(world)

    response = await world.client.delete(revoke_path(data["id"]), headers=auth(world.admin_key))

    assert response.status_code == 200
    revoked = response.json()["data"]
    assert revoked["id"] == data["id"]
    assert revoked["revoked_at"] is not None
    assert "token" not in revoked
    assert HASH_MARKER not in response.text
    listed = (await world.client.get(TOKENS, headers=auth(world.admin_key))).json()["data"]
    assert listed[0]["revoked_at"] is not None


async def test_revoking_twice_is_idempotent_and_audits_once(world: World) -> None:
    data = await minted(world)
    headers = auth(world.admin_key)

    first = await world.client.delete(revoke_path(data["id"]), headers=headers)
    second = await world.client.delete(revoke_path(data["id"]), headers=headers)

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["data"]["revoked_at"] == first.json()["data"]["revoked_at"]
    actions = [row.action for row in await token_audit_rows(world)]
    assert actions.count("scim_token.revoked") == 1


async def test_revoking_an_unknown_token_is_404(world: World) -> None:
    response = await world.client.delete(
        revoke_path("stk_doesnotexist"), headers=auth(world.admin_key)
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"


async def test_another_orgs_token_cannot_be_revoked(world: World) -> None:
    other_org = await add_org(world.app, "globex")
    other_admin = await seed_key(world.app, other_org, ADMIN_SCOPES)
    foreign = await minted(world, caller=other_admin)

    response = await world.client.delete(
        revoke_path(foreign["id"]), headers=auth(world.admin_key)
    )

    assert response.status_code == 404
    assert (await stored_tokens(world, other_org))[0].revoked_at is None


# --- authorization ------------------------------------------------------------------------


async def test_a_developer_key_gets_403_on_every_route(world: World) -> None:
    developer = await seed_key(world.app, world.org_id, DEVELOPER_SCOPES)
    data = await minted(world)
    headers = auth(developer)

    created = await mint(world, caller=developer)
    listed = await world.client.get(TOKENS, headers=headers)
    revoked = await world.client.delete(revoke_path(data["id"]), headers=headers)

    for response in (created, listed, revoked):
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "FORBIDDEN"
    remaining = await stored_tokens(world)
    assert len(remaining) == 1
    assert remaining[0].revoked_at is None


async def test_calls_without_credentials_get_401(world: World) -> None:
    created = await world.client.post(TOKENS, json={"name": "x", "max_role": "viewer"})
    listed = await world.client.get(TOKENS)

    assert created.status_code == 401
    assert listed.status_code == 401


async def test_a_scim_token_is_a_401_outside_scim_paths(world: World) -> None:
    data = await minted(world, max_role=OrgRole.ADMIN)

    listed = await world.client.get(TOKENS, headers=auth(data["token"]))
    other = await world.client.get("/v1/api-keys", headers=auth(data["token"]))

    assert listed.status_code == 401
    assert other.status_code == 401


# --- exported spec ------------------------------------------------------------------------


async def test_the_routes_stay_out_of_the_exported_schema(world: World) -> None:
    paths = world.app.openapi()["paths"]

    assert not [path for path in paths if path.startswith(TOKENS)]
    assert not [path for path in paths if path.startswith("/scim")]


# --- the authenticator --------------------------------------------------------------------


async def test_a_valid_token_yields_the_scim_principal(world: World) -> None:
    data = await minted(world, max_role=OrgRole.DEVELOPER)

    principal = await authenticator(world).authenticate("Bearer " + data["token"])

    assert principal.org_id == world.org_id
    assert principal.key_id == data["id"]
    assert principal.scopes == role_scopes(OrgRole.DEVELOPER)
    assert Scope.API_KEYS_ADMIN not in principal.scopes
    assert principal.is_platform_admin is False
    assert principal.user_id is None


async def test_the_principal_scopes_follow_the_ceiling(world: World) -> None:
    admin = await minted(world, name="a", max_role=OrgRole.ADMIN)
    viewer = await minted(world, name="v", max_role=OrgRole.VIEWER)

    admin_principal = await authenticator(world).authenticate("Bearer " + admin["token"])
    viewer_principal = await authenticator(world).authenticate("Bearer " + viewer["token"])

    assert admin_principal.scopes == role_scopes(OrgRole.ADMIN)
    assert viewer_principal.scopes == role_scopes(OrgRole.VIEWER)


async def test_authenticating_touches_last_used(world: World) -> None:
    data = await minted(world)
    assert (await stored_tokens(world))[0].last_used_at is None

    await authenticator(world).authenticate("Bearer " + data["token"])

    assert (await stored_tokens(world))[0].last_used_at is not None


async def test_an_unknown_token_is_refused(world: World) -> None:
    unknown = generate_api_key(PEPPER, env="scim").key

    with pytest.raises(Unauthorized) as raised:
        await authenticator(world).authenticate("Bearer " + unknown)

    assert unknown not in str(raised.value)


async def test_a_wrong_secret_under_a_known_prefix_is_refused(world: World) -> None:
    data = await minted(world)
    token: str = data["token"]
    swapped = "B" if token[-1] == "A" else "A"
    forged = token[:-1] + swapped

    with pytest.raises(Unauthorized):
        await authenticator(world).authenticate("Bearer " + forged)

    assert (await stored_tokens(world))[0].last_used_at is None


async def test_a_revoked_token_is_refused(world: World) -> None:
    data = await minted(world)
    scim_auth = authenticator(world)
    await scim_auth.authenticate("Bearer " + data["token"])
    await world.client.delete(revoke_path(data["id"]), headers=auth(world.admin_key))

    with pytest.raises(Unauthorized) as raised:
        await scim_auth.authenticate("Bearer " + data["token"])

    assert "revoked" in str(raised.value)
    assert data["token"] not in str(raised.value)


async def test_an_api_key_is_refused_by_the_authenticator(world: World) -> None:
    with pytest.raises(Unauthorized):
        await authenticator(world).authenticate("Bearer " + world.admin_key)


async def test_malformed_and_missing_credentials_are_refused(world: World) -> None:
    scim_auth = authenticator(world)

    for header in (None, "", "Bearer", "Basic abc", "Bearer not-a-token"):
        with pytest.raises(Unauthorized):
            await scim_auth.authenticate(header)
