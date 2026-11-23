"""SCIM authentication, member guards and refusals over HTTP (phase 10, slice 9).

Only a SCIM token opens ``/scim/v2``: no credentials, an API key, a session token and a revoked
token are 401 in the SCIM error shape, and a SCIM token is 401 on ``/v1/sandboxes``. The role
ceiling and the last-admin guard of ``UserAdminService`` hold for SCIM writes, a deactivated
member's session token stops working at the next request, a token never sees another org, the
rate limiter answers 429 per SCIM token, uniqueness and immutability are refused in SCIM terms, a
refused PATCH changes nothing, and every write is audited with the SCIM token as the actor.
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sandfort.api.middleware.rate_limit import RATE_LIMITER_ATTR, TokenBucketRateLimiter
from sandfort.auth.session_tokens import mint_session_token
from sandfort.clock import FrozenClock
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import AuditEvent
from sandfort.domain.user import OrgRole
from test_scim_api import (
    ROLES_PRIMARY,
    SCIM,
    SESSION_SECRET,
    T0,
    TOKENS,
    USERS,
    World,
    add_org,
    assert_scim_error,
    bearer,
    create,
    mint_token,
    open_world,
    patch,
    role_of,
    seed_key,
    send,
    user_body,
    user_path,
)

SESSION_TTL_S = 600
MEMBERS = "/v1/org/members"
SANDBOXES = "/v1/sandboxes"


@pytest.fixture
async def world(tmp_path: Path) -> AsyncIterator[World]:
    async with open_world(tmp_path) as opened:
        yield opened


def session_headers(world: World, user_id: str, role: OrgRole) -> dict[str, str]:
    """A live session token for ``user_id`` in the world's org, as the SSO exchange mints it."""
    token = mint_session_token(
        SESSION_SECRET,
        user_id=user_id,
        org_id=world.org_id,
        role=role,
        now=datetime.now(UTC),
        ttl_s=SESSION_TTL_S,
    )
    return bearer(token)


async def audit_rows(world: World, user_id: str) -> list[AuditEvent]:
    async with UnitOfWork(world.app.state.session_factory) as uow:
        return list(await uow.audit.list(world.org_id, target_id=user_id, limit=200))


# --- only a SCIM token opens /scim/v2 -----------------------------------------------------


async def test_a_request_without_credentials_is_401(world: World) -> None:
    users = await world.client.get(USERS)
    discovery = await world.client.get(f"{SCIM}/ServiceProviderConfig")

    assert_scim_error(users, 401)
    assert_scim_error(discovery, 401)


async def test_an_api_key_is_401_on_scim_paths(world: World) -> None:
    key = world.admin_key

    listed = await send(world, "GET", USERS, token=key)
    discovery = await send(world, "GET", f"{SCIM}/Schemas", token=key)
    created = await send(world, "POST", USERS, user_body("ada@example.com"), token=key)

    for response in (listed, discovery, created):
        assert_scim_error(response, 401)
        assert key not in response.text
    assert (await send(world, "GET", USERS)).json()["totalResults"] == 0


async def test_a_session_token_is_401_on_scim_paths(world: World) -> None:
    member = await create(world, "ada@example.com", role="admin")
    session = session_headers(world, member["id"], OrgRole.ADMIN)
    assert (await world.client.get(MEMBERS, headers=session)).status_code == 200

    response = await world.client.get(USERS, headers=session)

    assert_scim_error(response, 401)


async def test_a_revoked_scim_token_is_401(world: World) -> None:
    minted = await mint_token(world, OrgRole.VIEWER, name="old")
    assert (await send(world, "GET", USERS, token=minted["token"])).status_code == 200
    revoke_path = f"{TOKENS}/{minted['id']}"
    revoked = await world.client.delete(revoke_path, headers=bearer(world.admin_key))
    assert revoked.status_code == 200

    response = await send(world, "GET", USERS, token=minted["token"])

    assert_scim_error(response, 401)
    assert minted["token"] not in response.text


async def test_a_scim_token_is_401_outside_scim_paths(world: World) -> None:
    headers = bearer(world.token)

    sandboxes = await world.client.get(SANDBOXES, headers=headers)
    members = await world.client.get(MEMBERS, headers=headers)

    for response in (sandboxes, members):
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "UNAUTHORIZED"


async def test_a_token_never_reaches_another_orgs_members(world: World) -> None:
    member = await create(world, "ada@example.com")
    other_org = await add_org(world.app, "globex")
    other_admin = await seed_key(world.app, other_org)
    other = (await mint_token(world, OrgRole.ADMIN, admin_key=other_admin))["token"]

    got = await send(world, "GET", user_path(member["id"]), token=other)
    listed = await send(world, "GET", USERS, token=other)
    deleted = await send(world, "DELETE", user_path(member["id"]), token=other)

    assert_scim_error(got, 404)
    assert listed.json()["totalResults"] == 0
    assert_scim_error(deleted, 404)
    assert (await send(world, "GET", user_path(member["id"]))).status_code == 200


# --- the role ceiling and the last-admin guard --------------------------------------------


async def test_a_developer_ceiling_cannot_create_or_promote_an_admin(world: World) -> None:
    token = (await mint_token(world, OrgRole.DEVELOPER, name="dev"))["token"]
    admin_body = user_body("ada@example.com", role="admin")
    developer_body = user_body("bob@example.com", role="developer")
    promote = patch(
        {"op": "replace", "path": "externalId", "value": "x1"},
        {"op": "replace", "path": ROLES_PRIMARY, "value": "admin"},
    )

    refused = await send(world, "POST", USERS, admin_body, token=token)
    allowed = await send(world, "POST", USERS, developer_body, token=token)
    promoted = await send(world, "PATCH", user_path(allowed.json()["id"]), promote, token=token)

    assert_scim_error(refused, 403)
    assert allowed.status_code == 201
    assert_scim_error(promoted, 403)
    lookup = {"filter": 'userName eq "ada@example.com"'}
    assert (await send(world, "GET", USERS, params=lookup)).json()["totalResults"] == 0
    current = (await send(world, "GET", user_path(allowed.json()["id"]))).json()
    assert current["roles"] == role_of("developer")
    assert "externalId" not in current


async def test_deactivating_or_demoting_the_last_admin_is_409(world: World) -> None:
    admin = await create(world, "ada@example.com", role="admin")
    path = user_path(admin["id"])
    deactivate = patch({"op": "replace", "value": {"active": False}})
    demote = patch({"op": "replace", "path": "roles", "value": role_of("viewer")})

    by_patch = await send(world, "PATCH", path, deactivate)
    by_put = await send(world, "PUT", path, user_body("ada@example.com", active=False))
    by_delete = await send(world, "DELETE", path)
    demoted = await send(world, "PATCH", path, demote)

    for response in (by_patch, by_put, by_delete, demoted):
        assert_scim_error(response, 409)
    current = (await send(world, "GET", path)).json()
    assert current["active"] is True
    assert current["roles"] == role_of("admin")


async def test_a_second_admin_lets_the_first_one_go(world: World) -> None:
    first = await create(world, "ada@example.com", role="admin")
    await create(world, "bob@example.com", role="admin")

    response = await send(world, "DELETE", user_path(first["id"]))

    assert response.status_code == 204


# --- sessions and rate limiting -----------------------------------------------------------


async def test_a_deactivated_members_session_token_stops_working(world: World) -> None:
    member = await create(world, "ada@example.com", role="developer")
    session = session_headers(world, member["id"], OrgRole.DEVELOPER)
    assert (await world.client.get(MEMBERS, headers=session)).status_code == 200
    deactivate = patch({"op": "replace", "path": "active", "value": False})

    deactivated = await send(world, "PATCH", user_path(member["id"]), deactivate)
    after = await world.client.get(MEMBERS, headers=session)

    assert deactivated.status_code == 200
    assert after.status_code == 401
    assert after.json()["error"]["code"] == "UNAUTHORIZED"


async def test_the_rate_limit_answers_429_per_scim_token(world: World) -> None:
    other = (await mint_token(world, OrgRole.VIEWER, name="second"))["token"]
    tight = TokenBucketRateLimiter(FrozenClock(T0), refill_per_s=1, burst=1)
    setattr(world.app.state, RATE_LIMITER_ATTR, tight)

    first = await send(world, "GET", USERS)
    second = await send(world, "GET", USERS)
    other_first = await send(world, "GET", USERS, token=other)

    assert first.status_code == 200
    assert_scim_error(second, 429)
    assert second.headers["retry-after"] == "1"
    assert other_first.status_code == 200


# --- refusals and audit -------------------------------------------------------------------


async def test_an_existing_member_or_external_id_is_409_uniqueness(world: World) -> None:
    await create(world, "ada@example.com", externalId="x1")

    member = await send(world, "POST", USERS, user_body("ADA@example.com"))
    external = await send(world, "POST", USERS, user_body("bob@example.com", externalId="x1"))

    assert_scim_error(member, 409, "uniqueness")
    assert_scim_error(external, 409, "uniqueness")


async def test_immutable_attributes_are_refused_by_replace_and_patch(world: World) -> None:
    created = await create(world, "ada@example.com", displayName="Ada")
    path = user_path(created["id"])
    rename = patch({"op": "replace", "path": "displayName", "value": "Eve"})

    by_put = await send(world, "PUT", path, user_body("eve@example.com"))
    by_patch = await send(world, "PATCH", path, rename)

    assert_scim_error(by_put, 400, "mutability")
    assert_scim_error(by_patch, 400, "mutability")
    current = (await send(world, "GET", path)).json()
    assert (current["userName"], current["displayName"]) == ("ada@example.com", "Ada")


async def test_a_refused_operation_leaves_the_whole_patch_unapplied(world: World) -> None:
    created = await create(world, "ada@example.com", externalId="e1")
    body = patch(
        {"op": "replace", "path": "externalId", "value": "e2"},
        {"op": "replace", "path": "roles", "value": [{"value": "root"}]},
    )

    response = await send(world, "PATCH", user_path(created["id"]), body)

    assert_scim_error(response, 400, "invalidValue")
    current = await send(world, "GET", user_path(created["id"]))
    assert current.json()["externalId"] == "e1"


async def test_writes_are_audited_with_the_scim_token_as_actor(world: World) -> None:
    created = await create(world, "ada@example.com", role="developer")
    demote = patch({"op": "replace", "path": ROLES_PRIMARY, "value": "viewer"})
    await send(world, "PATCH", user_path(created["id"]), demote)
    await send(world, "DELETE", user_path(created["id"]))

    rows = await audit_rows(world, created["id"])

    assert {row.action for row in rows} == {
        "user.created",
        "membership.added",
        "membership.role_changed",
        "membership.removed",
    }
    assert {row.actor_id for row in rows} == {world.token_id}
