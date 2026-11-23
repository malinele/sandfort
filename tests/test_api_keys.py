"""WP 4.4 API key management and per-key rate limits.

FakeDriver, a temp SQLite database, a frozen clock for the rate limiter and the ASGI client;
daemon-free. Routes are exercised over HTTP only (the API sits behind a mounted app: no
route-table introspection).
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.middleware import rate_limit
from sandfort.api.middleware.rate_limit import (
    RATE_LIMITER_ATTR,
    TokenBucketRateLimiter,
    install_rate_limit,
)
from sandfort.auth.api_keys import generate_api_key
from sandfort.auth.authenticate import authenticate
from sandfort.auth.principal import Principal
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import AuditEvent
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.errors import RateLimited
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
KEYS = "/v1/api-keys"
SANDBOXES = "/v1/sandboxes"
AUDIT = "/v1/audit-events"
ADMIN_SCOPES = frozenset({Scope.API_KEYS_ADMIN, Scope.SANDBOXES_READ, Scope.AUDIT_READ})
SANDBOX_SCOPES = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})
TINY_BURST = 3
REFILL_PER_S = 1
PAST = "2000-01-01T00:00:00Z"


@dataclass
class World:
    app: FastAPI
    client: httpx.AsyncClient
    clock: FrozenClock
    org_id: str
    admin_key: str


@asynccontextmanager
async def open_world(tmp_path: Path, **overrides: Any) -> AsyncIterator[World]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'keys.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(driver="fake", database_url=url, api_key_pepper=PEPPER, **overrides)
    app = create_app(settings)
    clock = FrozenClock(T0)
    if settings.rate_limit_enabled:  # same configured limits, driven by the frozen clock
        limiter = TokenBucketRateLimiter(
            clock, refill_per_s=settings.rate_limit_refill_per_s, burst=settings.rate_limit_burst
        )
        install_rate_limit(app, limiter)
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            org_id = await add_org(app, "acme")
            admin_key = await seed_key(app, org_id, ADMIN_SCOPES)
            yield World(app, http, clock, org_id, admin_key)
    finally:
        await app.state.engine.dispose()


@pytest.fixture
async def world(tmp_path: Path) -> AsyncIterator[World]:
    async with open_world(tmp_path) as opened:
        yield opened


@pytest.fixture
async def limited(tmp_path: Path) -> AsyncIterator[World]:
    async with open_world(
        tmp_path, rate_limit_burst=TINY_BURST, rate_limit_refill_per_s=REFILL_PER_S
    ) as opened:
        yield opened


async def add_org(app: FastAPI, slug: str) -> str:
    org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=T0)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def seed_key(
    app: FastAPI,
    org_id: str,
    scopes: frozenset[Scope],
    sandbox_labels: dict[str, str] | None = None,
) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="seed",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=scopes,
        sandbox_labels=sandbox_labels,
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


async def create_key(
    world: World, scopes: list[str], *, caller: str | None = None, name: str = "ci"
) -> httpx.Response:
    body = {"name": name, "scopes": scopes}
    return await world.client.post(KEYS, json=body, headers=auth(caller or world.admin_key))


# --- scope attenuation -------------------------------------------------------------------


async def test_a_sandboxes_key_cannot_create_an_admin_key(world: World) -> None:
    sandboxes_key = await seed_key(world.app, world.org_id, SANDBOX_SCOPES)

    response = await create_key(world, [Scope.API_KEYS_ADMIN.value], caller=sandboxes_key)

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


async def test_an_admin_key_cannot_grant_scopes_it_lacks(world: World) -> None:
    requested = [Scope.SANDBOXES_READ.value, Scope.WEBHOOKS_WRITE.value]

    response = await create_key(world, requested)

    assert response.status_code == 403
    error = response.json()["error"]
    assert error["code"] == "FORBIDDEN"
    assert error["details"]["excess_scopes"] == [Scope.WEBHOOKS_WRITE.value]
    listed = await world.client.get(KEYS, headers=auth(world.admin_key))
    assert len(listed.json()["data"]) == 1  # nothing was issued


async def test_an_attenuated_key_works_inside_its_scope_only(world: World) -> None:
    created = await create_key(world, [Scope.SANDBOXES_READ.value])
    assert created.status_code == 201
    data = created.json()["data"]
    assert data["scopes"] == [Scope.SANDBOXES_READ.value]
    key = data["key"]

    inside = await world.client.get(SANDBOXES, headers=auth(key))
    keys_route = await world.client.get(KEYS, headers=auth(key))
    audit_route = await world.client.get(AUDIT, headers=auth(key))

    assert inside.status_code == 200
    assert keys_route.status_code == 403
    assert audit_route.status_code == 403


async def test_an_expiry_in_the_past_is_rejected(world: World) -> None:
    body = {"name": "old", "scopes": [Scope.SANDBOXES_READ.value], "expires_at": PAST}

    response = await world.client.post(KEYS, json=body, headers=auth(world.admin_key))

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


# --- plaintext exactly once --------------------------------------------------------------


async def test_create_returns_the_plaintext_once_and_list_never_shows_it(world: World) -> None:
    created = (await create_key(world, [Scope.SANDBOXES_READ.value], name="deploy")).json()
    data = created["data"]
    plaintext = data["key"]
    assert plaintext.startswith(data["prefix"] + "_")
    assert "secret_hash" not in data

    listed = await world.client.get(KEYS, headers=auth(world.admin_key))

    assert listed.status_code == 200
    assert plaintext not in listed.text
    assert "secret_hash" not in listed.text
    items = {item["id"]: item for item in listed.json()["data"]}
    entry = items[data["id"]]
    assert "key" not in entry
    assert entry["name"] == "deploy"
    assert entry["prefix"] == data["prefix"]
    assert entry["revoked_at"] is None


# --- revoke ------------------------------------------------------------------------------


async def test_revoke_stops_the_key_and_is_idempotent(world: World) -> None:
    data = (await create_key(world, [Scope.SANDBOXES_READ.value])).json()["data"]
    key, key_id = data["key"], data["id"]
    assert (await world.client.get(SANDBOXES, headers=auth(key))).status_code == 200

    first = await world.client.delete(f"{KEYS}/{key_id}", headers=auth(world.admin_key))
    second = await world.client.delete(f"{KEYS}/{key_id}", headers=auth(world.admin_key))
    after = await world.client.get(SANDBOXES, headers=auth(key))

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["data"]["revoked_at"] is not None
    assert second.json()["data"]["revoked_at"] == first.json()["data"]["revoked_at"]
    assert after.status_code == 401


async def test_revoking_an_unknown_or_foreign_key_is_not_found(world: World) -> None:
    other_org = await add_org(world.app, "globex")
    other_admin = await seed_key(world.app, other_org, ADMIN_SCOPES)
    data = (await create_key(world, [Scope.SANDBOXES_READ.value])).json()["data"]

    foreign = await world.client.delete(f"{KEYS}/{data['id']}", headers=auth(other_admin))
    unknown = await world.client.delete(f"{KEYS}/key_missing", headers=auth(world.admin_key))
    still = await world.client.get(SANDBOXES, headers=auth(data["key"]))

    assert foreign.status_code == 404
    assert unknown.status_code == 404
    assert still.status_code == 200


# --- audit -------------------------------------------------------------------------------


async def test_create_and_revoke_are_audited_without_secret_material(world: World) -> None:
    data = (await create_key(world, [Scope.SANDBOXES_READ.value])).json()["data"]
    for _ in range(2):
        await world.client.delete(f"{KEYS}/{data['id']}", headers=auth(world.admin_key))

    every_row = await audit_rows(world.app, world.org_id)
    rows = [row for row in every_row if row.target_id == data["id"]]

    actions = [row.action for row in rows]
    assert actions.count("api_key.created") == 1
    assert actions.count("api_key.revoked") == 1  # the repeat revoke records nothing
    for row in rows:
        assert row.target_type == "api_key"
        assert data["key"] not in str(row.details)
        assert "secret_hash" not in row.details
    created = next(row for row in rows if row.action == "api_key.created")
    assert created.details["scopes"] == [Scope.SANDBOXES_READ.value]
    assert created.details["prefix"] == data["prefix"]


# --- label scope -------------------------------------------------------------------------

TEAM_GOV = {"team": "gov"}
SCOPED_ADMIN = ADMIN_SCOPES


async def create_labelled(
    world: World, labels: Any, *, caller: str | None = None
) -> httpx.Response:
    body = {"name": "scoped", "scopes": [Scope.SANDBOXES_READ.value], "sandbox_labels": labels}
    return await world.client.post(KEYS, json=body, headers=auth(caller or world.admin_key))


async def test_create_with_sandbox_labels_returns_and_lists_them(world: World) -> None:
    created = await create_labelled(world, TEAM_GOV)

    assert created.status_code == 201
    data = created.json()["data"]
    assert data["sandbox_labels"] == TEAM_GOV
    listed = await world.client.get(KEYS, headers=auth(world.admin_key))
    entry = next(item for item in listed.json()["data"] if item["id"] == data["id"])
    assert entry["sandbox_labels"] == TEAM_GOV


# --- list status filter ------------------------------------------------------------------


async def seed_expired_key(app: FastAPI, org_id: str) -> str:
    """A key whose ``expires_at`` is already behind the application's (system) clock."""
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="lapsed",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=SANDBOX_SCOPES,
        created_at=T0,
        expires_at=T0 + timedelta(hours=1),
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return stored.id


async def mixed_keys(world: World) -> dict[str, str]:
    """Key ids by role: a live one, a revoked one and an expired one (plus the seeded admin)."""
    live = (await create_key(world, [Scope.SANDBOXES_READ.value], name="live")).json()["data"]
    revoked = (await create_key(world, [Scope.SANDBOXES_READ.value], name="gone")).json()["data"]
    deleted = await world.client.delete(f"{KEYS}/{revoked['id']}", headers=auth(world.admin_key))
    assert deleted.status_code == 200
    expired_id = await seed_expired_key(world.app, world.org_id)
    return {"live": live["id"], "revoked": revoked["id"], "expired": expired_id}


async def test_list_without_status_returns_every_key(world: World) -> None:
    ids = await mixed_keys(world)

    response = await world.client.get(KEYS, headers=auth(world.admin_key))

    assert response.status_code == 200
    rows = response.json()["data"]
    assert {row["id"] for row in rows} >= set(ids.values())
    assert {row["status"] for row in rows} == {"active", "revoked", "expired"}


async def test_list_status_active_excludes_revoked_and_expired_keys(world: World) -> None:
    ids = await mixed_keys(world)

    response = await world.client.get(
        KEYS, params={"status": "active"}, headers=auth(world.admin_key)
    )

    assert response.status_code == 200
    rows = response.json()["data"]
    returned = {row["id"] for row in rows}
    assert ids["live"] in returned
    assert ids["revoked"] not in returned
    assert ids["expired"] not in returned
    assert {row["status"] for row in rows} == {"active"}  # filter agrees with displayed status


async def test_list_status_revoked_returns_only_the_revoked_key(world: World) -> None:
    ids = await mixed_keys(world)

    response = await world.client.get(
        KEYS, params={"status": "revoked"}, headers=auth(world.admin_key)
    )

    assert response.status_code == 200
    rows = response.json()["data"]
    assert [row["id"] for row in rows] == [ids["revoked"]]
    assert rows[0]["status"] == "revoked"


async def test_list_status_other_value_is_a_validation_error_naming_the_parameter(
    world: World,
) -> None:
    response = await world.client.get(
        KEYS, params={"status": "bogus"}, headers=auth(world.admin_key)
    )

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert [issue["loc"] for issue in error["details"]["errors"]] == [["query", "status"]]


async def test_list_still_rejects_an_unknown_query_parameter(world: World) -> None:
    response = await world.client.get(
        KEYS, params={"state": "active"}, headers=auth(world.admin_key)
    )

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert [issue["loc"] for issue in error["details"]["errors"]] == [["query", "state"]]
    assert "status" in error["message"]  # the accepted set now names the new parameter


async def test_list_status_filter_applies_to_a_label_scoped_admin_and_keeps_created_by_masked(
    world: World,
) -> None:
    red_admin = await mint(world, RED, ADMIN_SCOPES)
    red_live = await mint(world, RED_DEV, READ_ONLY)
    red_gone = await mint(world, RED_DEV, READ_ONLY)
    blue = await mint(world, BLUE, READ_ONLY)
    deleted = await world.client.delete(f"{KEYS}/{red_gone.id}", headers=auth(world.admin_key))
    assert deleted.status_code == 200

    active = await world.client.get(KEYS, params={"status": "active"}, headers=auth(red_admin.key))
    revoked = await world.client.get(
        KEYS, params={"status": "revoked"}, headers=auth(red_admin.key)
    )
    unscoped = await world.client.get(
        KEYS, params={"status": "active"}, headers=auth(world.admin_key)
    )

    assert active.status_code == 200
    active_rows = active.json()["data"]
    assert {row["id"] for row in active_rows} == {red_admin.id, red_live.id}  # scope and filter
    assert {row["status"] for row in active_rows} == {"active"}
    assert all(row["created_by"] is None for row in active_rows)  # masking is unchanged
    assert revoked.status_code == 200
    revoked_rows = revoked.json()["data"]
    assert [row["id"] for row in revoked_rows] == [red_gone.id]
    assert revoked_rows[0]["created_by"] is None
    unscoped_rows = {row["id"]: row for row in unscoped.json()["data"]}
    assert blue.id in unscoped_rows  # the unscoped caller still sees outside the scope
    assert unscoped_rows[red_live.id]["created_by"] is not None  # only masked for scoped callers


async def test_list_status_validation_does_not_run_before_authentication(world: World) -> None:
    response = await world.client.get(KEYS, params={"status": "bogus"})

    assert response.status_code == 401


async def test_list_unknown_query_parameter_is_reported_before_a_bad_status(
    world: World,
) -> None:
    response = await world.client.get(
        KEYS, params={"status": "bogus", "state": "active"}, headers=auth(world.admin_key)
    )

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert [issue["loc"] for issue in error["details"]["errors"]] == [["query", "state"]]
    assert "state" in error["message"]  # the unknown parameter is named, not the bad status


async def test_create_without_sandbox_labels_is_unscoped(world: World) -> None:
    created = await create_key(world, [Scope.SANDBOXES_READ.value])

    assert created.status_code == 201
    assert created.json()["data"]["sandbox_labels"] is None
    listed = await world.client.get(KEYS, headers=auth(world.admin_key))
    assert {item["sandbox_labels"] for item in listed.json()["data"]} == {None}


async def test_an_empty_label_scope_becomes_unscoped(world: World) -> None:
    created = await create_labelled(world, {})

    assert created.status_code == 201
    data = created.json()["data"]
    assert data["sandbox_labels"] is None
    listed = await world.client.get(KEYS, headers=auth(world.admin_key))
    entry = next(item for item in listed.json()["data"] if item["id"] == data["id"])
    assert entry["sandbox_labels"] is None


async def test_label_scope_rejects_reserved_names_and_more_than_eight_pairs(
    world: World,
) -> None:
    reserved = await create_labelled(world, {"sandfort.org_id": "x"})
    too_many = await create_labelled(world, {f"k{index}": "v" for index in range(9)})
    at_limit = await create_labelled(world, {f"k{index}": "v" for index in range(8)})

    assert reserved.status_code == 422  # request-body validation, like sandbox labels
    assert too_many.status_code == 422
    assert at_limit.status_code == 201
    listed = await world.client.get(KEYS, headers=auth(world.admin_key))
    assert len(listed.json()["data"]) == 2  # the seed key and the one valid key


async def test_the_created_key_audit_details_carry_the_label_scope(world: World) -> None:
    data = (await create_labelled(world, TEAM_GOV)).json()["data"]
    plain = (await create_key(world, [Scope.SANDBOXES_READ.value])).json()["data"]

    rows = await audit_rows(world.app, world.org_id)

    created = {row.target_id: row for row in rows if row.action == "api_key.created"}
    assert created[data["id"]].details["sandbox_labels"] == TEAM_GOV
    assert created[plain["id"]].details["sandbox_labels"] is None


async def test_a_scoped_creator_cannot_mint_an_unscoped_key(world: World) -> None:
    scoped = await seed_key(world.app, world.org_id, SCOPED_ADMIN, TEAM_GOV)

    unscoped = await create_key(world, [Scope.SANDBOXES_READ.value], caller=scoped)
    empty = await create_labelled(world, {}, caller=scoped)

    for response in (unscoped, empty):
        assert response.status_code == 403
        error = response.json()["error"]
        assert error["code"] == "FORBIDDEN"
        assert error["details"]["excess_labels"] == TEAM_GOV


async def test_a_scoped_creator_cannot_mint_a_wider_or_different_key(world: World) -> None:
    pairs = {"team": "gov", "env": "prod"}
    scoped = await seed_key(world.app, world.org_id, SCOPED_ADMIN, pairs)

    wider = await create_labelled(world, {"team": "gov"}, caller=scoped)
    other_value = await create_labelled(world, {"team": "ops", "env": "prod"}, caller=scoped)
    other_name = await create_labelled(world, {"squad": "gov", "env": "prod"}, caller=scoped)

    assert wider.status_code == 403
    assert wider.json()["error"]["details"]["excess_labels"] == {"env": "prod"}
    assert other_value.status_code == 403
    assert other_value.json()["error"]["details"]["excess_labels"] == {"team": "gov"}
    assert other_name.status_code == 403
    assert other_name.json()["error"]["details"]["excess_labels"] == {"team": "gov"}
    listed = await world.client.get(KEYS, headers=auth(world.admin_key))
    assert len(listed.json()["data"]) == 2  # the seed admin and the scoped creator


async def test_a_scoped_creator_can_mint_the_same_or_a_narrower_key(world: World) -> None:
    scoped = await seed_key(world.app, world.org_id, SCOPED_ADMIN, TEAM_GOV)

    same = await create_labelled(world, TEAM_GOV, caller=scoped)
    narrower = await create_labelled(world, {"team": "gov", "bot": "a1"}, caller=scoped)

    assert same.status_code == 201
    assert same.json()["data"]["sandbox_labels"] == TEAM_GOV
    assert narrower.status_code == 201
    assert narrower.json()["data"]["sandbox_labels"] == {"team": "gov", "bot": "a1"}


# --- label-scoped key administration -----------------------------------------------------

RED = {"team": "red"}
RED_DEV = {"team": "red", "env": "dev"}
BLUE = {"team": "blue"}
READ_ONLY = frozenset({Scope.SANDBOXES_READ})


@dataclass
class Minted:
    id: str
    key: str


async def mint(world: World, labels: dict[str, str] | None, scopes: frozenset[Scope]) -> Minted:
    body: dict[str, Any] = {"name": "m", "scopes": sorted(scope.value for scope in scopes)}
    if labels:
        body["sandbox_labels"] = labels
    created = await world.client.post(KEYS, json=body, headers=auth(world.admin_key))
    assert created.status_code == 201
    data = created.json()["data"]
    return Minted(data["id"], data["key"])


async def listed_ids(world: World, caller: str) -> set[str]:
    response = await world.client.get(KEYS, headers=auth(caller))
    assert response.status_code == 200
    return {item["id"] for item in response.json()["data"]}


async def key_works(world: World, key: str) -> bool:
    return (await world.client.get(SANDBOXES, headers=auth(key))).status_code == 200


async def test_a_scoped_admin_lists_only_keys_inside_its_scope(world: World) -> None:
    red_admin = await mint(world, RED, ADMIN_SCOPES)
    red_dev = await mint(world, RED_DEV, READ_ONLY)
    blue = await mint(world, BLUE, READ_ONLY)
    unscoped = await mint(world, None, READ_ONLY)

    visible = await listed_ids(world, red_admin.key)

    assert visible == {red_admin.id, red_dev.id}  # itself and the narrower key
    everything = await listed_ids(world, world.admin_key)
    assert {blue.id, unscoped.id} <= everything


async def test_a_scoped_admin_cannot_revoke_keys_outside_its_scope(world: World) -> None:
    red_admin = await mint(world, RED, ADMIN_SCOPES)
    blue = await mint(world, BLUE, READ_ONLY)
    unscoped = await mint(world, None, READ_ONLY)
    caller = auth(red_admin.key)

    unknown = await world.client.delete(f"{KEYS}/key_missing", headers=caller)
    hidden = [
        await world.client.delete(f"{KEYS}/{target.id}", headers=caller)
        for target in (blue, unscoped)
    ]

    assert unknown.status_code == 404
    for response, target in zip(hidden, (blue, unscoped), strict=True):
        assert response.status_code == 404
        expected = unknown.json()["error"]["message"].replace("key_missing", target.id)
        assert response.json()["error"]["message"] == expected
        assert await key_works(world, target.key)
    assert await key_works(world, world.admin_key)


async def test_a_scoped_admin_revokes_keys_inside_its_scope(world: World) -> None:
    red_admin = await mint(world, RED, ADMIN_SCOPES)
    red_dev = await mint(world, RED_DEV, READ_ONLY)

    revoked = await world.client.delete(f"{KEYS}/{red_dev.id}", headers=auth(red_admin.key))

    assert revoked.status_code == 200
    assert revoked.json()["data"]["revoked_at"] is not None
    assert not await key_works(world, red_dev.key)
    assert await key_works(world, red_admin.key)


async def test_an_unscoped_admin_still_lists_and_revokes_every_key(world: World) -> None:
    red = await mint(world, RED, READ_ONLY)
    blue = await mint(world, BLUE, READ_ONLY)
    unscoped = await mint(world, None, READ_ONLY)

    assert {red.id, blue.id, unscoped.id} <= await listed_ids(world, world.admin_key)
    for target in (red, blue, unscoped):
        response = await world.client.delete(f"{KEYS}/{target.id}", headers=auth(world.admin_key))
        assert response.status_code == 200
        assert not await key_works(world, target.key)


# --- authentication ----------------------------------------------------------------------


async def test_key_routes_require_authentication(world: World) -> None:
    listed = await world.client.get(KEYS)
    created = await world.client.post(KEYS, json={"name": "x", "scopes": ["sandboxes:read"]})
    revoked = await world.client.delete(f"{KEYS}/key_missing")

    assert listed.status_code == 401
    assert created.status_code == 401
    assert revoked.status_code == 401


# --- rate limits -------------------------------------------------------------------------


async def test_a_drained_bucket_answers_429_until_it_refills(limited: World) -> None:
    key = await seed_key(limited.app, limited.org_id, SANDBOX_SCOPES)
    other = await seed_key(limited.app, limited.org_id, SANDBOX_SCOPES)

    passed = [await limited.client.get(SANDBOXES, headers=auth(key)) for _ in range(TINY_BURST)]
    blocked = await limited.client.get(SANDBOXES, headers=auth(key))

    assert [response.status_code for response in passed] == [200] * TINY_BURST
    assert blocked.status_code == 429
    assert blocked.json()["error"]["code"] == "RATE_LIMITED"
    retry_after = blocked.headers["Retry-After"]
    assert retry_after.isdigit()
    assert int(retry_after) >= 1

    other_response = await limited.client.get(SANDBOXES, headers=auth(other))
    assert other_response.status_code == 200  # a separate bucket

    limited.clock.advance(timedelta(seconds=int(retry_after) + 1))
    assert (await limited.client.get(SANDBOXES, headers=auth(key))).status_code == 200


async def test_unauthenticated_and_health_requests_are_not_limited(limited: World) -> None:
    key = await seed_key(limited.app, limited.org_id, SANDBOX_SCOPES)

    for _ in range(TINY_BURST * 2):
        assert (await limited.client.get("/healthz")).status_code == 200
        assert (await limited.client.get(SANDBOXES)).status_code == 401
        bad = await limited.client.get(SANDBOXES, headers=auth("sf_live_aaaaaaaa_" + "x" * 43))
        assert bad.status_code == 401

    passed = [await limited.client.get(SANDBOXES, headers=auth(key)) for _ in range(TINY_BURST)]
    assert [response.status_code for response in passed] == [200] * TINY_BURST


async def test_rate_limit_runs_before_the_scope_check(limited: World) -> None:
    key = await seed_key(limited.app, limited.org_id, SANDBOX_SCOPES)
    for _ in range(TINY_BURST):
        assert (await limited.client.get(KEYS, headers=auth(key))).status_code == 403

    response = await limited.client.get(KEYS, headers=auth(key))

    assert response.status_code == 429
    assert response.json()["error"]["code"] == "RATE_LIMITED"


async def test_disabled_rate_limit_installs_no_limiter(tmp_path: Path) -> None:
    async with open_world(tmp_path, rate_limit_enabled=False) as opened:
        assert getattr(opened.app.state, RATE_LIMITER_ATTR, None) is None
        assert authenticate not in opened.app.dependency_overrides
        for _ in range(5):
            response = await opened.client.get(SANDBOXES, headers=auth(opened.admin_key))
            assert response.status_code == 200


# --- units -------------------------------------------------------------------------------


async def test_token_bucket_reports_whole_second_waits() -> None:
    clock = FrozenClock(T0)
    limiter = TokenBucketRateLimiter(clock, refill_per_s=2, burst=1)

    assert (await limiter.acquire("key_a")).allowed
    denied = await limiter.acquire("key_a")
    assert not denied.allowed
    assert denied.retry_after_s == 1
    clock.advance(timedelta(milliseconds=500))
    assert (await limiter.acquire("key_a")).allowed


async def test_sessions_of_one_user_share_a_bucket(monkeypatch: pytest.MonkeyPatch) -> None:
    limiter = TokenBucketRateLimiter(FrozenClock(T0), refill_per_s=1, burst=2)
    state = SimpleNamespace(**{RATE_LIMITER_ATTR: limiter})
    request: Any = SimpleNamespace(app=SimpleNamespace(state=state))
    current: list[Principal] = []

    async def fake_authenticate(_request: object) -> Principal:
        return current[0]

    monkeypatch.setattr(rate_limit, "authenticate", fake_authenticate)

    async def call(token_id: str, user_id: str) -> None:
        current[:] = [Principal("org_a", token_id, frozenset(), user_id=user_id)]
        await rate_limit.rate_limited_authenticate(request)

    await call("tok_1", "usr_ada")  # each exchange mints a fresh token id ...
    await call("tok_2", "usr_ada")
    with pytest.raises(RateLimited):
        await call("tok_3", "usr_ada")  # ... but they all draw on the user's one bucket
    await call("tok_4", "usr_bob")  # another user is unaffected


async def test_the_bucket_map_stays_bounded_by_sweeping_the_oldest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(rate_limit, "MAX_BUCKETS", 4)
    monkeypatch.setattr(rate_limit, "SWEEP_TARGET", 2)
    clock = FrozenClock(T0)
    limiter = TokenBucketRateLimiter(clock, refill_per_s=1, burst=1)

    for index in range(8):
        assert (await limiter.acquire(f"key_{index}")).allowed
        clock.advance(timedelta(seconds=1))
        assert len(limiter._buckets) <= 4

    assert "key_7" in limiter._buckets
    assert "key_0" not in limiter._buckets


def test_token_bucket_rejects_unusable_settings() -> None:
    with pytest.raises(ValueError):
        TokenBucketRateLimiter(FrozenClock(T0), refill_per_s=0, burst=1)
    with pytest.raises(ValueError):
        TokenBucketRateLimiter(FrozenClock(T0), refill_per_s=1, burst=0)


def test_rate_limit_settings_come_from_the_environment() -> None:
    settings = Settings.from_env(
        {
            "SANDFORT_RATE_LIMIT_ENABLED": "false",
            "SANDFORT_RATE_LIMIT_REFILL_PER_S": "7",
            "SANDFORT_RATE_LIMIT_BURST": "9",
        }
    )

    assert settings.rate_limit_enabled is False
    assert settings.rate_limit_refill_per_s == 7
    assert settings.rate_limit_burst == 9
    assert Settings.from_env({}).rate_limit_enabled is True
