"""Round 60: the usage report honours a key's label scope and documents its grouped reply.

A key limited to labelled sandboxes sees only those sandboxes (destroyed ones that carried the
labels included) in the totals, the per-sandbox groups and the per-label groups; an unscoped key
keeps the org-wide view. The grouped reply is a typed model (``UsageGroup``) in the OpenAPI
document, with cursor and limit parameters bound to the filter like the list routes.

FakeDriver, a temp SQLite database, a frozen clock and the ASGI client; daemon-free.
"""

from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.wiring import USAGE_SERVICE_ATTR
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.resources import DEFAULT_MEMORY_MIB, ResourceSpec
from sandfort.domain.sandbox import SandboxState
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.sandboxes import CreateSandboxCommand, SandboxService
from sandfort.services.usage import UsageService

ROOT = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
HOUR = timedelta(hours=1)
HALF_HOUR = timedelta(minutes=30)
PEPPER = "test-pepper"
USAGE = "/v1/org/usage"
ACTOR = "key_test"
READER = frozenset({Scope.USAGE_READ})
TEAM_A = {"team": "a"}


@dataclass
class World:
    app: FastAPI
    client: httpx.AsyncClient
    clock: FrozenClock
    sandboxes: SandboxService
    org_id: str


@dataclass(frozen=True)
class Fleet:
    """Four sandboxes of one org: two of team a (one destroyed), one of team b, one unlabeled."""

    a_main: str
    a_prod: str  # team=a, env=prod; destroyed after half an hour
    b_main: str
    bare: str


@pytest.fixture
async def world(tmp_path: Path) -> AsyncIterator[World]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'usage.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(driver="fake", database_url=url, api_key_pepper=PEPPER)
    app = create_app(settings)
    clock = FrozenClock(T0)
    setattr(app.state, USAGE_SERVICE_ATTR, UsageService(app.state.uow_factory, clock))
    sandboxes = SandboxService(app.state.uow_factory, FakeDriver(clock), settings, clock)
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=T0)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            yield World(app, http, clock, sandboxes, org.id)
    finally:
        await app.state.engine.dispose()


async def seed_key(world: World, labels: dict[str, str] | None = None) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=world.org_id,
        name="finops",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=READER,
        sandbox_labels=labels,
        created_at=T0,
    )
    async with UnitOfWork(world.app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


async def start(
    world: World, labels: dict[str, str], cpu_millicores: int = 1000, name: str | None = None
) -> str:
    resources = ResourceSpec(cpu_millicores=cpu_millicores)
    request = CreateSandboxCommand(name=name, resources=resources, labels=labels)
    sandbox = await world.sandboxes.create(world.org_id, ACTOR, request)
    assert sandbox.state is SandboxState.STARTED
    return sandbox.id


async def fleet(world: World) -> Fleet:
    a_main = await start(world, TEAM_A, cpu_millicores=2000, name="a-main")
    a_prod = await start(world, {**TEAM_A, "env": "prod"}, name="a-prod")
    b_main = await start(world, {"team": "b"}, name="b-main")
    bare = await start(world, {}, name="bare")
    world.clock.advance(HALF_HOUR)
    await world.sandboxes.delete(world.org_id, ACTOR, a_prod)  # destroyed, still carried labels
    world.clock.advance(HALF_HOUR)
    return Fleet(a_main, a_prod, b_main, bare)


async def usage(
    world: World, key: str, group_by: str | None = None, **extra: Any
) -> httpx.Response:
    params: dict[str, Any] = {"from": T0.isoformat(), "to": (T0 + HOUR).isoformat(), **extra}
    if group_by is not None:
        params["group_by"] = group_by
    return await world.client.get(
        USAGE, headers={"Authorization": f"Bearer {key}"}, params=params
    )


def total(group_or_row: dict[str, Any], dimension: str) -> float:
    rows = group_or_row["totals"] if "totals" in group_or_row else [group_or_row]
    return next(row["total"] for row in rows if row["dimension"] == dimension)


def vcpu_by_value(response: httpx.Response) -> dict[str | None, float]:
    assert response.status_code == 200, response.text
    return {group["group_value"]: total(group, "vcpu") for group in response.json()["data"]}


# --- scope: totals -----------------------------------------------------------------------


async def test_a_scoped_key_totals_cover_only_its_sandboxes_destroyed_included(
    world: World,
) -> None:
    await fleet(world)
    key = await seed_key(world, TEAM_A)

    response = await usage(world, key)

    assert response.status_code == 200, response.text
    by_dimension = {row["dimension"]: row["total"] for row in response.json()["data"]}
    assert by_dimension["vcpu"] == 2.0 * 3600 + 1800  # a_main, plus a_prod's half hour
    assert by_dimension["memory_mib"] == DEFAULT_MEMORY_MIB * (3600 + 1800)
    assert by_dimension["disk_gib"] == 0.0


async def test_a_key_with_two_labels_sees_only_sandboxes_carrying_both(world: World) -> None:
    await fleet(world)
    key = await seed_key(world, {**TEAM_A, "env": "prod"})

    response = await usage(world, key)

    assert total(response.json()["data"][0], "vcpu") == 1800.0


async def test_an_unscoped_key_totals_cover_the_whole_org(world: World) -> None:
    await fleet(world)
    key = await seed_key(world)

    response = await usage(world, key)

    expected = 2.0 * 3600 + 1800 + 3600 + 3600
    assert total(response.json()["data"][0], "vcpu") == expected


async def test_a_scope_matching_nothing_reports_zero(world: World) -> None:
    await fleet(world)
    key = await seed_key(world, {"team": "ghost"})

    response = await usage(world, key)

    assert [row["total"] for row in response.json()["data"]] == [0.0, 0.0, 0.0]


# --- scope: groups -----------------------------------------------------------------------


async def test_a_scoped_key_sandbox_groups_hold_only_its_sandbox_ids(world: World) -> None:
    ids = await fleet(world)
    key = await seed_key(world, TEAM_A)

    response = await usage(world, key, "sandbox")

    assert vcpu_by_value(response) == {ids.a_main: 7200.0, ids.a_prod: 1800.0}


async def test_an_unscoped_key_sandbox_groups_hold_every_sandbox(world: World) -> None:
    ids = await fleet(world)
    key = await seed_key(world)

    response = await usage(world, key, "sandbox")

    assert set(vcpu_by_value(response)) == {ids.a_main, ids.a_prod, ids.b_main, ids.bare}


async def test_a_scoped_key_label_groups_exclude_other_teams_and_the_null_of_others(
    world: World,
) -> None:
    await fleet(world)
    key = await seed_key(world, TEAM_A)

    by_team = await usage(world, key, "label:team")
    by_env = await usage(world, key, "label:env")

    assert vcpu_by_value(by_team) == {"a": 7200.0 + 1800.0}
    assert vcpu_by_value(by_env) == {"prod": 1800.0, None: 7200.0}


async def test_an_unscoped_key_label_groups_cover_every_team(world: World) -> None:
    await fleet(world)
    key = await seed_key(world)

    response = await usage(world, key, "label:team")

    assert vcpu_by_value(response) == {"a": 9000.0, "b": 3600.0, None: 3600.0}


# --- the grouped model -------------------------------------------------------------------


async def test_a_sandbox_group_carries_the_name_and_the_labels_at_report_time(
    world: World,
) -> None:
    ids = await fleet(world)
    key = await seed_key(world)

    response = await usage(world, key, "sandbox")

    groups = {group["group_value"]: group for group in response.json()["data"]}
    assert set(groups[ids.a_prod]) == {"group_key", "group_value", "totals", "name", "labels"}
    assert groups[ids.a_prod]["group_key"] == "sandbox"
    assert groups[ids.a_prod]["name"] == "a-prod"
    assert groups[ids.a_prod]["labels"] == {"team": "a", "env": "prod"}
    assert groups[ids.bare]["labels"] == {}
    assert {row["unit"] for row in groups[ids.bare]["totals"]} == {
        "vcpu_seconds",
        "mib_seconds",
        "gib_seconds",
    }


async def test_a_label_group_has_no_sandbox_name_or_labels(world: World) -> None:
    await fleet(world)
    key = await seed_key(world)

    response = await usage(world, key, "label:team")

    for group in response.json()["data"]:
        assert group["name"] is None
        assert group["labels"] is None


async def test_the_openapi_document_carries_both_response_shapes(world: World) -> None:
    document = world.app.openapi()

    schemas = document["components"]["schemas"]
    group = schemas["UsageGroup"]
    assert set(group["properties"]) == {"group_key", "group_value", "totals", "name", "labels"}
    ok = document["paths"][USAGE]["get"]["responses"]["200"]["content"]["application/json"]
    rendered = str(ok["schema"])
    assert "UsageGroup" in rendered
    assert "UsageTotalResponse" in rendered
    names = {parameter["name"] for parameter in document["paths"][USAGE]["get"]["parameters"]}
    assert {"cursor", "limit", "group_by"} <= names


async def test_the_route_description_states_the_label_scope_rule(world: World) -> None:
    operation = world.app.openapi()["paths"][USAGE]["get"]

    assert "label" in operation["description"].lower()
    assert "scope" in operation["description"].lower()


# --- paging ------------------------------------------------------------------------------


async def test_sandbox_groups_page_with_a_cursor_until_the_end(world: World) -> None:
    ids = await fleet(world)
    key = await seed_key(world)

    first = await usage(world, key, "sandbox", limit=3)
    cursor = first.json()["meta"]["next_cursor"]
    second = await usage(world, key, "sandbox", limit=3, cursor=cursor)

    seen = [g["group_value"] for g in first.json()["data"] + second.json()["data"]]
    assert len(first.json()["data"]) == 3
    assert cursor is not None
    assert second.json()["meta"]["next_cursor"] is None
    assert seen == sorted([ids.a_main, ids.a_prod, ids.b_main, ids.bare])


async def test_label_groups_page_one_at_a_time_with_the_null_group_last(world: World) -> None:
    await fleet(world)
    key = await seed_key(world)

    values: list[str | None] = []
    cursor: str | None = None
    for _ in range(5):
        extra = {} if cursor is None else {"cursor": cursor}
        page = await usage(world, key, "label:team", limit=1, **extra)
        assert page.status_code == 200, page.text
        values += [group["group_value"] for group in page.json()["data"]]
        cursor = page.json()["meta"]["next_cursor"]
        if cursor is None:
            break

    assert values == ["a", "b", None]


async def test_the_default_page_returns_every_group_when_few(world: World) -> None:
    await fleet(world)
    key = await seed_key(world)

    response = await usage(world, key, "sandbox")

    assert len(response.json()["data"]) == 4
    assert response.json()["meta"]["next_cursor"] is None


async def test_a_cursor_from_another_group_by_is_refused(world: World) -> None:
    await fleet(world)
    key = await seed_key(world)
    cursor = (await usage(world, key, "sandbox", limit=1)).json()["meta"]["next_cursor"]

    response = await usage(world, key, "label:team", cursor=cursor)

    assert response.status_code == 422, response.text
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert "different filter" in error["details"]["errors"][0]["msg"]
    assert "group_by" in error["details"]["errors"][0]["ctx"]["fields"]


async def test_a_cursor_from_another_period_is_refused(world: World) -> None:
    await fleet(world)
    key = await seed_key(world)
    cursor = (await usage(world, key, "sandbox", limit=1)).json()["meta"]["next_cursor"]
    params = {
        "from": T0.isoformat(),
        "to": (T0 + 2 * HOUR).isoformat(),
        "group_by": "sandbox",
        "cursor": cursor,
    }

    response = await world.client.get(
        USAGE, headers={"Authorization": f"Bearer {key}"}, params=params
    )

    assert response.status_code == 422, response.text
    assert "to" in response.json()["error"]["details"]["errors"][0]["ctx"]["fields"]


@pytest.mark.parametrize("cursor", ["", "not-a-cursor", "c2J4XzEyMw"])
async def test_a_malformed_cursor_is_a_422(world: World, cursor: str) -> None:
    await fleet(world)
    key = await seed_key(world)

    response = await usage(world, key, "sandbox", cursor=cursor)

    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


async def test_cursor_and_limit_without_group_by_are_refused(world: World) -> None:
    await fleet(world)
    key = await seed_key(world)

    with_limit = await usage(world, key, limit=2)
    with_cursor = await usage(world, key, cursor="abc")

    assert with_limit.status_code == 422, with_limit.text
    assert with_cursor.status_code == 422, with_cursor.text


@pytest.mark.parametrize("limit", [0, 101, -1])
async def test_a_limit_out_of_range_is_a_422(world: World, limit: int) -> None:
    await fleet(world)
    key = await seed_key(world)

    response = await usage(world, key, "sandbox", limit=limit)

    assert response.status_code == 422, response.text


async def test_the_ungrouped_reply_keeps_its_shape(world: World) -> None:
    await fleet(world)
    key = await seed_key(world)

    response = await usage(world, key)

    data = response.json()["data"]
    assert [set(row) for row in data] == [{"dimension", "unit", "total"}] * 3
    assert response.json()["meta"] == {"next_cursor": None}
