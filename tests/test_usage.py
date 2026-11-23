"""WP 4.3 metering: intervals on lifecycle moves, rollups, the disk sampler, the usage report.

FakeDriver, a temp SQLite database, a frozen clock and the ASGI client; daemon-free. Routes
are exercised over HTTP only (the API sits behind a mounted app: no route-table introspection).
"""

import sqlite3
from collections.abc import AsyncIterator, Callable
from contextlib import closing
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
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.resources import DEFAULT_MEMORY_MIB, ResourceSpec
from sandfort.domain.sandbox import SandboxState
from sandfort.domain.usage import UsageDimension, UsageRollup
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.sandboxes import CreateSandboxCommand, SandboxService
from sandfort.services.usage import BYTES_PER_GIB, UsageService
from sandfort.workers.metering import MeteringWorker

ROOT = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
HOUR = timedelta(hours=1)
HALF_HOUR = timedelta(minutes=30)
PEPPER = "test-pepper"
USAGE = "/v1/org/usage"
ACTOR = "key_test"
SAMPLE_INTERVAL_S = 300
READER = frozenset({Scope.USAGE_READ})
VCPU = UsageDimension.VCPU
MEMORY = UsageDimension.MEMORY_MIB
DISK = UsageDimension.DISK_GIB


class SizedDriver(FakeDriver):
    """A fake driver that can cheaply report 2 GiB for every instance."""

    async def instance_size_bytes(self, provider_id: str) -> int | None:
        return 2 * BYTES_PER_GIB


@dataclass
class World:
    app: FastAPI
    client: httpx.AsyncClient
    clock: FrozenClock
    driver: SizedDriver
    uow_factory: Callable[[], UnitOfWorkPort]
    sandboxes: SandboxService
    usage: UsageService
    db_path: Path


@pytest.fixture
async def world(tmp_path: Path) -> AsyncIterator[World]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    db_path = tmp_path / "usage.db"
    url = f"sqlite+aiosqlite:///{db_path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(driver="fake", database_url=url, api_key_pepper=PEPPER)
    app = create_app(settings)
    clock = FrozenClock(T0)
    driver = SizedDriver(clock)
    uow_factory = app.state.uow_factory
    usage = UsageService(uow_factory, clock)
    setattr(app.state, USAGE_SERVICE_ATTR, usage)  # the route reads the frozen clock
    sandboxes = SandboxService(uow_factory, driver, settings, clock)
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            yield World(app, http, clock, driver, uow_factory, sandboxes, usage, db_path)
    finally:
        await app.state.engine.dispose()


async def add_org(world: World, slug: str) -> str:
    org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=T0)
    async with UnitOfWork(world.app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def seed_key(world: World, org_id: str, scopes: frozenset[Scope]) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=scopes,
        created_at=T0,
    )
    async with UnitOfWork(world.app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def start_sandbox(world: World, org_id: str, cpu_millicores: int = 2000) -> str:
    request = CreateSandboxCommand(resources=ResourceSpec(cpu_millicores=cpu_millicores))
    sandbox = await world.sandboxes.create(org_id, ACTOR, request)
    assert sandbox.state is SandboxState.STARTED
    return sandbox.id


async def totals(
    world: World, org_id: str, start: datetime, end: datetime
) -> dict[UsageDimension, float]:
    report = await world.usage.report(org_id, start, end)
    return {item.dimension: item.total for item in report}


def metering(world: World, driver: FakeDriver | None = None, lookback: int = 2) -> MeteringWorker:
    return MeteringWorker(
        world.uow_factory,
        driver or world.driver,
        world.clock,
        rollup_interval_s=3600,
        sample_interval_s=SAMPLE_INTERVAL_S,
        lookback_hours=lookback,
    )


def raw_rollups(db_path: Path) -> list[tuple[Any, ...]]:
    sql = "SELECT org_id, period_start, dimension, total FROM usage_rollups ORDER BY 2, 3"
    with closing(sqlite3.connect(db_path)) as connection:
        return connection.execute(sql).fetchall()


async def get_usage(
    world: World, key: str | None, start: datetime, end: datetime, group_by: str | None = None
) -> httpx.Response:
    params = {"from": start.isoformat(), "to": end.isoformat()}
    if group_by is not None:
        params["group_by"] = group_by
    headers = {} if key is None else auth(key)
    return await world.client.get(USAGE, headers=headers, params=params)


def by_dimension(response: httpx.Response) -> dict[str, float]:
    assert response.status_code == 200, response.text
    return {row["dimension"]: row["total"] for row in response.json()["data"]}


# --- interval accounting ----------------------------------------------------------------


async def test_two_vcpus_running_one_hour_report_exactly_7200_vcpu_seconds(world: World) -> None:
    org_id = await add_org(world, "acme")
    sandbox_id = await start_sandbox(world, org_id, cpu_millicores=2000)
    world.clock.advance(HOUR)
    await world.sandboxes.stop(org_id, ACTOR, sandbox_id)

    got = await totals(world, org_id, T0, T0 + HOUR)

    assert got[VCPU] == 7200.0
    assert got[MEMORY] == DEFAULT_MEMORY_MIB * 3600.0
    assert got[DISK] == 2.0 * 3600  # the final sample at stop: SizedDriver reports 2 GiB


async def test_stop_then_start_splits_intervals_and_the_sum_is_unchanged(world: World) -> None:
    org_id = await add_org(world, "acme")
    sandbox_id = await start_sandbox(world, org_id)
    world.clock.advance(HALF_HOUR)
    await world.sandboxes.stop(org_id, ACTOR, sandbox_id)
    world.clock.advance(HALF_HOUR)  # stopped: nothing is metered
    await world.sandboxes.start(org_id, ACTOR, sandbox_id)
    world.clock.advance(HALF_HOUR)
    await world.sandboxes.stop(org_id, ACTOR, sandbox_id)

    async with world.uow_factory() as uow:
        listed = await uow.usage.list_intervals(T0, T0 + 2 * HOUR, org_id=org_id)
    vcpu = [interval for interval in listed if interval.dimension is VCPU]
    got = await totals(world, org_id, T0, T0 + 2 * HOUR)

    assert len(vcpu) == 2
    first, second = vcpu
    assert (first.started_at, first.ended_at) == (T0, T0 + HALF_HOUR)
    assert (second.started_at, second.ended_at) == (T0 + HOUR, T0 + HOUR + HALF_HOUR)
    assert got[VCPU] == 7200.0


async def test_delete_closes_the_open_intervals(world: World) -> None:
    org_id = await add_org(world, "acme")
    sandbox_id = await start_sandbox(world, org_id)
    world.clock.advance(HALF_HOUR)
    await world.sandboxes.delete(org_id, ACTOR, sandbox_id)
    world.clock.advance(HOUR)  # a destroyed sandbox accrues nothing more

    got = await totals(world, org_id, T0, T0 + 2 * HOUR)

    assert got[VCPU] == 2.0 * 1800


# --- rollups -----------------------------------------------------------------------------


async def test_rollup_pass_is_idempotent_on_rerun(world: World) -> None:
    org_id = await add_org(world, "acme")
    await start_sandbox(world, org_id)
    world.clock.advance(2 * HOUR)
    worker = metering(world, lookback=2)

    written = await worker.rollup_once()
    first = raw_rollups(world.db_path)
    world.clock.advance(timedelta(minutes=10))  # same completed hours, one more pass
    await worker.rollup_once()
    second = raw_rollups(world.db_path)

    assert written == 4  # two completed hours, vcpu and memory each
    assert len(first) == 4
    assert second == first
    assert {row[3] for row in first if row[2] == "vcpu"} == {7200.0}


async def test_an_unfinished_hour_is_never_rolled_up(world: World) -> None:
    org_id = await add_org(world, "acme")
    await start_sandbox(world, org_id)
    world.clock.advance(HALF_HOUR)

    written = await world.usage.rollup_hour(T0)

    assert written == 0
    assert raw_rollups(world.db_path) == []


# --- disk sampler ------------------------------------------------------------------------


async def test_sampler_records_a_disk_sample_for_a_running_sandbox(world: World) -> None:
    org_id = await add_org(world, "acme")
    await start_sandbox(world, org_id)
    world.clock.advance(timedelta(seconds=SAMPLE_INTERVAL_S))

    recorded = await metering(world).sample_once()
    got = await totals(world, org_id, T0, T0 + timedelta(seconds=SAMPLE_INTERVAL_S))

    assert recorded == 1
    assert got[DISK] == 2.0 * SAMPLE_INTERVAL_S


async def test_sampler_skips_a_driver_without_a_cheap_size(world: World) -> None:
    org_id = await add_org(world, "acme")
    await start_sandbox(world, org_id)
    world.clock.advance(timedelta(seconds=SAMPLE_INTERVAL_S))

    recorded = await metering(world, driver=FakeDriver(world.clock)).sample_once()
    got = await totals(world, org_id, T0, T0 + HOUR)

    assert recorded == 0
    assert got[DISK] == 0.0


# --- report api --------------------------------------------------------------------------


async def test_report_api_combines_rollups_and_live_intervals(world: World) -> None:
    org_id = await add_org(world, "acme")
    key = await seed_key(world, org_id, READER)
    await start_sandbox(world, org_id)  # still running at the end of the period
    end = T0 + 2 * HOUR + HALF_HOUR
    world.clock.set(end)
    await metering(world, lookback=3).rollup_once()  # hours 12:00 and 13:00 are completed

    response = await get_usage(world, key, T0, end)

    assert by_dimension(response)["vcpu"] == 2.0 * 9000  # two rolled hours plus half a live one
    assert response.json()["meta"]["next_cursor"] is None
    async with world.uow_factory() as uow:  # a stored rollup, not the intervals, answers its hour
        sentinel = UsageRollup(org_id=org_id, period_start=T0, dimension=VCPU, total=100.0)
        await uow.usage.upsert_rollup(sentinel)
        await uow.commit()
    assert (await totals(world, org_id, T0, end))[VCPU] == 100.0 + 7200.0 + 3600.0


async def test_report_api_rejects_a_period_that_ends_before_it_starts(world: World) -> None:
    org_id = await add_org(world, "acme")
    key = await seed_key(world, org_id, READER)

    response = await get_usage(world, key, T0 + HOUR, T0)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "UNPROCESSABLE"


async def test_report_api_requires_authentication(world: World) -> None:
    response = await get_usage(world, None, T0, T0 + HOUR)

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


async def test_report_api_requires_the_usage_scope(world: World) -> None:
    org_id = await add_org(world, "acme")
    key = await seed_key(world, org_id, frozenset({Scope.ORG_READ}))

    response = await get_usage(world, key, T0, T0 + HOUR)

    assert response.status_code == 403


async def test_report_api_isolates_orgs(world: World) -> None:
    acme = await add_org(world, "acme")
    globex = await add_org(world, "globex")
    acme_key = await seed_key(world, acme, READER)
    globex_key = await seed_key(world, globex, READER)
    acme_sandbox = await start_sandbox(world, acme, cpu_millicores=2000)
    globex_sandbox = await start_sandbox(world, globex, cpu_millicores=1000)
    world.clock.advance(HOUR)
    await world.sandboxes.stop(acme, ACTOR, acme_sandbox)
    await world.sandboxes.stop(globex, ACTOR, globex_sandbox)

    acme_usage = by_dimension(await get_usage(world, acme_key, T0, T0 + HOUR))
    globex_usage = by_dimension(await get_usage(world, globex_key, T0, T0 + HOUR))

    assert acme_usage["vcpu"] == 7200.0
    assert globex_usage["vcpu"] == 3600.0
    assert acme_usage["memory_mib"] == globex_usage["memory_mib"] == DEFAULT_MEMORY_MIB * 3600.0


# --- grouped report (chargeback) ----------------------------------------------------------


async def start_labeled(
    world: World, org_id: str, labels: dict[str, str], cpu_millicores: int = 1000
) -> str:
    resources = ResourceSpec(cpu_millicores=cpu_millicores)
    request = CreateSandboxCommand(resources=resources, labels=labels)
    sandbox = await world.sandboxes.create(org_id, ACTOR, request)
    assert sandbox.state is SandboxState.STARTED
    return sandbox.id


def vcpu_by_group(response: httpx.Response) -> dict[str | None, float]:
    assert response.status_code == 200, response.text
    groups: dict[str | None, float] = {}
    for group in response.json()["data"]:
        totals = {row["dimension"]: row["total"] for row in group["totals"]}
        assert set(totals) == {"vcpu", "memory_mib", "disk_gib"}
        groups[group["group_value"]] = totals["vcpu"]
    return groups


async def test_report_without_group_by_keeps_the_org_totals_shape(world: World) -> None:
    org_id = await add_org(world, "acme")
    key = await seed_key(world, org_id, READER)
    await start_labeled(world, org_id, {"team": "platform"}, cpu_millicores=2000)
    await start_labeled(world, org_id, {})
    world.clock.advance(HOUR)

    response = await get_usage(world, key, T0, T0 + HOUR)

    data = response.json()["data"]
    assert [set(row) for row in data] == [{"dimension", "unit", "total"}] * 3
    assert by_dimension(response)["vcpu"] == 3.0 * 3600
    assert response.json()["meta"]["next_cursor"] is None


async def test_group_by_sandbox_splits_two_sandboxes(world: World) -> None:
    org_id = await add_org(world, "acme")
    key = await seed_key(world, org_id, READER)
    big = await start_sandbox(world, org_id, cpu_millicores=2000)
    small = await start_sandbox(world, org_id, cpu_millicores=1000)
    world.clock.advance(HOUR)

    response = await get_usage(world, key, T0, T0 + HOUR, group_by="sandbox")

    assert vcpu_by_group(response) == {big: 7200.0, small: 3600.0}
    assert {group["group_key"] for group in response.json()["data"]} == {"sandbox"}
    assert response.json()["meta"]["next_cursor"] is None


async def test_group_by_label_groups_values_and_collects_unlabeled_in_null(
    world: World,
) -> None:
    org_id = await add_org(world, "acme")
    key = await seed_key(world, org_id, READER)
    await start_labeled(world, org_id, {"team": "platform"})
    await start_labeled(world, org_id, {"team": "platform", "cost-center": "cc1"})
    await start_labeled(world, org_id, {"team": "data"}, cpu_millicores=2000)
    unlabeled = await start_labeled(world, org_id, {"cost-center": "cc2"})
    world.clock.advance(HALF_HOUR)
    await world.sandboxes.delete(org_id, ACTOR, unlabeled)  # destroyed still counts
    world.clock.advance(HALF_HOUR)

    response = await get_usage(world, key, T0, T0 + HOUR, group_by="label:team")

    data = response.json()["data"]
    assert [group["group_value"] for group in data] == ["data", "platform", None]
    assert {group["group_key"] for group in data} == {"team"}
    assert vcpu_by_group(response) == {"data": 7200.0, "platform": 7200.0, None: 1800.0}
    memory = {
        group["group_value"]: next(
            row["total"] for row in group["totals"] if row["dimension"] == "memory_mib"
        )
        for group in data
    }
    assert memory["platform"] == 2.0 * DEFAULT_MEMORY_MIB * 3600


NOTE_NOPE = "label key 'nope' was not found on any sandbox in this window; check the key"


async def test_label_key_seen_on_no_sandbox_adds_a_meta_note_r65(world: World) -> None:
    org_id = await add_org(world, "acme")
    key = await seed_key(world, org_id, READER)
    await start_labeled(world, org_id, {"team": "platform"})
    world.clock.advance(HOUR)

    response = await get_usage(world, key, T0, T0 + HOUR, group_by="label:nope")

    assert response.status_code == 200, response.text
    assert vcpu_by_group(response) == {None: 3600.0}  # data shape unchanged
    assert response.json()["meta"]["note"] == NOTE_NOPE
    assert response.json()["meta"]["next_cursor"] is None


async def test_no_note_when_the_label_key_is_seen_or_nothing_ran_r65(world: World) -> None:
    org_id = await add_org(world, "acme")
    key = await seed_key(world, org_id, READER)
    empty = await get_usage(world, key, T0, T0 + HOUR, group_by="label:team")
    assert empty.json()["data"] == [] and "note" not in empty.json()["meta"]
    await start_labeled(world, org_id, {"team": "platform"})
    await start_labeled(world, org_id, {})
    world.clock.advance(HOUR)

    partly = await get_usage(world, key, T0, T0 + HOUR, group_by="label:team")
    plain = await get_usage(world, key, T0, T0 + HOUR, group_by="sandbox")
    totals_only = await get_usage(world, key, T0, T0 + HOUR)

    for response in (partly, plain, totals_only):  # the field is absent, not null
        assert "note" not in response.json()["meta"]


async def test_grouped_totals_clip_intervals_at_the_window_edges(world: World) -> None:
    org_id = await add_org(world, "acme")
    sandbox_id = await start_sandbox(world, org_id, cpu_millicores=2000)
    world.clock.advance(2 * HOUR)
    await world.sandboxes.stop(org_id, ACTOR, sandbox_id)
    start, end = T0 + HALF_HOUR, T0 + HOUR + HALF_HOUR  # strictly inside the interval

    groups = await world.usage.report_grouped(org_id, start, end, "sandbox")
    ungrouped = await totals(world, org_id, start, end)

    assert [group.value for group in groups] == [sandbox_id]
    grouped = {item.dimension: item.total for item in groups[0].totals}
    assert grouped[VCPU] == 2.0 * 3600
    assert grouped == ungrouped


@pytest.mark.parametrize(
    "group_by", ["label", "label:", "team", "Sandbox", "label:sandfort.mounts", ""]
)
async def test_an_unknown_group_by_is_a_422_not_ignored(world: World, group_by: str) -> None:
    org_id = await add_org(world, "acme")
    key = await seed_key(world, org_id, READER)

    response = await get_usage(world, key, T0, T0 + HOUR, group_by=group_by)

    assert response.status_code == 422, response.text
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert "group_by must be 'sandbox' or 'label:<key>'" in error["message"]
