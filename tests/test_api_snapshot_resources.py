"""Snapshots record the resources of their source sandbox; ``inherit_resources`` adopts them.

FakeDriver, temp SQLite database migrated to head (so the ``r0026`` migration is exercised by
every test here). The per-sandbox maximum of ``migrated_app`` is 2000 millicores, 2048 MiB and
10 GiB; a snapshot recorded above it is seeded straight into the database.
"""

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import update

from sandfort.db.models.snapshots import SnapshotRow
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import Scope
from sandfort.domain.resources import ResourceSpec
from sandfort.domain.snapshot import Snapshot, SnapshotState
from sandfort.ids import new_snapshot_id
from test_api_sandboxes import BASE, NOW, add_org, migrated_app, seed_key, send
from test_snapshots import run_jobs

SNAPSHOTS = "/v1/snapshots"
QUOTA = "/v1/org/quota"
AUDIT = "/v1/audit-events"
SCOPES = frozenset(
    {
        Scope.SANDBOXES_READ,
        Scope.SANDBOXES_WRITE,
        Scope.SNAPSHOTS_READ,
        Scope.SNAPSHOTS_WRITE,
        Scope.ORG_READ,
        Scope.AUDIT_READ,
    }
)
REGISTRY_IMAGE = "alpine:3.20"
RECORDED = {"cpu_millicores": 1500, "memory_mib": 1024, "disk_gib": 5}
DEFAULTS = {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3}
ABOVE_MAXIMUM = {"cpu_millicores": 4000, "memory_mib": 1024, "disk_gib": 5}


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    async with migrated_app(tmp_path) as application:
        yield application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    return await add_org(app, "resources")


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id, SCOPES)


async def seed_snapshot(
    app: FastAPI, org_id: str, resources: dict[str, int] | None, name: str = "seeded"
) -> str:
    """A ready snapshot row whose recorded resources are ``resources`` (None = not recorded)."""
    snapshot = Snapshot(
        id=new_snapshot_id(),
        org_id=org_id,
        name=name,
        image_ref=f"sandfort-snapshot:{name}",
        digest="sha256:" + "ab" * 32,
        layer_count=1,
        state=SnapshotState.READY,
        resources=None if resources is None else ResourceSpec(**resources),
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.snapshots.add(snapshot)
        await uow.commit()
    return snapshot.id


async def create_sandbox(
    client: httpx.AsyncClient, key: str, *, status: int = 201, **payload: Any
) -> dict[str, Any]:
    return await send(client, "POST", BASE, key, status=status, json=payload)


async def reserved(client: httpx.AsyncClient, key: str) -> dict[str, Any]:
    body = await send(client, "GET", QUOTA, key, status=200)
    held: dict[str, Any] = body["data"]["reserved"]
    return held


async def audit_details(client: httpx.AsyncClient, key: str, action: str) -> list[dict[str, Any]]:
    body = await send(client, "GET", AUDIT, key, status=200, params={"action": action})
    return [event["details"] for event in body["data"]]


# --- recording -----------------------------------------------------------------------


async def test_a_snapshot_from_a_sandbox_records_and_shows_its_resources(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    source = (await create_sandbox(client, key, resources=RECORDED))["data"]
    payload = {"sandbox_id": source["id"], "name": "snap"}

    accepted = await send(
        client, "POST", f"{SNAPSHOTS}/from-sandbox", key, status=202, json=payload
    )
    snapshot_id = accepted["data"]["id"]
    await run_jobs(app)
    fetched = await send(client, "GET", f"{SNAPSHOTS}/{snapshot_id}", key, status=200)
    listed = await send(client, "GET", SNAPSHOTS, key, status=200)

    assert accepted["data"]["resources"] == RECORDED  # shown while still pending
    assert fetched["data"]["resources"] == RECORDED
    assert [item["resources"] for item in listed["data"]] == [RECORDED]
    async with UnitOfWork(app.state.session_factory) as uow:
        stored = await uow.snapshots.get(org_id, snapshot_id)
    assert stored is not None
    assert stored.resources == ResourceSpec(**RECORDED)


async def test_snapshot_create_audit_details_include_the_resources(
    client: httpx.AsyncClient, key: str
) -> None:
    source = (await create_sandbox(client, key, resources=RECORDED))["data"]
    payload = {"sandbox_id": source["id"], "name": "snap"}
    await send(client, "POST", f"{SNAPSHOTS}/from-sandbox", key, status=202, json=payload)

    [details] = await audit_details(client, key, "snapshot.create")

    assert details["resources"] == RECORDED
    assert details["sandbox_id"] == source["id"]


async def test_registered_snapshots_have_no_resources(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    payload = {"image": REGISTRY_IMAGE}

    registered = await send(client, "POST", SNAPSHOTS, key, status=201, json=payload)
    snapshot_id = registered["data"]["id"]
    fetched = await send(client, "GET", f"{SNAPSHOTS}/{snapshot_id}", key, status=200)

    assert registered["data"]["resources"] is None
    assert fetched["data"]["resources"] is None
    async with UnitOfWork(app.state.session_factory) as uow:
        stored = await uow.snapshots.get(org_id, snapshot_id)
    assert stored is not None and stored.resources is None


async def test_a_snapshot_row_without_resources_answers_null(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    snapshot_id = await seed_snapshot(app, org_id, None)

    fetched = await send(client, "GET", f"{SNAPSHOTS}/{snapshot_id}", key, status=200)

    assert fetched["data"]["resources"] is None


async def test_a_row_with_only_some_resource_columns_set_reads_as_unrecorded(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    snapshot_id = await seed_snapshot(app, org_id, RECORDED)
    async with app.state.session_factory() as session:
        await session.execute(
            update(SnapshotRow).where(SnapshotRow.id == snapshot_id).values(memory_mib=None)
        )
        await session.commit()

    fetched = await send(client, "GET", f"{SNAPSHOTS}/{snapshot_id}", key, status=200)
    created = await create_sandbox(client, key, snapshot=snapshot_id, inherit_resources=True)

    assert fetched["data"]["resources"] is None  # never a half-filled record
    assert created["data"]["resources"] == DEFAULTS


# --- inheriting ----------------------------------------------------------------------


async def test_inherit_resources_adopts_the_recorded_values(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    snapshot_id = await seed_snapshot(app, org_id, RECORDED)

    created = await create_sandbox(client, key, snapshot=snapshot_id, inherit_resources=True)

    assert created["data"]["resources"] == RECORDED


async def test_inherited_values_reach_quota_and_audit(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    snapshot_id = await seed_snapshot(app, org_id, RECORDED)

    await create_sandbox(client, key, snapshot=snapshot_id, inherit_resources=True)

    held = await reserved(client, key)
    assert held["vcpus"] == RECORDED["cpu_millicores"] / 1000
    assert held["memory_mib"] == RECORDED["memory_mib"]
    assert held["disk_gib"] == RECORDED["disk_gib"]
    [details] = await audit_details(client, key, "sandbox.create")
    assert details["resources"] == RECORDED


async def test_inherit_resources_resolves_a_snapshot_name_too(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    await seed_snapshot(app, org_id, RECORDED, name="named")

    created = await create_sandbox(client, key, snapshot="named", inherit_resources=True)

    assert created["data"]["resources"] == RECORDED


async def test_an_explicit_field_wins_and_the_others_inherit(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    snapshot_id = await seed_snapshot(app, org_id, RECORDED)

    created = await create_sandbox(
        client,
        key,
        snapshot=snapshot_id,
        inherit_resources=True,
        resources={"cpu_millicores": 500},
    )

    assert created["data"]["resources"] == {**RECORDED, "cpu_millicores": 500}


async def test_an_explicit_value_equal_to_the_default_still_wins(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    snapshot_id = await seed_snapshot(app, org_id, RECORDED)

    created = await create_sandbox(
        client,
        key,
        snapshot=snapshot_id,
        inherit_resources=True,
        resources={"memory_mib": DEFAULTS["memory_mib"]},
    )

    assert created["data"]["resources"] == {**RECORDED, "memory_mib": DEFAULTS["memory_mib"]}


# --- the per-sandbox maximum ----------------------------------------------------------


async def test_a_recorded_value_above_the_maximum_is_a_422_with_the_merged_values(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    snapshot_id = await seed_snapshot(app, org_id, ABOVE_MAXIMUM)

    refused = await create_sandbox(
        client, key, status=422, snapshot=snapshot_id, inherit_resources=True
    )

    assert refused["error"]["details"]["requested"] == ABOVE_MAXIMUM
    assert refused["error"]["details"]["maximum"]["cpu_millicores"] == 2000
    assert (await reserved(client, key))["sandboxes"] == 0  # nothing was clamped or created


async def test_an_explicit_field_can_bring_an_oversized_record_under_the_maximum(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    snapshot_id = await seed_snapshot(app, org_id, ABOVE_MAXIMUM)

    created = await create_sandbox(
        client,
        key,
        snapshot=snapshot_id,
        inherit_resources=True,
        resources={"cpu_millicores": 2000},
    )

    assert created["data"]["resources"] == {**ABOVE_MAXIMUM, "cpu_millicores": 2000}


# --- no-ops --------------------------------------------------------------------------


async def test_without_the_flag_the_recorded_resources_are_ignored(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    snapshot_id = await seed_snapshot(app, org_id, RECORDED)

    created = await create_sandbox(client, key, snapshot=snapshot_id)
    explicit_false = await create_sandbox(
        client, key, snapshot=snapshot_id, inherit_resources=False
    )

    assert created["data"]["resources"] == DEFAULTS
    assert explicit_false["data"]["resources"] == DEFAULTS


async def test_the_flag_changes_nothing_for_a_snapshot_without_resources(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    snapshot_id = await seed_snapshot(app, org_id, None)

    created = await create_sandbox(client, key, snapshot=snapshot_id, inherit_resources=True)

    assert created["data"]["resources"] == DEFAULTS


async def test_the_flag_changes_nothing_for_a_registered_image_snapshot(
    client: httpx.AsyncClient, key: str
) -> None:
    registered = await send(
        client, "POST", SNAPSHOTS, key, status=201, json={"image": REGISTRY_IMAGE}
    )

    created = await create_sandbox(
        client, key, snapshot=registered["data"]["id"], inherit_resources=True
    )

    assert created["data"]["resources"] == DEFAULTS


async def test_the_flag_changes_nothing_for_an_image_reference(
    client: httpx.AsyncClient, key: str
) -> None:
    created = await create_sandbox(client, key, snapshot=REGISTRY_IMAGE, inherit_resources=True)

    assert created["data"]["resources"] == DEFAULTS


async def test_the_flag_changes_nothing_without_a_snapshot(
    client: httpx.AsyncClient, key: str
) -> None:
    created = await create_sandbox(client, key, inherit_resources=True)
    sized = await create_sandbox(
        client, key, inherit_resources=True, resources={"cpu_millicores": 700}
    )

    assert created["data"]["resources"] == DEFAULTS
    assert sized["data"]["resources"] == {**DEFAULTS, "cpu_millicores": 700}


# --- validation ----------------------------------------------------------------------


@pytest.mark.parametrize("value", ["true", "false", 1, 0])
async def test_inherit_resources_must_be_a_json_boolean(
    client: httpx.AsyncClient, key: str, value: object
) -> None:
    refused = await create_sandbox(client, key, status=422, inherit_resources=value)

    issues = refused["error"]["details"]["errors"]
    assert [issue["loc"] for issue in issues] == [["body", "inherit_resources"]]
