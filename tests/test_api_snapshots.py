"""Snapshots keep the isolation tier of the sandbox they were taken from.

FakeDriver, temp SQLite database migrated to head. The ``snapshot.create`` job is driven by the
app's own runner. A deployment offering ``microvm`` is a tier map that names it.
"""

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from sandfort.clock import SystemClock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.isolation import ISOLATION_LABEL
from sandfort.domain.org import Scope
from sandfort.domain.snapshot import Snapshot, SnapshotState
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_snapshot_id
from sandfort.services.snapshots import SnapshotService
from test_api_sandboxes import BASE, NOW, add_org, migrated_app, seed_key, send
from test_snapshots import run_jobs

SNAPSHOTS = "/v1/snapshots"
FULL_TIERS = (("container", ""), ("gvisor", "runsc"), ("microvm", "kata"))
NO_MICROVM = FULL_TIERS[:2]
SCOPES = frozenset(
    {Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.SNAPSHOTS_READ, Scope.SNAPSHOTS_WRITE}
)
REGISTRY_IMAGE = "alpine:3.20"


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    async with migrated_app(tmp_path, isolation_runtimes=FULL_TIERS) as application:
        yield application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    return await add_org(app, "tiers")


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id, SCOPES)


async def make_sandbox(client: httpx.AsyncClient, key: str, **payload: Any) -> dict[str, Any]:
    body = await send(client, "POST", BASE, key, status=201, json=payload)
    data: dict[str, Any] = body["data"]
    return data


async def request_snapshot(
    client: httpx.AsyncClient, key: str, sandbox_id: str
) -> dict[str, Any]:
    payload = {"sandbox_id": sandbox_id, "name": "snap"}
    path = f"{SNAPSHOTS}/from-sandbox"
    return await send(client, "POST", path, key, status=202, json=payload)


async def snapshot_of(
    app: FastAPI, client: httpx.AsyncClient, key: str, sandbox_id: str
) -> dict[str, Any]:
    """Snapshot ``sandbox_id``, run the commit job, and return the ready snapshot."""
    pending = (await request_snapshot(client, key, sandbox_id))["data"]
    assert pending["state"] == "pending"
    assert await run_jobs(app) == 1
    fetched = await send(client, "GET", f"{SNAPSHOTS}/{pending['id']}", key, status=200)
    ready: dict[str, Any] = fetched["data"]
    assert ready["state"] == "ready"
    return ready


async def stored_snapshot(app: FastAPI, org_id: str, snapshot_id: str) -> Snapshot:
    async with UnitOfWork(app.state.session_factory) as uow:
        found = await uow.snapshots.get(org_id, snapshot_id)
    assert found is not None
    return found


async def stored_label(app: FastAPI, org_id: str, sandbox_id: str) -> str:
    async with UnitOfWork(app.state.session_factory) as uow:
        sandbox = await uow.sandboxes.get(org_id, sandbox_id)
    assert sandbox is not None
    return sandbox.labels[ISOLATION_LABEL]


async def seed_snapshot(app: FastAPI, org_id: str, isolation: str | None) -> str:
    snapshot = Snapshot(
        id=new_snapshot_id(),
        org_id=org_id,
        name="seeded",
        image_ref="sandfort-snapshot:seeded",
        digest="sha256:" + "ab" * 32,
        layer_count=1,
        state=SnapshotState.READY,
        isolation=isolation,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.snapshots.add(snapshot)
        await uow.commit()
    return snapshot.id


# --- recording ------------------------------------------------------------------


@pytest.mark.parametrize("tier", ["gvisor", "microvm"])
async def test_a_snapshot_records_and_shows_the_tier_of_its_source(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str, tier: str
) -> None:
    source = await make_sandbox(client, key, isolation=tier)

    accepted = await request_snapshot(client, key, source["id"])
    snapshot_id = accepted["data"]["id"]
    await run_jobs(app)
    fetched = await send(client, "GET", f"{SNAPSHOTS}/{snapshot_id}", key, status=200)
    listed = await send(client, "GET", SNAPSHOTS, key, status=200)

    assert accepted["data"]["isolation"] == tier  # shown while still pending
    assert fetched["data"]["isolation"] == tier
    assert [item["isolation"] for item in listed["data"]] == [tier]
    assert (await stored_snapshot(app, org_id, snapshot_id)).isolation == tier


async def test_a_snapshot_of_a_default_tier_sandbox_records_the_default(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    source = await make_sandbox(client, key)

    snapshot = await snapshot_of(app, client, key, source["id"])

    assert snapshot["isolation"] == "container"


async def test_image_snapshots_have_no_isolation(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    payload = {"image": REGISTRY_IMAGE}

    registered = await send(client, "POST", SNAPSHOTS, key, status=201, json=payload)
    snapshot_id = registered["data"]["id"]
    fetched = await send(client, "GET", f"{SNAPSHOTS}/{snapshot_id}", key, status=200)

    assert registered["data"]["isolation"] is None
    assert fetched["data"]["isolation"] is None
    assert (await stored_snapshot(app, org_id, snapshot_id)).isolation is None


async def test_a_source_without_the_label_records_the_service_default_tier(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    source = await make_sandbox(client, key)
    async with UnitOfWork(app.state.session_factory) as uow:
        row = await uow.sandboxes.get(org_id, source["id"])
        assert row is not None
        legacy = row.model_copy(update={"labels": {}})
        await uow.sandboxes.update(org_id, legacy, expected_version=row.version)
        await uow.commit()

    def uow_factory() -> UnitOfWorkPort:
        return UnitOfWork(app.state.session_factory)

    def service(default_tier: str | None) -> SnapshotService:
        return SnapshotService(
            uow_factory, app.state.driver, SystemClock(), default_tier=default_tier
        )

    with_default = await service("gvisor").create_from_sandbox(org_id, None, row.id, "a")
    without_default = await service(None).create_from_sandbox(org_id, None, row.id, "b")

    assert with_default.isolation == "gvisor"
    assert without_default.isolation is None


# --- inheritance ----------------------------------------------------------------


@pytest.mark.parametrize("tier", ["gvisor", "microvm"])
async def test_a_create_from_a_snapshot_inherits_its_tier(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str, tier: str
) -> None:
    source = await make_sandbox(client, key, isolation=tier)
    snapshot = await snapshot_of(app, client, key, source["id"])

    created = await make_sandbox(client, key, snapshot=snapshot["id"])

    assert created["isolation"] == tier  # not the deployment default
    assert await stored_label(app, org_id, created["id"]) == tier


async def test_an_explicit_isolation_overrides_the_snapshot_tier(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    source = await make_sandbox(client, key, isolation="microvm")
    snapshot = await snapshot_of(app, client, key, source["id"])

    created = await make_sandbox(client, key, snapshot=snapshot["id"], isolation="gvisor")

    assert created["isolation"] == "gvisor"
    assert await stored_label(app, org_id, created["id"]) == "gvisor"


async def test_a_snapshot_without_a_tier_gives_the_deployment_default(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    snapshot_id = await seed_snapshot(app, org_id, None)

    created = await make_sandbox(client, key, snapshot=snapshot_id)

    assert created["isolation"] == "container"


async def test_an_unavailable_recorded_tier_is_refused_not_downgraded(tmp_path: Path) -> None:
    async with migrated_app(tmp_path, isolation_runtimes=NO_MICROVM) as limited:
        org_id = await add_org(limited, "limited")
        key = await seed_key(limited, org_id, SCOPES)
        snapshot_id = await seed_snapshot(limited, org_id, "microvm")
        transport = httpx.ASGITransport(app=limited)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            refused = await send(
                http, "POST", BASE, key, status=422, json={"snapshot": snapshot_id}
            )
            driver = limited.state.driver
            assert isinstance(driver, FakeDriver)
            none_made = await driver.list_managed()
            explicit = {"snapshot": snapshot_id, "isolation": "gvisor"}
            allowed = await send(http, "POST", BASE, key, status=201, json=explicit)

    error = refused["error"]
    assert error["code"] == "UNPROCESSABLE"
    assert "isolation 'microvm'" in error["message"]
    assert snapshot_id in error["message"]
    assert error["message"].endswith("available: container, gvisor")
    assert error["details"] == {"requested": "microvm", "available": ["container", "gvisor"]}
    assert none_made == []  # no container was created on the default tier
    assert allowed["data"]["isolation"] == "gvisor"  # an explicit tier still wins
