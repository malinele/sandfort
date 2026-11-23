"""Security review of snapshot labels (round 64): shared-snapshot delete, source-sandbox reach,
audit labels, and the model defaults of the labels columns.

Through the API on the fake driver and a temp SQLite database migrated to head; no network.
"""

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from sandfort.db.models.snapshots import SnapshotRow
from sandfort.db.models.volumes import VolumeRow
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import AuditEvent
from test_api_sandboxes import add_org, migrated_app, send
from test_snapshot_labels_r64 import FORBIDDEN_STATUS, from_sandbox, register
from test_snapshot_scope import BLUE, RED, make_sandbox, seed_key
from test_snapshots import run_jobs

SNAPSHOTS = "/v1/snapshots"


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
    return await add_org(app, "snapshot-review")


@pytest.fixture
async def admin(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id, None)


@pytest.fixture
async def red(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id, RED)


async def audit_details(app: FastAPI, org_id: str, action: str, target: str) -> dict[str, Any]:
    async with UnitOfWork(app.state.session_factory) as uow:
        events: list[AuditEvent] = list(await uow.audit.list(org_id, limit=200))
    (event,) = [e for e in events if e.action == action and e.target_id == target]
    return dict(event.details)


# --- 2: a shared (unlabelled, sourceless) snapshot is not deletable by a scoped key ------------


async def test_scoped_key_cannot_delete_an_unlabelled_shared_snapshot(
    client: httpx.AsyncClient, admin: str, red: str
) -> None:
    shared = await register(client, admin, "shared")

    body = await send(
        client, "DELETE", f"{SNAPSHOTS}/{shared['id']}", red, status=FORBIDDEN_STATUS
    )

    assert body["error"]["message"] == (
        f"snapshot {shared['id']} is shared across the org; "
        "only a key without sandbox_labels can delete it"
    )
    await send(client, "GET", f"{SNAPSHOTS}/{shared['id']}", red, status=200)
    await send(client, "DELETE", f"{SNAPSHOTS}/{shared['id']}", admin, status=200)


async def test_scoped_key_still_reads_and_runs_a_shared_snapshot(
    client: httpx.AsyncClient, admin: str, red: str
) -> None:
    shared = await register(client, admin, "shared")

    listed = await send(client, "GET", SNAPSHOTS, red, status=200)

    assert [item["id"] for item in listed["data"]] == [shared["id"]]


async def test_scoped_key_deletes_a_snapshot_that_carries_its_scope(
    client: httpx.AsyncClient, red: str
) -> None:
    mine = await register(client, red, "mine")

    await send(client, "DELETE", f"{SNAPSHOTS}/{mine['id']}", red, status=200)


async def test_scoped_key_deletes_an_unlabelled_snapshot_through_its_source_sandbox(
    app: FastAPI, client: httpx.AsyncClient, admin: str, red: str
) -> None:
    sandbox_id = await make_sandbox(client, admin, labels=RED)
    bare = await from_sandbox(client, admin, sandbox_id, "bare")
    assert await run_jobs(app) == 1

    await send(client, "DELETE", f"{SNAPSHOTS}/{bare['id']}", red, status=200)


# --- 6: a labelled snapshot is also visible through its source sandbox --------------------------


async def test_labelled_snapshot_is_visible_through_a_visible_source_sandbox(
    app: FastAPI, client: httpx.AsyncClient, admin: str, red: str
) -> None:
    sandbox_id = await make_sandbox(client, admin, labels=RED)
    other = await from_sandbox(client, admin, sandbox_id, "env-prod", {"env": "prod"})
    assert await run_jobs(app) == 1

    await send(client, "GET", f"{SNAPSHOTS}/{other['id']}", red, status=200)
    listed = await send(client, "GET", SNAPSHOTS, red, status=200)
    assert [item["id"] for item in listed["data"]] == [other["id"]]
    await send(client, "DELETE", f"{SNAPSHOTS}/{other['id']}", red, status=200)


async def test_labelled_snapshot_stays_hidden_when_neither_labels_nor_source_match(
    app: FastAPI, client: httpx.AsyncClient, admin: str, red: str
) -> None:
    sandbox_id = await make_sandbox(client, admin, labels=BLUE)
    other = await from_sandbox(client, admin, sandbox_id, "blue-snap", {"env": "prod"})
    assert await run_jobs(app) == 1

    await send(client, "GET", f"{SNAPSHOTS}/{other['id']}", red, status=404)
    await send(client, "DELETE", f"{SNAPSHOTS}/{other['id']}", red, status=404)
    assert (await send(client, "GET", SNAPSHOTS, red, status=200))["data"] == []


# --- 5: audit details carry the stored labels --------------------------------------------------


async def test_register_and_create_audit_the_stored_labels(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, red: str
) -> None:
    registered = await register(client, red, "audited", {"env": "dev"})
    sandbox_id = await make_sandbox(client, red)
    created = await from_sandbox(client, red, sandbox_id, "audited-too")

    stored = {"team": "red", "env": "dev"}
    register_details = await audit_details(app, org_id, "snapshot.register", registered["id"])
    create_details = await audit_details(app, org_id, "snapshot.create", created["id"])
    assert register_details["labels"] == stored
    assert create_details["labels"] == RED


# --- 7: the model keeps the server default of the migration -------------------------------------


@pytest.mark.parametrize("row", [SnapshotRow, VolumeRow])
def test_labels_column_has_the_empty_mapping_server_default(row: Any) -> None:
    default = row.__table__.c.labels.server_default

    assert default is not None
    assert str(default.arg) == "'{}'"
