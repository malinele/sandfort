"""Round 100 (B35): a second org cannot delete, snapshot from or run another org's snapshot."""

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_snapshot_id
from sandfort.services.image_policy import RESERVED_IMAGE_MESSAGE
from test_api_sandboxes import migrated_app
from test_snapshots import (
    SANDBOXES,
    SNAPSHOTS,
    add_org,
    audit_rows,
    auth,
    call,
    error_code,
    fetch,
    run_jobs,
    seed_key,
    snapshot_sandbox,
    start_sandbox,
)


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
def driver(app: FastAPI) -> FakeDriver:
    fake = app.state.driver
    assert isinstance(fake, FakeDriver)
    return fake


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    return await add_org(app, "acme")


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id)


async def ready_snapshot(app: FastAPI, client: httpx.AsyncClient, key: str) -> dict[str, Any]:
    """A ready snapshot of a fresh started sandbox of the key's org."""
    source = await start_sandbox(client, key)
    pending = await snapshot_sandbox(client, key, source["id"])
    assert await run_jobs(app) == 1
    return await fetch(client, key, pending["id"])


async def test_delete_of_another_orgs_snapshot_is_not_found(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, key: str, org_id: str
) -> None:
    other_key = await seed_key(app, await add_org(app, "other"))
    snapshot = await ready_snapshot(app, client, key)
    assert snapshot["state"] == "ready"

    response = await client.delete(f"{SNAPSHOTS}/{snapshot['id']}", headers=auth(other_key))

    assert response.status_code == 404
    assert error_code(response) == "NOT_FOUND"
    assert response.json()["error"]["message"] == f"snapshot {snapshot['id']} not found"
    missing = new_snapshot_id()
    absent = await client.delete(f"{SNAPSHOTS}/{missing}", headers=auth(other_key))
    assert absent.status_code == 404
    assert error_code(absent) == "NOT_FOUND"
    assert absent.json()["error"]["message"] == f"snapshot {missing} not found"
    assert (await fetch(client, key, snapshot["id"]))["state"] == "ready"
    assert await driver.image_exists(snapshot["image_ref"])
    assert "snapshot.delete" not in {event.action for event in await audit_rows(app, org_id)}


async def test_create_from_sandbox_naming_another_orgs_sandbox_is_not_found(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    other_key = await seed_key(app, await add_org(app, "other"))
    source = await start_sandbox(client, key)

    response = await client.post(
        f"{SNAPSHOTS}/from-sandbox",
        headers=auth(other_key),
        json={"sandbox_id": source["id"], "name": "stolen"},
    )

    assert response.status_code == 404
    assert error_code(response) == "NOT_FOUND"
    assert response.json()["error"]["message"] == f"sandbox {source['id']} not found"
    assert await run_jobs(app) == 0
    assert (await call(client, "GET", SNAPSHOTS, key, status=200))["data"] == []
    assert (await call(client, "GET", SNAPSHOTS, other_key, status=200))["data"] == []
    owned = await call(client, "GET", f"{SANDBOXES}/{source['id']}", key, status=200)
    assert owned["data"]["state"] == "started"


@pytest.mark.parametrize("variant", ["as_is", "upper"])
async def test_raw_reference_to_another_orgs_snapshot_image_is_refused(
    app: FastAPI, client: httpx.AsyncClient, key: str, variant: str
) -> None:
    other_key = await seed_key(app, await add_org(app, "other"))
    snapshot = await ready_snapshot(app, client, key)
    reference: str = snapshot["image_ref"]
    assert reference.startswith("sandfort-snapshot:")
    if variant == "upper":
        reference = reference.upper()

    # The owner is refused too, by design: snapshots are reached by id only.
    for caller in (other_key, key):
        response = await client.post(SANDBOXES, headers=auth(caller), json={"snapshot": reference})
        assert response.status_code == 422
        assert error_code(response) == "UNPROCESSABLE"
        assert response.json()["error"]["message"] == RESERVED_IMAGE_MESSAGE

    other_listing = await call(client, "GET", SANDBOXES, other_key, status=200)
    assert other_listing["data"] == []
    owner_listing = await call(client, "GET", SANDBOXES, key, status=200)
    assert [item["id"] for item in owner_listing["data"]] == [snapshot["source_sandbox_id"]]
