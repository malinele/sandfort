"""A sandbox create accepts a snapshot name as well as a snapshot id.

FakeDriver, temp SQLite database migrated to head. A name of the org's snapshots is resolved to
the snapshot id before every later step, so a create by name equals a create by id; a name that
matches no snapshot stays an image reference.
"""

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import Scope
from sandfort.drivers.fake import FakeDriver
from test_api_sandboxes import BASE, add_org, migrated_app, seed_key, send
from test_api_snapshots import FULL_TIERS, SNAPSHOTS, request_snapshot, snapshot_of
from test_snapshot_scope import BLUE, RED
from test_snapshot_scope import seed_key as seed_scoped_key

SNAPSHOT_NAME = "snap"  # the name ``snapshot_of`` gives its snapshot
UNKNOWN_IMAGE = "python:3.12"
SCOPES = frozenset(
    {Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.SNAPSHOTS_READ, Scope.SNAPSHOTS_WRITE}
)


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
    return await add_org(app, "by-name")


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id, SCOPES)


async def create(
    client: httpx.AsyncClient, key: str, *, status: int, **payload: Any
) -> dict[str, Any]:
    return await send(client, "POST", BASE, key, status=status, json=payload)


async def stored_image(app: FastAPI, org_id: str, sandbox_id: str) -> str:
    async with UnitOfWork(app.state.session_factory) as uow:
        sandbox = await uow.sandboxes.get(org_id, sandbox_id)
    assert sandbox is not None
    return sandbox.image_ref


async def test_create_by_name_equals_create_by_id(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    source = (await create(client, key, status=201, isolation="gvisor"))["data"]
    snapshot = await snapshot_of(app, client, key, source["id"])
    assert snapshot["name"] == SNAPSHOT_NAME

    by_id = (await create(client, key, status=201, snapshot=snapshot["id"]))["data"]
    by_name = (await create(client, key, status=201, snapshot=SNAPSHOT_NAME))["data"]

    assert by_name["isolation"] == by_id["isolation"] == "gvisor"  # the tier is inherited
    assert await stored_image(app, org_id, by_name["id"]) == snapshot["image_ref"]
    assert await stored_image(app, org_id, by_id["id"]) == snapshot["image_ref"]
    driver = app.state.driver
    assert isinstance(driver, FakeDriver)
    pinned = await driver.inspect(f"fake-sf-{by_name['id']}")
    assert pinned.image == snapshot["image_ref"]


async def test_an_unknown_name_still_takes_the_image_path(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    source = (await create(client, key, status=201))["data"]
    await snapshot_of(app, client, key, source["id"])  # a snapshot exists, under another name

    created = (await create(client, key, status=201, snapshot=UNKNOWN_IMAGE))["data"]

    assert await stored_image(app, org_id, created["id"]) == UNKNOWN_IMAGE


async def test_a_name_of_another_org_is_not_resolved(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    other_key = await seed_key(app, await add_org(app, "elsewhere"), SCOPES)
    other_source = (await create(client, other_key, status=201))["data"]
    await snapshot_of(app, client, other_key, other_source["id"])

    created = (await create(client, key, status=201, snapshot=SNAPSHOT_NAME))["data"]

    assert await stored_image(app, org_id, created["id"]) == SNAPSHOT_NAME


async def test_an_out_of_scope_name_looks_like_an_unknown_name(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    blue_source = (await create(client, key, status=201, labels=BLUE))["data"]
    blue = await snapshot_of(app, client, key, blue_source["id"])
    red_key = await seed_scoped_key(app, org_id, RED)
    headers = {"Authorization": f"Bearer {red_key}"}

    by_id = await create(client, red_key, status=404, snapshot=blue["id"])
    out_of_scope = await client.post(BASE, headers=headers, json={"snapshot": SNAPSHOT_NAME})
    unknown = await client.post(BASE, headers=headers, json={"snapshot": "no-such-snapshot"})

    assert by_id["error"]["message"] == f"snapshot {blue['id']} not found"
    assert out_of_scope.status_code == unknown.status_code
    assert blue["id"] not in out_of_scope.text
    assert blue["id"] not in unknown.text


async def test_a_scoped_key_reaches_an_in_scope_snapshot_by_name(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    red_source = (await create(client, key, status=201, labels=RED))["data"]
    red_snapshot = await snapshot_of(app, client, key, red_source["id"])
    red_key = await seed_scoped_key(app, org_id, RED)

    created = (await create(client, red_key, status=201, snapshot=SNAPSHOT_NAME))["data"]

    assert await stored_image(app, org_id, created["id"]) == red_snapshot["image_ref"]


async def test_a_pending_snapshot_by_name_behaves_as_by_id(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    source = (await create(client, key, status=201))["data"]
    pending = (await request_snapshot(client, key, source["id"]))["data"]
    assert pending["state"] == "pending"

    by_id = await create(client, key, status=409, snapshot=pending["id"])
    by_name = await create(client, key, status=409, snapshot=SNAPSHOT_NAME)

    for field in ("code", "message", "details"):  # the request id differs per request
        assert by_name["error"].get(field) == by_id["error"].get(field)
    assert by_id["error"]["message"] == f"snapshot {pending['id']} is pending"
    listing = await send(client, "GET", SNAPSHOTS, key, status=200)
    assert [item["state"] for item in listing["data"]] == ["pending"]
