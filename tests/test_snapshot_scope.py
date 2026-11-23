"""Snapshot images are reachable only through their owner's scope.

Through the API on the fake driver and a temp SQLite database. Two findings:

- the local ``sandfort-snapshot`` repository is reserved: a sandbox is created from a snapshot
  id, never from a raw reference into that repository (which would cross org boundaries);
- a label-scoped key reaches a snapshot committed from a sandbox only when it can see that
  sandbox; registered images and builds have no source sandbox and stay usable.
"""

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from sandfort.auth.api_keys import generate_api_key
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Scope
from sandfort.ids import new_api_key_id
from test_api_sandboxes import BASE, NOW, PEPPER, add_org, migrated_app, send
from test_snapshots import run_jobs

SNAPSHOTS = "/v1/snapshots"
SCOPES = frozenset(
    {
        Scope.SANDBOXES_READ,
        Scope.SANDBOXES_WRITE,
        Scope.SNAPSHOTS_READ,
        Scope.SNAPSHOTS_WRITE,
    }
)
RED = {"team": "red"}
BLUE = {"team": "blue"}
REGISTRY_IMAGE = "alpine:3.20"
RESERVED = "images in the sandfort-snapshot repository are reserved; pass the snapshot id instead"
DIGEST = "sha256:" + "ab" * 32
ID_MESSAGE = "image IDs are not accepted; pass an image name such as python:3.12-slim"
ID_LIKE_FORMS = (
    DIGEST,
    "ab" * 32,
    "4f2a9c",
    "4F2A9C",
    DIGEST.upper(),
    "  " + "ab" * 32 + "  ",
    "@" + DIGEST,
)
RESERVED_FORMS = (
    "sandfort-snapshot:snap_abc",
    "sandfort-snapshot",
    "SANDFORT-SNAPSHOT:SNAP_ABC",
    "Sandfort-Snapshot:snap_abc",
    "registry.example.com/sandfort-snapshot:snap_abc",
    "localhost:5000/team/sandfort-snapshot:snap_abc",
    "docker.io/library/SandFort-Snapshot@sha256:" + "ab" * 32,
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


async def seed_key(app: FastAPI, org_id: str, labels: dict[str, str] | None) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=SCOPES,
        created_at=NOW,
        sandbox_labels=labels,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    return await add_org(app, "scoped-snapshots")


@pytest.fixture
async def unscoped(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id, None)


@pytest.fixture
async def red(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id, RED)


async def make_sandbox(client: httpx.AsyncClient, key: str, **payload: Any) -> str:
    body = await send(client, "POST", BASE, key, status=201, json=payload)
    return str(body["data"]["id"])


async def commit_snapshot(
    app: FastAPI, client: httpx.AsyncClient, key: str, sandbox_id: str
) -> str:
    """Snapshot ``sandbox_id`` with ``key``, run the commit job, and return the ready id."""
    payload = {"sandbox_id": sandbox_id, "name": f"snap-{sandbox_id}"}
    path = f"{SNAPSHOTS}/from-sandbox"
    pending = (await send(client, "POST", path, key, status=202, json=payload))["data"]
    assert await run_jobs(app) == 1
    fetched = await send(client, "GET", f"{SNAPSHOTS}/{pending['id']}", key, status=200)
    assert fetched["data"]["state"] == "ready"
    return str(pending["id"])


async def stored_image(app: FastAPI, org_id: str, sandbox_id: str) -> str:
    async with UnitOfWork(app.state.session_factory) as uow:
        sandbox = await uow.sandboxes.get(org_id, sandbox_id)
    assert sandbox is not None
    return sandbox.image_ref


async def register_image(client: httpx.AsyncClient, key: str) -> str:
    payload = {"image": REGISTRY_IMAGE, "name": "public"}
    body = await send(client, "POST", SNAPSHOTS, key, status=201, json=payload)
    return str(body["data"]["id"])


async def listed_ids(client: httpx.AsyncClient, key: str) -> set[str]:
    body = await send(client, "GET", SNAPSHOTS, key, status=200)
    return {item["id"] for item in body["data"]}


@pytest.fixture
async def blue_snapshot(app: FastAPI, client: httpx.AsyncClient, unscoped: str) -> str:
    sandbox_id = await make_sandbox(client, unscoped, labels=BLUE)
    return await commit_snapshot(app, client, unscoped, sandbox_id)


@pytest.fixture
async def red_snapshot(app: FastAPI, client: httpx.AsyncClient, unscoped: str) -> str:
    sandbox_id = await make_sandbox(client, unscoped, labels=RED)
    return await commit_snapshot(app, client, unscoped, sandbox_id)


# --- (a) the reserved repository ---------------------------------------------------------


@pytest.mark.parametrize("reference", RESERVED_FORMS)
async def test_raw_snapshot_repository_reference_is_refused(
    client: httpx.AsyncClient, unscoped: str, red: str, reference: str
) -> None:
    for key in (unscoped, red):
        body = await send(client, "POST", BASE, key, status=422, json={"snapshot": reference})

        assert body["error"]["code"] == "UNPROCESSABLE"
        assert body["error"]["message"] == RESERVED


async def test_refused_reference_creates_no_sandbox(
    client: httpx.AsyncClient, unscoped: str
) -> None:
    payload = {"snapshot": "sandfort-snapshot:snap_abc"}
    await send(client, "POST", BASE, unscoped, status=422, json=payload)

    body = await send(client, "GET", BASE, unscoped, status=200)

    assert body["data"] == []


@pytest.mark.parametrize("reference", ID_LIKE_FORMS)
async def test_image_id_reference_is_refused(
    client: httpx.AsyncClient, unscoped: str, red: str, reference: str
) -> None:
    for key in (unscoped, red):
        body = await send(client, "POST", BASE, key, status=422, json={"snapshot": reference})

        assert body["error"]["code"] == "UNPROCESSABLE"
        assert body["error"]["message"] == ID_MESSAGE
    assert (await send(client, "GET", BASE, unscoped, status=200))["data"] == []


@pytest.mark.parametrize(
    "reference",
    [
        REGISTRY_IMAGE,
        "registry.example.com/sandfort-snapshots:1",
        "my/sandfort-snapshot-tools:2",
        "alpine@" + DIGEST,
        "ghcr.io/o/r:t",
    ],
)
async def test_normal_image_reference_still_works(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, unscoped: str, red: str, reference: str
) -> None:
    for key in (unscoped, red):
        sandbox_id = await make_sandbox(client, key, snapshot=reference)
        assert await stored_image(app, org_id, sandbox_id) == reference


async def test_snapshot_id_of_the_same_org_still_resolves(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, unscoped: str, red_snapshot: str
) -> None:
    sandbox_id = await make_sandbox(client, unscoped, snapshot=red_snapshot)

    assert (await stored_image(app, org_id, sandbox_id)).startswith("sandfort-snapshot:")


# --- (b) label scope ---------------------------------------------------------------------


async def test_scoped_key_cannot_get_a_snapshot_from_another_scope(
    client: httpx.AsyncClient, red: str, blue_snapshot: str
) -> None:
    body = await send(client, "GET", f"{SNAPSHOTS}/{blue_snapshot}", red, status=404)

    assert body["error"]["message"] == f"snapshot {blue_snapshot} not found"


async def test_scoped_key_list_omits_a_snapshot_from_another_scope(
    client: httpx.AsyncClient, red: str, blue_snapshot: str, red_snapshot: str
) -> None:
    assert await listed_ids(client, red) == {red_snapshot}


async def test_scoped_key_cannot_create_from_a_snapshot_of_another_scope(
    client: httpx.AsyncClient, red: str, blue_snapshot: str
) -> None:
    body = await send(client, "POST", BASE, red, status=404, json={"snapshot": blue_snapshot})

    assert body["error"]["message"] == f"snapshot {blue_snapshot} not found"
    assert (await send(client, "GET", BASE, red, status=200))["data"] == []


async def test_scoped_key_cannot_delete_a_snapshot_of_another_scope(
    client: httpx.AsyncClient, unscoped: str, red: str, blue_snapshot: str
) -> None:
    await send(client, "DELETE", f"{SNAPSHOTS}/{blue_snapshot}", red, status=404)

    assert blue_snapshot in await listed_ids(client, unscoped)


async def test_scoped_key_uses_a_snapshot_from_its_own_scope(
    client: httpx.AsyncClient, red: str, red_snapshot: str
) -> None:
    got = await send(client, "GET", f"{SNAPSHOTS}/{red_snapshot}", red, status=200)
    created = await send(client, "POST", BASE, red, status=201, json={"snapshot": red_snapshot})

    assert got["data"]["id"] == red_snapshot
    assert created["data"]["labels"]["team"] == "red"


async def test_scoped_key_uses_a_registered_image_snapshot(
    client: httpx.AsyncClient, unscoped: str, red: str
) -> None:
    public = await register_image(client, unscoped)

    got = await send(client, "GET", f"{SNAPSHOTS}/{public}", red, status=200)
    created = await send(client, "POST", BASE, red, status=201, json={"snapshot": public})

    assert got["data"]["id"] == public
    assert public in await listed_ids(client, red)
    assert created["data"]["id"].startswith("sbx_")


async def test_a_deleted_source_sandbox_still_decides(
    client: httpx.AsyncClient, unscoped: str, red: str, blue_snapshot: str
) -> None:
    sandboxes = (await send(client, "GET", BASE, unscoped, status=200))["data"]
    for sandbox in sandboxes:
        await send(client, "DELETE", f"{BASE}/{sandbox['id']}", unscoped, status=200)

    await send(client, "GET", f"{SNAPSHOTS}/{blue_snapshot}", red, status=404)
    assert blue_snapshot not in await listed_ids(client, red)


async def test_unscoped_key_is_unchanged(
    client: httpx.AsyncClient, unscoped: str, blue_snapshot: str, red_snapshot: str
) -> None:
    public = await register_image(client, unscoped)

    assert await listed_ids(client, unscoped) == {blue_snapshot, red_snapshot, public}
    for snapshot_id in (blue_snapshot, red_snapshot, public):
        await send(client, "GET", f"{SNAPSHOTS}/{snapshot_id}", unscoped, status=200)
        await send(client, "POST", BASE, unscoped, status=201, json={"snapshot": snapshot_id})


async def test_scoped_list_pages_over_hidden_snapshots(
    app: FastAPI, client: httpx.AsyncClient, unscoped: str, red: str, blue_snapshot: str
) -> None:
    first = await commit_snapshot(
        app, client, unscoped, await make_sandbox(client, unscoped, labels=RED)
    )
    second = await commit_snapshot(
        app, client, unscoped, await make_sandbox(client, unscoped, labels=RED)
    )

    page = await send(client, "GET", SNAPSHOTS, red, status=200, params={"limit": 1})
    rest = await send(
        client,
        "GET",
        SNAPSHOTS,
        red,
        status=200,
        params={"limit": 5, "cursor": page["meta"]["next_cursor"]},
    )

    seen = [item["id"] for item in page["data"]] + [item["id"] for item in rest["data"]]
    assert sorted(seen) == sorted([first, second])
    assert blue_snapshot not in seen
