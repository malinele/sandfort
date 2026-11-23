"""WP 3.4 volumes over the FakeDriver and the ASGI app (daemon-free).

A temp SQLite database migrated to head. The fake driver shares files written under a mount
path between every instance mounting the same volume, so sharing is checked end to end
through the fs toolbox.
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import AuditEvent
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id, new_volume_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
VOLUMES = "/v1/volumes"
SANDBOXES = "/v1/sandboxes"
MOUNT = "/data"
FULL_ACCESS = frozenset(
    {
        Scope.SANDBOXES_READ,
        Scope.SANDBOXES_WRITE,
        Scope.TOOLBOX,
        Scope.VOLUMES_READ,
        Scope.VOLUMES_WRITE,
    }
)


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'volumes.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))
    try:
        yield application
    finally:
        await application.state.engine.dispose()


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


async def add_org(app: FastAPI, slug: str) -> str:
    org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def seed_key(app: FastAPI, org_id: str) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=FULL_ACCESS,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    return await add_org(app, "acme")


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id)


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def error_code(response: httpx.Response) -> str:
    code: str = response.json()["error"]["code"]
    return code


async def call(
    client: httpx.AsyncClient, method: str, path: str, key: str, *, status: int, **kwargs: Any
) -> dict[str, Any]:
    response = await client.request(method, path, headers=auth(key), **kwargs)
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    return body


async def create_volume(
    client: httpx.AsyncClient, key: str, name: str = "data"
) -> dict[str, Any]:
    created = await call(client, "POST", VOLUMES, key, status=201, json={"name": name})
    data: dict[str, Any] = created["data"]
    return data


async def start_sandbox(client: httpx.AsyncClient, key: str, **body: Any) -> dict[str, Any]:
    created = await call(client, "POST", SANDBOXES, key, status=201, json=body)
    data: dict[str, Any] = created["data"]
    assert data["state"] == "started", data
    return data


def mounting(volume_id: str, path: str = MOUNT) -> dict[str, Any]:
    return {"volumes": [{"volume_id": volume_id, "mount_path": path}]}


async def audit_rows(app: FastAPI, org_id: str) -> list[AuditEvent]:
    async with UnitOfWork(app.state.session_factory) as uow:
        return list(await uow.audit.list(org_id, limit=200))


# --- crud ----------------------------------------------------------------------------


async def test_create_get_list_delete_round_trip(
    client: httpx.AsyncClient, driver: FakeDriver, key: str
) -> None:
    created = await create_volume(client, key, "cache")

    assert created["state"] == "ready"
    assert created["name"] == "cache"
    assert created["size_bytes"] is None
    assert [item.name for item in await driver.list_volumes()] == [
        f"sf-vol-{created['id'].lower()}"
    ]

    fetched = (await call(client, "GET", f"{VOLUMES}/{created['id']}", key, status=200))["data"]
    assert fetched["size_bytes"] == 0  # sampled from the driver on read
    listing = (await call(client, "GET", VOLUMES, key, status=200))["data"]
    assert [item["id"] for item in listing] == [created["id"]]

    deleted = await call(client, "DELETE", f"{VOLUMES}/{created['id']}", key, status=200)

    assert deleted["data"]["state"] == "deleting"
    await call(client, "GET", f"{VOLUMES}/{created['id']}", key, status=404)
    assert await driver.list_volumes() == []


async def test_volume_names_are_unique_per_org(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    await create_volume(client, key, "shared")
    other_key = await seed_key(app, await add_org(app, "other"))

    duplicate = await client.post(VOLUMES, headers=auth(key), json={"name": "shared"})
    elsewhere = await create_volume(client, other_key, "shared")

    assert duplicate.status_code == 409
    assert error_code(duplicate) == "CONFLICT"
    assert elsewhere["name"] == "shared"


async def test_foreign_and_missing_volumes_are_not_found(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    other_key = await seed_key(app, await add_org(app, "other"))
    foreign = await create_volume(client, other_key)

    for volume_id in (foreign["id"], new_volume_id()):
        for method in ("GET", "DELETE"):
            response = await client.request(method, f"{VOLUMES}/{volume_id}", headers=auth(key))
            assert response.status_code == 404
    assert (await call(client, "GET", VOLUMES, key, status=200))["data"] == []


# --- mounts ----------------------------------------------------------------------------


async def test_create_sandbox_with_a_mount_records_it(
    client: httpx.AsyncClient, key: str
) -> None:
    volume = await create_volume(client, key)

    sandbox = await start_sandbox(client, key, labels={"team": "a"}, **mounting(volume["id"]))

    expected = [{"volume_id": volume["id"], "mount_path": MOUNT, "read_only": False}]
    assert sandbox["volumes"] == expected
    assert sandbox["labels"] == {"team": "a"}  # the mount record never shows as a label
    fetched = (await call(client, "GET", f"{SANDBOXES}/{sandbox['id']}", key, status=200))["data"]
    assert fetched["volumes"] == expected


async def test_two_sandboxes_share_files_through_a_volume(
    client: httpx.AsyncClient, key: str
) -> None:
    volume = await create_volume(client, key)
    first = await start_sandbox(client, key, **mounting(volume["id"]))
    second = await start_sandbox(client, key, **mounting(volume["id"], "/mnt/shared"))
    payload = b"shared \x00 bytes"

    upload = f"{SANDBOXES}/{first['id']}/toolbox/fs/upload"
    params = {"path": f"{MOUNT}/note.bin"}
    await call(client, "PUT", upload, key, status=200, params=params, content=payload)
    download = f"{SANDBOXES}/{second['id']}/toolbox/fs/download"
    read = await client.get(download, headers=auth(key), params={"path": "/mnt/shared/note.bin"})

    assert read.status_code == 200, read.text
    assert read.content == payload
    sampled = (await call(client, "GET", f"{VOLUMES}/{volume['id']}", key, status=200))["data"]
    assert sampled["size_bytes"] == len(payload)


async def test_delete_is_refused_while_mounted_and_allowed_after_the_sandbox_goes(
    client: httpx.AsyncClient, driver: FakeDriver, key: str
) -> None:
    volume = await create_volume(client, key)
    sandbox = await start_sandbox(client, key, **mounting(volume["id"]))
    # replacing user labels must not drop the mount record
    patch = {"labels": {"b": "2"}}
    await call(client, "PATCH", f"{SANDBOXES}/{sandbox['id']}", key, status=200, json=patch)

    refused = await client.delete(f"{VOLUMES}/{volume['id']}", headers=auth(key))

    assert refused.status_code == 409
    assert error_code(refused) == "CONFLICT"
    assert refused.json()["error"]["details"] == {
        "reason": "in_use",
        "sandbox_id": sandbox["id"],
    }
    assert len(await driver.list_volumes()) == 1

    await call(client, "DELETE", f"{SANDBOXES}/{sandbox['id']}", key, status=200)
    await call(client, "DELETE", f"{VOLUMES}/{volume['id']}", key, status=200)

    assert await driver.list_volumes() == []


async def test_a_foreign_or_missing_volume_in_create_is_not_found(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    other_key = await seed_key(app, await add_org(app, "other"))
    foreign = await create_volume(client, other_key)

    for volume_id in (foreign["id"], new_volume_id()):
        response = await client.post(SANDBOXES, headers=auth(key), json=mounting(volume_id))
        assert response.status_code == 404, response.text
        assert error_code(response) == "NOT_FOUND"
    assert (await call(client, "GET", SANDBOXES, key, status=200))["data"] == []


@pytest.mark.parametrize(
    "mounts",
    [
        [("same", "/data"), ("same", "/data")],
        [("same", "/data"), ("other", "/data")],
        [("same", "data")],
        [("same", "/data/../etc")],
        [("same", "/")],
        [("same", "/proc/self")],
    ],
)
async def test_duplicate_or_invalid_mount_paths_are_422(
    client: httpx.AsyncClient, key: str, mounts: list[tuple[str, str]]
) -> None:
    volume_ids: dict[str, str] = {}
    for name in ("same", "other"):
        volume_ids[name] = (await create_volume(client, key, name))["id"]
    body = {
        "volumes": [{"volume_id": volume_ids[name], "mount_path": path} for name, path in mounts]
    }

    response = await client.post(SANDBOXES, headers=auth(key), json=body)

    assert response.status_code == 422, response.text


async def test_reserved_label_names_are_rejected(client: httpx.AsyncClient, key: str) -> None:
    labels = {"sandfort.volume_mounts": "[]"}
    created = await client.post(SANDBOXES, headers=auth(key), json={"labels": labels})
    sandbox = await start_sandbox(client, key)
    patched = await client.patch(
        f"{SANDBOXES}/{sandbox['id']}", headers=auth(key), json={"labels": labels}
    )

    assert created.status_code == 422
    assert patched.status_code == 422


# --- auth and audit ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", VOLUMES),
        ("POST", VOLUMES),
        ("GET", f"{VOLUMES}/vol_whatever"),
        ("DELETE", f"{VOLUMES}/vol_whatever"),
    ],
)
async def test_volume_routes_require_authentication(
    client: httpx.AsyncClient, method: str, path: str
) -> None:
    response = await client.request(method, path, json={"name": "x"})

    assert response.status_code == 401


async def test_volume_commands_are_audited(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    volume = await create_volume(client, key)
    await call(client, "DELETE", f"{VOLUMES}/{volume['id']}", key, status=200)

    recorded = {(event.action, event.target_id) for event in await audit_rows(app, org_id)}

    assert {("volume.create", volume["id"]), ("volume.delete", volume["id"])} <= recorded
