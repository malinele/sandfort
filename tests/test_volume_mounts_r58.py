"""Isolation audit M3 follow-up: mounts by volume labels and read-only mounts.

Through the API on the fake driver and a temp SQLite database. A label-scoped key may mount a
volume whose labels contain its scope and is refused (403 naming the volume) on any other. A
mount carries ``read_only`` (default false): read-only needs ``volumes:read``, read-write needs
``volumes:write``.
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
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.drivers.base import SandboxSpec, VolumeBind
from sandfort.ids import new_api_key_id, new_org_id, new_volume_id
from sandfort.services.sandboxes import MountingLifecycle
from sandfort.services.volumes import (
    MountRequest,
    VolumeMount,
    decode_mounts,
    encode_mount_requests,
    encode_mounts,
    mount_scopes,
    take_mount_requests,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
VOLUMES = "/v1/volumes"
SANDBOXES = "/v1/sandboxes"
SANDBOX_SCOPES = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
FULL_ACCESS = SANDBOX_SCOPES | {Scope.VOLUMES_READ, Scope.VOLUMES_WRITE}
READ_ONLY_KEY = SANDBOX_SCOPES | {Scope.VOLUMES_READ}
TEAM_A = {"team": "a"}
TEAM_B = {"team": "b"}


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'volmounts.db'}"
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
async def org_id(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def add_key(
    app: FastAPI,
    org_id: str,
    scopes: frozenset[Scope],
    labels: dict[str, str] | None = None,
) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=scopes,
        created_at=NOW,
        sandbox_labels=labels,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def new_volume(client: httpx.AsyncClient, key: str) -> str:
    response = await client.post(VOLUMES, headers=auth(key), json={"name": "data"})
    assert response.status_code == 201, response.text
    volume_id: str = response.json()["data"]["id"]
    return volume_id


async def create_sandbox(client: httpx.AsyncClient, key: str, **body: Any) -> httpx.Response:
    return await client.post(SANDBOXES, headers=auth(key), json=body)


def mounting(volume_id: str, **extra: Any) -> list[dict[str, Any]]:
    return [{"volume_id": volume_id, "mount_path": "/data", **extra}]


def error(response: httpx.Response) -> dict[str, Any]:
    body: dict[str, Any] = response.json()["error"]
    return body


async def sandbox_count(app: FastAPI, org_id: str) -> int:
    async with UnitOfWork(app.state.session_factory) as uow:
        return len(await uow.sandboxes.list(org_id, limit=200))


async def recorded_mounts(
    app: FastAPI, org_id: str, response: httpx.Response
) -> tuple[VolumeMount, ...]:
    async with UnitOfWork(app.state.session_factory) as uow:
        sandbox = await uow.sandboxes.get(org_id, response.json()["data"]["id"])
    assert sandbox is not None
    return decode_mounts(sandbox.labels)


# -- mounts by volume labels ---------------------------------------------------------------


async def test_scoped_key_mounts_a_volume_carrying_its_scope(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    scoped = await add_key(app, org_id, FULL_ACCESS, TEAM_A)
    volume_id = await new_volume(client, scoped)  # the scope is merged into the volume labels
    response = await create_sandbox(client, scoped, labels=TEAM_A, volumes=mounting(volume_id))
    assert response.status_code == 201, response.text
    assert [mount.volume_id for mount in await recorded_mounts(app, org_id, response)] == [
        volume_id
    ]


async def test_scoped_key_mounts_a_volume_with_extra_labels(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    admin = await add_key(app, org_id, FULL_ACCESS)
    made = await client.post(
        VOLUMES, headers=auth(admin), json={"name": "x", "labels": {**TEAM_A, "tier": "gold"}}
    )
    assert made.status_code == 201, made.text
    scoped = await add_key(app, org_id, FULL_ACCESS, TEAM_A)
    response = await create_sandbox(
        client, scoped, labels=TEAM_A, volumes=mounting(made.json()["data"]["id"])
    )
    assert response.status_code == 201, response.text


async def test_scoped_key_is_refused_on_another_teams_volume(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    other = await add_key(app, org_id, FULL_ACCESS, TEAM_B)
    volume_id = await new_volume(client, other)
    scoped = await add_key(app, org_id, FULL_ACCESS, TEAM_A)
    response = await create_sandbox(client, scoped, labels=TEAM_A, volumes=mounting(volume_id))
    assert response.status_code == 403, response.text
    assert error(response)["code"] == "FORBIDDEN"
    assert "team=a" in error(response)["message"]
    assert volume_id in error(response)["message"]
    assert await sandbox_count(app, org_id) == 0


async def test_scoped_key_is_refused_on_an_unlabelled_volume(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    admin = await add_key(app, org_id, FULL_ACCESS)
    volume_id = await new_volume(client, admin)
    scoped = await add_key(app, org_id, FULL_ACCESS, TEAM_A)
    response = await create_sandbox(client, scoped, labels=TEAM_A, volumes=mounting(volume_id))
    assert response.status_code == 403, response.text
    assert await sandbox_count(app, org_id) == 0


async def test_scoped_refusal_is_the_same_for_a_missing_volume(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    scoped = await add_key(app, org_id, FULL_ACCESS, TEAM_A)
    missing = new_volume_id()
    response = await create_sandbox(client, scoped, labels=TEAM_A, volumes=mounting(missing))
    assert response.status_code == 403, response.text
    assert missing in error(response)["message"]


async def test_unscoped_key_still_mounts_any_volume(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    other = await add_key(app, org_id, FULL_ACCESS, TEAM_B)
    volume_id = await new_volume(client, other)
    admin = await add_key(app, org_id, FULL_ACCESS)
    response = await create_sandbox(client, admin, volumes=mounting(volume_id))
    assert response.status_code == 201, response.text


# -- read-only mounts ----------------------------------------------------------------------


async def test_read_only_mount_with_volumes_read_passes_and_is_recorded(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    admin = await add_key(app, org_id, FULL_ACCESS)
    volume_id = await new_volume(client, admin)
    reader = await add_key(app, org_id, READ_ONLY_KEY)
    body = mounting(volume_id, read_only=True)
    response = await create_sandbox(client, reader, volumes=body)
    assert response.status_code == 201, response.text
    mounts = await recorded_mounts(app, org_id, response)
    assert [(mount.volume_id, mount.read_only) for mount in mounts] == [(volume_id, True)]


async def test_read_write_mount_with_volumes_read_is_refused(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    admin = await add_key(app, org_id, FULL_ACCESS)
    volume_id = await new_volume(client, admin)
    reader = await add_key(app, org_id, READ_ONLY_KEY)
    for body in (mounting(volume_id), mounting(volume_id, read_only=False)):
        response = await create_sandbox(client, reader, volumes=body)
        assert response.status_code == 403, response.text
        assert "volumes:write" in error(response)["message"]
        assert error(response)["details"] == {"missing_scopes": ["volumes:write"]}
    assert await sandbox_count(app, org_id) == 0


async def test_read_only_mount_without_volumes_read_is_refused(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    admin = await add_key(app, org_id, FULL_ACCESS)
    volume_id = await new_volume(client, admin)
    writer = await add_key(app, org_id, SANDBOX_SCOPES | {Scope.VOLUMES_WRITE})
    response = await create_sandbox(client, writer, volumes=mounting(volume_id, read_only=True))
    assert response.status_code == 403, response.text
    assert error(response)["details"] == {"missing_scopes": ["volumes:read"]}


async def test_read_write_mount_is_recorded_as_not_read_only(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    admin = await add_key(app, org_id, FULL_ACCESS)
    volume_id = await new_volume(client, admin)
    response = await create_sandbox(client, admin, volumes=mounting(volume_id))
    assert response.status_code == 201, response.text
    mounts = await recorded_mounts(app, org_id, response)
    assert [mount.read_only for mount in mounts] == [False]


async def test_read_only_must_be_a_boolean(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    admin = await add_key(app, org_id, FULL_ACCESS)
    volume_id = await new_volume(client, admin)
    # "yes" is a valid lax boolean, so only a strict field refuses it (a lax one would not).
    response = await create_sandbox(client, admin, volumes=mounting(volume_id, read_only="yes"))
    assert response.status_code == 422, response.text


# -- service helpers -----------------------------------------------------------------------


def test_mount_scopes_follow_the_mode_of_each_mount() -> None:
    read = MountRequest("vol_x", "/a", read_only=True)
    write = MountRequest("vol_y", "/b")
    assert mount_scopes([]) == frozenset()
    assert mount_scopes([read]) == frozenset({Scope.VOLUMES_READ})
    assert mount_scopes([write]) == frozenset({Scope.VOLUMES_WRITE})
    assert mount_scopes([read, write]) == frozenset({Scope.VOLUMES_READ, Scope.VOLUMES_WRITE})


def test_mount_request_carrier_round_trips_the_mode() -> None:
    requests = (MountRequest("vol_x", "/a", read_only=True), MountRequest("vol_y", "/b"))
    _, taken = take_mount_requests(encode_mount_requests(requests))
    assert taken == requests


def test_mount_record_round_trips_the_mode_and_defaults_to_read_write() -> None:
    mounts = (VolumeMount("vol_x", "sf-vol-x", "/a", read_only=True), VolumeMount("v", "p", "/b"))
    assert decode_mounts(encode_mounts(mounts)) == mounts
    assert VolumeMount("vol_x", "sf-vol-x", "/a").read_only is False


# -- the driver bind carries the mode --------------------------------------------------------


def test_lifecycle_spec_binds_carry_read_only() -> None:
    mounts = (VolumeMount("vol_x", "sf-vol-x", "/a", read_only=True), VolumeMount("v", "p", "/b"))
    sandbox = Sandbox(
        id="sbx_bind",
        org_id="org_bind",
        name="bind",
        state=SandboxState.PENDING,
        image_ref="alpine:3.20",
        driver="fake",
        labels=encode_mounts(mounts),
        created_at=NOW,
        updated_at=NOW,
    )

    spec = MountingLifecycle.spec(sandbox)

    assert spec.volumes == (
        VolumeBind("sf-vol-x", "/a", read_only=True),
        VolumeBind("p", "/b", read_only=False),
    )


async def test_create_and_reset_bind_a_read_only_mount_read_only(
    app: FastAPI,
    client: httpx.AsyncClient,
    org_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = await add_key(app, org_id, FULL_ACCESS)
    volume_id = await new_volume(client, admin)
    driver = app.state.driver
    specs: list[SandboxSpec] = []
    create = driver.create

    async def recording_create(spec: SandboxSpec) -> Any:
        specs.append(spec)
        return await create(spec)

    monkeypatch.setattr(driver, "create", recording_create)
    response = await create_sandbox(client, admin, volumes=mounting(volume_id, read_only=True))
    assert response.status_code == 201, response.text
    sandbox_id = response.json()["data"]["id"]

    reset = await client.post(f"{SANDBOXES}/{sandbox_id}/reset", headers=auth(admin))

    assert reset.status_code == 200, reset.text
    assert len(specs) == 2  # the create and the reset
    for spec in specs:
        assert [(bind.mount_path, bind.read_only) for bind in spec.volumes] == [("/data", True)]
