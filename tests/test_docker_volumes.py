"""Volumes against a real local daemon (skipped when none is reachable).

Everything goes through the api on ``alpine:3.20``: a volume is created, two sandboxes mount
it at the same path, bytes written with the fs toolbox in the first are read back unchanged
through the fs toolbox in the second, the volume delete is refused while it is mounted, then
the sandboxes and the volume are deleted and the docker volume is gone.
"""

import contextlib
import uuid
from collections.abc import AsyncIterator, Iterator
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
from sandfort.drivers.docker.client import make_client
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.volumes import provider_volume_name

pytestmark = pytest.mark.docker

docker = pytest.importorskip("docker")

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "alpine:3.20"
PEPPER = "test-pepper"
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
MOUNT = "/shared"
FILE_PATH = f"{MOUNT}/payload.bin"
FULL_ACCESS = frozenset(
    {
        Scope.SANDBOXES_READ,
        Scope.SANDBOXES_WRITE,
        Scope.TOOLBOX,
        Scope.VOLUMES_READ,
        Scope.VOLUMES_WRITE,
    }
)


@pytest.fixture(scope="module")
def client() -> Any:
    try:
        api_client = make_client()
        api_client.ping()
    except Exception as exc:
        pytest.skip(f"no reachable Docker daemon: {exc}")
    return api_client


@pytest.fixture
def image(client: Any) -> str:
    try:
        client.images.get(IMAGE)
    except docker.errors.ImageNotFound:
        try:
            client.images.pull(IMAGE)
        except Exception as exc:
            pytest.skip(f"cannot pull {IMAGE}: {exc}")
    return IMAGE


@pytest.fixture
async def app(tmp_path: Path, client: Any, image: str) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'docker-volumes.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(Settings(driver="docker", database_url=url, api_key_pepper=PEPPER))
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def http(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as api:
        yield api


@pytest.fixture
async def key(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug=f"acme-{uuid.uuid4().hex[:6]}", created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=FULL_ACCESS,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


class Cleanup:
    """Force-removes whatever a failed test left behind on the daemon (containers first)."""

    def __init__(self, client: Any) -> None:
        self._client = client
        self.sandbox_ids: list[str] = []
        self.volume_ids: list[str] = []

    def run(self) -> None:
        for sandbox_id in self.sandbox_ids:
            with contextlib.suppress(docker.errors.NotFound):
                self._client.api.remove_container(f"sf-{sandbox_id}", v=True, force=True)
        for volume_id in self.volume_ids:
            with contextlib.suppress(docker.errors.NotFound):
                self._client.api.remove_volume(provider_volume_name(volume_id), force=True)


@pytest.fixture
def cleanup(client: Any) -> Iterator[Cleanup]:
    tracker = Cleanup(client)
    try:
        yield tracker
    finally:
        tracker.run()


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def call(
    http: httpx.AsyncClient, method: str, path: str, key: str, *, status: int, **kwargs: Any
) -> dict[str, Any]:
    response = await http.request(method, path, headers=auth(key), **kwargs)
    assert response.status_code == status, response.text
    data: dict[str, Any] = response.json()["data"]
    return data


async def start_mounting(
    http: httpx.AsyncClient, key: str, volume_id: str, cleanup: Cleanup
) -> str:
    body = {"snapshot": IMAGE, "volumes": [{"volume_id": volume_id, "mount_path": MOUNT}]}
    created = await call(http, "POST", "/v1/sandboxes", key, status=201, json=body)
    cleanup.sandbox_ids.append(created["id"])
    assert created["state"] == "started", created
    expected_mount = {"volume_id": volume_id, "mount_path": MOUNT, "read_only": False}
    assert created["volumes"] == [expected_mount]
    sandbox_id: str = created["id"]
    return sandbox_id


async def test_two_sandboxes_share_a_volume(
    client: Any, http: httpx.AsyncClient, key: str, cleanup: Cleanup
) -> None:
    volume = await call(http, "POST", "/v1/volumes", key, status=201, json={"name": "shared"})
    cleanup.volume_ids.append(volume["id"])
    provider_name = provider_volume_name(volume["id"])
    assert client.volumes.get(provider_name).attrs["Labels"]["sandfort.managed"] == "true"

    writer_id = await start_mounting(http, key, volume["id"], cleanup)
    reader_id = await start_mounting(http, key, volume["id"], cleanup)
    payload = f"volume-{uuid.uuid4().hex}\n".encode() + bytes(range(256))

    await call(
        http,
        "PUT",
        f"/v1/sandboxes/{writer_id}/toolbox/fs/upload",
        key,
        status=200,
        params={"path": FILE_PATH},
        content=payload,
    )
    read = await http.get(
        f"/v1/sandboxes/{reader_id}/toolbox/fs/download",
        headers=auth(key),
        params={"path": FILE_PATH},
    )
    assert read.status_code == 200, read.text
    assert read.content == payload

    await call(http, "DELETE", f"/v1/volumes/{volume['id']}", key, status=409)
    for sandbox_id in (reader_id, writer_id):
        await call(http, "DELETE", f"/v1/sandboxes/{sandbox_id}", key, status=200)
    deleted = await call(http, "DELETE", f"/v1/volumes/{volume['id']}", key, status=200)

    assert deleted["state"] == "deleting"
    await call(http, "GET", f"/v1/volumes/{volume['id']}", key, status=404)
    with pytest.raises(docker.errors.NotFound):
        client.volumes.get(provider_name)
