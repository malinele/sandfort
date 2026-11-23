"""Snapshots against a real local daemon (skipped when none is reachable).

Everything goes through the api on ``alpine:3.20``: a marker file is written into a sandbox
with the fs toolbox, the sandbox is snapshotted (the app's job runner commits it while the
test polls the snapshot through the api), a second sandbox starts from the snapshot id and
reads the marker back, then everything is deleted. Registering ``alpine:3.20`` pins a digest.
"""

import asyncio
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
from sandfort.services.snapshots import snapshot_image_reference

pytestmark = pytest.mark.docker

docker = pytest.importorskip("docker")

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "alpine:3.20"
PEPPER = "test-pepper"
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
MARKER_PATH = "/root/sf-snapshot-marker.txt"
SNAPSHOT_WAIT_S = 60.0
POLL_S = 0.2
FULL_ACCESS = frozenset(
    {
        Scope.SANDBOXES_READ,
        Scope.SANDBOXES_WRITE,
        Scope.TOOLBOX,
        Scope.SNAPSHOTS_READ,
        Scope.SNAPSHOTS_WRITE,
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
    url = f"sqlite+aiosqlite:///{tmp_path / 'docker-snapshots.db'}"
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
    """Force-removes whatever a failed test left behind on the daemon."""

    def __init__(self, client: Any) -> None:
        self._client = client
        self.sandbox_ids: list[str] = []
        self.snapshot_ids: list[str] = []

    def run(self) -> None:
        for sandbox_id in self.sandbox_ids:
            with contextlib.suppress(docker.errors.NotFound):
                self._client.api.remove_container(f"sf-{sandbox_id}", v=True, force=True)
        for snapshot_id in self.snapshot_ids:
            with contextlib.suppress(docker.errors.NotFound):
                self._client.api.remove_image(snapshot_image_reference(snapshot_id), force=True)


@pytest.fixture
def cleanup(client: Any) -> Iterator[Cleanup]:
    tracker = Cleanup(client)
    try:
        yield tracker
    finally:
        tracker.run()


async def call(
    http: httpx.AsyncClient, method: str, path: str, key: str, *, status: int, **kwargs: Any
) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {key}"}
    response = await http.request(method, path, headers=headers, **kwargs)
    assert response.status_code == status, response.text
    data: dict[str, Any] = response.json()["data"]
    return data


async def start_sandbox(
    http: httpx.AsyncClient, key: str, snapshot: str, cleanup: Cleanup
) -> str:
    body = {"snapshot": snapshot}
    created = await call(http, "POST", "/v1/sandboxes", key, status=201, json=body)
    cleanup.sandbox_ids.append(created["id"])
    assert created["state"] == "started", created
    sandbox_id: str = created["id"]
    return sandbox_id


async def wait_settled(http: httpx.AsyncClient, key: str, snapshot_id: str) -> dict[str, Any]:
    """Poll the snapshot through the api until it leaves ``pending`` (bounded)."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + SNAPSHOT_WAIT_S
    while True:
        snapshot = await call(http, "GET", f"/v1/snapshots/{snapshot_id}", key, status=200)
        if snapshot["state"] != "pending" or loop.time() >= deadline:
            return snapshot
        await asyncio.sleep(POLL_S)


async def test_snapshot_round_trip_carries_the_marker_file(
    app: FastAPI, client: Any, http: httpx.AsyncClient, key: str, cleanup: Cleanup
) -> None:
    marker = f"marker-{uuid.uuid4().hex}"
    source_id = await start_sandbox(http, key, IMAGE, cleanup)
    await call(
        http,
        "PUT",
        f"/v1/sandboxes/{source_id}/toolbox/fs/upload",
        key,
        status=200,
        params={"path": MARKER_PATH},
        content=marker.encode(),
    )

    async with app.state.job_runner:  # the lifespan is not run under ASGITransport
        body = {"sandbox_id": source_id, "name": "with-marker"}
        path = "/v1/snapshots/from-sandbox"
        pending = await call(http, "POST", path, key, status=202, json=body)
        cleanup.snapshot_ids.append(pending["id"])
        assert pending["state"] == "pending"
        ready = await wait_settled(http, key, pending["id"])

    assert ready["state"] == "ready", ready
    assert ready["digest"].startswith("sha256:")
    assert ready["layer_count"] >= 1

    copy_id = await start_sandbox(http, key, pending["id"], cleanup)
    read = await call(
        http,
        "GET",
        f"/v1/sandboxes/{copy_id}/toolbox/fs/download",
        key,
        status=200,
        params={"path": MARKER_PATH, "inline": "true"},
    )
    assert read["content"] == marker

    await call(http, "DELETE", f"/v1/snapshots/{pending['id']}", key, status=409)
    for sandbox_id in (copy_id, source_id):
        await call(http, "DELETE", f"/v1/sandboxes/{sandbox_id}", key, status=200)
    await call(http, "DELETE", f"/v1/snapshots/{pending['id']}", key, status=200)
    await call(http, "GET", f"/v1/snapshots/{pending['id']}", key, status=404)
    with pytest.raises(docker.errors.ImageNotFound):
        client.images.get(ready["image_ref"])


async def test_registering_a_registry_image_pins_its_digest(
    client: Any, http: httpx.AsyncClient, key: str
) -> None:
    body = {"image": IMAGE}
    registered = await call(http, "POST", "/v1/snapshots", key, status=201, json=body)

    assert registered["state"] == "ready"
    assert registered["digest"].startswith("sha256:")
    assert registered["image_ref"] == f"alpine@{registered['digest']}"
    assert registered["layer_count"] >= 1
    assert client.images.get(registered["image_ref"]).id == client.images.get(IMAGE).id

    await call(http, "DELETE", f"/v1/snapshots/{registered['id']}", key, status=200)
    await call(http, "GET", f"/v1/snapshots/{registered['id']}", key, status=404)
