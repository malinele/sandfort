"""Declarative image build against a real local daemon (skipped when none is reachable).

Everything goes through the api on ``alpine:3.20``: a one-file spec is built (the app's job
runner runs the build while the test polls the snapshot), a sandbox starts from the resulting
snapshot and the inline file is read back with the fs toolbox, then everything is deleted.
"""

import asyncio
import contextlib
import uuid
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
from sandfort.drivers.docker.client import make_client
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.snapshots import snapshot_image_reference

pytestmark = pytest.mark.docker

docker = pytest.importorskip("docker")

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "alpine:3.20"
PEPPER = "test-pepper"
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
FILE_PATH = "/opt/sf-build/hello.txt"
BUILD_WAIT_S = 120.0
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
    url = f"sqlite+aiosqlite:///{tmp_path / 'docker-image-builds.db'}"
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


async def call(
    http: httpx.AsyncClient, method: str, path: str, key: str, *, status: int, **kwargs: Any
) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {key}"}
    response = await http.request(method, path, headers=headers, **kwargs)
    assert response.status_code == status, response.text
    data: dict[str, Any] = response.json()["data"]
    return data


async def wait_settled(http: httpx.AsyncClient, key: str, snapshot_id: str) -> dict[str, Any]:
    """Poll the snapshot through the api until it leaves ``pending`` (bounded)."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + BUILD_WAIT_S
    while True:
        snapshot = await call(http, "GET", f"/v1/snapshots/{snapshot_id}", key, status=200)
        if snapshot["state"] != "pending" or loop.time() >= deadline:
            return snapshot
        await asyncio.sleep(POLL_S)


async def test_a_declared_image_builds_and_carries_its_inline_file(
    app: FastAPI, client: Any, http: httpx.AsyncClient, key: str
) -> None:
    marker = f"marker-{uuid.uuid4().hex}\n"
    spec = {"base_image": IMAGE, "files": [{"destination": FILE_PATH, "content": marker}]}
    snapshot_id: str | None = None
    sandbox_id: str | None = None
    try:
        async with app.state.job_runner:  # the lifespan is not run under ASGITransport
            pending = await call(
                http, "POST", "/v1/images/builds", key, status=202, json={"spec": spec}
            )
            snapshot_id = pending["id"]
            assert pending["state"] == "pending"
            ready = await wait_settled(http, key, pending["id"])

        assert ready["state"] == "ready", ready
        assert ready["digest"].startswith("sha256:")

        created = await call(
            http, "POST", "/v1/sandboxes", key, status=201, json={"snapshot": pending["id"]}
        )
        sandbox_id = created["id"]
        assert created["state"] == "started", created
        read = await call(
            http,
            "GET",
            f"/v1/sandboxes/{sandbox_id}/toolbox/fs/download",
            key,
            status=200,
            params={"path": FILE_PATH, "inline": "true"},
        )
        assert read["content"] == marker
    finally:
        if sandbox_id is not None:
            with contextlib.suppress(docker.errors.NotFound):
                client.api.remove_container(f"sf-{sandbox_id}", v=True, force=True)
        if snapshot_id is not None:
            with contextlib.suppress(docker.errors.NotFound):
                client.api.remove_image(snapshot_image_reference(snapshot_id), force=True)
