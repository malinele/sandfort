"""Reconciler against a real local daemon (skipped when none is reachable).

A sandbox is created through the api on ``alpine:3.20``, its container is then removed straight
through the docker client (behind the platform's back), one reconcile pass runs directly and the
api must report the sandbox as ``error``. The default orphan grace applies, so the pass never
removes any other platform container that happens to be on the daemon.
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
from sandfort.api.wiring import RECONCILER_ATTR
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.drivers.docker.client import make_client
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.workers.reconciler import Reconciler

pytestmark = pytest.mark.docker

docker = pytest.importorskip("docker")

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "alpine:3.20"
PEPPER = "test-pepper"
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})


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
    url = f"sqlite+aiosqlite:///{tmp_path / 'docker-reconciler.db'}"
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


@pytest.fixture
def sandbox_ids(client: Any) -> Iterator[list[str]]:
    """Force-removes whatever a failed test left behind on the daemon."""
    created: list[str] = []
    try:
        yield created
    finally:
        for sandbox_id in created:
            with contextlib.suppress(docker.errors.NotFound):
                client.api.remove_container(f"sf-{sandbox_id}", v=True, force=True)


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def test_container_removed_behind_the_back_marks_the_sandbox_error(
    client: Any, app: FastAPI, http: httpx.AsyncClient, key: str, sandbox_ids: list[str]
) -> None:
    created = await http.post("/v1/sandboxes", headers=auth(key), json={"snapshot": IMAGE})
    assert created.status_code == 201, created.text
    sandbox_id: str = created.json()["data"]["id"]
    sandbox_ids.append(sandbox_id)
    assert created.json()["data"]["state"] == "started"

    client.api.remove_container(f"sf-{sandbox_id}", v=True, force=True)
    reconciler: Reconciler = getattr(app.state, RECONCILER_ATTR)
    report = await reconciler.reconcile_once()

    fetched = await http.get(f"/v1/sandboxes/{sandbox_id}", headers=auth(key))
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["data"]["state"] == "error"
    assert report.drifted == (sandbox_id,)
    assert (await reconciler.reconcile_once()).drifted == ()  # idempotent against the daemon too
