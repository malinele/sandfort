"""Interactive terminals against a real local daemon (skipped when none is reachable).

Drives the API and the websocket bridge through Starlette's ``TestClient`` on ``alpine:3.20``
(busybox ``sh``): typed input comes back through the tty, a resize is visible to ``stty size``
inside the shell, and closing marks the row closed. Setup coroutines run on the TestClient's
event loop through its portal. Every blocking read is guarded by a timer that closes the
terminal, so a silent shell fails the test instead of hanging it.
"""

import contextlib
import threading
import uuid
from collections.abc import Awaitable, Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from starlette.testclient import TestClient, WebSocketTestSession
from starlette.websockets import WebSocketDisconnect

from sandfort.api.app import create_app
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.repositories.ports import PtySessionRecord
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.resources import ResourceSpec
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.drivers.base import SandboxSpec
from sandfort.drivers.docker.client import make_client
from sandfort.ids import new_api_key_id, new_org_id, new_sandbox_id

pytestmark = pytest.mark.docker

docker = pytest.importorskip("docker")

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "alpine:3.20"
PEPPER = "test-pepper"
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
READ_TIMEOUT_S = 20.0
NORMAL_CLOSE = 1000


@pytest.fixture(scope="module")
def docker_client() -> Any:
    try:
        client = make_client()
        client.ping()
    except Exception as exc:
        pytest.skip(f"no reachable Docker daemon: {exc}")
    return client


@pytest.fixture
def image(docker_client: Any) -> str:
    try:
        docker_client.images.get(IMAGE)
    except docker.errors.ImageNotFound:
        try:
            docker_client.images.pull(IMAGE)
        except Exception as exc:
            pytest.skip(f"cannot pull {IMAGE}: {exc}")
    return IMAGE


@pytest.fixture
def app(tmp_path: Path, docker_client: Any, image: str) -> FastAPI:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'docker-pty.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    return create_app(Settings(driver="docker", database_url=url, api_key_pepper=PEPPER))


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:  # lifespan disposes the engine on exit
        yield test_client


def run[T](client: TestClient, func: Callable[..., Awaitable[T]], *args: Any) -> T:
    portal = client.portal
    assert portal is not None
    return portal.call(func, *args)


async def register_sandbox(app: FastAPI, image: str) -> tuple[str, str, str, str]:
    """Start a real container and record it as a started sandbox: (key, org, sandbox, ref)."""
    org = Org(id=new_org_id(), name="Acme", slug=f"acme-{uuid.uuid4().hex[:6]}", created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored_key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=FULL_ACCESS,
        created_at=NOW,
    )
    sandbox_id = new_sandbox_id()
    spec = SandboxSpec(
        sandbox_id=sandbox_id,
        org_id=org.id,
        name=f"sf-{sandbox_id}",
        image=image,
        resources=ResourceSpec(cpu_millicores=1000, memory_mib=512, disk_gib=1),
        labels={"suite": "test_docker_pty"},
    )
    info = await app.state.driver.create(spec)
    await app.state.driver.start(info.ref)
    sandbox = Sandbox(
        id=sandbox_id,
        org_id=org.id,
        name=sandbox_id,
        state=SandboxState.STARTED,
        image_ref=image,
        driver="docker",
        driver_ref=info.ref,
        started_at=NOW,
        created_at=NOW,
        updated_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored_key)
        await uow.sandboxes.add(sandbox)
        await uow.commit()
    return generated.key, org.id, sandbox_id, info.ref


async def load_pty(app: FastAPI, org_id: str, pty_id: str) -> PtySessionRecord | None:
    async with UnitOfWork(app.state.session_factory) as uow:
        return await uow.pty_sessions.get(org_id, pty_id)


@pytest.fixture
def started_sandbox(
    app: FastAPI, client: TestClient, docker_client: Any, image: str
) -> Iterator[tuple[str, str, str]]:
    """``(api_key, org_id, sandbox_id)`` for a real alpine container."""
    key, org_id, sandbox_id, ref = run(client, register_sandbox, app, image)
    try:
        yield key, org_id, sandbox_id
    finally:
        with contextlib.suppress(docker.errors.NotFound):
            docker_client.api.remove_container(ref, v=True, force=True)


def pty_path(sandbox_id: str, *parts: str) -> str:
    return "/".join([f"/v1/sandboxes/{sandbox_id}/toolbox/pty", *parts])


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def call(client: TestClient, method: str, path: str, key: str, **kwargs: Any) -> Any:
    response = client.request(method, path, headers=auth(key), **kwargs)
    assert response.status_code in (200, 201), response.text
    return response.json()["data"]


def read_until(
    ws: WebSocketTestSession, marker: bytes, on_timeout: Callable[[], object]
) -> bytes:
    """Collect terminal output until ``marker`` shows up; ``on_timeout`` ends a silent wait."""
    timer = threading.Timer(READ_TIMEOUT_S, on_timeout)
    timer.start()
    received = b""
    try:
        while marker not in received:
            try:
                received += ws.receive_bytes()
            except WebSocketDisconnect as exc:
                message = f"terminal closed before {marker!r}: {received!r}"
                raise AssertionError(message) from exc
    finally:
        timer.cancel()
    return received


def test_pty_echo_resize_and_close(
    app: FastAPI, client: TestClient, started_sandbox: tuple[str, str, str]
) -> None:
    key, org_id, sandbox_id = started_sandbox
    created = call(client, "POST", pty_path(sandbox_id), key, json={"rows": 24, "cols": 80})
    pty_id = created["pty_id"]
    path = pty_path(sandbox_id, pty_id)

    def give_up() -> object:
        return client.request("DELETE", path, headers=auth(key))

    with client.websocket_connect(f"{path}/connect?token={created['token']}") as ws:
        # the tty echoes the typed line verbatim; only the shell's output has the expanded marker
        ws.send_bytes(b"echo SF-$((40+2))-MARK\n")
        assert b"SF-42-MARK" in read_until(ws, b"SF-42-MARK", give_up)

        resized = call(client, "POST", f"{path}/resize", key, json={"rows": 33, "cols": 107})
        assert (resized["rows"], resized["cols"]) == (33, 107)
        ws.send_bytes(b"stty size\n")
        assert b"33 107" in read_until(ws, b"33 107", give_up)

        closed = call(client, "DELETE", path, key)
        assert closed["state"] == "closed"
        with pytest.raises(WebSocketDisconnect) as ended:
            while True:
                ws.receive_bytes()  # drain output until the server closes the bridge

    assert ended.value.code == NORMAL_CLOSE
    row = run(client, load_pty, app, org_id, pty_id)
    assert row is not None
    assert (row.state, row.rows, row.cols) == ("closed", 33, 107)
    assert row.closed_at is not None
