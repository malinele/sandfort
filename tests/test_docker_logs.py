"""Container log streaming against a real local daemon (skipped when none is reachable).

The container's main process on ``alpine:3.20`` prints a numbered line every 200 ms. The follow
stream is read straight off the ASGI interface: a line written after the request must arrive
within two seconds, and once the client disconnects the docker stream is closed so the shared
thread limiter returns to idle.
"""

import asyncio
import contextlib
import json
import time
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
from sandfort.drivers.docker import client as docker_client
from sandfort.drivers.docker.client import make_client
from sandfort.drivers.docker.labels import build_labels
from sandfort.ids import new_api_key_id, new_org_id, new_sandbox_id

pytestmark = pytest.mark.docker

docker = pytest.importorskip("docker")

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "alpine:3.20"
PEPPER = "test-pepper"
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
TICK_SCRIPT = "i=0; while true; do i=$((i+1)); echo tick-$i; sleep 0.2; done"
HISTORY_S = 0.6
NEW_LINE_DEADLINE_S = 2.0
RELEASE_DEADLINE_S = 5.0
POLL_S = 0.05


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
    url = f"sqlite+aiosqlite:///{tmp_path / 'docker-logs.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(Settings(driver="docker", database_url=url, api_key_pepper=PEPPER))
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def ticking_sandbox(
    app: FastAPI, client: Any, image: str
) -> AsyncIterator[tuple[str, str]]:
    """``(api_key, sandbox_id)`` for a started sandbox whose main process prints ticks."""
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
    container = None
    try:
        container = client.containers.run(
            image,
            entrypoint=["sh", "-c", TICK_SCRIPT],
            name=f"sf-{sandbox_id}",
            labels=build_labels(sandbox_id, org.id, {"suite": "test_docker_logs"}),
            detach=True,
        )
        sandbox = Sandbox(
            id=sandbox_id,
            org_id=org.id,
            name=sandbox_id,
            state=SandboxState.STARTED,
            image_ref=image,
            driver="docker",
            driver_ref=container.id,
            started_at=NOW,
            created_at=NOW,
            updated_at=NOW,
        )
        async with UnitOfWork(app.state.session_factory) as uow:
            await uow.orgs.add(org)
            await uow.api_keys.add(stored_key)
            await uow.sandboxes.add(sandbox)
            await uow.commit()
        yield generated.key, sandbox_id
    finally:
        if container is not None:
            with contextlib.suppress(docker.errors.NotFound):
                client.api.remove_container(container.id, v=True, force=True)


class FollowStream:
    """Calls the ASGI app directly: SSE frames are collected as they are sent."""

    def __init__(self, app: FastAPI, path: str, key: str, query: str) -> None:
        self._app = app
        self._scope: dict[str, Any] = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": query.encode(),
            "root_path": "",
            "headers": [(b"host", b"test"), (b"authorization", f"Bearer {key}".encode())],
            "client": ("127.0.0.1", 12345),
            "server": ("test", 80),
        }
        self._requested = False
        self._gone = asyncio.Event()
        self._changed = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._pending = ""
        self.status: int | None = None
        self.frames: list[dict[str, str]] = []

    async def _receive(self) -> dict[str, Any]:
        if not self._requested:
            self._requested = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await self._gone.wait()
        return {"type": "http.disconnect"}

    async def _send(self, message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            self.status = message["status"]
        elif message["type"] == "http.response.body" and message.get("body"):
            self._pending += message["body"].decode()
            *blocks, self._pending = self._pending.split("\n\n")
            for block in blocks:
                if block.strip() and not block.startswith(":"):
                    self.frames.append(dict(line.split(": ", 1) for line in block.split("\n")))
            self._changed.set()

    def start(self) -> None:
        self._task = asyncio.create_task(self._app(self._scope, self._receive, self._send))

    def ticks(self) -> list[int]:
        lines = [json.loads(frame["data"])["line"] for frame in self.frames]
        return [int(line.removeprefix("tick-")) for line in lines if line.startswith("tick-")]

    async def wait_for_ticks(self, count: int, timeout_s: float) -> list[int]:
        async with asyncio.timeout(timeout_s):
            while len(self.ticks()) < count:
                self._changed.clear()
                await self._changed.wait()
        return self.ticks()

    async def disconnect(self, timeout_s: float = RELEASE_DEADLINE_S) -> None:
        self._gone.set()
        assert self._task is not None
        await asyncio.wait_for(self._task, timeout_s)


async def wait_until_limiter_idle() -> None:
    limiter = docker_client._get_limiter()
    deadline = time.monotonic() + RELEASE_DEADLINE_S
    while limiter.statistics().borrowed_tokens:
        assert time.monotonic() < deadline, "the docker log stream still holds a worker thread"
        await asyncio.sleep(POLL_S)


async def test_follow_streams_new_lines_and_disconnect_releases_the_limiter(
    app: FastAPI, ticking_sandbox: tuple[str, str]
) -> None:
    key, sandbox_id = ticking_sandbox
    await asyncio.sleep(HISTORY_S)  # let some lines exist before the request
    stream = FollowStream(app, f"/v1/sandboxes/{sandbox_id}/logs", key, "follow=true&tail=1")

    requested_at = time.monotonic()
    stream.start()
    try:
        ticks = await stream.wait_for_ticks(2, NEW_LINE_DEADLINE_S)
        arrived_after_s = time.monotonic() - requested_at
    finally:
        await stream.disconnect()

    assert stream.status == 200
    last_existing, *later = ticks
    assert later and later[0] > last_existing  # written after the request, delivered live
    assert arrived_after_s < NEW_LINE_DEADLINE_S
    stamps = [float(frame["id"]) for frame in stream.frames]
    assert stamps == sorted(stamps)
    assert {frame["event"] for frame in stream.frames} == {"stdout"}
    await wait_until_limiter_idle()
