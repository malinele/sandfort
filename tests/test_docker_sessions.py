"""Exec sessions against a real local daemon (skipped when none is reachable).

Drives the API through the ASGI app on ``alpine:3.20`` (busybox ``sh``): the working directory a
command leaves behind is carried to the next one, and an async command's SSE follow stream is
read straight off the ASGI interface so arrival times can be asserted while the command runs.
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
MIN_STREAM_SPREAD_S = 0.5


@pytest.fixture(scope="module")
def client() -> Any:
    try:
        docker_client = make_client()
        docker_client.ping()
    except Exception as exc:
        pytest.skip(f"no reachable Docker daemon: {exc}")
    return docker_client


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
    url = f"sqlite+aiosqlite:///{tmp_path / 'docker-sessions.db'}"
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
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as session:
        yield session


@pytest.fixture
async def started_sandbox(app: FastAPI, client: Any, image: str) -> AsyncIterator[tuple[str, str]]:
    """``(api_key, sandbox_id)`` for a real alpine container registered as a started sandbox."""
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
        labels={"suite": "test_docker_sessions"},
    )
    ref = ""
    try:
        info = await app.state.driver.create(spec)
        ref = info.ref
        await app.state.driver.start(ref)
        sandbox = Sandbox(
            id=sandbox_id,
            org_id=org.id,
            name=sandbox_id,
            state=SandboxState.STARTED,
            image_ref=image,
            driver="docker",
            driver_ref=ref,
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
        if ref:
            with contextlib.suppress(docker.errors.NotFound):
                client.api.remove_container(ref, v=True, force=True)


def sessions_path(sandbox_id: str, *parts: str) -> str:
    return "/".join([f"/v1/sandboxes/{sandbox_id}/toolbox/process/sessions", *parts])


async def post(http: httpx.AsyncClient, path: str, key: str, payload: dict[str, Any]) -> Any:
    response = await http.post(path, headers={"Authorization": f"Bearer {key}"}, json=payload)
    assert response.status_code in (200, 201, 202), response.text
    return response.json()["data"]


async def read_sse_with_arrival_times(
    app: FastAPI, path: str, key: str
) -> list[tuple[float, dict[str, str]]]:
    """Call the ASGI app directly so each streamed body message is timestamped on arrival."""
    arrivals: list[tuple[float, dict[str, str]]] = []
    delivered_request = False

    async def receive() -> dict[str, Any]:
        nonlocal delivered_request
        if not delivered_request:
            delivered_request = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.Event().wait()  # the client never disconnects
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            assert message["status"] == 200
        elif message["type"] == "http.response.body" and message.get("body"):
            for block in message["body"].decode().split("\n\n"):
                if block.strip() and not block.startswith(":"):
                    fields = dict(line.split(": ", 1) for line in block.split("\n"))
                    arrivals.append((time.monotonic(), fields))

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"test"), (b"authorization", f"Bearer {key}".encode())],
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
    }
    await asyncio.wait_for(app(scope, receive, send), 60)
    return arrivals


async def test_working_directory_persists_between_commands(
    http: httpx.AsyncClient, started_sandbox: tuple[str, str]
) -> None:
    key, sandbox_id = started_sandbox
    session = await post(http, sessions_path(sandbox_id), key, {})
    commands = sessions_path(sandbox_id, session["id"], "commands")

    changed = await post(http, commands, key, {"command": "cd /tmp"})
    printed = await post(http, commands, key, {"command": "pwd"})

    assert changed["result"]["exit_code"] == 0
    assert changed["result"]["stdout"] == "" and changed["result"]["stderr"] == ""
    assert changed["cwd"] == "/tmp"
    assert printed["result"]["stdout"] == "/tmp\n"
    assert printed["result"]["stderr"] == ""
    detail = await http.get(
        sessions_path(sandbox_id, session["id"]), headers={"Authorization": f"Bearer {key}"}
    )
    assert detail.json()["data"]["cwd"] == "/tmp"


async def test_async_command_streams_ordered_events_while_running(
    app: FastAPI, http: httpx.AsyncClient, started_sandbox: tuple[str, str]
) -> None:
    key, sandbox_id = started_sandbox
    session = await post(http, sessions_path(sandbox_id), key, {})
    started = await post(
        http,
        sessions_path(sandbox_id, session["id"], "commands"),
        key,
        {"command": "for i in 1 2 3; do echo line$i; sleep 0.4; done", "mode": "async"},
    )
    command_id = started["command"]["id"]
    assert started["command"]["state"] == "running"

    arrivals = await read_sse_with_arrival_times(
        app, sessions_path(sandbox_id, session["id"], "commands", command_id, "logs", "follow"), key
    )

    output = [(t, f) for t, f in arrivals if f["event"] == "stdout"]
    assert "".join(json.loads(f["data"])["line"] for _, f in output) == "line1\nline2\nline3\n"
    offsets = [json.loads(f["data"])["offset"] for _, f in output]
    assert offsets == sorted(offsets) and offsets[0] == 0
    assert output[-1][0] - output[0][0] >= MIN_STREAM_SPREAD_S  # delivered live, not buffered
    final_time, final = arrivals[-1]
    assert final["event"] == "exit" and json.loads(final["data"])["exit_code"] == 0
    assert final_time >= output[-1][0]
    assert final["id"] == output[-1][1]["id"] == "18"
    status = await http.get(
        sessions_path(sandbox_id, session["id"], "commands", command_id),
        headers={"Authorization": f"Bearer {key}"},
    )
    assert status.json()["data"]["state"] == "exited"
