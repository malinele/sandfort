"""One per-org cap covers every live log stream: container logs, command logs and build logs.

The three follow endpoints share the app's single ``OrgSlots`` (``LOG_STREAM_SLOTS_ATTR``). Real
streams are used where they are easy to hold open (a command that hangs, a build nobody has run
yet); elsewhere a slot is held directly on the wired ``OrgSlots``. Fixtures mirror
``tests/test_log_stream_cap.py``, ``tests/test_toolbox_sessions.py`` and
``tests/test_image_builds.py``.
"""

import asyncio
import time
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
from sandfort.api.wiring import LOG_STREAM_SLOTS_ATTR
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.drivers.base import ExecEvent, ExecRequest, OutputChunk
from sandfort.drivers.fake import FakeDriver
from sandfort.errors import CapacityExceeded
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.toolbox.pty import OrgSlots

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
BUILDS = "/v1/images/builds"
ALL_SCOPES = frozenset(
    {
        Scope.SANDBOXES_READ,
        Scope.SANDBOXES_WRITE,
        Scope.TOOLBOX,
        Scope.SNAPSHOTS_READ,
        Scope.SNAPSHOTS_WRITE,
    }
)
DEADLINE_S = 2.0
POLL_S = 0.01
CAP_ONE: list[dict[str, Any]] = [{"max_log_streams_per_org": 1}]
CAP_ZERO: list[dict[str, Any]] = [{"max_log_streams_per_org": 0}]
HELD = "held-by-test"
LIVE_STREAMS = {"resource": "live log streams", "limit": 1}


# --- fixtures ---------------------------------------------------------------------


@pytest.fixture
async def app(tmp_path: Path, request: pytest.FixtureRequest) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    overrides: dict[str, Any] = getattr(request, "param", {})
    url = f"sqlite+aiosqlite:///{tmp_path / 'log-cap2.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(driver="fake", database_url=url, api_key_pepper=PEPPER, **overrides)
    application = create_app(settings)
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


@pytest.fixture
def hanging_stream(driver: FakeDriver, monkeypatch: pytest.MonkeyPatch) -> None:
    """An exec stream that emits one chunk, then blocks (a command that stays running)."""

    async def hang(ref: str, request: ExecRequest) -> AsyncIterator[ExecEvent]:
        yield OutputChunk("stdout", b"partial\n")
        await asyncio.sleep(3600)

    monkeypatch.setattr(driver, "exec_stream", hang)


@pytest.fixture
def slots(app: FastAPI) -> OrgSlots:
    wired = getattr(app.state, LOG_STREAM_SLOTS_ATTR)
    assert isinstance(wired, OrgSlots)
    return wired


async def add_org(app: FastAPI, slug: str) -> str:
    org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def add_key(app: FastAPI, org_id: str) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=ALL_SCOPES,
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
    return await add_key(app, org_id)


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def create_sandbox(client: httpx.AsyncClient, key: str) -> str:
    response = await client.post(SANDBOXES, headers=auth(key), json={})
    assert response.status_code == 201, response.text
    sandbox_id: str = response.json()["data"]["id"]
    return sandbox_id


@pytest.fixture
async def sandbox_id(client: httpx.AsyncClient, key: str) -> str:
    return await create_sandbox(client, key)


async def start_command(client: httpx.AsyncClient, key: str, sandbox_id: str) -> str:
    """Create a session and start a command that keeps running; return the follow path."""
    base = f"{SANDBOXES}/{sandbox_id}/toolbox/process/sessions"
    created = await client.post(base, headers=auth(key), json={})
    assert created.status_code == 201, created.text
    session_id = created.json()["data"]["id"]
    started = await client.post(
        f"{base}/{session_id}/commands?async=true", headers=auth(key), json={"command": "sleep 9"}
    )
    assert started.status_code == 202, started.text
    command_id = started.json()["data"]["command"]["id"]
    return f"{base}/{session_id}/commands/{command_id}/logs/follow"


async def pending_build(client: httpx.AsyncClient, key: str) -> str:
    """Submit a build that nobody runs yet; return its log-stream path."""
    spec = {"base_image": "alpine:3.20", "files": [{"destination": "/a.txt", "content": "x\n"}]}
    response = await client.post(BUILDS, headers=auth(key), json={"spec": spec})
    assert response.status_code == 202, response.text
    return f"{BUILDS}/{response.json()['data']['id']}/logs"


def container_path(sandbox_id: str) -> str:
    return f"{SANDBOXES}/{sandbox_id}/logs"


class LiveStream:
    """Calls the ASGI app directly: the body streams until the client leaves."""

    def __init__(self, app: FastAPI, path: str, key: str, query: str = "") -> None:
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
        self._task: asyncio.Task[None] | None = None
        self.status: int | None = None

    async def _receive(self) -> dict[str, Any]:
        if not self._requested:
            self._requested = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await self._gone.wait()
        return {"type": "http.disconnect"}

    async def _send(self, message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            self.status = message["status"]

    async def open(self) -> "LiveStream":
        """Start the request and wait until the server has answered 200 (the slot is held)."""
        self._task = asyncio.create_task(self._app(self._scope, self._receive, self._send))
        deadline = time.monotonic() + DEADLINE_S
        while self.status is None:
            assert time.monotonic() < deadline, "the stream never answered"
            await asyncio.sleep(POLL_S)
        assert self.status == 200
        return self

    async def close(self) -> None:
        self._gone.set()
        assert self._task is not None
        await asyncio.wait_for(self._task, DEADLINE_S)


async def wait_until_slot_free(slots: OrgSlots, org_id: str) -> None:
    """Poll until the org can take a slot again (the probe slot is given straight back)."""
    deadline = time.monotonic() + DEADLINE_S
    while True:
        try:
            slots.hold(org_id, "probe")
        except CapacityExceeded:
            assert time.monotonic() < deadline, "the log stream slot was never released"
            await asyncio.sleep(POLL_S)
        else:
            slots.release("probe")
            return


def assert_capacity_refusal(response: httpx.Response) -> None:
    assert response.status_code == 503, response.text
    error = response.json()["error"]
    assert error["code"] == "CAPACITY"
    assert error["details"] == LIVE_STREAMS
    assert response.headers["retry-after"] == "30"


def missing_follow_paths(sandbox_id: str) -> dict[str, str]:
    """Follow paths whose target does not exist: only the cap can answer them with a 503."""
    sessions = f"{SANDBOXES}/{sandbox_id}/toolbox/process/sessions"
    return {
        "command": f"{sessions}/ses_missing/commands/cmd_missing/logs/follow",
        "build": f"{BUILDS}/snap_missing/logs",
    }


# --- one cap across the three kinds -----------------------------------------------


@pytest.mark.parametrize("app", CAP_ONE, indirect=True)
async def test_an_open_command_follow_refuses_container_and_build_follows(
    app: FastAPI,
    client: httpx.AsyncClient,
    org_id: str,
    key: str,
    sandbox_id: str,
    slots: OrgSlots,
    hanging_stream: None,
) -> None:
    follow_path = await start_command(client, key, sandbox_id)
    build_path = await pending_build(client, key)
    first = await LiveStream(app, follow_path, key).open()
    try:
        container = await client.get(
            container_path(sandbox_id), headers=auth(key), params={"follow": "true"}
        )
        build = await client.get(build_path, headers=auth(key))
        second_command = await client.get(follow_path, headers=auth(key))

        for refused in (container, build, second_command):
            assert_capacity_refusal(refused)
    finally:
        await first.close()
    await wait_until_slot_free(slots, org_id)


@pytest.mark.parametrize("app", CAP_ONE, indirect=True)
async def test_an_open_build_follow_refuses_command_follows_until_it_ends(
    app: FastAPI,
    client: httpx.AsyncClient,
    org_id: str,
    key: str,
    sandbox_id: str,
    slots: OrgSlots,
) -> None:
    build_path = await pending_build(client, key)
    first = await LiveStream(app, build_path, key).open()
    try:
        refused = await client.get(missing_follow_paths(sandbox_id)["command"], headers=auth(key))
        assert_capacity_refusal(refused)
        while await app.state.job_runner.run_once():  # the build finishes: its stream ends
            pass
    finally:
        await first.close()

    await wait_until_slot_free(slots, org_id)
    after = await client.get(missing_follow_paths(sandbox_id)["command"], headers=auth(key))
    assert after.status_code == 404  # the cap no longer answers; the lookup does


@pytest.mark.parametrize("kind", ["command", "build"])
@pytest.mark.parametrize("app", CAP_ONE, indirect=True)
async def test_a_refused_follow_answers_503_even_for_a_target_that_does_not_exist(
    client: httpx.AsyncClient, org_id: str, key: str, sandbox_id: str, slots: OrgSlots, kind: str
) -> None:
    slots.hold(org_id, HELD)  # as if a container-log follow were open
    try:
        refused = await client.get(missing_follow_paths(sandbox_id)[kind], headers=auth(key))
    finally:
        slots.release(HELD)

    assert_capacity_refusal(refused)
    unheld = await client.get(missing_follow_paths(sandbox_id)[kind], headers=auth(key))
    assert unheld.status_code == 404  # without a held slot the lookup answers


@pytest.mark.parametrize("app", CAP_ONE, indirect=True)
async def test_a_held_slot_refuses_a_follow_of_a_real_command_and_a_real_build(
    client: httpx.AsyncClient, org_id: str, key: str, sandbox_id: str, slots: OrgSlots
) -> None:
    follow_path = await start_command(client, key, sandbox_id)
    build_path = await pending_build(client, key)
    slots.hold(org_id, HELD)
    try:
        for path in (follow_path, build_path):
            assert_capacity_refusal(await client.get(path, headers=auth(key)))
    finally:
        slots.release(HELD)


@pytest.mark.parametrize("app", CAP_ONE, indirect=True)
async def test_closing_a_command_follow_frees_the_slot_for_the_next_one(
    app: FastAPI,
    client: httpx.AsyncClient,
    org_id: str,
    key: str,
    sandbox_id: str,
    slots: OrgSlots,
    hanging_stream: None,
) -> None:
    follow_path = await start_command(client, key, sandbox_id)
    first = await LiveStream(app, follow_path, key).open()
    assert_capacity_refusal(await client.get(follow_path, headers=auth(key)))

    await first.close()
    await wait_until_slot_free(slots, org_id)

    second = await LiveStream(app, follow_path, key).open()
    await second.close()
    await wait_until_slot_free(slots, org_id)


@pytest.mark.parametrize("app", CAP_ONE, indirect=True)
async def test_a_refused_follow_leaves_no_slot_behind(
    client: httpx.AsyncClient, org_id: str, key: str, sandbox_id: str, slots: OrgSlots
) -> None:
    slots.hold(org_id, HELD)
    for _ in range(3):
        assert_capacity_refusal(
            await client.get(missing_follow_paths(sandbox_id)["build"], headers=auth(key))
        )
    slots.release(HELD)

    # had a refusal kept a slot, the cap of one would still be full
    slots.hold(org_id, "after")
    slots.release("after")


@pytest.mark.parametrize("app", CAP_ONE, indirect=True)
async def test_a_follow_whose_lookup_fails_gives_its_slot_back(
    client: httpx.AsyncClient, org_id: str, key: str, sandbox_id: str, slots: OrgSlots
) -> None:
    paths = missing_follow_paths(sandbox_id)

    for kind in ("command", "build", "command", "build"):  # a leaked slot would turn these 503
        response = await client.get(paths[kind], headers=auth(key))
        assert response.status_code == 404, response.text
    slots.hold(org_id, "after")
    slots.release("after")


# --- cap 0 and tenancy -------------------------------------------------------------


@pytest.mark.parametrize("app", CAP_ZERO, indirect=True)
async def test_a_zero_cap_admits_every_kind_of_follow_together(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    sandbox_id: str,
    hanging_stream: None,
) -> None:
    follow_path = await start_command(client, key, sandbox_id)
    build_path = await pending_build(client, key)
    streams = [
        await LiveStream(app, follow_path, key).open(),
        await LiveStream(app, build_path, key).open(),
        await LiveStream(app, container_path(sandbox_id), key, "follow=true").open(),
        await LiveStream(app, follow_path, key).open(),
    ]
    for stream in streams:
        await stream.close()


@pytest.mark.parametrize("app", CAP_ONE, indirect=True)
async def test_another_org_is_unaffected_by_a_held_slot(
    app: FastAPI,
    client: httpx.AsyncClient,
    org_id: str,
    slots: OrgSlots,
    hanging_stream: None,
) -> None:
    other_key = await add_key(app, await add_org(app, "globex"))
    other_sandbox = await create_sandbox(client, other_key)
    other_follow = await start_command(client, other_key, other_sandbox)
    other_build = await pending_build(client, other_key)
    slots.hold(org_id, HELD)
    try:
        command_stream = await LiveStream(app, other_follow, other_key).open()
        try:
            refused = await client.get(other_build, headers=auth(other_key))  # its own cap
            assert_capacity_refusal(refused)
        finally:
            await command_stream.close()
        build_stream = await LiveStream(app, other_build, other_key).open()
        await build_stream.close()
    finally:
        slots.release(HELD)
