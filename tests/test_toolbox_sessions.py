"""Exec sessions and async commands: command log store units plus API tests over FakeDriver.

Daemon-free: temp SQLite, ``httpx.ASGITransport``, scripted exec handlers. The sessions router is
mounted by ``create_app``; routes are only exercised through HTTP responses.
"""

import asyncio
import json
import threading
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.routes.toolbox import sessions as session_routes
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.drivers.base import ExecEvent, ExecRequest, ExecResult, ExitEvent, OutputChunk
from sandfort.drivers.fake import FakeDriver
from sandfort.errors import CapacityExceeded
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.toolbox import command_logs
from sandfort.toolbox.command_logs import CommandLog, CommandLogStore
from sandfort.toolbox.sessions import SessionRuntime

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})


# --- command log store ------------------------------------------------------------


def test_log_cap_stops_appending_and_still_records_the_exit() -> None:
    log = CommandLog(cap=5)

    log.append("stdout", b"abc")
    log.append("stderr", b"defg")
    log.append("stdout", b"more")
    log.finish("exited", 3)

    page = log.read(0)
    assert [(c.stream, c.offset, c.data) for c in page.chunks] == [
        ("stdout", 0, b"abc"),
        ("stderr", 3, b"de"),
    ]
    assert page.truncated is True
    assert (page.state, page.exit_code, page.complete) == ("exited", 3, True)


def test_log_read_resumes_from_any_byte_offset() -> None:
    log = CommandLog()
    log.append("stdout", b"abc")
    log.append("stderr", b"def")

    assert [(c.stream, c.offset, c.data) for c in log.read(1).chunks] == [
        ("stdout", 1, b"bc"),
        ("stderr", 3, b"def"),
    ]
    assert [(c.offset, c.data) for c in log.read(4).chunks] == [(4, b"ef")]
    assert log.read(6).chunks == ()
    assert [c.data for c in log.read(0, max_bytes=4).chunks] == [b"abc", b"d"]


def test_log_stream_counts_and_first_finish_wins() -> None:
    log = CommandLog()
    log.append("stdout", b"abc")
    log.append("stderr", b"de")
    log.finish("killed", None)
    log.finish("exited", 0)
    log.append("stdout", b"late")

    assert (log.stream_bytes("stdout"), log.stream_bytes("stderr")) == (3, 2)
    assert log.read(0).state == "killed"


async def test_log_waiter_wakes_when_another_thread_appends() -> None:
    log = CommandLog()
    waiter = asyncio.create_task(log.wait_for_change(0, timeout_s=5))
    await asyncio.sleep(0)

    threading.Thread(target=log.append, args=("stdout", b"x")).start()

    await asyncio.wait_for(waiter, 2)
    assert log.read(0).chunks[0].data == b"x"


def test_one_byte_appends_coalesce_and_page_identically() -> None:
    log = CommandLog()
    payload = bytes(range(256)) * 20
    for value in payload:
        log.append("stdout", bytes([value]))

    page = log.read(0)
    assert len(page.chunks) < 5
    assert b"".join(c.data for c in page.chunks) == payload
    paged = bytearray()
    offset = 0
    while offset < len(payload):
        page = log.read(offset, 7)
        paged += b"".join(c.data for c in page.chunks)
        assert page.chunks[0].offset == offset
        offset = page.next_offset
    assert bytes(paged) == payload


def test_coalescing_respects_stream_changes_and_chunk_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(command_logs, "COALESCE_MAX_BYTES", 4)
    log = CommandLog()
    for stream, data in [("stdout", b"ab"), ("stdout", b"cd"), ("stdout", b"e"), ("stderr", b"f")]:
        log.append(stream, data)

    assert [(c.stream, c.offset, c.data) for c in log.read(0).chunks] == [
        ("stdout", 0, b"abcd"),
        ("stdout", 4, b"e"),
        ("stderr", 5, b"f"),
    ]


def test_store_budget_evicts_finished_logs_first() -> None:
    store = CommandLogStore(max_bytes=10)
    old = store.create("old", "org_a")
    old.append("stdout", b"123456")
    old.finish("exited", 0)
    running = store.create("running", "org_a")
    running.append("stdout", b"abcd")
    assert store.get("old") is not None

    running.append("stdout", b"e")

    assert store.get("old") is None
    assert store.get("running") is running
    assert running.read(0).chunks[0].data == b"abcde"
    assert running.truncated is False


def test_store_budget_drops_oldest_bytes_of_a_running_log(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(command_logs, "COALESCE_MAX_BYTES", 4)
    store = CommandLogStore(max_bytes=10)
    log = store.create("cmd", "org_a")
    for _ in range(5):
        log.append("stdout", b"abcd")

    page = log.read(0)
    assert page.truncated is True
    assert page.total_bytes == 20
    assert page.chunks[0].offset > 0
    assert sum(len(c.data) for c in page.chunks) <= 10
    assert page.next_offset == 20
    log.append("stdout", b"z")
    tail = log.read(20)
    assert [(c.offset, c.data) for c in tail.chunks] == [(20, b"z")]
    assert tail.total_bytes == 21
    assert store.get("cmd") is log


# --- fixtures ---------------------------------------------------------------------


@pytest.fixture
async def app(tmp_path: Path, request: pytest.FixtureRequest) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'sessions.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    overrides: dict[str, Any] = getattr(request, "param", {})  # indirect settings overrides
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


class Script:
    """Exec handler: answers the cwd read-back (``cat``) and records every request."""

    def __init__(self) -> None:
        self.seen: list[ExecRequest] = []
        self.stdout = b""
        self.stderr = b""
        self.exit_code = 0
        self.cwd = b"/work\n"

    def __call__(self, env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        self.seen.append(request)
        if request.argv[0] == "cat":
            return ExecResult(exit_code=0, stdout=self.cwd)
        return ExecResult(exit_code=self.exit_code, stdout=self.stdout, stderr=self.stderr)

    @property
    def scripts(self) -> list[str]:
        return [r.argv[2] for r in self.seen if r.argv[0] == "sh"]


@pytest.fixture
def script(driver: FakeDriver) -> Script:
    handler = Script()
    driver.exec_handler = handler
    return handler


async def add_org(app: FastAPI, slug: str) -> str:
    org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def add_key(app: FastAPI, org_id: str, scopes: frozenset[Scope]) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=scopes,
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
    return await add_key(app, org_id, FULL_ACCESS)


async def send(
    client: httpx.AsyncClient, method: str, path: str, key: str, *, status: int, **kwargs: Any
) -> dict[str, Any]:
    response = await client.request(
        method, path, headers={"Authorization": f"Bearer {key}"}, **kwargs
    )
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    assert body["success"] is (status < 400)
    return body


async def create_sandbox(client: httpx.AsyncClient, key: str) -> str:
    body = await send(client, "POST", BASE, key, status=201, json={})
    sandbox_id: str = body["data"]["id"]
    return sandbox_id


def sessions_path(sandbox_id: str, *parts: str) -> str:
    return "/".join([f"{BASE}/{sandbox_id}/toolbox/process/sessions", *parts])


async def create_session(
    client: httpx.AsyncClient, key: str, sandbox_id: str, **payload: Any
) -> str:
    body = await send(client, "POST", sessions_path(sandbox_id), key, status=201, json=payload)
    session_id: str = body["data"]["id"]
    return session_id


async def start_async(
    client: httpx.AsyncClient, key: str, sandbox_id: str, session_id: str, cmd: str
) -> str:
    body = await send(
        client,
        "POST",
        sessions_path(sandbox_id, session_id, "commands") + "?async=true",
        key,
        status=202,
        json={"command": cmd},
    )
    assert body["data"]["command"]["state"] == "running"
    command_id: str = body["data"]["command"]["id"]
    return command_id


async def wait_for_state(client: httpx.AsyncClient, key: str, path: str, state: str) -> Any:
    for _ in range(300):
        body = await send(client, "GET", path, key, status=200)
        if body["data"]["state"] == state:
            return body["data"]
        await asyncio.sleep(0.01)
    raise AssertionError(f"command never reached {state}")


def parse_sse(text: str) -> list[dict[str, str]]:
    frames = []
    for block in text.split("\n\n"):
        if block.strip() and not block.startswith(":"):
            frames.append(dict(line.split(": ", 1) for line in block.split("\n")))
    return frames


@pytest.fixture
def hanging_stream(driver: FakeDriver, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """An exec stream that emits one chunk, then blocks until it is abandoned (killed)."""
    events: list[str] = []

    async def hang(ref: str, request: ExecRequest) -> AsyncIterator[ExecEvent]:
        yield OutputChunk("stdout", b"partial\n")
        try:
            await asyncio.sleep(3600)
        finally:
            events.append("abandoned")
        yield ExitEvent(0)

    monkeypatch.setattr(driver, "exec_stream", hang)
    return events


# --- sessions ---------------------------------------------------------------------


async def test_create_list_and_get_session(client: httpx.AsyncClient, key: str) -> None:
    sandbox_id = await create_sandbox(client, key)

    session_id = await create_session(client, key, sandbox_id, cwd="/work", env={"A": "1"})

    detail = await send(client, "GET", sessions_path(sandbox_id, session_id), key, status=200)
    assert detail["data"]["cwd"] == "/work"
    assert detail["data"]["env"] == {"A": "1"}
    assert detail["data"]["state"] == "active"
    assert detail["data"]["sandbox_id"] == sandbox_id
    listing = await send(client, "GET", sessions_path(sandbox_id), key, status=200)
    assert [item["id"] for item in listing["data"]] == [session_id]


async def test_create_rejects_reserved_env_and_relative_cwd(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)

    for payload in ({"env": {"SANDFORT_X": "1"}}, {"cwd": "relative"}):
        body = await send(client, "POST", sessions_path(sandbox_id), key, status=422, json=payload)
        assert body["error"]["code"] == "UNPROCESSABLE"


async def test_sync_command_returns_output_and_persists_cwd(
    client: httpx.AsyncClient, key: str, script: Script
) -> None:
    script.stdout = b"hi\n"
    script.cwd = b"/tmp\n"
    sandbox_id = await create_sandbox(client, key)
    session_id = await create_session(client, key, sandbox_id, cwd="/work", env={"A": "x y"})
    path = sessions_path(sandbox_id, session_id, "commands")

    first = await send(client, "POST", path, key, status=200, json={"command": "cd /tmp"})
    await send(client, "POST", path, key, status=200, json={"command": "pwd"})

    assert first["data"]["mode"] == "sync"
    assert first["data"]["result"]["stdout"] == "hi\n"
    assert first["data"]["cwd"] == "/tmp"
    detail = await send(client, "GET", sessions_path(sandbox_id, session_id), key, status=200)
    assert detail["data"]["cwd"] == "/tmp"
    request = next(r for r in script.seen if r.argv[0] == "sh")
    assert len(request.argv) == 3 and request.argv[1] == "-c"
    one, two = script.scripts
    assert "cd -- /work || exit 1" in one and "cd -- /tmp || exit 1" in two
    assert "export A='x y'" in one
    assert "eval 'cd /tmp'" in one
    assert "pwd > /tmp/.sf-session-" in one and "2>/dev/null" in one


async def test_async_command_lifecycle_and_ordered_logs(
    client: httpx.AsyncClient, key: str, script: Script
) -> None:
    script.stdout = b"one\n"
    script.stderr = b"two\n"
    sandbox_id = await create_sandbox(client, key)
    session_id = await create_session(client, key, sandbox_id)
    command_id = await start_async(client, key, sandbox_id, session_id, "make")
    status_path = sessions_path(sandbox_id, session_id, "commands", command_id)

    status = await wait_for_state(client, key, status_path, "exited")

    assert (status["exit_code"], status["stdout_bytes"], status["stderr_bytes"]) == (0, 4, 4)
    assert status["finished_at"] is not None
    page = (await send(client, "GET", status_path + "/logs", key, status=200))["data"]
    assert [(e["stream"], e["offset"], e["line"]) for e in page["events"]] == [
        ("stdout", 0, "one\n"),
        ("stderr", 4, "two\n"),
    ]
    assert (page["next_offset"], page["complete"], page["exit_code"]) == (8, True, 0)
    assert page["truncated"] is False


async def test_log_resume_returns_exactly_the_remaining_bytes(
    client: httpx.AsyncClient, key: str, script: Script
) -> None:
    script.stdout = b"one\n"
    script.stderr = b"two\n"
    sandbox_id = await create_sandbox(client, key)
    session_id = await create_session(client, key, sandbox_id)
    command_id = await start_async(client, key, sandbox_id, session_id, "make")
    status_path = sessions_path(sandbox_id, session_id, "commands", command_id)
    await wait_for_state(client, key, status_path, "exited")

    page = (await send(client, "GET", status_path + "/logs?offset=2", key, status=200))["data"]
    assert "".join(e["line"] for e in page["events"]) == "e\ntwo\n"
    assert page["events"][0]["offset"] == 2

    follow_url = status_path + "/logs/follow"
    auth = {"Authorization": f"Bearer {key}"}
    resumed = await client.get(follow_url, headers={**auth, "Last-Event-ID": "4"})
    frames = parse_sse(resumed.text)
    assert resumed.headers["content-type"].startswith("text/event-stream")
    assert [f["event"] for f in frames] == ["stderr", "exit"]
    assert json.loads(frames[0]["data"]) == {"stream": "stderr", "offset": 4, "line": "two\n"}
    assert frames[0]["id"] == "8"
    assert json.loads(frames[1]["data"])["exit_code"] == 0
    full = parse_sse((await client.get(follow_url + "?offset=0", headers=auth)).text)
    assert [f["id"] for f in full] == ["4", "8", "8"]


async def test_log_cap_marks_truncation_and_still_records_exit(
    client: httpx.AsyncClient, key: str, script: Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(command_logs, "MAX_LOG_BYTES", 6)
    script.stdout = b"abcdefgh"
    script.exit_code = 7
    sandbox_id = await create_sandbox(client, key)
    session_id = await create_session(client, key, sandbox_id)
    command_id = await start_async(client, key, sandbox_id, session_id, "flood")
    status_path = sessions_path(sandbox_id, session_id, "commands", command_id)

    status = await wait_for_state(client, key, status_path, "exited")

    assert (status["exit_code"], status["stdout_bytes"]) == (7, 6)
    page = (await send(client, "GET", status_path + "/logs", key, status=200))["data"]
    assert "".join(e["line"] for e in page["events"]) == "abcdef"
    assert (page["truncated"], page["complete"], page["next_offset"]) == (True, True, 6)


async def test_kill_stops_the_stream_and_marks_the_command_killed(
    client: httpx.AsyncClient, key: str, hanging_stream: list[str]
) -> None:
    sandbox_id = await create_sandbox(client, key)
    session_id = await create_session(client, key, sandbox_id)
    command_id = await start_async(client, key, sandbox_id, session_id, "sleep 3600")
    base = sessions_path(sandbox_id, session_id, "commands", command_id)
    for _ in range(300):
        page = (await send(client, "GET", base + "/logs", key, status=200))["data"]
        if page["events"]:
            break
        await asyncio.sleep(0.01)
    assert page["complete"] is False and page["state"] == "running"

    killed = await send(client, "POST", base + "/kill", key, status=200)

    assert killed["data"]["state"] == "killed"
    assert hanging_stream == ["abandoned"]
    status = (await send(client, "GET", base, key, status=200))["data"]
    assert (status["state"], status["exit_code"], status["stdout_bytes"]) == ("killed", None, 8)
    final = (await send(client, "GET", base + "/logs", key, status=200))["data"]
    assert (final["state"], final["complete"]) == ("killed", True)
    again = await send(client, "POST", base + "/kill", key, status=200)
    assert again["data"]["state"] == "killed"


async def test_follow_sends_keepalive_while_idle_then_exit_on_kill(
    client: httpx.AsyncClient,
    key: str,
    hanging_stream: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(session_routes, "KEEPALIVE_INTERVAL_S", 0.05)
    sandbox_id = await create_sandbox(client, key)
    session_id = await create_session(client, key, sandbox_id)
    command_id = await start_async(client, key, sandbox_id, session_id, "sleep 3600")
    base = sessions_path(sandbox_id, session_id, "commands", command_id)
    auth = {"Authorization": f"Bearer {key}"}

    follower = asyncio.create_task(client.get(base + "/logs/follow", headers=auth))
    await asyncio.sleep(0.3)
    await send(client, "POST", base + "/kill", key, status=200)
    response = await asyncio.wait_for(follower, 5)

    assert ": keepalive\n\n" in response.text
    frames = parse_sse(response.text)
    assert [f["event"] for f in frames] == ["stdout", "exit"]
    assert json.loads(frames[1]["data"])["state"] == "killed"


# --- per-org running command cap --------------------------------------------------


async def kill(
    client: httpx.AsyncClient, key: str, sandbox_id: str, session_id: str, command_id: str
) -> None:
    path = sessions_path(sandbox_id, session_id, "commands", command_id, "kill")
    await send(client, "POST", path, key, status=200)


def test_runtime_slots_are_per_org_and_forgetting_a_command_frees_one() -> None:
    runtime = SessionRuntime(max_running_per_org=1)
    runtime.slots.hold("org_a", "cmd_1")

    with pytest.raises(CapacityExceeded):
        runtime.slots.hold("org_a", "cmd_2")
    runtime.slots.hold("org_b", "cmd_3")  # the cap is per org
    runtime.forget("cmd_1")
    runtime.slots.hold("org_a", "cmd_2")


async def test_seventeenth_running_command_is_refused_until_a_kill_frees_a_slot(
    client: httpx.AsyncClient, key: str, hanging_stream: list[str]
) -> None:
    sandbox_id = await create_sandbox(client, key)
    session_id = await create_session(client, key, sandbox_id)
    running = [await start_async(client, key, sandbox_id, session_id, "sleep 9") for _ in range(16)]
    path = sessions_path(sandbox_id, session_id, "commands") + "?async=true"

    refused = await send(client, "POST", path, key, status=503, json={"command": "one more"})

    assert refused["error"]["code"] == "CAPACITY"
    await kill(client, key, sandbox_id, session_id, running.pop())
    running.append(await start_async(client, key, sandbox_id, session_id, "one more"))
    for command_id in running:
        await kill(client, key, sandbox_id, session_id, command_id)


async def test_a_command_that_exits_gives_its_slot_back(
    app: FastAPI, client: httpx.AsyncClient, key: str, script: Script
) -> None:
    runtime = SessionRuntime(max_running_per_org=1)
    setattr(app.state, session_routes.SESSION_RUNTIME_ATTR, runtime)
    sandbox_id = await create_sandbox(client, key)
    session_id = await create_session(client, key, sandbox_id)
    first = await start_async(client, key, sandbox_id, session_id, "true")
    pump = runtime.tasks.get(first)
    if pump is not None:  # still running: wait for it to end (its done callback frees the slot)
        await asyncio.wait({pump})

    second = await start_async(client, key, sandbox_id, session_id, "true")

    status_path = sessions_path(sandbox_id, session_id, "commands", second)
    assert (await wait_for_state(client, key, status_path, "exited"))["exit_code"] == 0


@pytest.mark.parametrize("app", [{"max_async_commands_per_org": 0}], indirect=True)
async def test_a_zero_command_cap_admits_a_seventeenth_running_command(
    client: httpx.AsyncClient, key: str, hanging_stream: list[str]
) -> None:
    sandbox_id = await create_sandbox(client, key)
    session_id = await create_session(client, key, sandbox_id)

    running = [await start_async(client, key, sandbox_id, session_id, "sleep 9") for _ in range(17)]

    for command_id in running:
        await kill(client, key, sandbox_id, session_id, command_id)
    assert hanging_stream == ["abandoned"] * 17


# --- access control and audit -----------------------------------------------------


async def test_unauthenticated_requests_are_rejected(client: httpx.AsyncClient) -> None:
    response = await client.get(sessions_path("sbx_missing"))

    assert response.status_code == 401
    assert response.json()["success"] is False


async def test_another_orgs_sandbox_session_and_command_are_not_found(
    app: FastAPI, client: httpx.AsyncClient, key: str, script: Script
) -> None:
    sandbox_id = await create_sandbox(client, key)
    session_id = await create_session(client, key, sandbox_id)
    command_id = await start_async(client, key, sandbox_id, session_id, "ls")
    other = await add_key(app, await add_org(app, "globex"), FULL_ACCESS)
    base = sessions_path(sandbox_id, session_id)

    calls = [
        ("GET", sessions_path(sandbox_id), None),
        ("POST", sessions_path(sandbox_id), {}),
        ("GET", base, None),
        ("POST", base + "/commands", {"command": "ls"}),
        ("GET", f"{base}/commands/{command_id}", None),
        ("GET", f"{base}/commands/{command_id}/logs", None),
        ("GET", f"{base}/commands/{command_id}/logs/follow", None),
        ("POST", f"{base}/commands/{command_id}/kill", None),
    ]
    for method, path, payload in calls:
        body = await send(client, method, path, other, status=404, json=payload)
        assert body["error"]["code"] == "NOT_FOUND", path


async def test_actions_are_audited_without_command_text_or_output(
    app: FastAPI,
    client: httpx.AsyncClient,
    org_id: str,
    key: str,
    script: Script,
    hanging_stream: list[str],
) -> None:
    script.stdout = b"TOP-SECRET-OUTPUT"
    sandbox_id = await create_sandbox(client, key)
    session_id = await create_session(client, key, sandbox_id, env={"TOKEN": "hunter2"})
    path = sessions_path(sandbox_id, session_id, "commands")
    await send(client, "POST", path, key, status=200, json={"command": "echo SECRET-COMMAND"})
    command_id = await start_async(client, key, sandbox_id, session_id, "sleep 3600")
    await send(client, "POST", f"{path}/{command_id}/kill", key, status=200)

    async with UnitOfWork(app.state.session_factory) as uow:
        events = await uow.audit.list(org_id, limit=200)

    ordered = sorted(events, key=lambda event: event.occurred_at)
    session_events = [e for e in ordered if e.action.startswith("toolbox.session.")]
    assert [e.action for e in session_events] == [
        "toolbox.session.create",
        "toolbox.session.exec",
        "toolbox.session.exec",
        "toolbox.session.kill",
    ]
    assert all(e.target_id == sandbox_id for e in session_events)
    dumped = json.dumps([dict(e.details) for e in session_events])
    for leaked in ("SECRET-COMMAND", "TOP-SECRET-OUTPUT", "hunter2", "partial"):
        assert leaked not in dumped
