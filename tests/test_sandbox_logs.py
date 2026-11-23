"""Container log streaming (``GET /v1/sandboxes/{id}/logs``) over FakeDriver.

Daemon-free: temp SQLite and the ASGI app. Finite streams go through ``httpx.ASGITransport``;
follow streams are read straight off the ASGI interface so lines can be awaited while the stream
is open and the client can disconnect. Routes are only exercised through HTTP responses.
"""

import asyncio
import json
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
from sandfort.api.routes import sandbox_logs as log_routes
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.drivers.docker.logs import _LogStream
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
LIVE_LINE_DEADLINE_S = 0.5
RELEASE_DEADLINE_S = 2.0
POLL_S = 0.01


# --- fixtures ---------------------------------------------------------------------


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'logs.db'}"
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
def driver(app: FastAPI) -> FakeDriver:
    fake = app.state.driver
    assert isinstance(fake, FakeDriver)
    return fake


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


@pytest.fixture
async def sandbox(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> tuple[str, str]:
    """``(sandbox_id, driver_ref)`` of a started sandbox in the ``acme`` org."""
    response = await client.post(BASE, headers={"Authorization": f"Bearer {key}"}, json={})
    assert response.status_code == 201, response.text
    sandbox_id: str = response.json()["data"]["id"]
    async with UnitOfWork(app.state.session_factory) as uow:
        stored = await uow.sandboxes.get(org_id, sandbox_id)
    assert stored is not None and stored.driver_ref is not None
    return sandbox_id, stored.driver_ref


def logs_path(sandbox_id: str) -> str:
    return f"{BASE}/{sandbox_id}/logs"


def parse_sse(text: str) -> list[dict[str, str]]:
    frames = []
    for block in text.split("\n\n"):
        if block.strip() and not block.startswith(":"):
            frames.append(dict(line.split(": ", 1) for line in block.split("\n")))
    return frames


def lines_of(frames: list[dict[str, str]]) -> list[str]:
    return [json.loads(frame["data"])["line"] for frame in frames]


async def get_logs(
    client: httpx.AsyncClient, key: str, sandbox_id: str, **params: Any
) -> list[dict[str, str]]:
    response = await client.get(
        logs_path(sandbox_id), headers={"Authorization": f"Bearer {key}"}, params=params
    )
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/event-stream")
    return parse_sse(response.text)


class FollowStream:
    """Calls the ASGI app directly: the body is read while it streams, then the client leaves."""

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
        self._chunks: asyncio.Queue[bytes] = asyncio.Queue()
        self._task: asyncio.Task[None] | None = None
        self.status: int | None = None
        self.text = ""

    async def _receive(self) -> dict[str, Any]:
        if not self._requested:
            self._requested = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await self._gone.wait()
        return {"type": "http.disconnect"}

    async def _send(self, message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            self.status = message["status"]
        elif message["type"] == "http.response.body":
            self._chunks.put_nowait(message.get("body", b""))

    def start(self) -> None:
        self._task = asyncio.create_task(self._app(self._scope, self._receive, self._send))

    async def read_until(self, needle: str, timeout_s: float) -> str:
        async with asyncio.timeout(timeout_s):
            while needle not in self.text:
                self.text += (await self._chunks.get()).decode()
        return self.text

    async def disconnect(self, timeout_s: float = RELEASE_DEADLINE_S) -> None:
        self._gone.set()
        assert self._task is not None
        await asyncio.wait_for(self._task, timeout_s)


async def wait_until_released(driver: FakeDriver) -> None:
    deadline = time.monotonic() + RELEASE_DEADLINE_S
    while driver.open_log_streams:
        assert time.monotonic() < deadline, "the driver log stream was never closed"
        await asyncio.sleep(POLL_S)


# --- finite streams ---------------------------------------------------------------


async def test_non_follow_returns_the_tail_and_ends(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, sandbox: tuple[str, str]
) -> None:
    sandbox_id, ref = sandbox
    written = [
        driver.append_log(ref, f"line-{n}", stream="stderr" if n == 4 else "stdout")
        for n in range(1, 6)
    ]

    frames = await get_logs(client, key, sandbox_id, tail=3)

    assert lines_of(frames) == ["line-3", "line-4", "line-5"]
    assert [frame["event"] for frame in frames] == ["stdout", "stderr", "stdout"]
    expected_ids = [f"{entry.timestamp.timestamp():.6f}" for entry in written[2:]]
    assert [frame["id"] for frame in frames] == expected_ids
    first = json.loads(frames[0]["data"])
    assert first["timestamp"] == pytest.approx(written[2].timestamp.timestamp())
    assert first["stream"] == "stdout"
    assert driver.open_log_streams == 0


async def test_default_tail_is_one_hundred_lines(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, sandbox: tuple[str, str]
) -> None:
    sandbox_id, ref = sandbox
    for n in range(120):
        driver.append_log(ref, f"line-{n}")

    frames = await get_logs(client, key, sandbox_id)

    assert lines_of(frames) == [f"line-{n}" for n in range(20, 120)]


async def test_tail_is_capped(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    sandbox: tuple[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(log_routes, "MAX_TAIL", 3)
    sandbox_id, ref = sandbox
    for n in range(10):
        driver.append_log(ref, f"line-{n}")

    frames = await get_logs(client, key, sandbox_id, tail=1000)

    assert lines_of(frames) == ["line-7", "line-8", "line-9"]


async def test_since_filters_older_lines(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, sandbox: tuple[str, str]
) -> None:
    sandbox_id, ref = sandbox
    old = driver.append_log(ref, "old")
    await asyncio.sleep(0.02)
    new = driver.append_log(ref, "new")
    cutoff = (old.timestamp.timestamp() + new.timestamp.timestamp()) / 2

    frames = await get_logs(client, key, sandbox_id, since=cutoff)

    assert lines_of(frames) == ["new"]


async def test_rejects_a_negative_tail(
    client: httpx.AsyncClient, key: str, sandbox: tuple[str, str]
) -> None:
    sandbox_id, _ = sandbox
    response = await client.get(
        logs_path(sandbox_id), headers={"Authorization": f"Bearer {key}"}, params={"tail": -1}
    )

    assert response.status_code == 422
    assert response.json()["success"] is False


# --- follow -----------------------------------------------------------------------


async def test_follow_delivers_a_line_appended_after_the_stream_started(
    app: FastAPI, key: str, driver: FakeDriver, sandbox: tuple[str, str]
) -> None:
    sandbox_id, ref = sandbox
    driver.append_log(ref, "before")
    stream = FollowStream(app, logs_path(sandbox_id), key, "follow=true")
    stream.start()
    try:
        await stream.read_until("before", RELEASE_DEADLINE_S)
        assert stream.status == 200

        appended_at = time.monotonic()
        driver.append_log(ref, "after", stream="stderr")
        await stream.read_until("after", LIVE_LINE_DEADLINE_S)

        assert time.monotonic() - appended_at < LIVE_LINE_DEADLINE_S
        frames = parse_sse(stream.text)
        assert lines_of(frames) == ["before", "after"]
        assert frames[-1]["event"] == "stderr"
    finally:
        await stream.disconnect()


async def test_follow_sends_keepalive_comments_while_idle(
    app: FastAPI,
    key: str,
    driver: FakeDriver,
    sandbox: tuple[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(log_routes, "KEEPALIVE_INTERVAL_S", 0.05)
    sandbox_id, _ = sandbox
    stream = FollowStream(app, logs_path(sandbox_id), key, "follow=true")
    stream.start()
    try:
        text = await stream.read_until(": keepalive\n\n", RELEASE_DEADLINE_S)
    finally:
        await stream.disconnect()

    assert parse_sse(text) == []


async def test_disconnect_releases_the_driver_stream(
    app: FastAPI, key: str, driver: FakeDriver, sandbox: tuple[str, str]
) -> None:
    sandbox_id, ref = sandbox
    driver.append_log(ref, "hello")
    stream = FollowStream(app, logs_path(sandbox_id), key, "follow=true")
    stream.start()
    await stream.read_until("hello", RELEASE_DEADLINE_S)
    assert driver.open_log_streams == 1

    await stream.disconnect()

    await wait_until_released(driver)
    assert driver.open_log_streams == 0


# --- access control and audit -----------------------------------------------------


async def test_unauthenticated_request_is_rejected(
    client: httpx.AsyncClient, sandbox: tuple[str, str]
) -> None:
    sandbox_id, _ = sandbox
    response = await client.get(logs_path(sandbox_id))

    assert response.status_code == 401
    assert response.json()["success"] is False


async def test_another_orgs_sandbox_is_not_found(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, sandbox: tuple[str, str]
) -> None:
    sandbox_id, ref = sandbox
    driver.append_log(ref, "private")
    other = await add_key(app, await add_org(app, "globex"), FULL_ACCESS)

    response = await client.get(
        logs_path(sandbox_id), headers={"Authorization": f"Bearer {other}"}
    )

    assert response.status_code == 404
    body = response.json()
    assert body["success"] is False
    assert body["error"]["code"] == "NOT_FOUND"
    assert "private" not in response.text
    assert driver.open_log_streams == 0


async def test_missing_read_scope_is_forbidden(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, sandbox: tuple[str, str]
) -> None:
    sandbox_id, _ = sandbox
    toolbox_only = await add_key(app, org_id, frozenset({Scope.TOOLBOX}))

    response = await client.get(
        logs_path(sandbox_id), headers={"Authorization": f"Bearer {toolbox_only}"}
    )

    assert response.status_code == 403
    assert response.json()["success"] is False


async def test_read_is_audited_without_log_content(
    app: FastAPI,
    client: httpx.AsyncClient,
    org_id: str,
    key: str,
    driver: FakeDriver,
    sandbox: tuple[str, str],
) -> None:
    sandbox_id, ref = sandbox
    driver.append_log(ref, "TOP-SECRET-LINE")

    frames = await get_logs(client, key, sandbox_id, tail=5)

    assert lines_of(frames) == ["TOP-SECRET-LINE"]
    async with UnitOfWork(app.state.session_factory) as uow:
        events = await uow.audit.list(org_id, limit=200)
    reads = [event for event in events if event.action == "sandbox.logs.read"]
    assert len(reads) == 1
    assert reads[0].target_type == "sandbox"
    assert reads[0].target_id == sandbox_id
    assert reads[0].details["tail"] == 5
    assert reads[0].details["follow"] is False
    assert "TOP-SECRET-LINE" not in json.dumps(dict(reads[0].details))


# --- docker stream wake -----------------------------------------------------------


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[str] = []


class _ShutdownSocket(_Recorder):
    def shutdown(self, how: int) -> None:
        self.calls.append("shutdown")


class _RawSocketIO(_Recorder):
    """SocketIO-like: no shutdown of its own, the raw socket sits in ``_sock``."""

    def __init__(self) -> None:
        super().__init__()
        self._sock = _ShutdownSocket()

    def close(self) -> None:
        self.calls.append("close")


class _BareFile(_Recorder):
    def close(self) -> None:
        self.calls.append("close")
        raise ValueError("I/O operation on closed file")


def test_wake_shuts_down_a_socket_with_shutdown() -> None:
    sock = _ShutdownSocket()
    stream = _LogStream("ref", object(), sock)

    stream.wake()
    stream.wake()

    assert sock.calls == ["shutdown", "shutdown"]


def test_wake_shuts_down_the_raw_socket_of_a_socketio_wrapper() -> None:
    wrapper = _RawSocketIO()
    stream = _LogStream("ref", object(), wrapper)

    stream.wake()
    stream.wake()

    assert wrapper._sock.calls == ["shutdown", "shutdown"]
    assert wrapper.calls == []


def test_wake_closes_a_bare_file_like_and_swallows_value_error() -> None:
    bare = _BareFile()
    stream = _LogStream("ref", object(), bare)

    stream.wake()
    stream.wake()

    assert bare.calls == ["close", "close"]
