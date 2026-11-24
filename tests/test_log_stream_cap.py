"""Per-org cap on live container-log follow streams (``GET /v1/sandboxes/{id}/logs?follow=true``).

Only follow streams hold a slot; non-follow reads never do. The fixtures mirror
``tests/test_sandbox_logs.py`` with a ``Settings`` override hook (``indirect`` ``app`` param).
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
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
AUDIT_ACTION = "sandbox.logs.read"
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
RELEASE_DEADLINE_S = 2.0
POLL_S = 0.01
CAP_ONE: list[dict[str, Any]] = [{"max_log_streams_per_org": 1}]
CAP_ZERO: list[dict[str, Any]] = [{"max_log_streams_per_org": 0}]
RETRY_AFTER_S = "30"


# --- fixtures ---------------------------------------------------------------------


@pytest.fixture
async def app(tmp_path: Path, request: pytest.FixtureRequest) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    overrides: dict[str, Any] = getattr(request, "param", {})
    url = f"sqlite+aiosqlite:///{tmp_path / 'log-cap.db'}"
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


async def create_sandbox(client: httpx.AsyncClient, key: str) -> str:
    response = await client.post(BASE, headers={"Authorization": f"Bearer {key}"}, json={})
    assert response.status_code == 201, response.text
    sandbox_id: str = response.json()["data"]["id"]
    return sandbox_id


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    return await add_org(app, "acme")


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await add_key(app, org_id, FULL_ACCESS)


@pytest.fixture
async def sandbox_id(client: httpx.AsyncClient, key: str) -> str:
    return await create_sandbox(client, key)


def logs_path(sandbox_id: str) -> str:
    return f"{BASE}/{sandbox_id}/logs"


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

    def start(self) -> None:
        self._task = asyncio.create_task(self._app(self._scope, self._receive, self._send))

    async def disconnect(self, timeout_s: float = RELEASE_DEADLINE_S) -> None:
        self._gone.set()
        assert self._task is not None
        await asyncio.wait_for(self._task, timeout_s)


async def open_follow(app: FastAPI, key: str, sandbox_id: str) -> FollowStream:
    """Start a follow stream and wait until the server has answered 200 (the slot is held)."""
    stream = FollowStream(app, logs_path(sandbox_id), key, "follow=true")
    stream.start()
    deadline = time.monotonic() + RELEASE_DEADLINE_S
    while stream.status is None:
        assert time.monotonic() < deadline, "the follow stream never answered"
        await asyncio.sleep(POLL_S)
    assert stream.status == 200
    return stream


async def follow_once_more(client: httpx.AsyncClient, key: str, sandbox_id: str) -> httpx.Response:
    return await client.get(
        logs_path(sandbox_id),
        headers={"Authorization": f"Bearer {key}"},
        params={"follow": "true"},
    )


async def wait_for_open(driver: FakeDriver, count: int) -> None:
    deadline = time.monotonic() + RELEASE_DEADLINE_S
    while driver.open_log_streams != count:
        assert time.monotonic() < deadline, f"{driver.open_log_streams} driver streams, not {count}"
        await asyncio.sleep(POLL_S)


async def wait_until_released(driver: FakeDriver) -> None:
    deadline = time.monotonic() + RELEASE_DEADLINE_S
    while driver.open_log_streams:
        assert time.monotonic() < deadline, "the driver log stream was never closed"
        await asyncio.sleep(POLL_S)


async def audited_reads(app: FastAPI, org_id: str) -> int:
    async with UnitOfWork(app.state.session_factory) as uow:
        events = await uow.audit.list(org_id, limit=200)
    return sum(1 for event in events if event.action == AUDIT_ACTION)


# --- settings ---------------------------------------------------------------------


def test_the_cap_defaults_to_sixteen_and_loads_from_the_environment() -> None:
    defaults = Settings()
    loaded = Settings.from_env({"SANDFORT_MAX_LOG_STREAMS_PER_ORG": "3"})
    unlimited = Settings.from_env({"SANDFORT_MAX_LOG_STREAMS_PER_ORG": "0"})

    assert defaults.max_log_streams_per_org == 16
    assert loaded.max_log_streams_per_org == 3
    assert unlimited.max_log_streams_per_org == 0
    with pytest.raises(ValueError, match="MAX_LOG_STREAMS_PER_ORG"):
        Settings.from_env({"SANDFORT_MAX_LOG_STREAMS_PER_ORG": "-1"})


# --- the cap ----------------------------------------------------------------------


@pytest.mark.parametrize("app", CAP_ONE, indirect=True)
async def test_a_second_concurrent_follow_is_refused_without_an_audit_row(
    app: FastAPI,
    client: httpx.AsyncClient,
    org_id: str,
    key: str,
    driver: FakeDriver,
    sandbox_id: str,
) -> None:
    first = await open_follow(app, key, sandbox_id)
    await wait_for_open(driver, 1)
    try:
        refused = await follow_once_more(client, key, sandbox_id)

        assert refused.status_code == 503
        error = refused.json()["error"]
        assert error["code"] == "CAPACITY"
        assert error["details"] == {"resource": "live log streams", "limit": 1}
        assert refused.headers["retry-after"] == RETRY_AFTER_S
        await asyncio.sleep(POLL_S * 3)
        assert driver.open_log_streams == 1  # the refusal made no driver call
        assert await audited_reads(app, org_id) == 1  # only the first follow was audited
    finally:
        await first.disconnect()


@pytest.mark.parametrize("app", CAP_ONE, indirect=True)
async def test_closing_the_first_stream_frees_the_slot(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    sandbox_id: str,
) -> None:
    first = await open_follow(app, key, sandbox_id)
    assert (await follow_once_more(client, key, sandbox_id)).status_code == 503

    await first.disconnect()
    await wait_until_released(driver)

    second = await open_follow(app, key, sandbox_id)
    await second.disconnect()
    await wait_until_released(driver)


@pytest.mark.parametrize("app", CAP_ONE, indirect=True)
async def test_non_follow_reads_take_no_slot(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    sandbox_id: str,
) -> None:
    first = await open_follow(app, key, sandbox_id)
    try:
        for _ in range(3):
            response = await client.get(
                logs_path(sandbox_id), headers={"Authorization": f"Bearer {key}"}
            )
            assert response.status_code == 200, response.text
    finally:
        await first.disconnect()
    await wait_until_released(driver)
    # the finite reads left no slot behind: a follow still opens once the first one closed
    again = await open_follow(app, key, sandbox_id)
    await again.disconnect()


@pytest.mark.parametrize("app", CAP_ZERO, indirect=True)
async def test_a_zero_cap_admits_any_number_of_follow_streams(
    app: FastAPI, key: str, driver: FakeDriver, sandbox_id: str
) -> None:
    streams = [await open_follow(app, key, sandbox_id) for _ in range(3)]
    try:
        await wait_for_open(driver, 3)
    finally:
        for stream in streams:
            await stream.disconnect()
    await wait_until_released(driver)


@pytest.mark.parametrize("app", CAP_ONE, indirect=True)
async def test_another_org_is_unaffected_by_a_held_slot(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    sandbox_id: str,
) -> None:
    other_key = await add_key(app, await add_org(app, "globex"), FULL_ACCESS)
    other_sandbox = await create_sandbox(client, other_key)
    first = await open_follow(app, key, sandbox_id)
    try:
        other = await open_follow(app, other_key, other_sandbox)
        try:
            await wait_for_open(driver, 2)
        finally:
            await other.disconnect()
    finally:
        await first.disconnect()
    await wait_until_released(driver)
