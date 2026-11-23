"""A sandbox whose saved state becomes ``error`` publishes one ``sandbox.error`` event.

FakeDriver, temp SQLite migrated to head, httpx over ASGI. The event goes through the same
outbox publisher path as the other state events and carries ``reason`` and ``error_code`` next
to ``sandbox_id`` and ``state``. A failed start is staged by replacing one driver method.
"""

import re
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402

from sandfort.api.schemas.webhooks import EVENT_PATTERN  # noqa: E402
from sandfort.db.unit_of_work import UnitOfWork  # noqa: E402
from sandfort.domain.events import EventType  # noqa: E402
from sandfort.domain.org import Scope  # noqa: E402
from sandfort.domain.sandbox import ERROR_START_FAILED, SandboxState  # noqa: E402
from sandfort.drivers.base import InstanceInfo, SandboxSpec  # noqa: E402
from sandfort.drivers.errors import DriverError  # noqa: E402
from sandfort.drivers.fake import FakeDriver  # noqa: E402
from sandfort.services.events import STATE_EVENTS  # noqa: E402
from test_api_sandboxes import BASE, add_org, migrated_app, seed_key, send  # noqa: E402

REASON = "no capacity left on the node"
READ_WRITE = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    async with migrated_app(tmp_path) as application:
        yield application


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
async def key(app: FastAPI) -> str:
    return await seed_key(app, await add_org(app, "errevent"), READ_WRITE)


async def outbox(app: FastAPI, event_type: EventType) -> list[dict[str, Any]]:
    """Payloads of the undispatched outbox rows of one type, oldest first."""
    async with UnitOfWork(app.state.session_factory) as uow:
        rows = await uow.events.list_undispatched(limit=100)
    return [dict(row.payload) for row in rows if row.event_type == event_type.value]


async def stopped_sandbox(client: httpx.AsyncClient, key: str) -> str:
    created = await send(client, "POST", BASE, key, status=201, json={})
    sandbox_id: str = created["data"]["id"]
    await send(client, "POST", f"{BASE}/{sandbox_id}/stop", key, status=200)
    return sandbox_id


async def start_failing(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
    sandbox_id: str,
) -> None:
    async def failing_start(ref: str) -> None:
        raise DriverError(REASON)

    monkeypatch.setattr(driver, "start", failing_start)
    failed = await send(client, "POST", f"{BASE}/{sandbox_id}/start", key, status=200)
    assert failed["data"]["state"] == SandboxState.ERROR.value
    monkeypatch.undo()


async def test_a_failed_start_publishes_exactly_one_sandbox_error(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox_id = await stopped_sandbox(client, key)
    assert await outbox(app, EventType.SANDBOX_ERROR) == []

    await start_failing(client, key, driver, monkeypatch, sandbox_id)

    [event] = await outbox(app, EventType.SANDBOX_ERROR)
    assert event["sandbox_id"] == sandbox_id
    assert event["state"] == "error"
    assert event["reason"] == REASON
    assert event["error_code"] == ERROR_START_FAILED
    # error is only left through destroying, so a retry is refused and publishes nothing
    await send(client, "POST", f"{BASE}/{sandbox_id}/start", key, status=409)
    assert len(await outbox(app, EventType.SANDBOX_ERROR)) == 1


async def test_a_failed_create_publishes_one_sandbox_error(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def failing_create(spec: SandboxSpec) -> InstanceInfo:
        raise DriverError(REASON)

    monkeypatch.setattr(driver, "create", failing_create)
    created = await send(client, "POST", BASE, key, status=201, json={})

    [event] = await outbox(app, EventType.SANDBOX_ERROR)
    assert event["sandbox_id"] == created["data"]["id"]
    assert event["error_code"] == ERROR_START_FAILED
    assert event["reason"] == REASON


async def test_a_later_successful_restart_publishes_started_and_no_second_error(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failed_id = await stopped_sandbox(client, key)
    await start_failing(client, key, driver, monkeypatch, failed_id)
    healthy_id = await stopped_sandbox(client, key)
    before = await outbox(app, EventType.SANDBOX_STARTED)

    restarted = await send(client, "POST", f"{BASE}/{healthy_id}/start", key, status=200)

    assert restarted["data"]["state"] == "started"
    [error] = await outbox(app, EventType.SANDBOX_ERROR)
    assert error["sandbox_id"] == failed_id
    started = await outbox(app, EventType.SANDBOX_STARTED)
    assert len(started) == len(before) + 1
    assert started[-1]["sandbox_id"] == healthy_id
    assert started[-1]["reason"] is None
    assert started[-1]["error_code"] is None


def test_the_event_type_is_in_the_catalog_and_the_state_mapping() -> None:
    assert EventType.SANDBOX_ERROR.value == "sandbox.error"
    assert STATE_EVENTS[SandboxState.ERROR] is EventType.SANDBOX_ERROR
    assert {state: event.value for state, event in STATE_EVENTS.items()} == {
        SandboxState.STARTED: "sandbox.started",
        SandboxState.STOPPED: "sandbox.stopped",
        SandboxState.DESTROYED: "sandbox.deleted",
        SandboxState.ERROR: "sandbox.error",
    }


def test_the_webhook_filter_pattern_accepts_the_new_type() -> None:
    # The webhook schema has no list of event types, only this filter pattern.
    assert re.fullmatch(EVENT_PATTERN, EventType.SANDBOX_ERROR.value)
