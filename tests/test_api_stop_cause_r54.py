"""Round 54: the sandbox object and the lifecycle events show why and when a sandbox stopped.

FakeDriver, temp SQLite migrated to head, httpx over ASGI (no network, no sockets).
``stop_cause`` is null unless the state is stopping or stopped (a null stored cause reads
``unknown``); ``stopped_at`` is null unless the state is stopped. The SDK wire model parses
both and tolerates a server that does not send them.
"""

import sys
from collections.abc import AsyncIterator
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from sandfort_sdk import SandboxInfo  # noqa: E402

from sandfort.api.schemas.sandboxes import SandboxResponse  # noqa: E402
from sandfort.db.unit_of_work import UnitOfWork  # noqa: E402
from sandfort.domain.events import EventType  # noqa: E402
from sandfort.domain.org import Scope  # noqa: E402
from sandfort.domain.sandbox import (  # noqa: E402
    STOP_CAUSE_REQUESTED,
    STOP_CAUSE_UNKNOWN,
    STOP_CAUSES,
)
from test_api_sandboxes import BASE, add_org, migrated_app, seed_key, send  # noqa: E402

READ_WRITE = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})
STOPPED_AT = "2026-11-10T12:00:00+00:00"


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
async def org_id(app: FastAPI) -> str:
    return await add_org(app, "stopcause")


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id, READ_WRITE)


async def fetch(client: httpx.AsyncClient, key: str, sandbox_id: str) -> dict[str, Any]:
    body = await send(client, "GET", f"{BASE}/{sandbox_id}", key, status=200)
    data: dict[str, Any] = body["data"]
    return data


async def started_sandbox(client: httpx.AsyncClient, key: str) -> str:
    created = await send(client, "POST", BASE, key, status=201, json={})
    assert created["data"]["state"] == "started"
    sandbox_id: str = created["data"]["id"]
    return sandbox_id


async def stop(client: httpx.AsyncClient, key: str, sandbox_id: str) -> None:
    await send(client, "POST", f"{BASE}/{sandbox_id}/stop", key, status=200)


async def outbox(app: FastAPI, event_type: EventType) -> list[dict[str, Any]]:
    """Payloads of the undispatched outbox rows of one type, oldest first."""
    async with UnitOfWork(app.state.session_factory) as uow:
        rows = await uow.events.list_undispatched(limit=100)
    return [dict(row.payload) for row in rows if row.event_type == event_type.value]


async def null_stored_cause(app: FastAPI, org_id: str, sandbox_id: str) -> None:
    async with UnitOfWork(app.state.session_factory) as uow:
        row = await uow.sandboxes.get(org_id, sandbox_id)
        assert row is not None and row.stop_cause is not None
        cleared = row.model_copy(update={"stop_cause": None})
        await uow.sandboxes.update(org_id, cleared, expected_version=row.version)
        await uow.commit()


async def test_get_after_a_manual_stop_shows_requested_and_stopped_at(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await started_sandbox(client, key)

    await stop(client, key, sandbox_id)

    fetched = await fetch(client, key, sandbox_id)
    assert fetched["state"] == "stopped"
    assert fetched["stop_cause"] == STOP_CAUSE_REQUESTED
    stopped_at = datetime.fromisoformat(fetched["stopped_at"])
    assert stopped_at.tzinfo is not None


async def test_a_started_sandbox_shows_both_null(client: httpx.AsyncClient, key: str) -> None:
    sandbox_id = await started_sandbox(client, key)

    fetched = await fetch(client, key, sandbox_id)

    assert fetched["stop_cause"] is None
    assert fetched["stopped_at"] is None


async def test_a_stopped_row_with_a_null_stored_cause_shows_unknown(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    sandbox_id = await started_sandbox(client, key)
    await stop(client, key, sandbox_id)

    await null_stored_cause(app, org_id, sandbox_id)

    fetched = await fetch(client, key, sandbox_id)
    assert fetched["state"] == "stopped"
    assert fetched["stop_cause"] == STOP_CAUSE_UNKNOWN
    assert fetched["stopped_at"] is not None


async def test_after_a_start_both_are_null(client: httpx.AsyncClient, key: str) -> None:
    sandbox_id = await started_sandbox(client, key)
    await stop(client, key, sandbox_id)

    restarted = await send(client, "POST", f"{BASE}/{sandbox_id}/start", key, status=200)

    assert restarted["data"]["state"] == "started"
    fetched = await fetch(client, key, sandbox_id)
    assert fetched["stop_cause"] is None
    assert fetched["stopped_at"] is None


def test_the_description_names_every_stop_cause() -> None:
    description = SandboxResponse.model_fields["stop_cause"].description or ""

    for cause in STOP_CAUSES:
        assert cause in description, cause
    assert "stopping or stopped" in description
    stopped_at = SandboxResponse.model_fields["stopped_at"].description or ""
    assert "null unless the state is stopped" in stopped_at


async def test_the_stopped_event_carries_the_cause_and_started_carries_null(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await started_sandbox(client, key)
    await stop(client, key, sandbox_id)

    [stopped] = await outbox(app, EventType.SANDBOX_STOPPED)
    assert stopped["sandbox_id"] == sandbox_id
    assert stopped["state"] == "stopped"
    assert stopped["stop_cause"] == STOP_CAUSE_REQUESTED
    assert stopped["error_code"] is None

    await send(client, "POST", f"{BASE}/{sandbox_id}/start", key, status=200)

    started = await outbox(app, EventType.SANDBOX_STARTED)
    assert started and started[-1]["sandbox_id"] == sandbox_id
    assert all("stop_cause" in event for event in started)
    assert all(event["stop_cause"] is None for event in started)


def test_sandbox_info_parses_both_fields() -> None:
    info = SandboxInfo.from_payload(
        {
            "id": "sbx_1",
            "name": "demo",
            "state": "stopped",
            "stop_cause": STOP_CAUSE_REQUESTED,
            "stopped_at": STOPPED_AT,
        }
    )

    assert info.stop_cause == STOP_CAUSE_REQUESTED
    assert info.stopped_at == datetime.fromisoformat(STOPPED_AT)


def test_sandbox_info_tolerates_their_absence() -> None:
    info = SandboxInfo.from_payload({"id": "sbx_1", "name": "demo", "state": "started"})

    assert info.stop_cause is None
    assert info.stopped_at is None
