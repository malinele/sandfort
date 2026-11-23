"""r35: a create replay shows the sandbox's current state; stream errors carry the request id."""

import json
import sys
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from sandfort_sdk import ApiError, AsyncCodeContext, CodeContext  # noqa: E402
from sandfort_sdk._transport import AsyncTransport, SyncTransport, client_kwargs  # noqa: E402

from sandfort.api.app import create_app  # noqa: E402
from sandfort.auth.api_keys import generate_api_key  # noqa: E402
from sandfort.config import Settings  # noqa: E402
from sandfort.db.unit_of_work import UnitOfWork  # noqa: E402
from sandfort.domain.org import ApiKey, Org, Scope  # noqa: E402
from sandfort.ids import new_api_key_id, new_org_id  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
HEADER = "Idempotency-Key"
REPLAYED = "idempotent-replayed"


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'replay.db'}"
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
async def auth(app: FastAPI) -> dict[str, str]:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE}),
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored)
        await uow.commit()
    return {"Authorization": f"Bearer {generated.key}"}


async def create(
    client: httpx.AsyncClient, auth: dict[str, str], key: str, body: dict[str, Any]
) -> httpx.Response:
    return await client.post(SANDBOXES, headers={**auth, HEADER: key}, json=body)


async def test_replay_after_delete_answers_destroyed(
    client: httpx.AsyncClient, auth: dict[str, str]
) -> None:
    body = {"name": "alpha"}
    first = await create(client, auth, "k-del", body)
    sandbox_id = first.json()["data"]["id"]
    deleted = await client.delete(f"{SANDBOXES}/{sandbox_id}", headers=auth)
    assert (first.status_code, first.json()["data"]["state"]) == (201, "started")
    assert deleted.status_code == 200, deleted.text

    replay = await create(client, auth, "k-del", body)

    assert replay.status_code == 201, replay.text
    assert replay.headers[REPLAYED] == "true"
    data = replay.json()["data"]
    assert data["id"] == sandbox_id
    assert data["state"] == "destroyed"
    assert set(data) == set(first.json()["data"])
    current = await client.get(f"{SANDBOXES}/{sandbox_id}", headers=auth)
    assert replay.json()["data"] == current.json()["data"]


async def test_replay_of_a_live_sandbox_is_unchanged(
    client: httpx.AsyncClient, auth: dict[str, str]
) -> None:
    body = {"name": "beta"}
    first = await create(client, auth, "k-live", body)

    replay = await create(client, auth, "k-live", body)

    assert replay.status_code == first.status_code == 201
    assert replay.headers[REPLAYED] == "true"
    assert replay.json() == first.json()


def test_create_operation_documents_the_replay_window(app: FastAPI) -> None:
    description = app.openapi()["paths"][SANDBOXES]["post"]["description"]

    assert "one day" in description
    assert "current representation" in description


BASE = "http://sandfort.test"
KEY = "sf_test_key"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
CID = "ctx_0123456789abcdef"
REQUEST_ID = "req_abc123"


def error_stream(_: httpx.Request) -> httpx.Response:
    payload = json.dumps({"code": "NOT_FOUND", "message": "context was removed"})
    return httpx.Response(
        200,
        content=f"event: error\ndata: {payload}\n\n".encode(),
        headers={"Content-Type": "text/event-stream", "x-request-id": REQUEST_ID},
    )


def assert_stream_error(error: ApiError) -> None:
    assert error.request_id == REQUEST_ID
    assert error.status_code == 200
    assert error.code == "NOT_FOUND"


def test_sync_stream_error_event_carries_the_request_id() -> None:
    transport = SyncTransport(BASE, KEY, 30.0, max_retries=0)
    transport._http.close()
    transport._http = httpx.Client(
        transport=httpx.MockTransport(error_stream), **client_kwargs(BASE, KEY, 30.0)
    )
    context = CodeContext(SID, CID, "/work", transport)

    with pytest.raises(ApiError) as caught:
        list(context.run_stream("x"))

    assert_stream_error(caught.value)


async def test_async_stream_error_event_carries_the_request_id() -> None:
    transport = AsyncTransport(BASE, KEY, 30.0, max_retries=0)
    transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(error_stream), **client_kwargs(BASE, KEY, 30.0)
    )
    context = AsyncCodeContext(SID, CID, "/work", transport)

    with pytest.raises(ApiError) as caught:
        async with await context.run_stream("x") as events:
            _ = [event async for event in events]

    assert_stream_error(caught.value)
