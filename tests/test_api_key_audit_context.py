"""Key create and revoke audit events carry the request id, client ip and user agent.

Through the app on the fake driver and a temp SQLite database; the events are read back from
the org's audit chain. The ASGI test transport reports a peer address, which is the client ip.
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import AuditEvent
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.api_key_admin import KEY_CREATED, KEY_REVOKED

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
KEYS = "/v1/api-keys"
REQUEST_ID = "req-key-lifecycle-1"
USER_AGENT = "governance-review/1.0"
ADMIN_SCOPES = frozenset({Scope.API_KEYS_ADMIN, Scope.SANDBOXES_READ})


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'keys.db'}"
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
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as http:
        yield http


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


@pytest.fixture
async def admin_key(app: FastAPI, org_id: str) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="seed",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=ADMIN_SCOPES,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


def headers(key: str, request_id: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {key}",
        "X-Request-Id": request_id,
        "User-Agent": USER_AGENT,
    }


async def events_for(app: FastAPI, org_id: str, action: str) -> list[AuditEvent]:
    async with UnitOfWork(app.state.session_factory) as uow:
        rows = await uow.audit.list(org_id, limit=200)
    return [row for row in rows if row.action == action]


def assert_carries_context(event: AuditEvent, request_id: str) -> None:
    assert event.request_id == request_id
    assert event.user_agent == USER_AGENT
    assert event.ip


async def test_key_create_event_carries_request_id_ip_and_user_agent(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, admin_key: str
) -> None:
    body = {"name": "ci", "scopes": [Scope.SANDBOXES_READ.value]}

    response = await client.post(KEYS, json=body, headers=headers(admin_key, REQUEST_ID))

    assert response.status_code == 201
    (event,) = await events_for(app, org_id, KEY_CREATED)
    assert event.target_id == response.json()["data"]["id"]
    assert_carries_context(event, REQUEST_ID)


async def test_key_revoke_event_carries_request_id_ip_and_user_agent(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, admin_key: str
) -> None:
    body = {"name": "ci", "scopes": [Scope.SANDBOXES_READ.value]}
    created = await client.post(KEYS, json=body, headers=headers(admin_key, "req-create"))
    key_id = created.json()["data"]["id"]

    response = await client.delete(f"{KEYS}/{key_id}", headers=headers(admin_key, REQUEST_ID))

    assert response.status_code == 200
    (event,) = await events_for(app, org_id, KEY_REVOKED)
    assert event.target_id == key_id
    assert_carries_context(event, REQUEST_ID)
