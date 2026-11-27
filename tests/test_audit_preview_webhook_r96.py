"""B7: minting a preview token and updating a webhook endpoint each write an audit row.

Both calls used to leave no trace. The rows carry ids and the names of the fields that
changed, never the token, the preview URL, the webhook URL or the signing secret. A refusal
after a valid key keeps the existing convention (one ``request.denied`` row, no success row).
Daemon-free: FakeDriver and a temp SQLite database migrated to head.
"""

import json
from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.deps import AUDIT_RECORDER_ATTR
from sandfort.api.errors import DENIED_ACTION
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import SystemClock
from sandfort.config import Settings
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import AuditEvent, AuditOutcome
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.audit import AuditRecorder

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
HOOKS = "/v1/webhooks"
PREVIEW_ACTION = "sandbox.preview_token_created"
UPDATE_ACTION = "webhook.endpoint_updated"
OLD_URL = "https://hooks.example.com/old-path"
NEW_URL = "https://hooks.example.com/new-path?credential=url-secret-4d2a"
PUBLIC_IP = "93.184.216.34"
SCOPES = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.WEBHOOKS_WRITE})


class ExplodingRecorder(AuditRecorder):
    async def record(self, uow: UnitOfWorkPort, **kwargs: Any) -> AuditEvent:
        raise RuntimeError("audit store unavailable")


@pytest.fixture(autouse=True)
def public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolve(host: str) -> Sequence[str]:
        return [PUBLIC_IP]

    monkeypatch.setattr("sandfort.webhooks.ssrf.resolve_host", resolve)


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'r96.db'}"
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


async def add_org(app: FastAPI, slug: str) -> str:
    org = Org(id=new_org_id(), name=slug, slug=slug, created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def add_key(app: FastAPI, org_id: str) -> tuple[str, str]:
    """Return ``(raw key, key id)``."""
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=SCOPES,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key, stored.id


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    return await add_org(app, "acme")


@pytest.fixture
async def key_pair(app: FastAPI, org_id: str) -> tuple[str, str]:
    return await add_key(app, org_id)


async def send(
    client: httpx.AsyncClient, method: str, path: str, key: str, *, status: int, **kwargs: Any
) -> dict[str, Any]:
    response = await client.request(
        method, path, headers={"Authorization": f"Bearer {key}"}, **kwargs
    )
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    return body


async def rows(app: FastAPI, org_id: str) -> list[AuditEvent]:
    async with UnitOfWork(app.state.session_factory) as uow:
        return list(await uow.audit.list(org_id, limit=200))


def dump(events: list[AuditEvent]) -> str:
    return json.dumps(
        [{**vars(event), "outcome": event.outcome.value} for event in events], default=str
    )


async def create_sandbox(client: httpx.AsyncClient, key: str) -> str:
    body = await send(client, "POST", SANDBOXES, key, status=201, json={})
    sandbox_id: str = body["data"]["id"]
    return sandbox_id


async def create_endpoint(client: httpx.AsyncClient, key: str) -> dict[str, Any]:
    body = await send(
        client,
        "POST",
        HOOKS,
        key,
        status=201,
        json={"url": OLD_URL, "event_types": ["sandbox.started"]},
    )
    data: dict[str, Any] = body["data"]
    return data


# --- preview tokens -----------------------------------------------------------------


async def test_minting_a_preview_token_writes_one_row_without_the_token(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key_pair: tuple[str, str]
) -> None:
    key, key_id = key_pair
    sandbox_id = await create_sandbox(client, key)
    before = len(await rows(app, org_id))

    body = await send(
        client,
        "POST",
        f"{SANDBOXES}/{sandbox_id}/preview-tokens",
        key,
        status=201,
        json={"port": 3000, "ttl_seconds": 600},
    )

    events = await rows(app, org_id)
    assert len(events) == before + 1
    [event] = [e for e in events if e.action == PREVIEW_ACTION]
    assert event.outcome is AuditOutcome.SUCCESS
    assert event.actor_id == key_id
    assert (event.target_type, event.target_id) == ("sandbox", sandbox_id)
    assert event.details["port"] == 3000
    assert event.details["ttl_seconds"] == 600
    assert datetime.fromisoformat(event.details["expires_at"]) == datetime.fromisoformat(
        body["data"]["expires_at"]
    )
    token = body["data"]["token"]
    assert token not in dump(events)
    assert body["data"]["url"] not in dump(events)


async def test_a_refused_mint_writes_only_a_denied_row(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key_pair: tuple[str, str]
) -> None:
    key, _ = key_pair
    sandbox_id = await create_sandbox(client, key)
    await send(client, "POST", f"{SANDBOXES}/{sandbox_id}/stop", key, status=200)
    path = f"{SANDBOXES}/{sandbox_id}/preview-tokens"

    await send(client, "POST", path, key, status=409, json={"port": 3000})

    events = await rows(app, org_id)
    assert PREVIEW_ACTION not in {e.action for e in events}
    denied = [e for e in events if e.action == DENIED_ACTION]
    assert [(e.outcome, e.details["status"], e.details["path"]) for e in denied] == [
        (AuditOutcome.DENIED, 409, path)
    ]


async def test_another_orgs_sandbox_mint_writes_no_row_in_the_owner_org(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key_pair: tuple[str, str]
) -> None:
    key, _ = key_pair
    sandbox_id = await create_sandbox(client, key)
    other_org = await add_org(app, "globex")
    other_key, _ = await add_key(app, other_org)

    await send(
        client,
        "POST",
        f"{SANDBOXES}/{sandbox_id}/preview-tokens",
        other_key,
        status=404,
        json={"port": 3000},
    )

    assert PREVIEW_ACTION not in {e.action for e in await rows(app, org_id)}
    assert PREVIEW_ACTION not in {e.action for e in await rows(app, other_org)}


# --- webhook endpoint update --------------------------------------------------------


async def test_updating_an_endpoint_writes_one_row_naming_the_changed_fields(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key_pair: tuple[str, str]
) -> None:
    key, key_id = key_pair
    endpoint = await create_endpoint(client, key)
    secret = endpoint["secret"]
    before = len(await rows(app, org_id))

    await send(
        client,
        "PATCH",
        f"{HOOKS}/{endpoint['id']}",
        key,
        status=200,
        json={"url": NEW_URL, "enabled": False},
    )

    events = await rows(app, org_id)
    assert len(events) == before + 1
    [event] = [e for e in events if e.action == UPDATE_ACTION]
    assert event.outcome is AuditOutcome.SUCCESS
    assert event.actor_id == key_id
    assert (event.target_type, event.target_id) == ("webhook_endpoint", endpoint["id"])
    assert event.details == {"changed": ["enabled", "url"], "failure_count_reset": False}
    assert secret not in dump(events)
    assert "url-secret-4d2a" not in dump(events)
    assert NEW_URL not in dump(events)


async def test_a_patch_that_changes_nothing_still_writes_a_row_with_no_fields(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key_pair: tuple[str, str]
) -> None:
    key, _ = key_pair
    endpoint = await create_endpoint(client, key)

    await send(
        client,
        "PATCH",
        f"{HOOKS}/{endpoint['id']}",
        key,
        status=200,
        json={"event_types": ["sandbox.started"]},
    )

    [event] = [e for e in await rows(app, org_id) if e.action == UPDATE_ACTION]
    assert event.details["changed"] == []


async def test_a_rejected_update_writes_only_a_denied_row_and_changes_nothing(
    app: FastAPI,
    client: httpx.AsyncClient,
    org_id: str,
    key_pair: tuple[str, str],
) -> None:
    key, _ = key_pair
    endpoint = await create_endpoint(client, key)

    await send(
        client,
        "PATCH",
        f"{HOOKS}/{endpoint['id']}",
        key,
        status=422,
        json={"url": "http://127.0.0.1/hook"},
    )
    await send(client, "PATCH", f"{HOOKS}/whk_missing", key, status=404, json={"enabled": False})

    events = await rows(app, org_id)
    assert UPDATE_ACTION not in {e.action for e in events}
    assert [e.details["status"] for e in events if e.action == DENIED_ACTION] == [422, 404]
    stored = await send(client, "GET", f"{HOOKS}/{endpoint['id']}", key, status=200)
    assert stored["data"]["url"] == OLD_URL


async def test_the_update_and_its_row_commit_together(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key_pair: tuple[str, str]
) -> None:
    key, _ = key_pair
    endpoint = await create_endpoint(client, key)
    setattr(app.state, AUDIT_RECORDER_ATTR, ExplodingRecorder(SystemClock()))

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as failing:
        response = await failing.request(
            "PATCH",
            f"{HOOKS}/{endpoint['id']}",
            headers={"Authorization": f"Bearer {key}"},
            json={"url": NEW_URL},
        )

    assert response.status_code == 500
    setattr(app.state, AUDIT_RECORDER_ATTR, AuditRecorder(SystemClock()))
    stored = await send(client, "GET", f"{HOOKS}/{endpoint['id']}", key, status=200)
    assert stored["data"]["url"] == OLD_URL
