"""Round 60: a 503 CAPACITY refusal of a create or a start writes an audit event.

``sandbox.create_refused`` / ``sandbox.start_refused`` (outcome ``denied``, reason ``capacity``,
the requested resources and ``host_full``; never the host-wide totals). FakeDriver, temp SQLite
database and the ASGI client; daemon-free.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.errors import audit_outcome_for
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import AuditOutcome
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.errors import CapacityExceeded
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
AUDIT = "/v1/audit-events"
CREATE_REFUSED = "sandbox.create_refused"
START_REFUSED = "sandbox.start_refused"
HOST_MILLICORES = 2000  # two default sandboxes fill the host
ADMIN = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.ORG_READ, Scope.AUDIT_READ})


def make_app(tmp_path: Path, **overrides: Any) -> FastAPI:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'capacity.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(driver="fake", database_url=url, api_key_pepper=PEPPER, **overrides)
    return create_app(settings)


@asynccontextmanager
async def serve(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            yield http
    finally:
        await app.state.engine.dispose()


async def seed_org_key(app: FastAPI, slug: str) -> tuple[str, str, str]:
    """An org plus an admin key: ``(org_id, key_id, secret)``."""
    org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=ADMIN,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored)
        await uow.commit()
    return org.id, stored.id, generated.key


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def create(client: httpx.AsyncClient, key: str) -> httpx.Response:
    return await client.post(SANDBOXES, headers=auth(key), json={})


async def events(client: httpx.AsyncClient, key: str, action: str) -> list[dict[str, Any]]:
    response = await client.get(AUDIT, headers=auth(key), params={"action": action})
    assert response.status_code == 200, response.text
    rows: list[dict[str, Any]] = response.json()["data"]
    return rows


@pytest.fixture
async def app(tmp_path: Path) -> FastAPI:
    return make_app(tmp_path, host_capacity_cpu_millicores=HOST_MILLICORES)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with serve(app) as http:
        yield http


async def fill_host(client: httpx.AsyncClient, key: str) -> None:
    for _ in range(2):
        assert (await create(client, key)).status_code == 201


async def test_create_refused_for_capacity_writes_an_audit_event(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    _, key_id, key = await seed_org_key(app, "acme")
    await fill_host(client, key)

    refused = await create(client, key)

    assert refused.status_code == 503
    assert refused.json()["error"]["code"] == "CAPACITY"
    [event] = await events(client, key, CREATE_REFUSED)
    assert event["outcome"] == "denied"
    assert event["actor_id"] == key_id
    assert event["details"]["reason"] == "capacity"
    assert event["details"]["host_full"] is True
    assert event["details"]["requested"]["sandboxes"] == 1
    assert event["details"]["requested"]["vcpus"] == 1


async def test_refusal_event_never_carries_host_wide_totals(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    _, _, key = await seed_org_key(app, "acme")
    _, _, other_key = await seed_org_key(app, "other")
    assert (await create(client, other_key)).status_code == 201  # another tenant holds capacity
    assert (await create(client, key)).status_code == 201

    assert (await create(client, key)).status_code == 503

    [event] = await events(client, key, CREATE_REFUSED)
    assert set(event["details"]) == {"reason", "requested", "host_full"}
    assert "reserved" not in event["details"]


async def test_start_refused_for_capacity_writes_an_audit_event(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    _, key_id, key = await seed_org_key(app, "acme")
    stopped = (await create(client, key)).json()["data"]["id"]
    assert (await client.post(f"{SANDBOXES}/{stopped}/stop", headers=auth(key))).status_code == 200
    await fill_host(client, key)

    refused = await client.post(f"{SANDBOXES}/{stopped}/start", headers=auth(key))

    assert refused.status_code == 503
    assert refused.json()["error"]["code"] == "CAPACITY"
    [event] = await events(client, key, START_REFUSED)
    assert event["outcome"] == "denied"
    assert event["actor_id"] == key_id
    assert event["target_id"] == stopped
    assert event["details"]["reason"] == "capacity"
    assert event["details"]["host_full"] is True
    assert event["details"]["requested"]["sandboxes"] == 1
    assert await events(client, key, CREATE_REFUSED) == []


async def test_refusal_event_lands_in_the_callers_org_only(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    _, _, key = await seed_org_key(app, "acme")
    _, _, other_key = await seed_org_key(app, "other")
    await fill_host(client, key)

    assert (await create(client, other_key)).status_code == 503

    assert len(await events(client, other_key, CREATE_REFUSED)) == 1
    assert await events(client, key, CREATE_REFUSED) == []


async def test_no_refusal_event_when_create_and_start_succeed(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    _, _, key = await seed_org_key(app, "acme")
    sandbox_id = (await create(client, key)).json()["data"]["id"]
    await client.post(f"{SANDBOXES}/{sandbox_id}/stop", headers=auth(key))

    started = await client.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))

    assert started.status_code == 200, started.text
    assert await events(client, key, CREATE_REFUSED) == []
    assert await events(client, key, START_REFUSED) == []


async def request_rows(client: httpx.AsyncClient, key: str, request_id: str) -> list[Any]:
    response = await client.get(AUDIT, headers=auth(key), params={"request_id": request_id})
    assert response.status_code == 200, response.text
    rows: list[dict[str, Any]] = response.json()["data"]
    return rows


async def test_create_refused_for_capacity_writes_exactly_one_row(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    _, _, key = await seed_org_key(app, "acme")
    await fill_host(client, key)

    refused = await create(client, key)

    assert refused.status_code == 503
    [row] = await request_rows(client, key, refused.headers["X-Request-Id"])
    assert row["action"] == CREATE_REFUSED  # no request.failed next to it
    assert row["outcome"] == "denied"


async def test_start_refused_for_capacity_writes_exactly_one_row(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    _, _, key = await seed_org_key(app, "acme")
    stopped = (await create(client, key)).json()["data"]["id"]
    assert (await client.post(f"{SANDBOXES}/{stopped}/stop", headers=auth(key))).status_code == 200
    await fill_host(client, key)

    refused = await client.post(f"{SANDBOXES}/{stopped}/start", headers=auth(key))

    assert refused.status_code == 503
    [row] = await request_rows(client, key, refused.headers["X-Request-Id"])
    assert row["action"] == START_REFUSED
    assert row["outcome"] == "denied"


async def test_unrecorded_capacity_refusal_gets_one_handler_row_labelled_denied(
    app: FastAPI, client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def recorded_nothing(*_args: Any, **_kwargs: Any) -> None:
        return None

    monkeypatch.setattr("sandfort.services.sandboxes.audit_capacity_refusal", recorded_nothing)
    _, _, key = await seed_org_key(app, "acme")
    await fill_host(client, key)

    refused = await create(client, key)

    assert refused.status_code == 503
    [row] = await request_rows(client, key, refused.headers["X-Request-Id"])
    assert row["action"] == "request.denied"
    assert row["outcome"] == "denied"
    assert row["details"]["status"] == 503
    assert row["details"]["error_code"] == "CAPACITY"


def test_capacity_answer_maps_to_denied_for_deferred_rows() -> None:
    outcome, details = audit_outcome_for(CapacityExceeded("host capacity exhausted"))

    assert outcome is AuditOutcome.DENIED
    assert details["status"] == 503


async def test_unguarded_host_never_writes_a_refusal_event(tmp_path: Path) -> None:
    app = make_app(tmp_path)  # no host capacity configured
    async with serve(app) as client:
        _, _, key = await seed_org_key(app, "acme")
        for _ in range(3):
            assert (await create(client, key)).status_code == 201

        assert await events(client, key, CREATE_REFUSED) == []
