"""WP 4.1 quotas: concurrent reservation, release paths, recount, host guard, admin route.

FakeDriver, temp SQLite database and the ASGI client; daemon-free. Routes are exercised
over HTTP only (the API sits behind a mounted app, so no route-table introspection).
"""

import asyncio
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
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.drivers.errors import DriverConflict
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
QUOTA = "/v1/org/quota"
RECOUNT = "/v1/org/quota/recount"
AUDIT = "/v1/audit-events"
CONCURRENT_CREATES = 50
VCPU_LIMIT = 10
MEMBER = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.ORG_READ})
ADMIN = MEMBER | {Scope.API_KEYS_ADMIN, Scope.AUDIT_READ}


def make_app(tmp_path: Path, **overrides: Any) -> FastAPI:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'quota.db'}"
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


@pytest.fixture
async def app(tmp_path: Path) -> FastAPI:
    return make_app(tmp_path)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with serve(app) as http:
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


async def seed_key(
    app: FastAPI, org_id: str, scopes: frozenset[Scope], *, platform: bool = False
) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=scopes,
        is_platform_admin=platform,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


async def org_with_admin(app: FastAPI) -> str:
    """A platform-admin key: replacing quota limits is a platform operation."""
    return await seed_key(app, await add_org(app, "acme"), ADMIN, platform=True)


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def set_limits(client: httpx.AsyncClient, key: str, **limits: Any) -> None:
    response = await client.put(QUOTA, headers=auth(key), json=limits)
    assert response.status_code == 200, response.text


async def create(client: httpx.AsyncClient, key: str) -> httpx.Response:
    return await client.post(SANDBOXES, headers=auth(key), json={})


async def reserved(client: httpx.AsyncClient, key: str) -> dict[str, Any]:
    response = await client.get(QUOTA, headers=auth(key))
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()["data"]["reserved"]
    return body


# --- concurrency ------------------------------------------------------------------


async def test_fifty_concurrent_creates_admit_exactly_the_quota(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver
) -> None:
    key = await org_with_admin(app)
    await set_limits(client, key, max_vcpus=VCPU_LIMIT)

    responses = await asyncio.gather(*(create(client, key) for _ in range(CONCURRENT_CREATES)))

    admitted = [r for r in responses if r.status_code == 201]
    refused = [r for r in responses if r.status_code == 429]
    assert len(admitted) == VCPU_LIMIT
    assert len(refused) == CONCURRENT_CREATES - VCPU_LIMIT
    assert {r.json()["error"]["code"] for r in refused} == {"QUOTA_EXCEEDED"}
    assert len(await driver.list_managed()) == VCPU_LIMIT
    held = await reserved(client, key)
    assert held["vcpus"] == VCPU_LIMIT
    assert held["sandboxes"] == VCPU_LIMIT


# --- release paths ------------------------------------------------------------------


async def test_failed_driver_create_releases_its_reservation(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = await org_with_admin(app)
    await set_limits(client, key, max_vcpus=1)

    async def refuse(spec: object) -> object:
        raise DriverConflict("daemon refused")

    with monkeypatch.context() as patch:
        patch.setattr(driver, "create", refuse)
        failed = await create(client, key)
    assert failed.json()["data"]["state"] == "error"
    assert (await reserved(client, key))["sandboxes"] == 0

    follow_up = await create(client, key)

    assert follow_up.status_code == 201
    assert follow_up.json()["data"]["state"] == "started"


async def test_stop_releases_the_reservation(app: FastAPI, client: httpx.AsyncClient) -> None:
    key = await org_with_admin(app)
    await set_limits(client, key, max_vcpus=1)
    first = (await create(client, key)).json()["data"]["id"]
    assert (await create(client, key)).status_code == 429

    stopped = await client.post(f"{SANDBOXES}/{first}/stop", headers=auth(key))

    assert stopped.status_code == 200
    assert (await reserved(client, key))["sandboxes"] == 0
    assert (await create(client, key)).status_code == 201


async def test_delete_releases_and_a_release_after_stop_is_idempotent(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    key = await org_with_admin(app)
    await set_limits(client, key, max_vcpus=1)
    first = (await create(client, key)).json()["data"]["id"]
    await client.post(f"{SANDBOXES}/{first}/stop", headers=auth(key))

    deleted = await client.delete(f"{SANDBOXES}/{first}", headers=auth(key))

    assert deleted.status_code == 200
    assert (await reserved(client, key))["sandboxes"] == 0
    assert (await create(client, key)).status_code == 201


# --- start re-reserves --------------------------------------------------------------


async def sandbox_state(client: httpx.AsyncClient, key: str, sandbox_id: str) -> str:
    response = await client.get(f"{SANDBOXES}/{sandbox_id}", headers=auth(key))
    assert response.status_code == 200, response.text
    state: str = response.json()["data"]["state"]
    return state


async def test_start_of_a_stopped_sandbox_is_refused_when_the_quota_is_full(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    key = await org_with_admin(app)
    limit = 3
    await set_limits(client, key, max_vcpus=limit)
    totals = []
    ids = [(await create(client, key)).json()["data"]["id"] for _ in range(limit)]
    totals.append((await reserved(client, key))["vcpus"])
    stopped_id = ids[0]
    await client.post(f"{SANDBOXES}/{stopped_id}/stop", headers=auth(key))
    totals.append((await reserved(client, key))["vcpus"])
    refill = await create(client, key)  # the released capacity is taken by a new sandbox
    assert refill.status_code == 201
    totals.append((await reserved(client, key))["vcpus"])

    refused = await client.post(f"{SANDBOXES}/{stopped_id}/start", headers=auth(key))

    assert refused.status_code == 429
    assert refused.json()["error"]["code"] == "QUOTA_EXCEEDED"
    assert await sandbox_state(client, key, stopped_id) == "stopped"
    held = await reserved(client, key)
    totals.append(held["vcpus"])
    assert held["sandboxes"] == limit
    assert max(totals) <= limit


async def test_start_under_quota_reserves_again_and_succeeds(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    key = await org_with_admin(app)
    await set_limits(client, key, max_vcpus=2)
    first = (await create(client, key)).json()["data"]["id"]
    await create(client, key)
    await client.post(f"{SANDBOXES}/{first}/stop", headers=auth(key))
    assert (await reserved(client, key))["sandboxes"] == 1

    started = await client.post(f"{SANDBOXES}/{first}/start", headers=auth(key))

    assert started.status_code == 200, started.text
    assert await sandbox_state(client, key, first) == "started"
    held = await reserved(client, key)
    assert held["sandboxes"] == 2
    assert held["vcpus"] == 2


async def test_start_is_never_refused_when_quota_enforcement_is_off(
    app: FastAPI, client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = await org_with_admin(app)
    await set_limits(client, key, max_vcpus=1)
    first = (await create(client, key)).json()["data"]["id"]
    await client.post(f"{SANDBOXES}/{first}/stop", headers=auth(key))
    assert (await create(client, key)).status_code == 201  # the limit is full again
    monkeypatch.setattr(app.state.sandbox_service, "_quota", None)

    started = await client.post(f"{SANDBOXES}/{first}/start", headers=auth(key))

    assert started.status_code == 200, started.text
    assert await sandbox_state(client, key, first) == "started"
    assert (await reserved(client, key))["sandboxes"] == 1  # the ledger is not touched


# --- recount ------------------------------------------------------------------------


async def test_recount_matches_the_ledger_after_the_dust_settles(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    key = await org_with_admin(app)
    await set_limits(client, key, max_vcpus=VCPU_LIMIT)
    responses = await asyncio.gather(*(create(client, key) for _ in range(15)))
    first = next(r for r in responses if r.status_code == 201).json()["data"]["id"]
    await client.post(f"{SANDBOXES}/{first}/stop", headers=auth(key))

    recount = await client.get(RECOUNT, headers=auth(key))

    assert recount.status_code == 200, recount.text
    data = recount.json()["data"]
    assert data["consistent"] is True
    assert data["ledger"] == data["recomputed"]
    assert data["ledger"] == await reserved(client, key)
    assert data["ledger"]["sandboxes"] == VCPU_LIMIT - 1


# --- host capacity ------------------------------------------------------------------


async def test_host_capacity_guard_answers_503_when_the_host_is_the_tighter_limit(
    tmp_path: Path,
) -> None:
    app = make_app(tmp_path, host_capacity_cpu_millicores=2000)
    async with serve(app) as client:
        key = await org_with_admin(app)
        await set_limits(client, key, max_vcpus=VCPU_LIMIT)
        statuses = [(await create(client, key)).status_code for _ in range(2)]

        refused = await create(client, key)

        assert statuses == [201, 201]
        assert refused.status_code == 503
        assert refused.json()["error"]["code"] == "CAPACITY"
        assert (await reserved(client, key))["sandboxes"] == 2


# --- admin route --------------------------------------------------------------------


async def test_put_quota_requires_the_admin_scope(app: FastAPI, client: httpx.AsyncClient) -> None:
    org_id = await add_org(app, "acme")
    member_key = await seed_key(app, org_id, MEMBER)

    denied = await client.put(QUOTA, headers=auth(member_key), json={"max_vcpus": 1})

    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "FORBIDDEN"
    unchanged = await client.get(QUOTA, headers=auth(member_key))
    assert unchanged.json()["data"]["limits"]["max_vcpus"] is None


async def test_put_quota_refuses_an_org_admin_key_without_the_platform_flag(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    key = await seed_key(app, await add_org(app, "acme"), ADMIN)

    denied = await client.put(QUOTA, headers=auth(key), json={})

    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "FORBIDDEN"
    assert "platform operation" in denied.json()["error"]["message"]
    unchanged = await client.get(QUOTA, headers=auth(key))
    assert unchanged.json()["data"]["limits"]["max_vcpus"] is None


async def test_put_quota_succeeds_for_a_platform_admin_key(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    key = await org_with_admin(app)

    updated = await client.put(QUOTA, headers=auth(key), json={"max_vcpus": 2})

    assert updated.status_code == 200, updated.text
    assert updated.json()["data"]["limits"]["max_vcpus"] == 2


async def test_quota_reads_work_for_org_read_scope_without_the_platform_flag(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    key = await seed_key(app, await add_org(app, "acme"), MEMBER)

    quota = await client.get(QUOTA, headers=auth(key))
    recount = await client.get(RECOUNT, headers=auth(key))

    assert quota.status_code == 200, quota.text
    assert recount.status_code == 200, recount.text


async def test_put_quota_updates_limits_and_audits(app: FastAPI, client: httpx.AsyncClient) -> None:
    key = await org_with_admin(app)

    updated = await client.put(QUOTA, headers=auth(key), json={"max_vcpus": 4, "max_sandboxes": 3})

    assert updated.status_code == 200, updated.text
    limits = updated.json()["data"]["limits"]
    assert limits["max_vcpus"] == 4
    assert limits["max_sandboxes"] == 3
    assert limits["max_memory_mib"] is None
    fetched = await client.get(QUOTA, headers=auth(key))
    assert fetched.json()["data"]["limits"] == limits
    events = await client.get(AUDIT, headers=auth(key), params={"action": "quota.updated"})
    assert events.status_code == 200, events.text
    [event] = events.json()["data"]
    assert event["action"] == "quota.updated"
    assert event["details"]["limits"]["max_vcpus"] == 4


async def test_quota_updated_event_carries_request_id_ip_and_user_agent(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    key = await seed_key(app, await add_org(app, "acme"), ADMIN, platform=True)
    headers = {
        **auth(key),
        "X-Request-Id": "req-quota-context-1",
        "User-Agent": "governance-review/1.0",
    }

    updated = await client.put(QUOTA, headers=headers, json={"max_vcpus": 2})

    assert updated.status_code == 200, updated.text
    events = await client.get(AUDIT, headers=auth(key), params={"action": "quota.updated"})
    [event] = events.json()["data"]
    assert event["request_id"] == "req-quota-context-1"
    assert event["user_agent"] == "governance-review/1.0"
    assert event["ip"]
