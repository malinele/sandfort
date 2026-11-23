"""WP 5.7 resize and capacity admission over the fake driver and the ASGI client.

Daemon-free; routes are exercised over HTTP only (the API sits behind a mounted app, so no
route-table introspection).
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
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
QUOTA = "/v1/org/quota"
RECOUNT = "/v1/org/quota/recount"
AUDIT = "/v1/audit-events"
ADMIN = frozenset(
    {
        Scope.SANDBOXES_READ,
        Scope.SANDBOXES_WRITE,
        Scope.ORG_READ,
        Scope.API_KEYS_ADMIN,
        Scope.AUDIT_READ,
    }
)
DEFAULT_CPU = 1000
DEFAULT_MEMORY = 512
DEFAULT_DISK = 3
GROWN_CPU = 2000
GROWN_MEMORY = 1024


def make_app(tmp_path: Path, **overrides: Any) -> FastAPI:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'resize.db'}"
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


async def key_for_new_org(app: FastAPI, slug: str) -> str:
    org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=ADMIN,
        is_platform_admin=True,  # the quota PUT used as fixture setup is a platform operation
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def stopped_sandbox(client: httpx.AsyncClient, key: str) -> str:
    created = await client.post(SANDBOXES, headers=auth(key), json={})
    assert created.status_code == 201, created.text
    sandbox_id: str = created.json()["data"]["id"]
    stopped = await client.post(f"{SANDBOXES}/{sandbox_id}/stop", headers=auth(key))
    assert stopped.json()["data"]["state"] == "stopped", stopped.text
    return sandbox_id


async def resize(
    client: httpx.AsyncClient, key: str, sandbox_id: str, **fields: int
) -> httpx.Response:
    return await client.post(f"{SANDBOXES}/{sandbox_id}/resize", headers=auth(key), json=fields)


async def reserved(client: httpx.AsyncClient, key: str) -> dict[str, Any]:
    response = await client.get(QUOTA, headers=auth(key))
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()["data"]["reserved"]
    return body


async def set_limits(client: httpx.AsyncClient, key: str, **limits: Any) -> None:
    response = await client.put(QUOTA, headers=auth(key), json=limits)
    assert response.status_code == 200, response.text


async def stored_resources(
    client: httpx.AsyncClient, key: str, sandbox_id: str
) -> dict[str, Any]:
    response = await client.get(f"{SANDBOXES}/{sandbox_id}", headers=auth(key))
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()["data"]["resources"]
    return body


# --- success path -------------------------------------------------------------------


async def test_resize_adjusts_the_ledger_and_the_next_start_recreates_the_container(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver
) -> None:
    key = await key_for_new_org(app, "acme")
    sandbox_id = await stopped_sandbox(client, key)
    [before] = await driver.list_managed()

    resized = await resize(
        client, key, sandbox_id, cpu_millicores=GROWN_CPU, memory_mib=GROWN_MEMORY
    )

    assert resized.status_code == 200, resized.text
    data = resized.json()["data"]
    assert data["state"] == "stopped"
    assert data["resources"]["cpu_millicores"] == GROWN_CPU
    assert data["resources"]["memory_mib"] == GROWN_MEMORY
    assert data["resources"]["disk_gib"] == DEFAULT_DISK  # omitted fields keep their value
    held = await reserved(client, key)
    assert held["vcpus"] == GROWN_CPU / 1000
    assert held["memory_mib"] == GROWN_MEMORY
    assert held["sandboxes"] == 1
    recount = (await client.get(RECOUNT, headers=auth(key))).json()["data"]
    assert recount["consistent"] is True
    assert recount["ledger"] == held
    [untouched] = await driver.list_managed()
    assert untouched.resources.cpu_millicores == DEFAULT_CPU  # nothing recreated until start

    started = await client.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))

    assert started.status_code == 200, started.text
    assert started.json()["data"]["state"] == "started"
    [after] = await driver.list_managed()
    assert after.resources.cpu_millicores == GROWN_CPU
    assert after.resources.memory_mib == GROWN_MEMORY
    assert after.created_at > before.created_at  # a new container, not the adopted one


async def test_start_without_a_resize_keeps_the_existing_container(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver
) -> None:
    key = await key_for_new_org(app, "acme")
    sandbox_id = await stopped_sandbox(client, key)
    [before] = await driver.list_managed()

    started = await client.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))

    assert started.status_code == 200, started.text
    [after] = await driver.list_managed()
    assert after.created_at == before.created_at
    assert after.resources == before.resources


# --- refusals -----------------------------------------------------------------------


async def test_resize_while_running_is_a_conflict(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    key = await key_for_new_org(app, "acme")
    created = await client.post(SANDBOXES, headers=auth(key), json={})
    sandbox_id = created.json()["data"]["id"]

    refused = await resize(client, key, sandbox_id, cpu_millicores=GROWN_CPU)

    assert refused.status_code == 409, refused.text
    assert refused.json()["error"]["code"] == "INVALID_STATE"
    assert (await stored_resources(client, key, sandbox_id))["cpu_millicores"] == DEFAULT_CPU


async def test_resize_beyond_the_org_quota_keeps_the_old_reservation(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    key = await key_for_new_org(app, "acme")
    await set_limits(client, key, max_vcpus=2)
    sandbox_id = await stopped_sandbox(client, key)
    assert (await resize(client, key, sandbox_id, memory_mib=GROWN_MEMORY)).status_code == 200
    held = await reserved(client, key)
    assert held["sandboxes"] == 1

    refused = await resize(client, key, sandbox_id, cpu_millicores=3000)

    assert refused.status_code == 429, refused.text
    assert refused.json()["error"]["code"] == "QUOTA_EXCEEDED"
    assert await reserved(client, key) == held
    row = await stored_resources(client, key, sandbox_id)
    assert row["cpu_millicores"] == DEFAULT_CPU
    assert row["memory_mib"] == GROWN_MEMORY


async def test_resize_beyond_the_effective_host_capacity_answers_503(tmp_path: Path) -> None:
    # Configured 2 vCPUs, factor 1.5: the host admits up to 3 vCPUs of reservations.
    app = make_app(tmp_path, host_capacity_cpu_millicores=2000, host_overcommit_factor=1.5)
    async with serve(app) as client:
        key = await key_for_new_org(app, "acme")
        sandbox_id = await stopped_sandbox(client, key)

        within = await resize(client, key, sandbox_id, cpu_millicores=2500)
        held = await reserved(client, key)
        refused = await resize(client, key, sandbox_id, cpu_millicores=3500)

        assert within.status_code == 200, within.text  # above the configured 2000, within 3000
        assert refused.status_code == 503, refused.text
        assert refused.json()["error"]["code"] == "CAPACITY"
        assert await reserved(client, key) == held
        assert (await stored_resources(client, key, sandbox_id))["cpu_millicores"] == 2500


async def test_a_resize_naming_no_field_is_rejected(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    key = await key_for_new_org(app, "acme")
    sandbox_id = await stopped_sandbox(client, key)

    refused = await resize(client, key, sandbox_id)

    assert refused.status_code in (400, 422), refused.text


# --- audit and access ---------------------------------------------------------------


async def test_resize_is_audited_with_old_and_new_resources(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    key = await key_for_new_org(app, "acme")
    sandbox_id = await stopped_sandbox(client, key)
    await resize(client, key, sandbox_id, cpu_millicores=GROWN_CPU)

    events = await client.get(AUDIT, headers=auth(key), params={"action": "sandbox.resized"})

    assert events.status_code == 200, events.text
    [event] = events.json()["data"]
    assert event["action"] == "sandbox.resized"
    assert event["details"]["old_resources"]["cpu_millicores"] == DEFAULT_CPU
    assert event["details"]["new_resources"]["cpu_millicores"] == GROWN_CPU
    assert event["details"]["old_resources"]["memory_mib"] == DEFAULT_MEMORY
    assert event["details"]["new_resources"]["memory_mib"] == DEFAULT_MEMORY


async def test_resize_requires_authentication(app: FastAPI, client: httpx.AsyncClient) -> None:
    key = await key_for_new_org(app, "acme")
    sandbox_id = await stopped_sandbox(client, key)

    response = await client.post(f"{SANDBOXES}/{sandbox_id}/resize", json={"disk_gib": 4})

    assert response.status_code == 401


async def test_resizing_another_orgs_sandbox_is_not_found(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    owner = await key_for_new_org(app, "acme")
    stranger = await key_for_new_org(app, "other")
    sandbox_id = await stopped_sandbox(client, owner)

    response = await resize(client, stranger, sandbox_id, disk_gib=4)

    assert response.status_code == 404, response.text
    assert response.json()["error"]["code"] == "NOT_FOUND"
    assert (await stored_resources(client, owner, sandbox_id))["disk_gib"] == DEFAULT_DISK
