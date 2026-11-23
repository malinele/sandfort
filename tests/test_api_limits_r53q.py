"""Client mistakes the API accepted or answered unlike its sibling routes (round 53).

* Numeric request fields read a JSON boolean as a number (``true`` stored as 1.0 for the org's
  ``max_vcpus``). Every numeric field of the org quota body and of the sandbox create, update
  and resize bodies (including the nested ``resources``) now answers 422 ``VALIDATION_ERROR``
  naming the field, and nothing is stored.
* ``GET /v1/org/usage`` with ``to`` not after ``from`` answered 400 ``VALIDATION_ERROR`` and
  left no audit row; it now answers like the audit export route: 422 ``UNPROCESSABLE``,
  recorded on the org audit chain as a refusal.

Through the API on the fake driver and a temp SQLite database; no network and no sockets.
"""

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
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
QUOTA = "/v1/org/quota"
USAGE = "/v1/org/usage"
EXPORT = "/v1/audit-events/export"
AUDIT_EVENTS = "/v1/audit-events"
DENIED_ACTION = "request.denied"
OK_STATUS = 200
CREATED_STATUS = 201
ACCEPTED_STATUS = 202
VALIDATION_STATUS = 422
BOOLEANS = (True, False)
QUOTA_FIELDS = ("max_vcpus", "max_memory_mib", "max_disk_gib", "max_sandboxes")
MINUTE_FIELDS = ("auto_stop_minutes", "auto_delete_minutes")
RESOURCE_FIELDS = ("cpu_millicores", "memory_mib", "disk_gib")
UNLIMITED: dict[str, None] = dict.fromkeys(QUOTA_FIELDS)
RESIZED_MEMORY_MIB = 512
# A period whose end is before its start, as both routes receive it.
BACKWARDS_PERIOD = {"from": "2026-11-10T12:00:00+01:00", "to": "2026-11-10T10:00:00Z"}


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'limits53q.db'}"
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
async def headers(app: FastAPI) -> dict[str, str]:
    org = Org(id=new_org_id(), name="Limits", slug="limits", created_at=NOW)
    generated = generate_api_key(PEPPER)
    key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="limits",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset(
            {
                Scope.SANDBOXES_WRITE,
                Scope.SANDBOXES_READ,
                Scope.ORG_READ,
                Scope.API_KEYS_ADMIN,
                Scope.AUDIT_READ,
                Scope.USAGE_READ,
            }
        ),
        created_at=NOW,
        is_platform_admin=True,  # replacing quota limits is a platform operation
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(key)
        await uow.commit()
    return {"Authorization": f"Bearer {generated.key}"}


@pytest.fixture
async def sandbox_id(client: httpx.AsyncClient, headers: dict[str, str]) -> str:
    response = await client.post(SANDBOXES, json={}, headers=headers)
    assert response.status_code == CREATED_STATUS, response.text
    value: str = response.json()["data"]["id"]
    return value


def error_locations(response: httpx.Response) -> list[list[str]]:
    assert response.status_code == VALIDATION_STATUS, response.text
    payload: dict[str, Any] = response.json()
    assert payload["success"] is False
    assert payload["error"]["code"] == "VALIDATION_ERROR"
    return [issue["loc"] for issue in payload["error"]["details"]["errors"]]


async def stored_limits(client: httpx.AsyncClient, headers: dict[str, str]) -> dict[str, Any]:
    response = await client.get(QUOTA, headers=headers)
    assert response.status_code == OK_STATUS, response.text
    limits: dict[str, Any] = response.json()["data"]["limits"]
    return limits


async def sandbox_ids(client: httpx.AsyncClient, headers: dict[str, str]) -> list[str]:
    response = await client.get(SANDBOXES, headers=headers)
    assert response.status_code == OK_STATUS, response.text
    return [item["id"] for item in response.json()["data"]]


async def read_sandbox(
    client: httpx.AsyncClient, headers: dict[str, str], ident: str
) -> dict[str, Any]:
    response = await client.get(f"{SANDBOXES}/{ident}", headers=headers)
    assert response.status_code == OK_STATUS, response.text
    data: dict[str, Any] = response.json()["data"]
    return data


async def stop(client: httpx.AsyncClient, headers: dict[str, str], ident: str) -> None:
    response = await client.post(f"{SANDBOXES}/{ident}/stop", headers=headers)
    assert response.status_code in (OK_STATUS, ACCEPTED_STATUS), response.text
    assert (await read_sandbox(client, headers, ident))["state"] == "stopped"


# --- org quota ------------------------------------------------------------------------


@pytest.mark.parametrize("field", QUOTA_FIELDS)
@pytest.mark.parametrize("value", BOOLEANS)
async def test_quota_boolean_answers_422_naming_the_field_and_stores_nothing(
    client: httpx.AsyncClient, headers: dict[str, str], field: str, value: bool
) -> None:
    response = await client.put(QUOTA, json={field: value}, headers=headers)

    assert ["body", field] in error_locations(response)
    assert await stored_limits(client, headers) == UNLIMITED


async def test_quota_ordinary_numbers_are_stored(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    body = {"max_vcpus": 1, "max_memory_mib": 0, "max_disk_gib": 20, "max_sandboxes": 3}

    response = await client.put(QUOTA, json=body, headers=headers)

    assert response.status_code == OK_STATUS, response.text
    assert await stored_limits(client, headers) == body


async def test_quota_numeric_forms_accepted_before_still_work(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    content = '{"max_vcpus": "1.5", "max_memory_mib": 2048.0, "max_disk_gib": "10"}'

    response = await client.put(
        QUOTA, content=content, headers={**headers, "Content-Type": "application/json"}
    )

    assert response.status_code == OK_STATUS, response.text
    limits = await stored_limits(client, headers)
    stored = (limits["max_vcpus"], limits["max_memory_mib"], limits["max_disk_gib"])
    assert stored == (1.5, 2048, 10)


# --- sandbox create ---------------------------------------------------------------------


@pytest.mark.parametrize("field", MINUTE_FIELDS)
@pytest.mark.parametrize("value", BOOLEANS)
async def test_create_boolean_minutes_answers_422_and_creates_nothing(
    client: httpx.AsyncClient, headers: dict[str, str], field: str, value: bool
) -> None:
    response = await client.post(SANDBOXES, json={field: value}, headers=headers)

    assert ["body", field] in error_locations(response)
    assert await sandbox_ids(client, headers) == []


@pytest.mark.parametrize("field", RESOURCE_FIELDS)
@pytest.mark.parametrize("value", BOOLEANS)
async def test_create_boolean_resource_answers_422_and_creates_nothing(
    client: httpx.AsyncClient, headers: dict[str, str], field: str, value: bool
) -> None:
    response = await client.post(SANDBOXES, json={"resources": {field: value}}, headers=headers)

    assert ["body", "resources", field] in error_locations(response)
    assert await sandbox_ids(client, headers) == []


async def test_create_ordinary_numbers_still_work(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    resources = {"cpu_millicores": 500, "memory_mib": 256, "disk_gib": 1}
    body = {"auto_stop_minutes": 0, "auto_delete_minutes": 1, "resources": resources}

    response = await client.post(SANDBOXES, json=body, headers=headers)

    assert response.status_code == CREATED_STATUS, response.text
    data = response.json()["data"]
    assert (data["auto_stop_minutes"], data["auto_delete_minutes"]) == (0, 1)
    assert data["resources"] == resources


# --- sandbox update ---------------------------------------------------------------------


@pytest.mark.parametrize("field", MINUTE_FIELDS)
@pytest.mark.parametrize("value", BOOLEANS)
async def test_update_boolean_minutes_answers_422_and_changes_nothing(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, field: str, value: bool
) -> None:
    before = await read_sandbox(client, headers, sandbox_id)

    response = await client.patch(f"{SANDBOXES}/{sandbox_id}", json={field: value}, headers=headers)

    assert ["body", field] in error_locations(response)
    assert (await read_sandbox(client, headers, sandbox_id))[field] == before[field]


async def test_update_ordinary_minutes_still_work(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    body = {"auto_stop_minutes": 30, "auto_delete_minutes": -1}

    response = await client.patch(f"{SANDBOXES}/{sandbox_id}", json=body, headers=headers)

    assert response.status_code == OK_STATUS, response.text
    data = response.json()["data"]
    assert (data["auto_stop_minutes"], data["auto_delete_minutes"]) == (30, -1)


# --- sandbox resize ---------------------------------------------------------------------


@pytest.mark.parametrize("field", RESOURCE_FIELDS)
@pytest.mark.parametrize("value", BOOLEANS)
async def test_resize_boolean_answers_422_and_changes_nothing(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, field: str, value: bool
) -> None:
    await stop(client, headers, sandbox_id)
    before = await read_sandbox(client, headers, sandbox_id)

    response = await client.post(
        f"{SANDBOXES}/{sandbox_id}/resize", json={field: value}, headers=headers
    )

    assert ["body", field] in error_locations(response)
    after = await read_sandbox(client, headers, sandbox_id)
    assert after["resources"] == before["resources"]


async def test_resize_ordinary_number_still_works(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    await stop(client, headers, sandbox_id)

    response = await client.post(
        f"{SANDBOXES}/{sandbox_id}/resize", json={"memory_mib": RESIZED_MEMORY_MIB}, headers=headers
    )

    assert response.status_code == OK_STATUS, response.text
    assert response.json()["data"]["resources"]["memory_mib"] == RESIZED_MEMORY_MIB


# --- org usage: period order ------------------------------------------------------------


async def test_usage_backwards_period_answers_like_the_export_route(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    export = await client.get(EXPORT, params=BACKWARDS_PERIOD, headers=headers)
    usage = await client.get(USAGE, params=BACKWARDS_PERIOD, headers=headers)

    assert export.status_code == VALIDATION_STATUS, export.text
    assert usage.status_code == export.status_code, usage.text
    assert usage.json()["error"]["code"] == export.json()["error"]["code"] == "UNPROCESSABLE"


async def test_usage_backwards_period_is_audited_as_a_refusal(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    response = await client.get(USAGE, params=BACKWARDS_PERIOD, headers=headers)
    assert response.status_code == VALIDATION_STATUS, response.text

    events = await client.get(AUDIT_EVENTS, params={"action": DENIED_ACTION}, headers=headers)

    assert events.status_code == OK_STATUS, events.text
    paths = [event["details"]["path"] for event in events.json()["data"]]
    assert USAGE in paths
