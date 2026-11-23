"""Request inputs that answered 500 INTERNAL instead of a 422 validation error (round 52).

* ``GET /v1/sandboxes/{id}/logs?since=``: an epoch past year 9999 overflowed the datetime
  conversion; it now has an exclusive upper bound.
* ``PUT /v1/org/quota`` ``max_vcpus``: unbounded and accepting non-finite floats; it now has the
  per-sandbox CPU ceiling (in vCPUs) and rejects infinity and NaN.
* ``GET /v1/audit-events`` and ``/export`` ``from``/``to``: an aware datetime at the edge of the
  range left it when converted to UTC; that is now a validation error naming the parameter.
* ``GET /v1/org/usage`` ``from``/``to``: the same edge, now bounded by the audit routes' shared
  validator.

Through the API on the fake driver and a temp SQLite database; no network and no sockets.
"""

import math
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
from sandfort.api.openapi import OPENAPI_PATH, build_document, render_spec
from sandfort.api.routes.sandbox_logs import SINCE_LIMIT_S
from sandfort.api.schemas.orgs import MAX_QUOTA_VCPUS
from sandfort.api.schemas.sandboxes import MAX_CPU_MILLICORES
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
AUDIT_ROUTES = ("/v1/audit-events", "/v1/audit-events/export")
OK_STATUS = 200
CREATED_STATUS = 201
VALIDATION_STATUS = 422
MILLICORES_PER_VCPU = 1000
LARGEST_VALID_SINCE = math.nextafter(float(SINCE_LIMIT_S), 0.0)
# Aware datetimes whose UTC equivalent lies past year 9999 or before year 1.
OUT_OF_RANGE_BOUNDS = ("9999-12-31T23:00:00-23:00", "0001-01-01T00:00:00+23:00")
# The latest instant that converts, given in UTC and with a large negative offset.
LATEST_VALID_BOUNDS = ("9999-12-31T23:59:59.999999Z", "9999-12-31T00:59:59.999999-23:00")


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'limits52.db'}"
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
    return {"Authorization": f"Bearer {generated.key}", "Content-Type": "application/json"}


@pytest.fixture
async def sandbox_id(client: httpx.AsyncClient, headers: dict[str, str]) -> str:
    response = await client.post(SANDBOXES, json={}, headers=headers)
    assert response.status_code == CREATED_STATUS, response.text
    value: str = response.json()["data"]["id"]
    return value


def error_locations(response: httpx.Response) -> list[list[str]]:
    payload: dict[str, Any] = response.json()
    assert payload["success"] is False
    assert payload["error"]["code"] == "VALIDATION_ERROR"
    return [issue["loc"] for issue in payload["error"]["details"]["errors"]]


# --- sandbox logs: since ----------------------------------------------------------------


@pytest.mark.parametrize("since", [str(SINCE_LIMIT_S), "1e300", "inf"])
async def test_logs_since_past_year_9999_answers_422_naming_the_parameter(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, since: str
) -> None:
    response = await client.get(
        f"{SANDBOXES}/{sandbox_id}/logs", params={"since": since}, headers=headers
    )

    assert response.status_code == VALIDATION_STATUS, response.text
    assert ["query", "since"] in error_locations(response)


def test_logs_since_limit_is_the_first_epoch_datetime_cannot_hold() -> None:
    assert datetime.fromtimestamp(LARGEST_VALID_SINCE, UTC).year == datetime.max.year
    with pytest.raises((OverflowError, ValueError)):
        datetime.fromtimestamp(SINCE_LIMIT_S, UTC)


@pytest.mark.parametrize("since", [LARGEST_VALID_SINCE, 0.0])
async def test_logs_since_at_the_largest_valid_value_streams(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, since: float
) -> None:
    response = await client.get(
        f"{SANDBOXES}/{sandbox_id}/logs", params={"since": repr(since)}, headers=headers
    )

    assert response.status_code == OK_STATUS, response.text


# --- org quota: max_vcpus ---------------------------------------------------------------


def test_max_vcpus_ceiling_matches_the_per_sandbox_cpu_ceiling() -> None:
    assert MAX_QUOTA_VCPUS * MILLICORES_PER_VCPU == MAX_CPU_MILLICORES


@pytest.mark.parametrize(
    "literal", ["1e309", "Infinity", "-Infinity", "NaN", str(MAX_QUOTA_VCPUS + 1)]
)
async def test_max_vcpus_non_finite_or_above_the_ceiling_answers_422(
    client: httpx.AsyncClient, headers: dict[str, str], literal: str
) -> None:
    response = await client.put(QUOTA, content=f'{{"max_vcpus": {literal}}}', headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert ["body", "max_vcpus"] in error_locations(response)


@pytest.mark.parametrize("value", [MAX_QUOTA_VCPUS, 0.5])
async def test_max_vcpus_at_the_ceiling_is_stored_and_read_back(
    client: httpx.AsyncClient, headers: dict[str, str], value: float
) -> None:
    response = await client.put(QUOTA, json={"max_vcpus": value}, headers=headers)

    assert response.status_code == OK_STATUS, response.text
    read = await client.get(QUOTA, headers=headers)
    assert read.status_code == OK_STATUS, read.text
    assert read.json()["data"]["limits"]["max_vcpus"] == value


# --- audit events: from / to ------------------------------------------------------------


@pytest.mark.parametrize("route", AUDIT_ROUTES)
@pytest.mark.parametrize("parameter", ["from", "to"])
@pytest.mark.parametrize("bound", OUT_OF_RANGE_BOUNDS)
async def test_audit_bound_leaving_the_range_in_utc_answers_422(
    client: httpx.AsyncClient, headers: dict[str, str], route: str, parameter: str, bound: str
) -> None:
    response = await client.get(route, params={parameter: bound}, headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert ["query", parameter] in error_locations(response)


@pytest.mark.parametrize("route", AUDIT_ROUTES)
@pytest.mark.parametrize("bound", LATEST_VALID_BOUNDS)
async def test_audit_bound_at_the_latest_valid_instant_is_accepted(
    client: httpx.AsyncClient, headers: dict[str, str], route: str, bound: str
) -> None:
    params = {"from": "0001-01-01T00:00:00Z", "to": bound}

    response = await client.get(route, params=params, headers=headers)

    assert response.status_code == OK_STATUS, response.text


async def test_audit_export_still_refuses_to_not_after_from(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    params = {"from": "2026-11-10T12:00:00+01:00", "to": "2026-11-10T11:00:00Z"}

    response = await client.get(AUDIT_ROUTES[1], params=params, headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert response.json()["error"]["code"] == "UNPROCESSABLE"


# --- org usage: from / to ---------------------------------------------------------------


@pytest.mark.parametrize("parameter", ["from", "to"])
@pytest.mark.parametrize("bound", OUT_OF_RANGE_BOUNDS)
async def test_usage_bound_leaving_the_range_in_utc_answers_422(
    client: httpx.AsyncClient, headers: dict[str, str], parameter: str, bound: str
) -> None:
    params = {"from": "2026-11-10T00:00:00Z", "to": "2026-11-10T01:00:00Z", parameter: bound}

    response = await client.get(USAGE, params=params, headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert ["query", parameter] in error_locations(response)


async def test_usage_ordinary_range_answers_200(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    params = {"from": "2026-11-10T00:00:00", "to": "2026-11-10T02:00:00+01:00"}

    response = await client.get(USAGE, params=params, headers=headers)

    assert response.status_code == OK_STATUS, response.text


# --- spec -------------------------------------------------------------------------------


def test_committed_openapi_spec_matches_a_fresh_render() -> None:
    expected = render_spec(build_document()).encode("utf-8")

    assert OPENAPI_PATH.read_bytes() == expected, (
        f"{OPENAPI_PATH} is stale: regenerate it with `python -m sandfort.api.openapi`"
    )
