"""Upper bounds on integer fields of the sandbox and org quota schemas (round 51).

A value at or above 2**31 used to reach the database and answer 500 INTERNAL. It is now a 422
VALIDATION_ERROR whose ``errors`` list names the field. Through the API on the fake driver and a
temp SQLite database; no network and no sockets.
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
from sandfort.api.openapi import OPENAPI_PATH, build_document, render_spec
from sandfort.api.schemas.orgs import (
    MAX_QUOTA_DISK_GIB,
    MAX_QUOTA_MEMORY_MIB,
    MAX_QUOTA_SANDBOXES,
)
from sandfort.api.schemas.sandboxes import (
    MAX_AUTO_MINUTES,
    MAX_CPU_MILLICORES,
    MAX_DISK_GIB,
    MAX_MEMORY_MIB,
)
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.quota import OrgQuota
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
QUOTA = "/v1/org/quota"
OK_STATUS = 200
INT32_OVERFLOW = 2**31
ENORMOUS_DECIMAL = "9" * 40  # a JSON integer literal far beyond any machine integer
MINUTE_FIELDS = ("auto_stop_minutes", "auto_delete_minutes")
VALIDATION_STATUS = 422
SERVER_ERROR_FLOOR = 500


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'limits51.db'}"
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
def org() -> Org:
    return Org(id=new_org_id(), name="Limits", slug="limits", created_at=NOW)


@pytest.fixture
async def headers(app: FastAPI, org: Org) -> dict[str, str]:
    generated = generate_api_key(PEPPER)
    key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="limits",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset(
            {Scope.SANDBOXES_WRITE, Scope.SANDBOXES_READ, Scope.ORG_READ, Scope.API_KEYS_ADMIN}
        ),
        created_at=NOW,
        is_platform_admin=True,  # replacing quota limits is a platform operation
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(key)
        await uow.commit()
    return {"Authorization": f"Bearer {generated.key}", "Content-Type": "application/json"}


async def post_raw(client: httpx.AsyncClient, headers: dict[str, str], body: str) -> httpx.Response:
    return await client.post(SANDBOXES, content=body, headers=headers)


def error_locations(response: httpx.Response) -> list[list[str]]:
    payload: dict[str, Any] = response.json()
    assert payload["success"] is False
    assert payload["error"]["code"] == "VALIDATION_ERROR"
    return [issue["loc"] for issue in payload["error"]["details"]["errors"]]


@pytest.mark.parametrize("field", MINUTE_FIELDS)
@pytest.mark.parametrize("literal", [str(INT32_OVERFLOW), ENORMOUS_DECIMAL])
async def test_minutes_above_the_maximum_answer_422_naming_the_field(
    client: httpx.AsyncClient, headers: dict[str, str], field: str, literal: str
) -> None:
    response = await post_raw(client, headers, f'{{"{field}": {literal}}}')

    assert response.status_code == VALIDATION_STATUS, response.text
    assert ["body", field] in error_locations(response)


@pytest.mark.parametrize("field", MINUTE_FIELDS)
async def test_one_minute_over_the_maximum_is_refused(
    client: httpx.AsyncClient, headers: dict[str, str], field: str
) -> None:
    response = await post_raw(client, headers, f'{{"{field}": {MAX_AUTO_MINUTES + 1}}}')

    assert response.status_code == VALIDATION_STATUS, response.text
    assert ["body", field] in error_locations(response)


@pytest.mark.parametrize("field", MINUTE_FIELDS)
async def test_the_documented_maximum_passes_validation(
    client: httpx.AsyncClient, headers: dict[str, str], field: str
) -> None:
    response = await post_raw(client, headers, f'{{"{field}": {MAX_AUTO_MINUTES}}}')

    # Shape-wise the request is valid; it may still fail later for other reasons.
    assert response.status_code != VALIDATION_STATUS, response.text
    assert response.status_code < SERVER_ERROR_FLOOR, response.text


@pytest.mark.parametrize(
    ("field", "maximum"),
    [
        ("cpu_millicores", MAX_CPU_MILLICORES),
        ("memory_mib", MAX_MEMORY_MIB),
        ("disk_gib", MAX_DISK_GIB),
    ],
)
async def test_resource_fields_above_the_maximum_answer_422(
    client: httpx.AsyncClient, headers: dict[str, str], field: str, maximum: int
) -> None:
    over = max(maximum + 1, INT32_OVERFLOW)

    response = await post_raw(client, headers, f'{{"resources": {{"{field}": {over}}}}}')

    assert response.status_code == VALIDATION_STATUS, response.text
    assert ["body", "resources", field] in error_locations(response)


async def test_update_minutes_above_the_maximum_answer_422(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    response = await client.patch(
        f"{SANDBOXES}/sbx_missing",
        content=f'{{"auto_stop_minutes": {INT32_OVERFLOW}}}',
        headers=headers,
    )

    assert response.status_code == VALIDATION_STATUS, response.text
    assert ["body", "auto_stop_minutes"] in error_locations(response)


QUOTA_FIELDS = [
    ("max_memory_mib", MAX_QUOTA_MEMORY_MIB),
    ("max_disk_gib", MAX_QUOTA_DISK_GIB),
    ("max_sandboxes", MAX_QUOTA_SANDBOXES),
]


@pytest.mark.parametrize(("field", "maximum"), QUOTA_FIELDS)
async def test_quota_fields_at_int32_overflow_answer_422_naming_the_field(
    client: httpx.AsyncClient, headers: dict[str, str], field: str, maximum: int
) -> None:
    assert maximum < INT32_OVERFLOW

    response = await client.put(QUOTA, content=f'{{"{field}": {INT32_OVERFLOW}}}', headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert ["body", field] in error_locations(response)


@pytest.mark.parametrize(("field", "maximum"), QUOTA_FIELDS)
async def test_quota_field_at_its_maximum_is_stored_and_read_back(
    client: httpx.AsyncClient, headers: dict[str, str], field: str, maximum: int
) -> None:
    response = await client.put(QUOTA, content=f'{{"{field}": {maximum}}}', headers=headers)

    assert response.status_code == OK_STATUS, response.text
    read = await client.get(QUOTA, headers=headers)
    assert read.status_code == OK_STATUS, read.text
    assert read.json()["data"]["limits"][field] == maximum


async def test_a_stored_quota_above_the_request_ceiling_still_reads_back(
    app: FastAPI, client: httpx.AsyncClient, headers: dict[str, str], org: Org
) -> None:
    legacy = INT32_OVERFLOW - 1  # a row written before the ceilings existed
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.quotas.upsert_limits(org.id, OrgQuota(max_memory_mib=legacy), NOW)
        await uow.commit()

    response = await client.get(QUOTA, headers=headers)

    assert response.status_code == OK_STATUS, response.text
    assert response.json()["data"]["limits"]["max_memory_mib"] == legacy


def test_committed_openapi_spec_matches_a_fresh_render() -> None:
    expected = render_spec(build_document()).encode("utf-8")

    assert OPENAPI_PATH.read_bytes() == expected, (
        f"{OPENAPI_PATH} is stale: regenerate it with `python -m sandfort.api.openapi`"
    )
