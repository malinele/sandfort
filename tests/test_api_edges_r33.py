"""API edges: audit list order, Retry-After on 503 CAPACITY, ``created_by`` and invalid JSON.

Through the API on the fake driver and a temp SQLite database. Audit rows are seeded straight
into the repository (with ids of increasing time) so the expected order is known.
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
from sandfort.api.schemas.api_keys import ApiKeyResponse
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import ActorType, AuditEvent
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.drivers.errors import DriverError
from sandfort.errors import CapacityExceeded
from sandfort.ids import AUDIT as AUDIT_PREFIX
from sandfort.ids import new_api_key_id, new_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
AUDIT = "/v1/audit-events"
KEYS = "/v1/api-keys"
SEEDED_ACTION = "seed.event"
SEEDED_COUNT = 5
FIRST_EVENT_MS = 1_800_000_000_000
LABELS = {"student": "ada"}
KEY_ADMIN = frozenset({Scope.API_KEYS_ADMIN})


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'edges33.db'}"
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
    org = Org(id=new_org_id(), name="Edges", slug="edges", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def seed_key(
    app: FastAPI,
    org_id: str,
    scopes: frozenset[Scope],
    *,
    labels: dict[str, str] | None = None,
    created_by: str | None = None,
) -> tuple[str, str]:
    """Store a key; return ``(key_id, plaintext)``."""
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="seed",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=scopes,
        sandbox_labels=labels,
        created_by=created_by,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return stored.id, generated.key


def bearer(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


# --- 1. audit list order -------------------------------------------------------------------


@pytest.fixture
async def seeded_ids(app: FastAPI, org_id: str) -> list[str]:
    """Ids of the seeded audit rows, oldest first."""
    ids = [new_id(AUDIT_PREFIX, now_ms=FIRST_EVENT_MS + step) for step in range(SEEDED_COUNT)]
    async with UnitOfWork(app.state.session_factory) as uow:
        for event_id in ids:
            await uow.audit.add(
                AuditEvent(
                    id=event_id,
                    org_id=org_id,
                    actor_type=ActorType.SYSTEM,
                    action=SEEDED_ACTION,
                    occurred_at=NOW,
                )
            )
        await uow.commit()
    return ids


@pytest.fixture
async def auditor(app: FastAPI, org_id: str) -> str:
    return (await seed_key(app, org_id, frozenset({Scope.AUDIT_READ})))[1]


async def list_ids(client: httpx.AsyncClient, key: str, **params: Any) -> list[str]:
    response = await client.get(AUDIT, params=params, headers=bearer(key))
    assert response.status_code == 200, response.text
    return [row["id"] for row in response.json()["data"]]


async def page_through(client: httpx.AsyncClient, key: str, limit: int, **params: Any) -> list[str]:
    """Follow ``next_cursor`` to the end; return the ids in the order they came."""
    seen: list[str] = []
    cursor: str | None = None
    for _ in range(SEEDED_COUNT + 1):
        query = {**params, "limit": limit, **({} if cursor is None else {"cursor": cursor})}
        response = await client.get(AUDIT, params=query, headers=bearer(key))
        assert response.status_code == 200, response.text
        body = response.json()
        seen.extend(row["id"] for row in body["data"])
        cursor = body["meta"]["next_cursor"]
        if cursor is None:
            return seen
    raise AssertionError("the cursor never ended")


async def test_the_audit_list_defaults_to_oldest_first(
    client: httpx.AsyncClient, auditor: str, seeded_ids: list[str]
) -> None:
    ids = await list_ids(client, auditor, action=SEEDED_ACTION)

    assert ids == seeded_ids


async def test_order_desc_lists_the_audit_newest_first(
    client: httpx.AsyncClient, auditor: str, seeded_ids: list[str]
) -> None:
    ids = await list_ids(client, auditor, action=SEEDED_ACTION, order="desc")

    assert ids == list(reversed(seeded_ids))


async def test_desc_paging_continues_in_the_same_order_without_gaps_or_repeats(
    client: httpx.AsyncClient, auditor: str, seeded_ids: list[str]
) -> None:
    seen = await page_through(client, auditor, 2, action=SEEDED_ACTION, order="desc")

    assert seen == list(reversed(seeded_ids))


async def test_asc_paging_still_walks_oldest_first(
    client: httpx.AsyncClient, auditor: str, seeded_ids: list[str]
) -> None:
    seen = await page_through(client, auditor, 2, action=SEEDED_ACTION, order="asc")

    assert seen == seeded_ids


async def test_an_unknown_order_is_a_validation_error(
    client: httpx.AsyncClient, auditor: str
) -> None:
    response = await client.get(AUDIT, params={"order": "sideways"}, headers=bearer(auditor))

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


# --- 2. Retry-After on 503 CAPACITY --------------------------------------------------------


async def test_a_503_capacity_answer_carries_retry_after(
    app: FastAPI, client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken(*_args: Any, **_kwargs: Any) -> None:
        raise DriverError("daemon unreachable")

    monkeypatch.setattr(app.state.driver, "list_managed", broken)

    response = await client.get("/readyz")

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "CAPACITY"
    assert response.headers["retry-after"] == "5"


def test_capacity_exceeded_defaults_to_five_seconds_and_can_be_overridden() -> None:
    assert CapacityExceeded("full").retry_after_s == 5
    assert CapacityExceeded("full", retry_after_s=30).retry_after_s == 30


# --- 3. created_by hidden from label-scoped keys -------------------------------------------


async def test_a_label_scoped_key_sees_created_by_null_and_an_org_wide_key_sees_it(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    admin_id, admin_key = await seed_key(app, org_id, KEY_ADMIN)
    scoped_id, scoped_key = await seed_key(
        app, org_id, KEY_ADMIN, labels=LABELS, created_by=admin_id
    )

    from_scoped = await client.get(KEYS, headers=bearer(scoped_key))
    from_admin = await client.get(KEYS, headers=bearer(admin_key))

    assert from_scoped.status_code == 200, from_scoped.text
    scoped_view = {row["id"]: row for row in from_scoped.json()["data"]}
    assert scoped_id in scoped_view
    assert all(row["created_by"] is None for row in scoped_view.values())
    admin_view = {row["id"]: row for row in from_admin.json()["data"]}
    assert admin_view[scoped_id]["created_by"] == admin_id


async def test_a_revoke_answer_hides_created_by_from_a_label_scoped_caller(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    admin_id, _ = await seed_key(app, org_id, KEY_ADMIN)
    scoped_id, scoped_key = await seed_key(
        app, org_id, KEY_ADMIN, labels=LABELS, created_by=admin_id
    )

    response = await client.delete(f"{KEYS}/{scoped_id}", headers=bearer(scoped_key))

    assert response.status_code == 200, response.text
    assert response.json()["data"]["created_by"] is None


def test_the_created_by_description_documents_the_rule() -> None:
    description = ApiKeyResponse.model_fields["created_by"].description or ""

    assert "label-scoped" in description


# --- 4. a readable invalid-JSON message ----------------------------------------------------


async def test_an_invalid_json_body_answers_a_readable_message(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    _, key = await seed_key(app, org_id, KEY_ADMIN)

    response = await client.post(
        KEYS, content=b"{not json", headers={**bearer(key), "Content-Type": "application/json"}
    )

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert error["message"] == "request body is not valid JSON"


async def test_other_validation_messages_are_unchanged(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    _, key = await seed_key(app, org_id, KEY_ADMIN)

    response = await client.post(KEYS, json={"scopes": ["org:read"]}, headers=bearer(key))

    assert response.status_code == 422
    assert response.json()["error"]["message"].startswith("request validation failed: body.name: ")
