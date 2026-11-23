"""A revoked or expired API key's refused call is audited as ``request.denied`` (throttled).

Through the app on the fake driver and a temp SQLite database. Only a stored key whose secret
verified names an org; unknown keys stay unaudited. The throttle allows one row per key per 60 s.
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
from sandfort.api.errors import DENIED_ACTION
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import AuditEvent, AuditOutcome
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.audit import AuditRecorder

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)
LONG_AGO = datetime(2020, 1, 1, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'revoked.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(
        Settings(driver="fake", database_url=url, api_key_pepper=PEPPER, rate_limit_enabled=False)
    )
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
    org = Org(id=new_org_id(), name="School", slug="school", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def seed_key(
    app: FastAPI,
    org_id: str,
    *,
    revoked_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> tuple[str, str]:
    """Store a key and return ``(key_id, plaintext key)``."""
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="seed",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset({Scope.SANDBOXES_READ}),
        revoked_at=revoked_at,
        expires_at=expires_at,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return stored.id, generated.key


def bearer(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def denials(app: FastAPI, org_id: str) -> list[AuditEvent]:
    async with UnitOfWork(app.state.session_factory) as uow:
        rows = await uow.audit.list(org_id, limit=200)
    return [row for row in rows if row.action == DENIED_ACTION]


async def test_a_revoked_key_call_is_refused_and_audited_with_reason_revoked(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    key_id, key = await seed_key(app, org_id, revoked_at=NOW)

    response = await client.get(SANDBOXES, headers=bearer(key))

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"
    (event,) = await denials(app, org_id)
    assert event.outcome is AuditOutcome.DENIED
    assert event.actor_id == key_id
    assert event.details["reason"] == "revoked"
    assert event.details["status"] == 401
    assert event.details["error_code"] == "UNAUTHORIZED"
    assert event.details["method"] == "GET"
    assert event.details["path"] == SANDBOXES


async def test_an_expired_key_call_is_audited_with_reason_expired(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    key_id, key = await seed_key(app, org_id, expires_at=LONG_AGO)

    response = await client.get(SANDBOXES, headers=bearer(key))

    assert response.status_code == 401
    (event,) = await denials(app, org_id)
    assert event.actor_id == key_id
    assert event.details["reason"] == "expired"


async def test_a_second_refusal_within_the_window_adds_no_row(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    _, key = await seed_key(app, org_id, revoked_at=NOW)

    first = await client.get(SANDBOXES, headers=bearer(key))
    second = await client.get(SANDBOXES, headers=bearer(key))

    assert first.status_code == second.status_code == 401
    assert len(await denials(app, org_id)) == 1


async def test_a_failed_first_audit_write_leaves_the_key_due_for_the_next_refusal(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, key = await seed_key(app, org_id, revoked_at=NOW)
    real_record = AuditRecorder.record
    calls = 0

    async def flaky_record(self: AuditRecorder, *args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("database is down")
        return await real_record(self, *args, **kwargs)

    monkeypatch.setattr(AuditRecorder, "record", flaky_record)

    first = await client.get(SANDBOXES, headers=bearer(key))
    assert first.status_code == 401
    assert await denials(app, org_id) == []

    second = await client.get(SANDBOXES, headers=bearer(key))
    third = await client.get(SANDBOXES, headers=bearer(key))

    assert second.status_code == third.status_code == 401
    assert calls == 2
    assert len(await denials(app, org_id)) == 1


async def test_an_unknown_key_adds_no_row(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    unknown = generate_api_key(PEPPER).key

    response = await client.get(SANDBOXES, headers=bearer(unknown))

    assert response.status_code == 401
    assert await denials(app, org_id) == []


async def test_the_401_body_is_the_same_as_before(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    _, key = await seed_key(app, org_id, revoked_at=NOW)

    response = await client.get(SANDBOXES, headers=bearer(key))

    error = response.json()["error"]
    assert error["code"] == "UNAUTHORIZED"
    assert error["message"] == "API key has been revoked"
    assert "reason" not in error.get("details", {})
