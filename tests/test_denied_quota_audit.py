"""A 429 QUOTA_EXCEEDED refusal is audited as ``request.denied``; RATE_LIMITED is not.

Round 65: the one exception is the per-key sandbox cap (``key_max_sandboxes``), which writes
``sandbox.create_refused`` instead, like a capacity refusal does, and no ``request.denied``.

Through the app on the fake driver and a temp SQLite database. The quota case hits the per-key
sandbox cap; the rate-limit case empties a tiny token bucket driven by a frozen clock.
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
from sandfort.api.errors import DENIED_ACTION
from sandfort.api.middleware.rate_limit import TokenBucketRateLimiter, install_rate_limit
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import AuditEvent, AuditOutcome
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.quota import OrgQuota
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
KEYS = "/v1/api-keys"
SANDBOX_SCOPES = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})
ADMIN_SCOPES = SANDBOX_SCOPES | {Scope.API_KEYS_ADMIN}
LABELS = {"student": "ada"}
CAP = 1
TINY_BURST = 3


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'denied.db'}"
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


def bearer(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def denials(app: FastAPI, org_id: str) -> list[AuditEvent]:
    async with UnitOfWork(app.state.session_factory) as uow:
        rows = await uow.audit.list(org_id, limit=200)
    return [row for row in rows if row.action == DENIED_ACTION]


async def test_a_create_at_the_per_key_cap_is_audited_as_create_refused(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, admin_key: str
) -> None:
    body = {
        "name": "student",
        "scopes": [scope.value for scope in SANDBOX_SCOPES],
        "sandbox_labels": LABELS,
        "max_sandboxes": CAP,
    }
    minted = await client.post(KEYS, json=body, headers=bearer(admin_key))
    student = str(minted.json()["data"]["key"])
    student_id = str(minted.json()["data"]["id"])
    first = await client.post(SANDBOXES, json={}, headers=bearer(student))
    assert first.status_code == 201, first.text

    refused = await client.post(SANDBOXES, json={}, headers=bearer(student))

    assert refused.status_code == 429
    assert refused.json()["error"]["code"] == "QUOTA_EXCEEDED"
    assert await denials(app, org_id) == []  # r65: no request.denied next to it
    async with UnitOfWork(app.state.session_factory) as uow:
        rows = await uow.audit.list(org_id, limit=200)
    (event,) = [row for row in rows if row.action == "sandbox.create_refused"]
    assert event.outcome is AuditOutcome.DENIED
    assert event.actor_id == student_id
    assert event.target_type == "org"
    assert event.target_id == org_id
    assert event.details["limit"] == "key_max_sandboxes"
    assert event.details["max"] == CAP
    assert event.details["current"] == CAP
    assert event.details["reason"] == "key_cap"


async def test_an_org_quota_429_is_still_audited_as_request_denied(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, admin_key: str
) -> None:
    """Only the key cap moved to ``sandbox.create_refused``; other quota 429s stay as they were."""
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.quotas.upsert_limits(org_id, OrgQuota(max_sandboxes=0), NOW)
        await uow.commit()

    refused = await client.post(SANDBOXES, json={}, headers=bearer(admin_key))

    assert refused.status_code == 429
    (event,) = await denials(app, org_id)
    assert event.details["error_code"] == "QUOTA_EXCEEDED"


async def test_a_rate_limited_429_is_not_audited(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, admin_key: str
) -> None:
    limiter = TokenBucketRateLimiter(FrozenClock(NOW), refill_per_s=1, burst=TINY_BURST)
    install_rate_limit(app, limiter)

    statuses = []
    for _ in range(TINY_BURST + 1):
        response = await client.get(SANDBOXES, headers=bearer(admin_key))
        statuses.append(response.status_code)

    assert statuses == [200] * TINY_BURST + [429]
    assert response.json()["error"]["code"] == "RATE_LIMITED"
    assert await denials(app, org_id) == []
