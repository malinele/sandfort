"""``GET /v1/audit-events/verify?from_id=...``: verify an org's chain from an anchor row on.

An org whose old history holds a fork (written before the chain lock) shows ``ok=false`` on a
full walk forever. From an anchor after the fork the walk proves the rest of the chain: the
anchor's own hash is still checked, only its link to the row before it is trusted.
"""

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from sqlalchemy import text

from sandfort.api.app import create_app
from sandfort.api.routes import audit as audit_routes
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import ActorType
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.audit import AuditRecorder
from sandfort.services.audit_chain import FindingKind, link_hash

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
VERIFY_URL = "/v1/audit-events/verify"
FORGED_PREV = "f" * 64  # a prev_hash pointing at a sibling that lost the race


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'anchor.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(driver="fake", database_url=url, api_key_pepper=PEPPER)
    application = create_app(settings)
    application.include_router(audit_routes.router)
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


async def add_org(app: FastAPI, slug: str) -> str:
    org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def add_key(app: FastAPI, org_id: str) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset({Scope.AUDIT_READ}),
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    return await add_org(app, "acme")


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await add_key(app, org_id)


async def seed_events(app: FastAPI, org_id: str, count: int) -> list[str]:
    """Record ``count`` correctly chained audit rows; return their ids in chain order."""
    recorder = AuditRecorder(FrozenClock(NOW))
    ids: list[str] = []
    for index in range(count):
        async with UnitOfWork(app.state.session_factory) as uow:
            event = await recorder.record(
                uow,
                org_id=org_id,
                actor_type=ActorType.SYSTEM,
                actor_id=None,
                action=f"test.step{index}",
                target_type="thing",
                target_id=f"thing-{index}",
                details={"n": index},
            )
            await uow.commit()
        ids.append(event.id)
    return ids


async def fork_at(app: FastAPI, org_id: str, index: int) -> None:
    """Make row ``index`` link to a hash that is not its predecessor's, as a pre-fix fork did.

    The forked row's own hash and every later link are recomputed, so the only defect in the
    chain is the one broken link into row ``index``.
    """
    async with UnitOfWork(app.state.session_factory) as uow:
        rows = list(await uow.audit.list_chained(org_id, limit=1000))
    prev = FORGED_PREV
    async with app.state.engine.begin() as connection:
        for row in rows[index:]:
            entry_hash = link_hash(prev, row.event)
            await connection.execute(
                text("UPDATE audit_events SET prev_hash = :prev, hash = :hash WHERE id = :id"),
                {"prev": prev, "hash": entry_hash, "id": row.event.id},
            )
            prev = entry_hash


async def verify(
    client: httpx.AsyncClient, key: str, *, status: int = 200, **params: str
) -> dict[str, Any]:
    response = await client.get(
        VERIFY_URL, headers={"Authorization": f"Bearer {key}"}, params=params
    )
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    return body


def kinds(data: dict[str, Any]) -> list[tuple[str, str]]:
    return [(finding["kind"], finding["event_id"]) for finding in data["findings"]]


async def test_an_early_fork_fails_the_full_walk_but_not_a_walk_from_after_it(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    ids = await seed_events(app, org_id, 6)
    await fork_at(app, org_id, 1)

    full = (await verify(client, key))["data"]
    anchored = (await verify(client, key, from_id=ids[2]))["data"]

    assert full["ok"] is False and full["checked"] == 6
    assert kinds(full) == [(FindingKind.LINK_BROKEN.value, ids[1])]
    assert full.get("anchor_id") is None
    assert anchored["ok"] is True and anchored["findings"] == []
    assert anchored["anchor_id"] == ids[2]
    assert anchored["checked"] == 4
    assert (anchored["first_id"], anchored["last_id"]) == (ids[2], ids[-1])
    assert anchored["last_hash"] == full["last_hash"]


async def test_the_anchor_rows_own_link_is_trusted(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    ids = await seed_events(app, org_id, 4)
    await fork_at(app, org_id, 1)

    data = (await verify(client, key, from_id=ids[1]))["data"]

    assert data["ok"] is True and data["checked"] == 3 and data["anchor_id"] == ids[1]


async def test_a_fork_after_the_anchor_is_still_found(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    ids = await seed_events(app, org_id, 6)
    await fork_at(app, org_id, 4)

    data = (await verify(client, key, from_id=ids[2]))["data"]

    assert data["ok"] is False and data["checked"] == 4 and data["anchor_id"] == ids[2]
    assert kinds(data) == [(FindingKind.LINK_BROKEN.value, ids[4])]


async def test_a_tampered_anchor_row_is_still_a_hash_mismatch(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    ids = await seed_events(app, org_id, 4)
    async with app.state.engine.begin() as connection:
        await connection.execute(
            text("UPDATE audit_events SET details = :details WHERE id = :id"),
            {"details": json.dumps({"n": 999}), "id": ids[1]},
        )

    data = (await verify(client, key, from_id=ids[1]))["data"]

    assert data["ok"] is False and data["checked"] == 3
    assert kinds(data) == [(FindingKind.HASH_MISMATCH.value, ids[1])]


async def test_a_page_boundary_after_the_anchor_keeps_the_walk_continuous(
    app: FastAPI,
    client: httpx.AsyncClient,
    org_id: str,
    key: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(audit_routes, "CHAIN_PAGE_SIZE", 2)
    ids = await seed_events(app, org_id, 7)
    await fork_at(app, org_id, 5)

    data = (await verify(client, key, from_id=ids[1]))["data"]

    assert data["checked"] == 6 and data["last_id"] == ids[-1]
    assert kinds(data) == [(FindingKind.LINK_BROKEN.value, ids[5])]


async def test_an_unknown_from_id_is_404(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    ids = await seed_events(app, org_id, 2)

    body = await verify(client, key, status=404, from_id=ids[0] + "x")

    assert body["success"] is False and body["error"]["code"] == "NOT_FOUND"


async def test_another_orgs_event_id_is_404(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    await seed_events(app, org_id, 2)
    other_org = await add_org(app, "other")
    other_ids = await seed_events(app, other_org, 2)

    body = await verify(client, key, status=404, from_id=other_ids[0])

    assert body["success"] is False and body["error"]["code"] == "NOT_FOUND"
