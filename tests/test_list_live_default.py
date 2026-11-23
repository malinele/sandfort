"""Sandbox listing hides ``destroyed`` tombstones by default; create requests reject unknown fields.

Daemon-free: the app on the fake driver over a freshly migrated SQLite file, driven through
httpx. Tombstones are seeded straight into the database so a long run of them is cheap.
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
from sandfort.db.repositories.ports import LiveSandboxListing
from sandfort.db.repositories.sandboxes import SqlSandboxRepository
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.ids import SANDBOX, new_api_key_id, new_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
KEYS = "/v1/api-keys"
SCOPES = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.API_KEYS_ADMIN})
TOMBSTONES = 60  # more than one default page (50) of destroyed rows ahead of the live ones
BASE_MS = 1_700_000_000_000  # a later ``start`` sorts later: ids are time-ordered


def ids_from(start: int, count: int) -> list[str]:
    """``count`` valid sandbox ids in ascending order; ``start`` places the group in the order."""
    return [new_id(SANDBOX, now_ms=BASE_MS + start + offset) for offset in range(count)]


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'api.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(driver="fake", database_url=url, api_key_pepper=PEPPER)
    application = create_app(settings)
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


@pytest.fixture
async def headers(app: FastAPI, org_id: str) -> dict[str, str]:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=SCOPES,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return {"Authorization": f"Bearer {generated.key}"}


async def seed(app: FastAPI, org_id: str, ids: list[str], state: SandboxState) -> None:
    """Store one sandbox per id in ``state``; ids order the listing, so callers pick them."""
    deleted_at = NOW if state is SandboxState.DESTROYED else None
    async with UnitOfWork(app.state.session_factory) as uow:
        for sandbox_id in ids:
            await uow.sandboxes.add(
                Sandbox(
                    id=sandbox_id,
                    org_id=org_id,
                    name=f"name-{sandbox_id}",
                    state=state,
                    image_ref="alpine:3.20",
                    driver="fake",
                    created_at=NOW,
                    updated_at=NOW,
                    deleted_at=deleted_at,
                )
            )
        await uow.commit()


async def listed(
    client: httpx.AsyncClient, headers: dict[str, str], **params: Any
) -> tuple[list[str], str | None]:
    response = await client.get(BASE, headers=headers, params=params)
    assert response.status_code == 200, response.text
    body = response.json()
    return [item["id"] for item in body["data"]], body["meta"]["next_cursor"]


@pytest.fixture
async def mixed(app: FastAPI, org_id: str) -> tuple[list[str], list[str]]:
    """Two tombstones, then two live sandboxes (ids sort tombstones first)."""
    gone = ids_from(0, 2)
    live = ids_from(1_000, 2)
    await seed(app, org_id, gone, SandboxState.DESTROYED)
    await seed(app, org_id, live, SandboxState.STOPPED)
    return gone, live


# --- listing ----------------------------------------------------------------------------------


async def test_unfiltered_list_hides_destroyed_tombstones(
    client: httpx.AsyncClient, headers: dict[str, str], mixed: tuple[list[str], list[str]]
) -> None:
    _, live = mixed

    ids, cursor = await listed(client, headers)

    assert ids == live
    assert cursor is None


async def test_state_destroyed_still_returns_the_tombstones(
    client: httpx.AsyncClient, headers: dict[str, str], mixed: tuple[list[str], list[str]]
) -> None:
    gone, _ = mixed

    ids, _ = await listed(client, headers, state="destroyed")

    assert ids == gone


async def test_include_destroyed_returns_tombstones_and_live_rows(
    client: httpx.AsyncClient, headers: dict[str, str], mixed: tuple[list[str], list[str]]
) -> None:
    gone, live = mixed

    ids, _ = await listed(client, headers, include_destroyed="true")

    assert ids == [*gone, *live]


async def test_include_destroyed_false_is_the_default(
    client: httpx.AsyncClient, headers: dict[str, str], mixed: tuple[list[str], list[str]]
) -> None:
    _, live = mixed

    ids, _ = await listed(client, headers, include_destroyed="false")

    assert ids == live


async def test_live_rows_after_many_tombstones_are_on_the_first_page(
    app: FastAPI, org_id: str, client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    await seed(app, org_id, ids_from(0, TOMBSTONES), SandboxState.DESTROYED)
    live = ids_from(1_000, 2)
    await seed(app, org_id, live, SandboxState.STARTED)

    ids, cursor = await listed(client, headers)

    assert ids == live
    assert cursor is None


async def test_cursor_walks_live_rows_across_a_run_of_tombstones(
    app: FastAPI, org_id: str, client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    head = ids_from(0, 1)
    tail = ids_from(10_000, 2)
    await seed(app, org_id, head, SandboxState.STARTED)
    await seed(app, org_id, ids_from(1_000, TOMBSTONES), SandboxState.DESTROYED)
    await seed(app, org_id, tail, SandboxState.STOPPED)

    first, cursor = await listed(client, headers, limit=2)
    assert cursor is not None
    second, cursor = await listed(client, headers, limit=2, cursor=cursor)

    assert first == [head[0], tail[0]]
    assert second == [tail[1]]
    assert cursor is None


async def test_tombstone_run_longer_than_a_scan_page_does_not_hide_live_rows(
    app: FastAPI, org_id: str, client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    await seed(app, org_id, ids_from(0, 450), SandboxState.DESTROYED)
    live = ids_from(10_000, 1)
    await seed(app, org_id, live, SandboxState.STARTED)

    ids, _ = await listed(client, headers)

    assert ids == live


async def test_sql_repository_lists_live_rows_through_list_live(
    app: FastAPI, org_id: str, mixed: tuple[list[str], list[str]]
) -> None:
    _, live = mixed
    async with UnitOfWork(app.state.session_factory) as uow:
        repository = uow.sandboxes
        assert isinstance(repository, SqlSandboxRepository)
        assert isinstance(repository, LiveSandboxListing)

        rows = await repository.list_live(org_id, cursor=live[0], limit=10)
        everything = await repository.list(org_id, limit=10)

    assert [row.id for row in rows] == live[1:]
    assert len(everything) == 4  # ``list`` itself keeps returning tombstones


# --- unknown fields ---------------------------------------------------------------------------


async def test_api_key_create_rejects_an_unknown_field(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    body = {"name": "capped", "scopes": ["sandboxes:read"], "max_sandboxes": 2}

    response = await client.post(KEYS, json=body, headers=headers)

    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert "max_sandboxes" in response.text


async def test_api_key_create_without_unknown_fields_still_succeeds(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    body = {"name": "plain", "scopes": ["sandboxes:read"], "sandbox_labels": {"team": "a"}}

    response = await client.post(KEYS, json=body, headers=headers)

    assert response.status_code == 201, response.text


async def test_sandbox_create_rejects_an_unknown_field(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    response = await client.post(BASE, json={"name": "demo", "gpu": 1}, headers=headers)

    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert "gpu" in response.text
    ids, _ = await listed(client, headers)
    assert ids == []  # nothing was created


async def test_sandbox_create_accepts_every_field_the_sdk_sends(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    body = {
        "name": "full",
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "env": {"A": "b"},
        "labels": {"team": "a"},
        "network": {"block_all": False},
        "auto_stop_minutes": 15,
        "auto_delete_minutes": -1,
        "public": False,
        "volumes": [],
        "egress_allowlist": None,
        "isolation": None,
    }

    response = await client.post(BASE, json=body, headers=headers)

    assert response.status_code == 201, response.text
