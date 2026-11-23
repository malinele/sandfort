"""``GET /v1/sandboxes?order=asc|desc``: oldest first (default) or newest first.

Through the API on the fake driver and a temp SQLite database. Sandbox ids sort by creation
time (millisecond prefix), so every create is followed by a short pause to keep that order exact.
"""

import asyncio
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
NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
TEAM_A = {"team": "a"}
TEAM_B = {"team": "b"}
ID_TICK_S = 0.005  # more than the one millisecond an id's time prefix resolves


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'order.db'}"
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


async def add_key(app: FastAPI, org_id: str, labels: dict[str, str] | None) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=FULL_ACCESS,
        created_at=NOW,
        sandbox_labels=labels,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await add_key(app, org_id, None)


@pytest.fixture
async def scoped(app: FastAPI, org_id: str) -> str:
    return await add_key(app, org_id, TEAM_A)


async def send(
    client: httpx.AsyncClient, method: str, path: str, api_key: str, *, status: int, **kwargs: Any
) -> dict[str, Any]:
    response = await client.request(
        method, path, headers={"Authorization": f"Bearer {api_key}"}, **kwargs
    )
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    return body


async def create(client: httpx.AsyncClient, api_key: str, **payload: Any) -> str:
    body = await send(client, "POST", BASE, api_key, status=201, json=payload)
    await asyncio.sleep(ID_TICK_S)
    return str(body["data"]["id"])


async def destroy(client: httpx.AsyncClient, api_key: str, sandbox_id: str) -> None:
    await send(client, "DELETE", f"{BASE}/{sandbox_id}", api_key, status=200)


async def page(
    client: httpx.AsyncClient, api_key: str, **params: Any
) -> tuple[list[str], str | None]:
    body = await send(client, "GET", BASE, api_key, status=200, params=params)
    return [item["id"] for item in body["data"]], body["meta"]["next_cursor"]


async def walk(client: httpx.AsyncClient, api_key: str, **params: Any) -> list[list[str]]:
    """Every page, following ``next_cursor`` until it is ``None``."""
    pages: list[list[str]] = []
    cursor: str | None = None
    while True:
        extra = {} if cursor is None else {"cursor": cursor}
        ids, cursor = await page(client, api_key, **params, **extra)
        pages.append(ids)
        if cursor is None:
            return pages


def flat(pages: list[list[str]]) -> list[str]:
    return [item for ids in pages for item in ids]


@pytest.fixture
async def created(client: httpx.AsyncClient, key: str) -> list[str]:
    """Five sandboxes, oldest first; the second and the fourth are destroyed."""
    ids = [await create(client, key) for _ in range(5)]
    await destroy(client, key, ids[1])
    await destroy(client, key, ids[3])
    return ids


async def test_desc_lists_the_newest_sandbox_first(
    client: httpx.AsyncClient, key: str, created: list[str]
) -> None:
    ids, _ = await page(client, key, include_destroyed="true", order="desc")

    assert ids == list(reversed(created))


async def test_desc_without_tombstones_lists_only_live_sandboxes_newest_first(
    client: httpx.AsyncClient, key: str, created: list[str]
) -> None:
    ids, _ = await page(client, key, order="desc")

    assert ids == [created[4], created[2], created[0]]


async def test_desc_with_a_state_filter_returns_the_tombstones_newest_first(
    client: httpx.AsyncClient, key: str, created: list[str]
) -> None:
    ids, _ = await page(client, key, state="destroyed", order="desc")

    assert ids == [created[3], created[1]]


@pytest.mark.parametrize("order", ["asc", "desc"])
async def test_paging_with_limit_two_visits_every_row_once_in_order(
    client: httpx.AsyncClient, key: str, created: list[str], order: str
) -> None:
    expected = created if order == "asc" else list(reversed(created))

    pages = await walk(client, key, include_destroyed="true", order=order, limit=2)

    assert [len(ids) for ids in pages] == [2, 2, 1]
    assert flat(pages) == expected


@pytest.mark.parametrize("order", ["asc", "desc"])
async def test_paging_live_rows_only_visits_every_live_row_once_in_order(
    client: httpx.AsyncClient, key: str, created: list[str], order: str
) -> None:
    live = [created[0], created[2], created[4]]
    expected = live if order == "asc" else list(reversed(live))

    pages = await walk(client, key, order=order, limit=2)

    assert flat(pages) == expected


async def test_default_order_equals_asc(
    client: httpx.AsyncClient, key: str, created: list[str]
) -> None:
    default = await walk(client, key, include_destroyed="true", limit=2)
    explicit = await walk(client, key, include_destroyed="true", limit=2, order="asc")

    assert default == explicit
    assert flat(default) == created


async def test_live_sandbox_is_on_the_first_desc_page_behind_many_tombstones(
    client: httpx.AsyncClient, key: str
) -> None:
    old = [await create(client, key) for _ in range(4)]
    for sandbox_id in old:
        await destroy(client, key, sandbox_id)
    newest = await create(client, key)

    ids, _ = await page(client, key, include_destroyed="true", order="desc", limit=2)

    assert ids == [newest, old[-1]]


async def test_a_bad_order_value_is_a_422(client: httpx.AsyncClient, key: str) -> None:
    for bad in ("newest", "DESC", ""):
        await send(client, "GET", BASE, key, status=422, params={"order": bad})


async def test_a_label_scoped_key_with_desc_sees_only_its_own_sandboxes(
    client: httpx.AsyncClient, key: str, scoped: str
) -> None:
    first = await create(client, scoped)
    await create(client, key, labels=TEAM_B)
    second = await create(client, scoped)
    await create(client, key, labels=TEAM_B)

    live, _ = await page(client, scoped, order="desc")
    with_tombstones, _ = await page(client, scoped, include_destroyed="true", order="desc")
    paged = flat(await walk(client, scoped, order="desc", limit=1))

    assert live == [second, first]
    assert with_tombstones == [second, first]
    assert paged == [second, first]
