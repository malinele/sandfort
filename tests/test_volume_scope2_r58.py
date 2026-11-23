"""Volume label scope, second pass: get and delete, the in-use scan, the filter key charset.

Through the API on the fake driver and a temp SQLite database migrated to head; no network.
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
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
VOLUMES = "/v1/volumes"
SANDBOXES = "/v1/sandboxes"
OK_STATUS = 200
CREATED_STATUS = 201
NOT_FOUND_STATUS = 404
CONFLICT_STATUS = 409
VALIDATION_STATUS = 422
ALL_SCOPES = frozenset(
    {
        Scope.VOLUMES_READ,
        Scope.VOLUMES_WRITE,
        Scope.SANDBOXES_READ,
        Scope.SANDBOXES_WRITE,
        Scope.TOOLBOX,
    }
)
TEAM_A = {"team": "a"}
TEAM_B = {"team": "b"}


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'volume_scope2.db'}"
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
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.fixture
async def org(app: FastAPI) -> Org:
    org = Org(id=new_org_id(), name="VolScope2", slug="vol-scope2", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org


async def make_key(
    app: FastAPI, org: Org, name: str, scope: dict[str, str] | None = None
) -> dict[str, str]:
    generated = generate_api_key(PEPPER)
    key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name=name,
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=ALL_SCOPES,
        sandbox_labels=scope,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(key)
        await uow.commit()
    return {"Authorization": f"Bearer {generated.key}"}


@pytest.fixture
async def headers(app: FastAPI, org: Org) -> dict[str, str]:
    return await make_key(app, org, "open")


@pytest.fixture
async def scoped(app: FastAPI, org: Org) -> dict[str, str]:
    return await make_key(app, org, "scoped", TEAM_A)


async def new_volume(
    client: httpx.AsyncClient, headers: dict[str, str], name: str, labels: dict[str, str]
) -> str:
    response = await client.post(VOLUMES, json={"name": name, "labels": labels}, headers=headers)
    assert response.status_code == CREATED_STATUS, response.text
    volume_id: str = response.json()["data"]["id"]
    return volume_id


# --- get and delete ---------------------------------------------------------------------------


async def test_scoped_get_of_a_foreign_volume_is_not_found(
    client: httpx.AsyncClient, headers: dict[str, str], scoped: dict[str, str]
) -> None:
    foreign = await new_volume(client, headers, "foreign", TEAM_B)
    bare = await new_volume(client, headers, "bare", {})
    own = await new_volume(client, headers, "own", {**TEAM_A, "env": "dev"})

    foreign_get = await client.get(f"{VOLUMES}/{foreign}", headers=scoped)
    bare_get = await client.get(f"{VOLUMES}/{bare}", headers=scoped)
    own_get = await client.get(f"{VOLUMES}/{own}", headers=scoped)
    open_get = await client.get(f"{VOLUMES}/{foreign}", headers=headers)

    assert foreign_get.status_code == NOT_FOUND_STATUS
    assert bare_get.status_code == NOT_FOUND_STATUS
    assert own_get.status_code == OK_STATUS
    assert open_get.status_code == OK_STATUS


async def test_scoped_delete_of_a_foreign_volume_is_not_found_and_keeps_it(
    client: httpx.AsyncClient, headers: dict[str, str], scoped: dict[str, str]
) -> None:
    foreign = await new_volume(client, headers, "foreign", TEAM_B)
    own = await new_volume(client, headers, "own", TEAM_A)

    refused = await client.delete(f"{VOLUMES}/{foreign}", headers=scoped)
    allowed = await client.delete(f"{VOLUMES}/{own}", headers=scoped)
    kept = await client.get(f"{VOLUMES}/{foreign}", headers=headers)

    assert refused.status_code == NOT_FOUND_STATUS, refused.text
    assert allowed.status_code == OK_STATUS, allowed.text
    assert kept.status_code == OK_STATUS


async def test_scoped_delete_is_refused_while_an_out_of_scope_sandbox_mounts_the_volume(
    client: httpx.AsyncClient, headers: dict[str, str], scoped: dict[str, str]
) -> None:
    volume_id = await new_volume(client, headers, "shared", TEAM_A)
    mount = [{"volume_id": volume_id, "mount_path": "/data"}]
    created = await client.post(
        SANDBOXES, json={"labels": TEAM_B, "volumes": mount}, headers=headers
    )
    assert created.status_code == CREATED_STATUS, created.text

    response = await client.delete(f"{VOLUMES}/{volume_id}", headers=scoped)
    kept = await client.get(f"{VOLUMES}/{volume_id}", headers=headers)

    assert response.status_code == CONFLICT_STATUS, response.text
    assert kept.status_code == OK_STATUS


# --- list filter keys -------------------------------------------------------------------------


@pytest.mark.parametrize("key", ['a"b', 'a"]', "a b", "$x", "a'b", "a\\b"])
async def test_a_filter_key_outside_the_label_key_charset_answers_422(
    client: httpx.AsyncClient, headers: dict[str, str], key: str
) -> None:
    await new_volume(client, headers, "tagged", TEAM_A)

    response = await client.get(VOLUMES, params={"label": f"{key}=v"}, headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text


async def test_a_filter_key_inside_the_charset_still_filters(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    await new_volume(client, headers, "dotted", {"app.kubernetes/name": "x"})
    await new_volume(client, headers, "other", TEAM_A)

    query = {"label": "app.kubernetes/name=x"}

    response = await client.get(VOLUMES, params=query, headers=headers)

    assert response.status_code == OK_STATUS, response.text
    assert [item["name"] for item in response.json()["data"]] == ["dotted"]
