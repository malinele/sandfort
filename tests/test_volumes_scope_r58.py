"""Isolation audit M3: volume mounts on sandbox create need volume scopes and no label scope.

Through the API on the fake driver and a temp SQLite database. A mount needs ``volumes:write``
(every mount is read-write); a label-scoped key cannot mount any volume because volumes carry
no labels. An unscoped key with the volume scopes mounts as before.
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
from sandfort.auth.label_scope import set_label_scope
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.errors import Forbidden
from sandfort.ids import new_api_key_id, new_org_id, new_volume_id
from sandfort.services.volumes import (
    MountRequest,
    mount_scopes,
    refuse_label_scoped_mounts,
    resolve_mounts,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
VOLUMES = "/v1/volumes"
SANDBOXES = "/v1/sandboxes"
SANDBOX_SCOPES = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
FULL_ACCESS = SANDBOX_SCOPES | {Scope.VOLUMES_READ, Scope.VOLUMES_WRITE}
TEAM_A = {"team": "a"}


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'volscope.db'}"
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


async def add_key(
    app: FastAPI,
    org_id: str,
    scopes: frozenset[Scope],
    labels: dict[str, str] | None = None,
) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=scopes,
        created_at=NOW,
        sandbox_labels=labels,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def new_volume(client: httpx.AsyncClient, key: str) -> str:
    response = await client.post(VOLUMES, headers=auth(key), json={"name": "data"})
    assert response.status_code == 201, response.text
    volume_id: str = response.json()["data"]["id"]
    return volume_id


async def create_sandbox(client: httpx.AsyncClient, key: str, **body: Any) -> httpx.Response:
    return await client.post(SANDBOXES, headers=auth(key), json=body)


def mounting(volume_id: str) -> list[dict[str, str]]:
    return [{"volume_id": volume_id, "mount_path": "/data"}]


def error(response: httpx.Response) -> dict[str, Any]:
    body: dict[str, Any] = response.json()["error"]
    return body


async def sandbox_count(app: FastAPI, org_id: str) -> int:
    async with UnitOfWork(app.state.session_factory) as uow:
        return len(await uow.sandboxes.list(org_id, limit=200))


# -- scope rule ----------------------------------------------------------------------------


async def test_mount_without_volumes_write_is_forbidden_naming_the_scope(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    admin = await add_key(app, org_id, FULL_ACCESS)
    volume_id = await new_volume(client, admin)
    for scopes in (SANDBOX_SCOPES, SANDBOX_SCOPES | {Scope.VOLUMES_READ}):
        key = await add_key(app, org_id, frozenset(scopes))
        response = await create_sandbox(client, key, volumes=mounting(volume_id))
        assert response.status_code == 403, response.text
        assert error(response)["code"] == "FORBIDDEN"
        assert "volumes:write" in error(response)["message"]
        assert error(response)["details"] == {"missing_scopes": ["volumes:write"]}
    assert await sandbox_count(app, org_id) == 0


async def test_create_without_mounts_needs_no_volume_scope(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    key = await add_key(app, org_id, SANDBOX_SCOPES)
    response = await create_sandbox(client, key)
    assert response.status_code == 201, response.text


async def test_unscoped_key_with_volume_scopes_mounts_unchanged(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    admin = await add_key(app, org_id, FULL_ACCESS)
    volume_id = await new_volume(client, admin)
    response = await create_sandbox(client, admin, volumes=mounting(volume_id))
    assert response.status_code == 201, response.text
    expected = [{**mount, "read_only": False} for mount in mounting(volume_id)]
    assert response.json()["data"]["volumes"] == expected


# -- label scope rule ----------------------------------------------------------------------


async def test_label_scoped_key_cannot_mount_any_volume(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    admin = await add_key(app, org_id, FULL_ACCESS)
    volume_id = await new_volume(client, admin)
    scoped = await add_key(app, org_id, FULL_ACCESS, TEAM_A)
    response = await create_sandbox(client, scoped, labels=TEAM_A, volumes=mounting(volume_id))
    assert response.status_code == 403, response.text
    assert error(response)["code"] == "FORBIDDEN"
    assert "cannot mount volumes" in error(response)["message"]
    assert "team=a" in error(response)["message"]
    assert await sandbox_count(app, org_id) == 0


async def test_label_scoped_refusal_does_not_reveal_whether_a_volume_exists(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    scoped = await add_key(app, org_id, FULL_ACCESS, TEAM_A)
    missing = new_volume_id()
    response = await create_sandbox(client, scoped, labels=TEAM_A, volumes=mounting(missing))
    assert response.status_code == 403, response.text
    assert error(response)["code"] == "FORBIDDEN"


async def test_label_scoped_key_still_creates_without_mounts(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    scoped = await add_key(app, org_id, FULL_ACCESS, TEAM_A)
    response = await create_sandbox(client, scoped, labels=TEAM_A)
    assert response.status_code == 201, response.text


async def test_label_scoped_key_missing_scope_is_reported_first(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    admin = await add_key(app, org_id, FULL_ACCESS)
    volume_id = await new_volume(client, admin)
    scoped = await add_key(app, org_id, SANDBOX_SCOPES, TEAM_A)
    response = await create_sandbox(client, scoped, labels=TEAM_A, volumes=mounting(volume_id))
    assert response.status_code == 403, response.text
    assert error(response)["details"] == {"missing_scopes": ["volumes:write"]}


# -- service helpers -----------------------------------------------------------------------


def test_mount_scopes_need_volumes_write_only_when_mounting() -> None:
    assert mount_scopes([]) == frozenset()
    assert mount_scopes([MountRequest("vol_x", "/data")]) == frozenset({Scope.VOLUMES_WRITE})


def test_refuse_label_scoped_mounts_passes_unscoped_and_empty_requests() -> None:
    refuse_label_scoped_mounts([MountRequest("vol_x", "/data")], None)
    refuse_label_scoped_mounts([], TEAM_A)
    with pytest.raises(Forbidden):
        refuse_label_scoped_mounts([MountRequest("vol_x", "/data")], TEAM_A)


async def test_resolve_mounts_refuses_under_a_label_scope(app: FastAPI, org_id: str) -> None:
    set_label_scope(TEAM_A)
    try:
        async with UnitOfWork(app.state.session_factory) as uow:
            with pytest.raises(Forbidden):
                await resolve_mounts(uow, org_id, [MountRequest("vol_x", "/data")])
    finally:
        set_label_scope(None)
