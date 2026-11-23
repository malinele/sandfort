"""Round 64: the ``volume.create`` audit row records the labels (and the size limit when one is
set) next to the name, like ``sandbox.create`` records its mounts."""

from collections.abc import AsyncIterator, Callable
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
from sandfort.domain.events import AuditEvent
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
VOLUMES = "/v1/volumes"
LIMIT = 4096
LABELS = {"team": "infra", "env": "ci"}
AppFactory = Callable[[int], FastAPI]


@pytest.fixture
async def make_app(tmp_path: Path) -> AsyncIterator[Callable[..., Any]]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    built: list[FastAPI] = []

    async def build(max_bytes: int = 0) -> FastAPI:
        url = f"sqlite+aiosqlite:///{tmp_path / f'audit{max_bytes}.db'}"
        config = Config(str(ROOT / "alembic.ini"))
        config.set_main_option("sqlalchemy.url", url)
        command.upgrade(config, "head")
        application = create_app(
            Settings(
                driver="fake", database_url=url, api_key_pepper=PEPPER, volume_max_bytes=max_bytes
            )
        )
        built.append(application)
        return application

    yield build
    for application in built:
        await application.state.engine.dispose()


async def seed(app: FastAPI) -> tuple[str, str]:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset({Scope.VOLUMES_READ, Scope.VOLUMES_WRITE}),
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored)
        await uow.commit()
    return org.id, generated.key


async def create_event(app: FastAPI, org_id: str, key: str, body: dict[str, Any]) -> AuditEvent:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        response = await http.post(VOLUMES, json=body, headers={"Authorization": f"Bearer {key}"})
    assert response.status_code == 201, response.text
    volume_id = response.json()["data"]["id"]
    async with UnitOfWork(app.state.session_factory) as uow:
        rows = list(await uow.audit.list(org_id, limit=200))
    return next(
        row for row in rows if row.action == "volume.create" and row.target_id == volume_id
    )


async def test_the_create_row_carries_the_name_and_the_labels(
    make_app: Callable[..., Any],
) -> None:
    app = await make_app()
    org_id, key = await seed(app)

    event = await create_event(app, org_id, key, {"name": "cache", "labels": LABELS})

    assert event.details["name"] == "cache"
    assert event.details["labels"] == LABELS
    assert "max_bytes" not in event.details


async def test_a_volume_without_labels_records_an_empty_label_map(
    make_app: Callable[..., Any],
) -> None:
    app = await make_app()
    org_id, key = await seed(app)

    event = await create_event(app, org_id, key, {"name": "plain"})

    assert event.details["labels"] == {}


async def test_the_create_row_records_the_size_limit_when_one_is_set(
    make_app: Callable[..., Any],
) -> None:
    app = await make_app(LIMIT)
    org_id, key = await seed(app)

    event = await create_event(app, org_id, key, {"name": "capped", "labels": LABELS})

    assert event.details["max_bytes"] == LIMIT
    assert event.details["labels"] == LABELS
