"""A label-scoped API key can carry a hard cap on the sandboxes inside its scope.

Through the API on the fake driver and a temp SQLite database. The cap counts the org's
non-destroyed, non-standby sandboxes carrying every scope label, inside the create transaction.
"""

import asyncio
import sqlite3
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.repositories.ports import ScopedSandboxCounting
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.errors import QuotaExceeded
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.events import NoOpEventPublisher, with_sandbox_events
from sandfort.services.label_scope import with_label_scope
from sandfort.services.sandboxes import SandboxService
from sandfort.services.usage import with_usage_metering

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
KEYS = "/v1/api-keys"
SANDBOX_SCOPES = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})
KEY_ADMIN_SCOPES = SANDBOX_SCOPES | {Scope.API_KEYS_ADMIN}
STUDENT = {"student": "ada"}
OTHER = {"student": "bob"}
CAP = 2


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'cap.db'}"
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
    org = Org(id=new_org_id(), name="School", slug="school", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def seed_key(
    app: FastAPI,
    org_id: str,
    scopes: frozenset[Scope],
    labels: dict[str, str] | None = None,
    cap: int | None = None,
) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="seed",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=scopes,
        sandbox_labels=labels,
        max_sandboxes=cap,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


def bearer(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


@pytest.fixture
async def instructor(app: FastAPI, org_id: str) -> str:
    """An unscoped key that may create sandboxes and mint keys."""
    return await seed_key(app, org_id, KEY_ADMIN_SCOPES)


async def mint(client: httpx.AsyncClient, caller: str, **extra: Any) -> httpx.Response:
    body = {"name": "student", "scopes": [s.value for s in SANDBOX_SCOPES], **extra}
    return await client.post(KEYS, json=body, headers=bearer(caller))


@pytest.fixture
async def student(client: httpx.AsyncClient, instructor: str) -> str:
    """A key minted through the API: scoped to student=ada, capped at two sandboxes."""
    created = await mint(client, instructor, sandbox_labels=STUDENT, max_sandboxes=CAP)
    assert created.status_code == 201, created.text
    return str(created.json()["data"]["key"])


async def create(client: httpx.AsyncClient, key: str, **payload: Any) -> httpx.Response:
    return await client.post(SANDBOXES, json=payload, headers=bearer(key))


async def delete(client: httpx.AsyncClient, key: str, sandbox_id: str) -> None:
    response = await client.delete(f"{SANDBOXES}/{sandbox_id}", headers=bearer(key))
    assert response.status_code == 200, response.text


async def fill(client: httpx.AsyncClient, key: str, count: int) -> list[str]:
    ids = []
    for _ in range(count):
        response = await create(client, key)
        assert response.status_code == 201, response.text
        ids.append(str(response.json()["data"]["id"]))
    return ids


# --- the key API ---------------------------------------------------------------------


async def test_create_returns_and_lists_the_cap(
    client: httpx.AsyncClient, instructor: str
) -> None:
    created = await mint(client, instructor, sandbox_labels=STUDENT, max_sandboxes=CAP)
    plain = await mint(client, instructor, sandbox_labels=STUDENT)
    listed = await client.get(KEYS, headers=bearer(instructor))

    assert created.json()["data"]["max_sandboxes"] == CAP
    assert plain.json()["data"]["max_sandboxes"] is None
    caps = {item["id"]: item["max_sandboxes"] for item in listed.json()["data"]}
    assert caps[created.json()["data"]["id"]] == CAP


@pytest.mark.parametrize("labels", [None, {}], ids=["absent", "empty"])
async def test_a_cap_without_labels_is_422_with_a_clear_message(
    client: httpx.AsyncClient, instructor: str, labels: dict[str, str] | None
) -> None:
    extra: dict[str, Any] = {"max_sandboxes": CAP}
    if labels is not None:
        extra["sandbox_labels"] = labels

    response = await mint(client, instructor, **extra)

    assert response.status_code == 422
    assert "max_sandboxes requires a non-empty sandbox_labels" in response.text
    assert "label scope" in response.text


@pytest.mark.parametrize("cap", [0, -1, 1001])
async def test_a_cap_outside_one_to_a_thousand_is_422(
    client: httpx.AsyncClient, instructor: str, cap: int
) -> None:
    response = await mint(client, instructor, sandbox_labels=STUDENT, max_sandboxes=cap)

    assert response.status_code == 422


@pytest.mark.parametrize("cap", [1, 1000])
async def test_the_bounds_of_the_cap_are_accepted(
    client: httpx.AsyncClient, instructor: str, cap: int
) -> None:
    response = await mint(client, instructor, sandbox_labels=STUDENT, max_sandboxes=cap)

    assert response.status_code == 201
    assert response.json()["data"]["max_sandboxes"] == cap


async def test_a_capped_creator_cannot_mint_an_uncapped_or_larger_key(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    capped_admin = await seed_key(app, org_id, KEY_ADMIN_SCOPES, STUDENT, CAP)

    uncapped = await mint(client, capped_admin, sandbox_labels=STUDENT)
    larger = await mint(client, capped_admin, sandbox_labels=STUDENT, max_sandboxes=CAP + 1)
    same = await mint(client, capped_admin, sandbox_labels=STUDENT, max_sandboxes=CAP)
    smaller = await mint(client, capped_admin, sandbox_labels=STUDENT, max_sandboxes=1)

    assert uncapped.status_code == 403
    assert larger.status_code == 403
    assert "at most 2" in uncapped.text
    assert same.status_code == 201
    assert smaller.status_code == 201


@pytest.mark.parametrize("cap", [1, CAP])
async def test_a_capped_creator_cannot_mint_a_key_with_extra_label_pairs(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, cap: int
) -> None:
    capped_admin = await seed_key(app, org_id, KEY_ADMIN_SCOPES, STUDENT, CAP)
    wider = {**STUDENT, "x": "1"}
    response = await mint(client, capped_admin, sandbox_labels=wider, max_sandboxes=cap)
    assert response.status_code == 403
    error = response.json()["error"]
    assert error["details"]["sandbox_labels"] == STUDENT
    assert "exactly" in error["message"]
    assert "student=ada" in error["message"]


async def test_a_child_with_the_creators_labels_shares_the_creators_cap(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    capped_admin = await seed_key(app, org_id, KEY_ADMIN_SCOPES, STUDENT, CAP)
    child = await mint(client, capped_admin, sandbox_labels=STUDENT, max_sandboxes=CAP)
    await fill(client, str(child.json()["data"]["key"]), CAP)
    assert (await create(client, capped_admin)).status_code == 429


async def test_an_uncapped_scoped_creator_may_still_narrow_the_scope(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    admin = await seed_key(app, org_id, KEY_ADMIN_SCOPES, STUDENT)
    response = await mint(client, admin, sandbox_labels={**STUDENT, "x": "1"}, max_sandboxes=CAP)
    assert response.status_code == 201


# --- enforcement ----------------------------------------------------------------------


async def test_the_create_past_the_cap_answers_429_with_the_details(
    client: httpx.AsyncClient, student: str
) -> None:
    await fill(client, student, CAP)

    refused = await create(client, student)

    assert refused.status_code == 429
    error = refused.json()["error"]
    assert error["code"] == "QUOTA_EXCEEDED"
    assert error["details"] == {"limit": "key_max_sandboxes", "max": CAP, "current": CAP}
    assert "capped at 2 sandboxes" in error["message"]
    assert "delete a sandbox" in error["message"]


async def test_deleting_a_sandbox_makes_room_for_another(
    client: httpx.AsyncClient, student: str
) -> None:
    first, _second = await fill(client, student, CAP)
    assert (await create(client, student)).status_code == 429

    await delete(client, student, first)

    assert (await create(client, student)).status_code == 201
    assert (await create(client, student)).status_code == 429


async def test_destroyed_rows_do_not_count(client: httpx.AsyncClient, student: str) -> None:
    for sandbox_id in await fill(client, student, CAP):
        await delete(client, student, sandbox_id)

    again = await fill(client, student, CAP)

    assert len(again) == CAP
    assert (await create(client, student)).status_code == 429


async def test_sandboxes_outside_the_scope_do_not_count(
    client: httpx.AsyncClient, student: str, instructor: str
) -> None:
    for _ in range(CAP + 1):
        assert (await create(client, instructor, labels=OTHER)).status_code == 201
        assert (await create(client, instructor)).status_code == 201

    assert len(await fill(client, student, CAP)) == CAP


async def test_sandboxes_in_the_scope_made_by_another_key_count(
    client: httpx.AsyncClient, student: str, instructor: str
) -> None:
    assert (await create(client, instructor, labels=STUDENT)).status_code == 201
    await fill(client, student, CAP - 1)

    assert (await create(client, student)).status_code == 429


async def test_a_scoped_key_without_a_cap_is_not_limited(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    uncapped = await seed_key(app, org_id, SANDBOX_SCOPES, STUDENT)

    assert len(await fill(client, uncapped, CAP + 2)) == CAP + 2


async def test_two_concurrent_creates_at_the_cap_minus_one_let_exactly_one_through(
    client: httpx.AsyncClient, student: str
) -> None:
    await fill(client, student, CAP - 1)

    responses = await asyncio.gather(create(client, student), create(client, student))

    assert sorted(r.status_code for r in responses) == [201, 429]
    refused = next(r for r in responses if r.status_code == 429)
    assert refused.json()["error"]["details"]["current"] == CAP
    live = await client.get(SANDBOXES, headers=bearer(student))
    assert len(live.json()["data"]) == CAP


async def test_many_concurrent_creates_never_exceed_the_cap(
    client: httpx.AsyncClient, student: str
) -> None:
    responses = await asyncio.gather(*(create(client, student) for _ in range(6)))

    assert sorted(r.status_code for r in responses) == [201] * CAP + [429] * (6 - CAP)


# --- storage ---------------------------------------------------------------------------


async def test_the_repository_counts_live_sandboxes_in_a_scope(
    app: FastAPI, client: httpx.AsyncClient, student: str, instructor: str, org_id: str
) -> None:
    ids = await fill(client, student, CAP)
    await create(client, instructor, labels={**STUDENT, "env": "ci"})
    await create(client, instructor, labels=OTHER)
    await delete(client, student, ids[0])

    async with UnitOfWork(app.state.session_factory) as uow:
        assert isinstance(uow.sandboxes, ScopedSandboxCounting)
        assert await uow.sandboxes.count_in_scope(org_id, STUDENT) == CAP
        assert await uow.sandboxes.count_in_scope(org_id, {**STUDENT, "env": "ci"}) == 1
        assert await uow.sandboxes.count_in_scope(org_id, {"student": "nobody"}) == 0


class RecordingRepo:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def count_in_scope(self, org_id: str, labels: Mapping[str, str]) -> int:
        self.calls.append("count_in_scope")
        return CAP

    async def list(self, org_id: str, **_: Any) -> list[Any]:
        self.calls.append("list")
        return []


async def test_the_decorated_repository_counts_in_sql_and_never_lists() -> None:
    repo = RecordingRepo()
    base: Callable[[], Any] = lambda: SimpleNamespace(sandboxes=repo)  # noqa: E731
    stack = with_usage_metering(  # the order SandboxService and the wiring build
        with_sandbox_events(with_label_scope(base), NoOpEventPublisher()), FrozenClock()
    )
    uow = stack()
    assert isinstance(uow.sandboxes, ScopedSandboxCounting)
    with pytest.raises(QuotaExceeded):
        await SandboxService._require_under_key_cap(uow, "org_1", STUDENT, CAP)
    assert repo.calls == ["count_in_scope"]


def column_names(db_path: Path) -> set[str]:
    with closing(sqlite3.connect(db_path)) as connection:
        rows = connection.execute("PRAGMA table_info(api_keys)").fetchall()
    return {row[1] for row in rows}


def test_the_migration_adds_and_drops_the_column(tmp_path: Path) -> None:
    pytest.importorskip("aiosqlite")
    db_path = tmp_path / "migrate.db"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")

    command.upgrade(config, "0015")
    assert "max_sandboxes" not in column_names(db_path)
    command.upgrade(config, "0016")
    assert "max_sandboxes" in column_names(db_path)
    command.downgrade(config, "0015")
    assert "max_sandboxes" not in column_names(db_path)
    assert "sandbox_labels" in column_names(db_path)
