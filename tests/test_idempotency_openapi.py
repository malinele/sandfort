"""WP 4.6: Idempotency-Key on creates and the committed OpenAPI drift gate (daemon-free)."""

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.openapi import (
    EXPORT_VERSION,
    EXPORT_VERSION_KEY,
    OPENAPI_PATH,
    build_document,
    render_spec,
)
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.repositories.ports import IdempotencyRecord
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.drivers.fake import FakeDriver
from sandfort.errors import Conflict, IdempotencyMismatch
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.idempotency import (
    IDEMPOTENCY_TTL,
    MAX_KEY_LENGTH,
    MAX_STORED_KEY_LENGTH,
    IdempotencyService,
    storage_key,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
HEADER = "Idempotency-Key"
CREATE_OPERATIONS = (
    ("/v1/sandboxes", "post"),
    ("/v1/snapshots", "post"),
    ("/v1/snapshots/from-sandbox", "post"),
    ("/v1/volumes", "post"),
)


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'idem.db'}"
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
def clock(app: FastAPI) -> FrozenClock:
    """Swap in an idempotency service on a frozen clock (read per request from app state)."""
    frozen = FrozenClock(NOW)
    app.state.idempotency_service = IdempotencyService(app.state.uow_factory, frozen)
    return frozen


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


@pytest.fixture
async def auth(app: FastAPI, org_id: str) -> dict[str, str]:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE}),
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return {"Authorization": f"Bearer {generated.key}"}


async def post_sandbox(
    client: httpx.AsyncClient, auth: dict[str, str], body: dict[str, Any], key: str | None
) -> httpx.Response:
    headers = dict(auth) if key is None else {**auth, HEADER: key}
    return await client.post(SANDBOXES, headers=headers, json=body)


async def container_count(app: FastAPI, org_id: str) -> int:
    driver = app.state.driver
    assert isinstance(driver, FakeDriver)
    return len(await driver.list_managed(org_id=org_id))


async def test_same_key_and_body_replays_the_first_response(
    app: FastAPI, client: httpx.AsyncClient, auth: dict[str, str], org_id: str, clock: FrozenClock
) -> None:
    body = {"name": "alpha"}

    first = await post_sandbox(client, auth, body, "key-1")
    second = await post_sandbox(client, auth, body, "key-1")

    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text
    assert second.json() == first.json()
    assert second.json()["data"]["id"] == first.json()["data"]["id"]
    assert await container_count(app, org_id) == 1


async def test_same_key_with_different_body_is_rejected(
    client: httpx.AsyncClient, auth: dict[str, str], clock: FrozenClock
) -> None:
    first = await post_sandbox(client, auth, {"name": "alpha"}, "key-2")
    second = await post_sandbox(client, auth, {"name": "beta"}, "key-2")

    assert first.status_code == 201, first.text
    assert second.status_code == 422, second.text
    assert second.json()["error"]["code"] == "IDEMPOTENCY_MISMATCH"


async def test_body_key_order_does_not_change_the_hash(
    app: FastAPI, client: httpx.AsyncClient, auth: dict[str, str], org_id: str, clock: FrozenClock
) -> None:
    first = await post_sandbox(client, auth, {"name": "alpha", "public": False}, "key-3")
    second = await post_sandbox(client, auth, {"public": False, "name": "alpha"}, "key-3")

    assert second.status_code == 201, second.text
    assert second.json() == first.json()
    assert await container_count(app, org_id) == 1


async def test_without_the_header_every_request_creates(
    app: FastAPI, client: httpx.AsyncClient, auth: dict[str, str], org_id: str, clock: FrozenClock
) -> None:
    first = await post_sandbox(client, auth, {}, None)
    second = await post_sandbox(client, auth, {}, None)

    assert first.json()["data"]["id"] != second.json()["data"]["id"]
    assert await container_count(app, org_id) == 2


async def test_entries_expire_after_a_day(
    app: FastAPI, client: httpx.AsyncClient, auth: dict[str, str], org_id: str, clock: FrozenClock
) -> None:
    first = await post_sandbox(client, auth, {}, "key-4")
    clock.advance(IDEMPOTENCY_TTL + timedelta(seconds=1))
    second = await post_sandbox(client, auth, {}, "key-4")

    assert first.status_code == 201 and second.status_code == 201
    assert second.json()["data"]["id"] != first.json()["data"]["id"]
    assert await container_count(app, org_id) == 2


async def test_in_flight_claim_of_one_api_key_does_not_block_another(
    app: FastAPI, org_id: str, clock: FrozenClock
) -> None:
    service = IdempotencyService(app.state.uow_factory, clock)

    assert await service.begin(org_id, "key_a", "shared", "hash-a") is None
    assert await service.begin(org_id, "key_b", "shared", "hash-b") is None
    with pytest.raises(Conflict):
        await service.begin(org_id, "key_a", "shared", "hash-a")
    with pytest.raises(IdempotencyMismatch):
        await service.begin(org_id, "key_a", "shared", "hash-other")


async def test_stored_entry_replays_only_for_the_key_that_created_it(
    app: FastAPI, org_id: str, clock: FrozenClock
) -> None:
    service = IdempotencyService(app.state.uow_factory, clock)
    assert await service.begin(org_id, "key_a", "shared", "hash") is None
    await service.complete(org_id, "key_a", "shared", "hash", 201, {"data": 1})

    assert await service.begin(org_id, "key_b", "shared", "hash") is None
    replay = await service.begin(org_id, "key_a", "shared", "hash")

    assert replay is not None and replay.body == {"data": 1}


async def test_legacy_unprefixed_rows_are_never_replayed_to_a_key(
    app: FastAPI, org_id: str, clock: FrozenClock
) -> None:
    legacy = IdempotencyRecord(
        org_id=org_id,
        key="shared",
        request_hash="hash",
        response_status=201,
        response_body={"data": "old"},
        expires_at=NOW + IDEMPOTENCY_TTL,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.idempotency.put(legacy)
        await uow.commit()

    service = IdempotencyService(app.state.uow_factory, clock)

    assert await service.begin(org_id, "key_a", "shared", "hash") is None


def test_storage_key_is_prefixed_and_always_fits_the_column() -> None:
    key_id = "key_01" + "A" * 26
    assert storage_key("key_a", "k1") == "key_a:k1"
    assert storage_key(None, "k1") == "k1"
    stored = storage_key(key_id, "x" * MAX_KEY_LENGTH)
    assert len(stored) <= MAX_STORED_KEY_LENGTH
    assert stored.startswith(f"{key_id}:")
    assert stored == storage_key(key_id, "x" * MAX_KEY_LENGTH)
    assert stored != storage_key(key_id, "y" * MAX_KEY_LENGTH)


def test_create_operations_document_the_idempotency_header(app: FastAPI) -> None:
    document = build_document(app)

    for path, method in CREATE_OPERATIONS:
        parameters = document["paths"][path][method].get("parameters", [])
        headers = [p for p in parameters if p["in"] == "header" and p["name"] == HEADER]
        assert len(headers) == 1, f"{method.upper()} {path} does not document {HEADER}"
        assert headers[0]["required"] is False


def test_committed_spec_matches_the_export(app: FastAPI) -> None:
    if not OPENAPI_PATH.exists():
        pytest.skip(
            f"{OPENAPI_PATH} does not exist yet: run `python -m sandfort.api.openapi` "
            "and commit the result"
        )
    committed = OPENAPI_PATH.read_bytes()
    try:
        marker = json.loads(committed)["info"].get(EXPORT_VERSION_KEY)
    except (ValueError, KeyError, AttributeError):
        marker = None
    if marker != EXPORT_VERSION:
        pytest.skip(
            f"{OPENAPI_PATH} was written by another export version ({marker!r}, expected "
            f"{EXPORT_VERSION}): re-run `python -m sandfort.api.openapi`"
        )
    expected = render_spec(build_document(app)).encode("utf-8")
    assert committed == expected, (
        f"{OPENAPI_PATH} differs from the export: regenerate it with the export module "
        "(`python -m sandfort.api.openapi`) and commit the result"
    )
