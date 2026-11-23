"""WP 3.2 snapshots over the FakeDriver and the ASGI app (daemon-free).

A temp SQLite database migrated to head. The ``snapshot.create`` job is driven by the app's
own runner (``run_once``) or by calling the registered handler, never by a background loop.
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
from sandfort.clock import SystemClock
from sandfort.config import Settings
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import AuditEvent, AuditOutcome
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import SandboxState
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id, new_snapshot_id
from sandfort.services.snapshots import MAX_LAYER_COUNT, SNAPSHOT_CREATE
from sandfort.workers.handlers import DEFAULT_REGISTRY, JobContext

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SNAPSHOTS = "/v1/snapshots"
SANDBOXES = "/v1/sandboxes"
REGISTRY_IMAGE = "alpine:3.20"
FULL_ACCESS = frozenset(
    {Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.SNAPSHOTS_READ, Scope.SNAPSHOTS_WRITE}
)


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'snapshots.db'}"
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
def driver(app: FastAPI) -> FakeDriver:
    fake = app.state.driver
    assert isinstance(fake, FakeDriver)
    return fake


async def add_org(app: FastAPI, slug: str) -> str:
    org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def seed_key(app: FastAPI, org_id: str) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=FULL_ACCESS,
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
    return await seed_key(app, org_id)


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def error_code(response: httpx.Response) -> str:
    code: str = response.json()["error"]["code"]
    return code


def without_time(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {name: value for name, value in snapshot.items() if name != "created_at"}


async def call(
    client: httpx.AsyncClient, method: str, path: str, key: str, *, status: int, **kwargs: Any
) -> dict[str, Any]:
    response = await client.request(method, path, headers=auth(key), **kwargs)
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    return body


async def start_sandbox(client: httpx.AsyncClient, key: str, **body: Any) -> dict[str, Any]:
    created = await call(client, "POST", SANDBOXES, key, status=201, json=body)
    data: dict[str, Any] = created["data"]
    assert data["state"] == "started"
    return data


async def register(client: httpx.AsyncClient, key: str, **body: Any) -> dict[str, Any]:
    payload = {"image": REGISTRY_IMAGE, **body}
    created = await call(client, "POST", SNAPSHOTS, key, status=201, json=payload)
    data: dict[str, Any] = created["data"]
    return data


async def snapshot_sandbox(
    client: httpx.AsyncClient, key: str, sandbox_id: str, name: str = "snap"
) -> dict[str, Any]:
    body = {"sandbox_id": sandbox_id, "name": name}
    accepted = await call(client, "POST", f"{SNAPSHOTS}/from-sandbox", key, status=202, json=body)
    data: dict[str, Any] = accepted["data"]
    return data


async def fetch(client: httpx.AsyncClient, key: str, snapshot_id: str) -> dict[str, Any]:
    found = await call(client, "GET", f"{SNAPSHOTS}/{snapshot_id}", key, status=200)
    data: dict[str, Any] = found["data"]
    return data


async def run_jobs(app: FastAPI) -> int:
    """Drive the app's runner until no job is due; returns how many jobs it processed."""
    processed = 0
    while await app.state.job_runner.run_once():
        processed += 1
    return processed


async def run_handler(app: FastAPI, org_id: str, snapshot_id: str) -> None:
    def uow_factory() -> UnitOfWorkPort:
        return UnitOfWork(app.state.session_factory)

    context = JobContext(uow_factory, app.state.driver, SystemClock())
    payload = {"org_id": org_id, "snapshot_id": snapshot_id, "actor_id": None}
    await DEFAULT_REGISTRY.lookup(SNAPSHOT_CREATE)(payload, context)


async def audit_rows(app: FastAPI, org_id: str) -> list[AuditEvent]:
    async with UnitOfWork(app.state.session_factory) as uow:
        return list(await uow.audit.list(org_id, limit=200))


# --- register ----------------------------------------------------------------------


async def test_register_pins_the_digest_and_records_the_layer_count(
    client: httpx.AsyncClient, driver: FakeDriver, key: str
) -> None:
    registered = await register(client, key, name="base")

    assert registered["state"] == "ready"
    assert registered["name"] == "base"
    assert registered["digest"].startswith("sha256:")
    assert registered["image_ref"] == f"alpine@{registered['digest']}"
    assert registered["layer_count"] == 1
    assert registered["source_sandbox_id"] is None
    assert await driver.image_exists(REGISTRY_IMAGE)
    assert without_time(await fetch(client, key, registered["id"])) == without_time(registered)
    listing = await call(client, "GET", SNAPSHOTS, key, status=200)
    assert [item["id"] for item in listing["data"]] == [registered["id"]]


async def test_register_without_a_name_uses_the_reference_and_names_are_unique(
    client: httpx.AsyncClient, key: str
) -> None:
    registered = await register(client, key)
    duplicate = await client.post(SNAPSHOTS, headers=auth(key), json={"image": REGISTRY_IMAGE})

    assert registered["name"] == REGISTRY_IMAGE
    assert duplicate.status_code == 409
    assert error_code(duplicate) == "CONFLICT"


# --- create from a sandbox ------------------------------------------------------------


async def test_create_from_sandbox_enqueues_and_the_job_makes_it_ready(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, key: str, org_id: str
) -> None:
    source = await start_sandbox(client, key)

    pending = await snapshot_sandbox(client, key, source["id"], name="work")

    assert pending["state"] == "pending"
    assert pending["digest"] is None
    assert pending["source_sandbox_id"] == source["id"]
    jobs = (await call(client, "GET", "/v1/jobs", key, status=200))["data"]
    assert [(job["kind"], job["payload"]["snapshot_id"]) for job in jobs] == [
        (SNAPSHOT_CREATE, pending["id"])
    ]

    assert await run_jobs(app) == 1

    ready = await fetch(client, key, pending["id"])
    assert ready["state"] == "ready"
    assert ready["digest"].startswith("sha256:")
    assert ready["layer_count"] == 1
    assert driver.flattened == []
    assert await driver.image_exists(pending["image_ref"])
    done = (await call(client, "GET", "/v1/jobs", key, status=200))["data"]
    assert [job["state"] for job in done] == ["done"]

    await run_handler(app, org_id, pending["id"])  # a retried job changes nothing
    assert await fetch(client, key, pending["id"]) == ready


async def test_sandbox_delete_is_refused_while_its_snapshot_is_pending(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, key: str, org_id: str
) -> None:
    source = await start_sandbox(client, key)
    pending = await snapshot_sandbox(client, key, source["id"])

    refused = await client.delete(f"{SANDBOXES}/{source['id']}", headers=auth(key))

    assert refused.status_code == 409
    assert error_code(refused) == "CONFLICT"
    assert "snapshot" in refused.json()["error"]["message"]
    kept = await call(client, "GET", f"{SANDBOXES}/{source['id']}", key, status=200)
    assert kept["data"]["state"] == "started"
    assert len(await driver.list_managed(org_id=org_id)) == 1

    assert await run_jobs(app) == 1

    assert (await fetch(client, key, pending["id"]))["state"] == "ready"
    deleted = await call(client, "DELETE", f"{SANDBOXES}/{source['id']}", key, status=200)
    assert deleted["data"]["state"] in {"destroying", "destroyed"}


async def test_sandbox_without_a_snapshot_deletes_as_before(
    client: httpx.AsyncClient, driver: FakeDriver, key: str, org_id: str
) -> None:
    source = await start_sandbox(client, key)

    deleted = await call(client, "DELETE", f"{SANDBOXES}/{source['id']}", key, status=200)

    assert deleted["data"]["state"] in {"destroying", "destroyed"}
    assert await driver.list_managed(org_id=org_id) == []


async def test_create_from_an_unknown_sandbox_is_not_found(
    client: httpx.AsyncClient, key: str
) -> None:
    body = {"sandbox_id": "sbx_missing", "name": "nope"}
    response = await client.post(f"{SNAPSHOTS}/from-sandbox", headers=auth(key), json=body)

    assert response.status_code == 404
    assert error_code(response) == "NOT_FOUND"


async def force_sandbox_row(
    app: FastAPI, org_id: str, sandbox_id: str, *, state: SandboxState, keep_ref: bool = True
) -> None:
    """Put the sandbox row into ``state``; ``keep_ref=False`` also drops its ``driver_ref``."""
    async with UnitOfWork(app.state.session_factory) as uow:
        row = await uow.sandboxes.get(org_id, sandbox_id)
        assert row is not None
        changes: dict[str, Any] = {"state": state}
        if not keep_ref:
            changes["driver_ref"] = None
        await uow.sandboxes.update(
            org_id, row.model_copy(update=changes), expected_version=row.version
        )
        await uow.commit()


async def test_a_sandbox_in_error_with_a_container_can_be_snapshotted_for_recovery(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, key: str, org_id: str
) -> None:
    source = await start_sandbox(client, key)
    await force_sandbox_row(app, org_id, source["id"], state=SandboxState.ERROR)

    pending = await snapshot_sandbox(client, key, source["id"], name="rescue")

    assert pending["state"] == "pending"
    assert pending["source_sandbox_id"] == source["id"]
    assert await run_jobs(app) == 1
    ready = await fetch(client, key, pending["id"])
    assert ready["state"] == "ready"
    assert await driver.image_exists(pending["image_ref"])


@pytest.mark.parametrize(
    ("state", "keep_ref"),
    [
        (SandboxState.ERROR, False),
        (SandboxState.DESTROYING, True),
        (SandboxState.DESTROYED, True),
        (SandboxState.CREATING, True),
        (SandboxState.STOPPED, False),
    ],
)
async def test_snapshot_of_an_unsuitable_sandbox_is_refused_with_409(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    state: SandboxState,
    keep_ref: bool,
) -> None:
    source = await start_sandbox(client, key)
    await force_sandbox_row(app, org_id, source["id"], state=state, keep_ref=keep_ref)
    body = {"sandbox_id": source["id"], "name": "nope"}

    response = await client.post(f"{SNAPSHOTS}/from-sandbox", headers=auth(key), json=body)

    assert response.status_code == 409
    assert error_code(response) == "INVALID_STATE"
    assert response.json()["error"]["details"] == {"state": state.value}
    assert "started, stopped or error" in response.json()["error"]["message"]
    assert (await call(client, "GET", SNAPSHOTS, key, status=200))["data"] == []


async def test_error_sandbox_whose_container_vanished_fails_through_the_usual_path(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, key: str, org_id: str
) -> None:
    source = await start_sandbox(client, key)
    pending = await snapshot_sandbox(client, key, source["id"])
    await force_sandbox_row(app, org_id, source["id"], state=SandboxState.ERROR)
    [instance] = await driver.list_managed(org_id=org_id)
    await driver.destroy(instance.ref)

    await run_jobs(app)

    assert (await fetch(client, key, pending["id"]))["state"] == "error"


@pytest.mark.parametrize(
    ("layers", "flattened"), [(MAX_LAYER_COUNT, False), (MAX_LAYER_COUNT + 1, True)]
)
async def test_flatten_runs_exactly_when_the_commit_exceeds_the_layer_cap(
    app: FastAPI,
    client: httpx.AsyncClient,
    driver: FakeDriver,
    key: str,
    org_id: str,
    layers: int,
    flattened: bool,
) -> None:
    driver.commit_layer_count = layers
    source = await start_sandbox(client, key)
    pending = await snapshot_sandbox(client, key, source["id"])

    await run_handler(app, org_id, pending["id"])

    ready = await fetch(client, key, pending["id"])
    assert ready["state"] == "ready"
    assert driver.flattened == ([pending["image_ref"]] if flattened else [])
    assert ready["layer_count"] == (1 if flattened else layers)


async def test_commit_failure_marks_the_snapshot_error_with_the_reason(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, key: str, org_id: str
) -> None:
    source = await start_sandbox(client, key)
    pending = await snapshot_sandbox(client, key, source["id"])
    [instance] = await driver.list_managed(org_id=org_id)
    await driver.destroy(instance.ref)  # the container vanished under the sandbox

    await run_jobs(app)

    assert (await fetch(client, key, pending["id"]))["state"] == "error"
    failures = [
        event
        for event in await audit_rows(app, org_id)
        if event.target_id == pending["id"] and event.outcome is AuditOutcome.ERROR
    ]
    assert [event.action for event in failures] == ["snapshot.create"]
    assert "no such instance" in failures[0].details["reason"]


# --- sandboxes from snapshots and delete ---------------------------------------------------


async def test_sandbox_from_a_snapshot_id_runs_the_pinned_reference(
    client: httpx.AsyncClient, driver: FakeDriver, key: str
) -> None:
    registered = await register(client, key)

    from_snapshot = await start_sandbox(client, key, snapshot=registered["id"])
    from_reference = await start_sandbox(client, key, snapshot="python:3.12")

    pinned = await driver.inspect(f"fake-sf-{from_snapshot['id']}")
    plain = await driver.inspect(f"fake-sf-{from_reference['id']}")
    assert pinned.image == registered["image_ref"]
    assert plain.image == "python:3.12"


async def test_foreign_and_missing_snapshot_ids_are_not_found(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    other_key = await seed_key(app, await add_org(app, "other"))
    foreign = await register(client, other_key)

    for snapshot_id in (foreign["id"], new_snapshot_id()):
        response = await client.post(SANDBOXES, headers=auth(key), json={"snapshot": snapshot_id})
        assert response.status_code == 404
        assert error_code(response) == "NOT_FOUND"
    hidden = await client.get(f"{SNAPSHOTS}/{foreign['id']}", headers=auth(key))
    assert hidden.status_code == 404
    assert (await call(client, "GET", SNAPSHOTS, key, status=200))["data"] == []


async def test_delete_is_refused_while_a_sandbox_uses_the_snapshot(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, key: str
) -> None:
    source = await start_sandbox(client, key)
    pending = await snapshot_sandbox(client, key, source["id"])
    await run_jobs(app)
    user = await start_sandbox(client, key, snapshot=pending["id"])

    refused = await client.delete(f"{SNAPSHOTS}/{pending['id']}", headers=auth(key))

    assert refused.status_code == 409
    assert error_code(refused) == "CONFLICT"
    assert refused.json()["error"]["details"] == {"reason": "in_use", "sandbox_id": user["id"]}
    assert (await fetch(client, key, pending["id"]))["state"] == "ready"

    await call(client, "DELETE", f"{SANDBOXES}/{user['id']}", key, status=200)
    deleted = await call(client, "DELETE", f"{SNAPSHOTS}/{pending['id']}", key, status=200)

    assert deleted["data"]["state"] == "deleting"
    await call(client, "GET", f"{SNAPSHOTS}/{pending['id']}", key, status=404)
    assert not await driver.image_exists(pending["image_ref"])


# --- auth and audit ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", SNAPSHOTS),
        ("POST", SNAPSHOTS),
        ("POST", f"{SNAPSHOTS}/from-sandbox"),
        ("GET", f"{SNAPSHOTS}/snap_whatever"),
        ("DELETE", f"{SNAPSHOTS}/snap_whatever"),
    ],
)
async def test_snapshot_routes_require_authentication(
    client: httpx.AsyncClient, method: str, path: str
) -> None:
    response = await client.request(method, path, json={})

    assert response.status_code == 401


async def test_snapshot_commands_are_audited(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    registered = await register(client, key)
    source = await start_sandbox(client, key)
    pending = await snapshot_sandbox(client, key, source["id"])
    await run_jobs(app)
    await call(client, "DELETE", f"{SNAPSHOTS}/{registered['id']}", key, status=200)

    recorded = {(event.action, event.target_id) for event in await audit_rows(app, org_id)}

    assert {
        ("snapshot.register", registered["id"]),
        ("snapshot.create", pending["id"]),
        ("snapshot.delete", registered["id"]),
    } <= recorded
