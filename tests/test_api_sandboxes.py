"""API tests for ``/v1/sandboxes``: FakeDriver, temp SQLite database, httpx AsyncClient.

Daemon-free. Every response goes through ``send``, which asserts the envelope shape.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.schemas.sandboxes import sandbox_response
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.isolation import ISOLATION_LABEL
from sandfort.domain.node import DEFAULT_NODE_ID
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import Sandbox
from sandfort.drivers.base import InstanceState
from sandfort.drivers.errors import DriverConflict
from sandfort.drivers.fake import FakeDriver
from sandfort.egress.env import NO_PROXY_VARIABLES, PROXY_VARIABLES
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.sandbox_jobs import Lifecycle
from sandfort.services.sandboxes import MountingLifecycle

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
ERROR_KEYS = {"code", "message", "details", "request_id"}
READ_WRITE = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})


@asynccontextmanager
async def migrated_app(tmp_path: Path, **overrides: Any) -> AsyncIterator[FastAPI]:
    """The app on the fake driver over a freshly migrated SQLite file; ``overrides`` settings."""
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'api.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(
        driver="fake",
        database_url=url,
        api_key_pepper=PEPPER,
        max_sandbox_cpu_millicores=2000,
        max_sandbox_memory_mib=2048,
        max_sandbox_disk_gib=10,
        **overrides,
    )
    application = create_app(settings)
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    async with migrated_app(tmp_path) as application:
        yield application


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


async def seed_key(app: FastAPI, org_id: str, scopes: frozenset[Scope]) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=scopes,
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
    return await seed_key(app, org_id, READ_WRITE)


def assert_envelope(response: httpx.Response) -> dict[str, Any]:
    body: dict[str, Any] = response.json()
    assert set(body) == {"success", "data", "error", "meta"}, body
    if body["success"]:
        assert response.status_code < 400
        assert body["data"] is not None and body["error"] is None
    else:
        assert response.status_code >= 400
        assert body["data"] is None and body["meta"] is None
        assert set(body["error"]) == ERROR_KEYS
        assert body["error"]["code"] and body["error"]["message"]
        assert body["error"]["request_id"]
    return body


async def send(
    client: httpx.AsyncClient,
    method: str,
    path: str,
    key: str | None,
    *,
    status: int,
    **kwargs: Any,
) -> dict[str, Any]:
    headers = {} if key is None else {"Authorization": f"Bearer {key}"}
    response = await client.request(method, path, headers=headers, **kwargs)
    assert response.status_code == status, response.text
    return assert_envelope(response)


async def create(client: httpx.AsyncClient, key: str, **payload: Any) -> dict[str, Any]:
    body = await send(client, "POST", BASE, key, status=201, json=payload)
    data: dict[str, Any] = body["data"]
    return data


# --- happy paths ----------------------------------------------------------------


async def test_create_returns_started_sandbox_and_creates_instance(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox = await create(client, key, name="demo", labels={"team": "a"}, env={"FOO": "bar"})

    assert sandbox["id"].startswith("sbx_")
    assert sandbox["state"] == "started"
    assert sandbox["name"] == "demo"
    assert sandbox["env"] == {"FOO": "***"}
    assert sandbox["resources"] == {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3}
    assert sandbox["node_id"] == DEFAULT_NODE_ID  # the fixture keeps the default local node
    [instance] = await driver.list_managed()
    assert instance.sandbox_id == sandbox["id"]
    assert instance.state is InstanceState.RUNNING


async def test_get_returns_sandbox_and_wait_for_returns_when_reached(
    client: httpx.AsyncClient, key: str
) -> None:
    created = await create(client, key)
    path = f"{BASE}/{created['id']}"

    plain = await send(client, "GET", path, key, status=200)
    waited = await send(client, "GET", path, key, status=200, params={"wait_for": "started"})

    assert plain["data"] == created
    assert plain["data"]["node_id"] == DEFAULT_NODE_ID
    assert waited["data"]["state"] == "started"


async def test_get_surfaces_the_node_a_sandbox_was_placed_on(
    client: httpx.AsyncClient, app: FastAPI, key: str
) -> None:
    sandbox_id = (await create(client, key))["id"]
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.nodes.assign_sandbox(sandbox_id, "node-b")
        await uow.commit()

    body = await send(client, "GET", f"{BASE}/{sandbox_id}", key, status=200)

    assert body["data"]["node_id"] == "node-b"


async def test_stop_start_delete_lifecycle(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = (await create(client, key))["id"]

    stopped = await send(client, "POST", f"{BASE}/{sandbox_id}/stop", key, status=200)
    [exited] = await driver.list_managed()
    started = await send(client, "POST", f"{BASE}/{sandbox_id}/start", key, status=200)
    [running] = await driver.list_managed()
    deleted = await send(client, "DELETE", f"{BASE}/{sandbox_id}", key, status=200)

    assert stopped["data"]["state"] == "stopped"
    assert exited.state is InstanceState.EXITED
    assert started["data"]["state"] == "started"
    assert running.state is InstanceState.RUNNING
    assert deleted["data"]["state"] == "destroyed"
    assert await driver.list_managed() == []


async def test_list_paginates_with_cursor(client: httpx.AsyncClient, key: str) -> None:
    created = [(await create(client, key))["id"] for _ in range(3)]

    first = await send(client, "GET", BASE, key, status=200, params={"limit": 2})
    cursor = first["meta"]["next_cursor"]
    second = await send(client, "GET", BASE, key, status=200, params={"limit": 2, "cursor": cursor})

    assert cursor is not None
    assert [item["id"] for item in first["data"]] == sorted(created)[:2]
    assert [item["id"] for item in second["data"]] == sorted(created)[2:]
    assert second["meta"] == {"next_cursor": None}


async def test_list_filters_by_state_and_label(client: httpx.AsyncClient, key: str) -> None:
    kept = await create(client, key, labels={"team": "a"})
    other = await create(client, key, labels={"team": "b"})
    await send(client, "POST", f"{BASE}/{other['id']}/stop", key, status=200)

    by_label = await send(client, "GET", BASE, key, status=200, params={"label": "team=a"})
    by_state = await send(client, "GET", BASE, key, status=200, params={"state": "stopped"})

    assert [item["id"] for item in by_label["data"]] == [kept["id"]]
    assert [item["id"] for item in by_state["data"]] == [other["id"]]


async def test_patch_updates_labels_and_timers(client: httpx.AsyncClient, key: str) -> None:
    sandbox_id = (await create(client, key, labels={"a": "1"}))["id"]

    patched = await send(
        client,
        "PATCH",
        f"{BASE}/{sandbox_id}",
        key,
        status=200,
        json={"labels": {"b": "2"}, "auto_stop_minutes": 30, "public": True},
    )

    assert patched["data"]["labels"] == {"b": "2"}
    assert patched["data"]["auto_stop_minutes"] == 30
    assert patched["data"]["public"] is True


async def test_driver_failure_marks_sandbox_error(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, monkeypatch: pytest.MonkeyPatch
) -> None:
    sandbox_id = (await create(client, key))["id"]

    async def refuse(ref: str, *, timeout_s: float = 10.0) -> None:
        raise DriverConflict("daemon refused", ref=ref)

    monkeypatch.setattr(driver, "stop", refuse)
    failed = await send(client, "POST", f"{BASE}/{sandbox_id}/stop", key, status=200)

    assert failed["data"]["state"] == "error"
    assert failed["data"]["error_reason"] == "daemon refused"


# --- errors ---------------------------------------------------------------------


@pytest.mark.parametrize("action", ["start", "stop"])
async def test_illegal_transition_yields_409(
    client: httpx.AsyncClient, key: str, action: str
) -> None:
    sandbox_id = (await create(client, key))["id"]
    await send(client, "DELETE", f"{BASE}/{sandbox_id}", key, status=200)

    body = await send(client, "POST", f"{BASE}/{sandbox_id}/{action}", key, status=409)

    assert body["error"]["code"] == "INVALID_STATE"


async def test_delete_of_destroyed_sandbox_is_a_noop(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = (await create(client, key))["id"]
    first = await send(client, "DELETE", f"{BASE}/{sandbox_id}", key, status=200)

    again = await send(client, "DELETE", f"{BASE}/{sandbox_id}", key, status=200)

    assert first["data"]["state"] == "destroyed"
    assert again["data"] == first["data"]
    assert await driver.list_managed() == []


async def test_stop_of_stopped_sandbox_is_a_noop(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = (await create(client, key))["id"]
    first = await send(client, "POST", f"{BASE}/{sandbox_id}/stop", key, status=200)

    again = await send(client, "POST", f"{BASE}/{sandbox_id}/stop", key, status=200)

    assert first["data"]["state"] == "stopped"
    assert again["data"] == first["data"]
    [exited] = await driver.list_managed()
    assert exited.state is InstanceState.EXITED


async def test_start_of_started_sandbox_is_a_noop(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    created = await create(client, key)

    again = await send(client, "POST", f"{BASE}/{created['id']}/start", key, status=200)

    assert created["state"] == "started"
    assert again["data"] == created
    [running] = await driver.list_managed()
    assert running.state is InstanceState.RUNNING


@pytest.mark.parametrize(
    "resources",
    [{"cpu_millicores": 2001}, {"memory_mib": 2049}, {"disk_gib": 11}],
)
async def test_oversize_resources_yield_422(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, resources: dict[str, int]
) -> None:
    body = await send(client, "POST", BASE, key, status=422, json={"resources": resources})

    assert body["error"]["code"] == "UNPROCESSABLE"
    assert body["error"]["details"]["maximum"] == {
        "cpu_millicores": 2000,
        "memory_mib": 2048,
        "disk_gib": 10,
    }
    assert await driver.list_managed() == []


async def test_resources_below_minimum_yield_422(client: httpx.AsyncClient, key: str) -> None:
    payload = {"resources": {"cpu_millicores": 1}}

    body = await send(client, "POST", BASE, key, status=422, json=payload)

    assert body["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.parametrize("name", ["SANDFORT_API_KEY_PEPPER", "sandfort_x"])
async def test_reserved_env_prefix_yields_422(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, name: str
) -> None:
    payload = {"env": {name: "x", "OK": "1"}}

    body = await send(client, "POST", BASE, key, status=422, json=payload)

    assert body["error"]["code"] == "UNPROCESSABLE"
    assert body["error"]["details"] == {"names": [name]}
    assert await driver.list_managed() == []


async def test_duplicate_name_yields_409(client: httpx.AsyncClient, key: str) -> None:
    await create(client, key, name="dup")

    body = await send(client, "POST", BASE, key, status=409, json={"name": "dup"})

    assert body["error"]["code"] == "CONFLICT"


async def test_destroyed_sandbox_name_can_be_reused(client: httpx.AsyncClient, key: str) -> None:
    first = await create(client, key, name="first")
    deleted = await send(client, "DELETE", f"{BASE}/{first['id']}", key, status=200)
    assert deleted["data"]["state"] == "destroyed"

    second = await create(client, key, name="first")

    assert second["name"] == "first"
    assert second["id"] != first["id"]
    assert second["state"] == "started"


async def test_live_duplicate_name_still_conflicts_after_reuse(
    client: httpx.AsyncClient, key: str
) -> None:
    first = await create(client, key, name="again")
    await send(client, "DELETE", f"{BASE}/{first['id']}", key, status=200)
    await create(client, key, name="again")

    body = await send(client, "POST", BASE, key, status=409, json={"name": "again"})

    assert body["error"]["code"] == "CONFLICT"


async def test_unknown_sandbox_and_bad_cursor(client: httpx.AsyncClient, key: str) -> None:
    missing = await send(client, "GET", f"{BASE}/sbx_{'0' * 25}", key, status=404)
    bad_cursor = await send(client, "GET", BASE, key, status=422, params={"cursor": "!!"})

    assert missing["error"]["code"] == "NOT_FOUND"
    assert bad_cursor["error"]["code"] == "VALIDATION_ERROR"
    assert [issue["loc"] for issue in bad_cursor["error"]["details"]["errors"]] == [
        ["query", "cursor"]
    ]


# --- authentication and authorization -------------------------------------------


async def test_missing_or_wrong_key_yields_401(client: httpx.AsyncClient, key: str) -> None:
    tampered = key[:-1] + ("B" if key[-1] == "A" else "A")
    unknown = generate_api_key(PEPPER).key

    for candidate in (None, tampered, unknown, "not-a-key"):
        for method, path in (("GET", BASE), ("POST", BASE), ("GET", f"{BASE}/sbx_x")):
            body = await send(client, method, path, candidate, status=401)
            assert body["error"]["code"] == "UNAUTHORIZED"


async def test_missing_scope_yields_403(
    client: httpx.AsyncClient, app: FastAPI, org_id: str
) -> None:
    reader = await seed_key(app, org_id, frozenset({Scope.SANDBOXES_READ}))
    writer = await seed_key(app, org_id, frozenset({Scope.SANDBOXES_WRITE}))
    sandbox_id = (await create(client, writer))["id"]

    denied_write = await send(client, "POST", BASE, reader, status=403, json={})
    denied_stop = await send(client, "POST", f"{BASE}/{sandbox_id}/stop", reader, status=403)
    denied_read = await send(client, "GET", BASE, writer, status=403)
    allowed = await send(client, "GET", f"{BASE}/{sandbox_id}", reader, status=200)

    assert denied_write["error"]["code"] == "FORBIDDEN"
    assert denied_write["error"]["details"] == {"missing_scopes": ["sandboxes:write"]}
    assert denied_stop["error"]["code"] == "FORBIDDEN"
    assert denied_read["error"]["details"] == {"missing_scopes": ["sandboxes:read"]}
    assert allowed["data"]["id"] == sandbox_id


async def test_other_orgs_sandbox_is_not_found(
    client: httpx.AsyncClient, app: FastAPI, key: str
) -> None:
    sandbox_id = (await create(client, key))["id"]
    outsider = await seed_key(app, await add_org(app, "other"), READ_WRITE)

    body = await send(client, "GET", f"{BASE}/{sandbox_id}", outsider, status=404)

    assert body["error"]["code"] == "NOT_FOUND"


# --- response env ---------------------------------------------------------------


def stored_sandbox(env: dict[str, str]) -> Sandbox:
    return Sandbox(
        id="sbx_env",
        org_id="org_env",
        name="env-box",
        image_ref="alpine:3.20",
        driver="fake",
        env=env,
        created_at=NOW,
        updated_at=NOW,
    )


def test_response_env_hides_injected_proxy_variables() -> None:
    token_url = "http://sbx_env:egress-token@proxy.internal:3128"
    env = {"MY_VAR": "kept"}
    env.update(dict.fromkeys(PROXY_VARIABLES, token_url))
    env.update(dict.fromkeys(NO_PROXY_VARIABLES, "localhost,127.0.0.1"))

    response = sandbox_response(stored_sandbox(env))

    assert response.env == {"MY_VAR": "***"}
    assert not set(PROXY_VARIABLES) & set(response.env)
    assert not set(NO_PROXY_VARIABLES) & set(response.env)
    assert "egress-token" not in response.model_dump_json()


def test_response_env_keeps_every_key_with_a_masked_value() -> None:
    env = {"MY_VAR": "kept", "OTHER": "also kept"}

    response = sandbox_response(stored_sandbox(env))

    assert set(response.env) == set(env)
    assert set(response.env.values()) == {"***"}


async def test_env_value_set_at_create_is_not_in_the_get_response(
    client: httpx.AsyncClient, key: str
) -> None:
    secret = "s3cr3t-value-0123456789"
    created = await create(client, key, env={"MY_SECRET": secret})

    headers = {"Authorization": f"Bearer {key}"}

    response = await client.get(f"{BASE}/{created['id']}", headers=headers)

    assert response.status_code == 200, response.text
    assert secret not in response.text
    assert response.json()["data"]["env"] == {"MY_SECRET": "***"}


async def test_validation_message_names_the_offending_field(
    client: httpx.AsyncClient, key: str
) -> None:
    body = await send(client, "POST", BASE, key, status=422, json={"name": "not a valid name!"})

    error = body["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert error["message"].startswith("request validation failed: body.name: ")
    assert error["details"]["errors"][0]["loc"] == ["body", "name"]


# --- health ---------------------------------------------------------------------


async def test_health_endpoints_need_no_key(client: httpx.AsyncClient) -> None:
    live = await send(client, "GET", "/healthz", None, status=200)
    ready = await send(client, "GET", "/readyz", None, status=200)

    assert live["data"] == {"status": "ok"}
    assert ready["data"] == {"status": "ready"}


# --- isolation tiers ------------------------------------------------------------

ISOLATION = "/v1/isolation"
TIER_MAP = (("container", ""), ("gvisor", "runsc"))


@pytest.fixture
async def tiered_app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    async with migrated_app(tmp_path, isolation_runtimes=TIER_MAP) as application:
        yield application


@pytest.fixture
async def tiered_client(tiered_app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=tiered_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.fixture
async def tiered_org(tiered_app: FastAPI) -> str:
    return await add_org(tiered_app, "tiered")


@pytest.fixture
async def tiered_key(tiered_app: FastAPI, tiered_org: str) -> str:
    return await seed_key(tiered_app, tiered_org, READ_WRITE)


async def stored_row(app: FastAPI, org_id: str, sandbox_id: str) -> Sandbox:
    async with UnitOfWork(app.state.session_factory) as uow:
        sandbox = await uow.sandboxes.get(org_id, sandbox_id)
    assert sandbox is not None
    return sandbox


async def test_create_without_isolation_gets_the_default_tier(
    client: httpx.AsyncClient, app: FastAPI, key: str, org_id: str
) -> None:
    created = await create(client, key, labels={"team": "infra"})

    assert created["isolation"] == "container"
    assert created["labels"] == {"team": "infra"}
    stored = await stored_row(app, org_id, created["id"])
    assert stored.labels == {"team": "infra", ISOLATION_LABEL: "container"}


async def test_create_with_an_offered_tier_records_and_reports_it(
    tiered_client: httpx.AsyncClient, tiered_app: FastAPI, tiered_key: str, tiered_org: str
) -> None:
    created = await create(tiered_client, tiered_key, isolation="gvisor", labels={"a": "1"})
    sandbox_id = created["id"]

    fetched = await send(tiered_client, "GET", f"{BASE}/{sandbox_id}", tiered_key, status=200)
    listed = await send(tiered_client, "GET", BASE, tiered_key, status=200)

    assert created["isolation"] == fetched["data"]["isolation"] == "gvisor"
    assert [item["isolation"] for item in listed["data"]] == ["gvisor"]
    assert created["labels"] == fetched["data"]["labels"] == {"a": "1"}
    row = await stored_row(tiered_app, tiered_org, sandbox_id)
    assert row.labels[ISOLATION_LABEL] == "gvisor"
    assert Lifecycle.spec(row).isolation == "gvisor"  # the job runner's spec
    assert MountingLifecycle.spec(row).isolation == "gvisor"  # the inline create's spec


async def test_create_with_the_default_tier_named_explicitly(
    tiered_client: httpx.AsyncClient, tiered_key: str
) -> None:
    created = await create(tiered_client, tiered_key, isolation="container")

    assert created["isolation"] == "container"


async def test_unavailable_tier_yields_422_with_the_offered_tiers(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    body = await send(client, "POST", BASE, key, status=422, json={"isolation": "gvisor"})

    assert body["error"]["code"] == "UNPROCESSABLE"
    assert body["error"]["message"] == (
        "isolation 'gvisor' is not available here; available: container"
    )
    assert body["error"]["details"] == {"requested": "gvisor", "available": ["container"]}
    assert await driver.list_managed() == []


async def test_unavailable_tier_message_lists_every_offered_tier(
    tiered_client: httpx.AsyncClient, tiered_key: str
) -> None:
    payload = {"isolation": "microvm"}

    body = await send(tiered_client, "POST", BASE, tiered_key, status=422, json=payload)

    assert body["error"]["message"] == (
        "isolation 'microvm' is not available here; available: container, gvisor"
    )
    assert body["error"]["details"] == {
        "requested": "microvm",
        "available": ["container", "gvisor"],
    }


async def test_an_unknown_tier_name_fails_request_validation(
    client: httpx.AsyncClient, key: str
) -> None:
    body = await send(client, "POST", BASE, key, status=422, json={"isolation": "vm"})

    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert body["error"]["details"]["errors"][0]["loc"] == ["body", "isolation"]


async def test_the_isolation_label_cannot_be_set_or_seen_by_users(
    tiered_client: httpx.AsyncClient, tiered_key: str
) -> None:
    spoof = {"labels": {ISOLATION_LABEL: "gvisor"}}
    refused = await send(tiered_client, "POST", BASE, tiered_key, status=422, json=spoof)
    created = await create(tiered_client, tiered_key, isolation="gvisor")
    path = f"{BASE}/{created['id']}"

    patched = await send(
        tiered_client, "PATCH", path, tiered_key, status=200, json={"labels": {"k": "v"}}
    )

    assert ISOLATION_LABEL in refused["error"]["message"]
    assert created["labels"] == {}
    assert patched["data"]["labels"] == {"k": "v"}
    assert patched["data"]["isolation"] == "gvisor"  # replacing user labels keeps the tier


def test_a_sandbox_without_the_label_reports_the_deployment_default() -> None:
    legacy = stored_sandbox({})

    assert sandbox_response(legacy).isolation == "container"
    assert sandbox_response(legacy, "gvisor").isolation == "gvisor"
    assert Lifecycle.spec(legacy).isolation is None  # the driver applies its default


async def test_isolation_without_a_map_offers_only_the_default(
    client: httpx.AsyncClient, key: str
) -> None:
    body = await send(client, "GET", ISOLATION, key, status=200)

    assert body["data"] == {"default": "container", "available": ["container"]}


async def test_isolation_lists_every_tier_of_the_map(
    tiered_client: httpx.AsyncClient, tiered_key: str
) -> None:
    body = await send(tiered_client, "GET", ISOLATION, tiered_key, status=200)

    assert body["data"] == {"default": "container", "available": ["container", "gvisor"]}


async def test_isolation_reports_a_non_container_default(tmp_path: Path) -> None:
    async with migrated_app(
        tmp_path, isolation_runtimes=TIER_MAP, default_isolation="gvisor"
    ) as application:
        reader = await seed_key(application, await add_org(application, "gv"), READ_WRITE)
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            listed = await send(http, "GET", ISOLATION, reader, status=200)
            created = await create(http, reader)

    assert listed["data"] == {"default": "gvisor", "available": ["container", "gvisor"]}
    assert created["isolation"] == "gvisor"


async def test_isolation_needs_the_sandboxes_read_scope(
    client: httpx.AsyncClient, app: FastAPI, org_id: str
) -> None:
    writer = await seed_key(app, org_id, frozenset({Scope.SANDBOXES_WRITE}))
    reader = await seed_key(app, org_id, frozenset({Scope.SANDBOXES_READ}))

    anonymous = await send(client, "GET", ISOLATION, None, status=401)
    denied = await send(client, "GET", ISOLATION, writer, status=403)
    allowed = await send(client, "GET", ISOLATION, reader, status=200)

    assert anonymous["error"]["code"] == "UNAUTHORIZED"
    assert denied["error"]["details"] == {"missing_scopes": ["sandboxes:read"]}
    assert allowed["data"]["default"] == "container"
