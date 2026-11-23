"""Sandbox reset: a fresh container for the same sandbox, over the fake driver and ASGI app.

The server tests run on a temp SQLite database. The SDK and CLI tests only check that they call
the route (respx-mocked), like the other SDK and CLI suites.
"""

import inspect
import io
import json
import sys
import tarfile
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from sandfort_cli import config as cli_config  # noqa: E402
from sandfort_cli.main import create_app as create_cli  # noqa: E402
from sandfort_sdk import AsyncClient, AsyncSandbox, Client, Sandbox  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

from sandfort.api.app import create_app  # noqa: E402
from sandfort.auth.api_keys import generate_api_key  # noqa: E402
from sandfort.config import Settings  # noqa: E402
from sandfort.db.unit_of_work import UnitOfWork  # noqa: E402
from sandfort.domain.org import ApiKey, Org, Scope  # noqa: E402
from sandfort.domain.sandbox import Sandbox as SandboxRow  # noqa: E402
from sandfort.domain.sandbox import SandboxState  # noqa: E402
from sandfort.drivers.base import InstanceInfo, SandboxSpec  # noqa: E402
from sandfort.drivers.errors import DriverError, DriverNotFound  # noqa: E402
from sandfort.drivers.fake import FakeDriver  # noqa: E402
from sandfort.ids import new_api_key_id, new_org_id  # noqa: E402

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
VOLUMES = "/v1/volumes"
AUDIT = "/v1/audit-events"
QUOTA = "/v1/org/quota"
FULL_ACCESS = frozenset(
    {
        Scope.SANDBOXES_READ,
        Scope.SANDBOXES_WRITE,
        Scope.TOOLBOX,
        Scope.VOLUMES_READ,
        Scope.VOLUMES_WRITE,
        Scope.AUDIT_READ,
        Scope.ORG_READ,
    }
)
WORK_FILE = "/work/poison.txt"
MOUNT = "/data"
LABELS = {"team": "a", "run": "7"}
RESOURCES = {"cpu_millicores": 500, "memory_mib": 256, "disk_gib": 2}
ENV = {"MODE": "eval"}
MISSING_ID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"

BASE = "http://sandfort.test"
KEY = "sf_test_key"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOX_URL = f"{SANDBOXES}/{SID}"
RESET_URL = f"{SANDBOX_URL}/reset"


# --- server fixtures and helpers ------------------------------------------------------------


def make_app(tmp_path: Path, **overrides: Any) -> FastAPI:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'reset.db'}"
    alembic = Config(str(ROOT / "alembic.ini"))
    alembic.set_main_option("sqlalchemy.url", url)
    command.upgrade(alembic, "head")
    settings = Settings(driver="fake", database_url=url, api_key_pepper=PEPPER, **overrides)
    return create_app(settings)


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    application = make_app(tmp_path)
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


async def add_org(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def add_key(
    app: FastAPI,
    org_id: str,
    labels: dict[str, str] | None = None,
    scopes: frozenset[Scope] = FULL_ACCESS,
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


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    return await add_org(app)


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await add_key(app, org_id)


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def send(
    client: httpx.AsyncClient, method: str, path: str, token: str, *, status: int, **kwargs: Any
) -> dict[str, Any]:
    response = await client.request(method, path, headers=auth(token), **kwargs)
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    return body


async def create_sandbox(client: httpx.AsyncClient, token: str, **body: Any) -> dict[str, Any]:
    created = await send(client, "POST", SANDBOXES, token, status=201, json=body)
    data: dict[str, Any] = created["data"]
    assert data["state"] == "started", data
    return data


async def reset(
    client: httpx.AsyncClient, token: str, sandbox_id: str, *, status: int = 200
) -> dict[str, Any]:
    return await send(client, "POST", f"{SANDBOXES}/{sandbox_id}/reset", token, status=status)


async def get_state(client: httpx.AsyncClient, token: str, sandbox_id: str) -> str:
    fetched = await send(client, "GET", f"{SANDBOXES}/{sandbox_id}", token, status=200)
    state: str = fetched["data"]["state"]
    return state


async def ref_of(driver: FakeDriver, sandbox_id: str) -> str:
    matches = [item.ref for item in await driver.list_managed() if item.sandbox_id == sandbox_id]
    assert len(matches) == 1, matches
    return matches[0]


def tar_of(name: str, content: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        member = tarfile.TarInfo(name)
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    return buffer.getvalue()


async def write_file(driver: FakeDriver, ref: str, path: str, content: bytes) -> None:
    directory, _, name = path.rpartition("/")

    async def chunks() -> AsyncIterator[bytes]:
        yield tar_of(name, content)

    await driver.put_archive(ref, directory or "/", chunks())


async def has_file(driver: FakeDriver, ref: str, path: str) -> bool:
    try:
        return bool([chunk async for chunk in driver.get_archive(ref, path)])
    except DriverNotFound:
        return False


async def force_state(app: FastAPI, org_id: str, sandbox_id: str, state: SandboxState) -> None:
    async with UnitOfWork(app.state.session_factory) as uow:
        current = await uow.sandboxes.get(org_id, sandbox_id)
        assert current is not None
        saved = current.model_copy(update={"state": state})
        await uow.sandboxes.update(org_id, saved, expected_version=current.version)
        await uow.commit()


# --- reset on a started sandbox -------------------------------------------------------------


async def test_a_file_written_before_the_reset_is_gone_after_it(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox = await create_sandbox(client, key)
    await write_file(driver, await ref_of(driver, sandbox["id"]), WORK_FILE, b"planted")

    await reset(client, key, sandbox["id"])

    assert not await has_file(driver, await ref_of(driver, sandbox["id"]), WORK_FILE)


async def test_reset_keeps_id_name_labels_resources_isolation_and_timers(
    client: httpx.AsyncClient, key: str
) -> None:
    before = await create_sandbox(
        client,
        key,
        name="worker-1",
        labels=LABELS,
        resources=RESOURCES,
        env=ENV,
        auto_stop_minutes=30,
        auto_delete_minutes=120,
        network={"block_all": True},
    )

    after = (await reset(client, key, before["id"]))["data"]

    assert after["state"] == "started"
    for field in (
        "id",
        "name",
        "labels",
        "resources",
        "env",
        "isolation",
        "network",
        "auto_stop_minutes",
        "auto_delete_minutes",
        "public",
    ):
        assert after[field] == before[field], field
    assert (after["name"], after["labels"], after["resources"]) == ("worker-1", LABELS, RESOURCES)


async def test_the_new_container_is_running_and_has_the_same_spec(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox = await create_sandbox(client, key, resources=RESOURCES, env=ENV)
    old = await driver.inspect(await ref_of(driver, sandbox["id"]))

    await reset(client, key, sandbox["id"])

    new = await driver.inspect(await ref_of(driver, sandbox["id"]))
    assert new.state.value == "running"
    assert (new.image, new.resources) == (old.image, old.resources)
    assert new.created_at >= old.created_at


async def test_reset_keeps_files_on_a_mounted_volume(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    volume = (await send(client, "POST", VOLUMES, key, status=201, json={"name": "data"}))["data"]
    mounts = [{"volume_id": volume["id"], "mount_path": MOUNT}]
    sandbox = await create_sandbox(client, key, volumes=mounts)
    ref = await ref_of(driver, sandbox["id"])
    await write_file(driver, ref, f"{MOUNT}/keep.txt", b"kept")
    await write_file(driver, ref, WORK_FILE, b"planted")

    after = (await reset(client, key, sandbox["id"]))["data"]

    new_ref = await ref_of(driver, sandbox["id"])
    assert after["volumes"] == [{**mount, "read_only": False} for mount in mounts]
    assert await has_file(driver, new_ref, f"{MOUNT}/keep.txt")
    assert not await has_file(driver, new_ref, WORK_FILE)


async def test_reset_writes_one_audit_row(
    client: httpx.AsyncClient, driver: FakeDriver, key: str
) -> None:
    sandbox = await create_sandbox(client, key)
    old_ref = await ref_of(driver, sandbox["id"])

    await reset(client, key, sandbox["id"])

    params = {"action": "sandbox.reset", "target_id": sandbox["id"]}
    listed = await send(client, "GET", AUDIT, key, status=200, params=params)
    [row] = listed["data"]
    assert (row["action"], row["target_type"], row["target_id"]) == (
        "sandbox.reset",
        "sandbox",
        sandbox["id"],
    )
    assert row["details"] == {"state": "started", "previous_driver_ref": old_ref}


async def test_reset_neither_stops_the_sandbox_nor_changes_the_quota(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox = await create_sandbox(client, key, resources=RESOURCES)
    before = (await send(client, "GET", QUOTA, key, status=200))["data"]

    await reset(client, key, sandbox["id"])

    after = (await send(client, "GET", QUOTA, key, status=200))["data"]
    assert after == before
    stops = await send(client, "GET", AUDIT, key, status=200, params={"action": "sandbox.stop"})
    assert stops["data"] == []
    assert await get_state(client, key, sandbox["id"]) == "started"


# --- reset on a stopped sandbox -------------------------------------------------------------


async def test_a_stopped_sandbox_stays_stopped_and_starts_clean(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox = await create_sandbox(client, key, labels=LABELS)
    await write_file(driver, await ref_of(driver, sandbox["id"]), WORK_FILE, b"planted")
    await send(client, "POST", f"{SANDBOXES}/{sandbox['id']}/stop", key, status=200)

    after = (await reset(client, key, sandbox["id"]))["data"]

    assert (after["state"], after["labels"]) == ("stopped", LABELS)
    assert await get_state(client, key, sandbox["id"]) == "stopped"
    started = await send(client, "POST", f"{SANDBOXES}/{sandbox['id']}/start", key, status=200)
    assert started["data"]["state"] == "started"
    assert not await has_file(driver, await ref_of(driver, sandbox["id"]), WORK_FILE)


async def test_a_started_sandbox_can_be_reset_twice(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox = await create_sandbox(client, key)

    await reset(client, key, sandbox["id"])
    await write_file(driver, await ref_of(driver, sandbox["id"]), WORK_FILE, b"second")
    await reset(client, key, sandbox["id"])

    assert await get_state(client, key, sandbox["id"]) == "started"
    assert not await has_file(driver, await ref_of(driver, sandbox["id"]), WORK_FILE)


# --- failures and concurrent writers --------------------------------------------------------


async def set_driver_ref(app: FastAPI, org_id: str, sandbox_id: str, ref: str) -> None:
    async with UnitOfWork(app.state.session_factory) as uow:
        current = await uow.sandboxes.get(org_id, sandbox_id)
        assert current is not None
        saved = current.model_copy(update={"driver_ref": ref})
        await uow.sandboxes.update(org_id, saved, expected_version=current.version)
        await uow.commit()


async def stored_row(app: FastAPI, org_id: str, sandbox_id: str) -> SandboxRow:
    async with UnitOfWork(app.state.session_factory) as uow:
        row = await uow.sandboxes.get(org_id, sandbox_id)
    assert row is not None
    return row


async def test_a_create_failure_moves_the_row_to_error_and_audits_it(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = await create_sandbox(client, key)

    async def failing_create(spec: SandboxSpec) -> InstanceInfo:
        raise DriverError("no capacity left on the node")

    monkeypatch.setattr(driver, "create", failing_create)

    body = await reset(client, key, sandbox["id"], status=502)

    assert body["error"]["message"] == "no capacity left on the node"
    row = await stored_row(app, org_id, sandbox["id"])
    assert row.state is SandboxState.ERROR
    assert row.error_reason == "no capacity left on the node"
    params = {"action": "sandbox.reset_failed", "target_id": sandbox["id"]}
    [event] = (await send(client, "GET", AUDIT, key, status=200, params=params))["data"]
    assert event["details"] == {"error": "no capacity left on the node"}
    assert await driver.list_managed() == []  # the old container is gone, none was created


async def test_a_start_failure_leaves_the_row_pointing_at_the_created_container(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = await create_sandbox(client, key)
    created_ref = await ref_of(driver, sandbox["id"])
    await set_driver_ref(app, org_id, sandbox["id"], "fake-sf-stale")  # not the created ref

    async def failing_start(ref: str) -> None:
        raise DriverError("cannot start the container", ref=ref)

    monkeypatch.setattr(driver, "start", failing_start)

    await reset(client, key, sandbox["id"], status=502)

    row = await stored_row(app, org_id, sandbox["id"])
    assert row.driver_ref == created_ref
    assert row.state is SandboxState.ERROR
    params = {"action": "sandbox.reset_failed", "target_id": sandbox["id"]}
    assert len((await send(client, "GET", AUDIT, key, status=200, params=params))["data"]) == 1
    await send(client, "DELETE", f"{SANDBOXES}/{sandbox['id']}", key, status=200)
    assert await driver.list_managed() == []  # delete removed the created container


async def test_a_sandbox_stopped_during_the_reset_loses_the_new_container_and_answers_409(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = await create_sandbox(client, key)
    original_create = driver.create

    async def create_then_stop_concurrently(spec: SandboxSpec) -> InstanceInfo:
        created = await original_create(spec)
        await force_state(app, org_id, sandbox["id"], SandboxState.STOPPED)  # a stop finished
        return created

    monkeypatch.setattr(driver, "create", create_then_stop_concurrently)

    body = await reset(client, key, sandbox["id"], status=409)

    assert body["error"]["code"] == "CONFLICT"
    assert "changed during the reset" in body["error"]["message"]
    assert "stopped" in body["error"]["message"]
    assert await driver.list_managed() == []  # the new container was destroyed
    assert (await stored_row(app, org_id, sandbox["id"])).state is SandboxState.STOPPED
    params = {"action": "sandbox.reset_failed"}
    assert (await send(client, "GET", AUDIT, key, status=200, params=params))["data"] == []


# --- refusals -------------------------------------------------------------------------------


async def test_a_destroyed_sandbox_answers_409_invalid_state(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox = await create_sandbox(client, key)
    await send(client, "DELETE", f"{SANDBOXES}/{sandbox['id']}", key, status=200)

    body = await reset(client, key, sandbox["id"], status=409)

    assert body["error"]["code"] == "INVALID_STATE"
    assert body["error"]["message"] == "illegal sandbox transition: destroyed -> reset"
    assert body["error"]["details"] == {"state": "destroyed", "target": "reset"}


async def test_an_errored_sandbox_answers_409_invalid_state(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str, driver: FakeDriver
) -> None:
    sandbox = await create_sandbox(client, key)
    ref = await ref_of(driver, sandbox["id"])
    await force_state(app, org_id, sandbox["id"], SandboxState.ERROR)

    body = await reset(client, key, sandbox["id"], status=409)

    assert body["error"]["code"] == "INVALID_STATE"
    assert body["error"]["details"]["state"] == "error"
    assert await ref_of(driver, sandbox["id"]) == ref  # the container was not touched


async def test_an_unknown_sandbox_answers_404(client: httpx.AsyncClient, key: str) -> None:
    body = await reset(client, key, MISSING_ID, status=404)

    assert body["error"]["code"] == "NOT_FOUND"


async def test_a_key_without_the_write_scope_answers_403(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    sandbox = await create_sandbox(client, key)
    reader = await add_key(app, org_id, scopes=frozenset({Scope.SANDBOXES_READ}))

    await reset(client, reader, sandbox["id"], status=403)


async def test_a_label_scoped_key_cannot_reset_an_out_of_scope_sandbox(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str, driver: FakeDriver
) -> None:
    scoped = await add_key(app, org_id, {"team": "a"})
    outside = await create_sandbox(client, key, labels={"team": "b"})
    inside = await create_sandbox(client, key, labels={"team": "a"})
    outside_ref = await ref_of(driver, outside["id"])
    await write_file(driver, outside_ref, WORK_FILE, b"theirs")

    body = await reset(client, scoped, outside["id"], status=404)

    assert body["error"]["code"] == "NOT_FOUND"
    assert await has_file(driver, outside_ref, WORK_FILE)  # untouched
    params = {"action": "sandbox.reset"}
    audited = await send(client, "GET", AUDIT, key, status=200, params=params)
    assert audited["data"] == []
    await reset(client, scoped, inside["id"])  # in scope: allowed


async def test_reset_is_refused_in_jobs_mode_with_a_clear_message(tmp_path: Path) -> None:
    application = make_app(tmp_path, sandbox_jobs_enabled=True)
    try:
        org = await add_org(application)
        token = await add_key(application, org)
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            created = await send(http, "POST", SANDBOXES, token, status=201, json={})

            body = await reset(http, token, created["data"]["id"], status=409)

        assert body["error"]["code"] == "CONFLICT"
        assert "jobs" in body["error"]["message"]
    finally:
        await application.state.engine.dispose()


# --- SDK ------------------------------------------------------------------------------------


def sandbox_json(state: str = "started") -> dict[str, Any]:
    return {
        "id": SID,
        "name": "demo",
        "state": state,
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "env": {},
        "labels": {},
        "network": {"block_all": False},
        "public": False,
        "auto_stop_minutes": 15,
        "auto_delete_minutes": -1,
        "error_reason": None,
        "job_id": None,
    }


def envelope(data: object) -> dict[str, object]:
    return {"success": True, "data": data, "error": None, "meta": None}


@pytest.fixture(params=["sync", "async"])
def kind(request: pytest.FixtureRequest) -> str:
    return str(request.param)


async def test_sdk_reset_posts_to_the_route_and_keeps_the_handle(kind: str) -> None:
    with respx.mock(base_url=BASE, assert_all_called=False) as api:
        api.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json("started")))
        route = api.post(RESET_URL).respond(200, json=envelope(sandbox_json("started")))
        if kind == "sync":
            with Client(BASE, KEY) as sync_client:
                sync_sandbox = sync_client.get(SID)
                result: Sandbox | AsyncSandbox = sync_sandbox.reset()
                sandbox: Sandbox | AsyncSandbox = sync_sandbox
        else:
            async with AsyncClient(BASE, KEY) as async_client:
                async_sandbox = await async_client.get(SID)
                result = await async_sandbox.reset()
                sandbox = async_sandbox

    assert route.call_count == 1
    assert route.calls.last.request.headers["authorization"] == f"Bearer {KEY}"
    assert result is sandbox
    assert (sandbox.id, sandbox.state) == (SID, "started")


def test_the_sdk_facades_expose_reset_with_the_right_kind() -> None:
    assert not inspect.iscoroutinefunction(Sandbox.reset)
    assert inspect.iscoroutinefunction(AsyncSandbox.reset)


# --- CLI ------------------------------------------------------------------------------------


@pytest.fixture
def cli_api(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    monkeypatch.setenv(cli_config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(cli_config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(cli_config.API_KEY_ENV, raising=False)
    cli_config.save_profile(BASE, KEY)
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        yield router


def test_cli_sandbox_reset_calls_the_route_and_shows_the_sandbox(cli_api: Any) -> None:
    cli_api.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json()))
    route = cli_api.post(RESET_URL).respond(200, json=envelope(sandbox_json()))

    result = CliRunner().invoke(create_cli(None), ["--json", "sandbox", "reset", SID])

    assert result.exit_code == 0, result.output
    assert route.call_count == 1
    assert json.loads(result.stdout)["id"] == SID


def test_cli_sandbox_reset_reports_the_server_refusal(cli_api: Any) -> None:
    cli_api.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json("error")))
    refusal = {
        "code": "INVALID_STATE",
        "message": "illegal sandbox transition: error -> reset",
        "details": {},
        "request_id": "req_1",
    }
    cli_api.post(RESET_URL).respond(
        409, json={"success": False, "data": None, "error": refusal, "meta": None}
    )

    result = CliRunner().invoke(create_cli(None), ["sandbox", "reset", SID])

    assert result.exit_code != 0
    assert "illegal sandbox transition: error -> reset" in result.output
