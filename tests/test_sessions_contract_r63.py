"""Round 63: the sessions contract, as the persona findings read it.

* An async session command answers 202; the exported spec lists 202 beside the sync 200.
* The stop line in a command's log follows the sandbox's stop cause.
* A session can be deleted (its running commands are killed); the SDK exposes it.
* ``POST .../process/sessions`` honours ``Idempotency-Key``.

Daemon-free: temp SQLite, ``httpx.ASGITransport``, ``FakeDriver`` with scripted exec streams; the
SDK part uses respx.
"""

import asyncio
import inspect
import json
import sys
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from sandfort_sdk import AsyncClient, Client, NotFound  # noqa: E402

from sandfort.api.app import create_app  # noqa: E402
from sandfort.api.openapi import build_document  # noqa: E402
from sandfort.auth.api_keys import generate_api_key  # noqa: E402
from sandfort.config import Settings  # noqa: E402
from sandfort.db.unit_of_work import UnitOfWork  # noqa: E402
from sandfort.domain.org import ApiKey, Org, Scope  # noqa: E402
from sandfort.domain.sandbox import SandboxState  # noqa: E402
from sandfort.drivers.base import (  # noqa: E402
    ExecEvent,
    ExecRequest,
    ExecResult,
    ExitEvent,
    OutputChunk,
)
from sandfort.drivers.docker.exec import SANDBOX_DIED_MESSAGE  # noqa: E402
from sandfort.drivers.fake import FakeDriver  # noqa: E402
from sandfort.errors import IdempotencyMismatch  # noqa: E402
from sandfort.ids import new_api_key_id, new_org_id  # noqa: E402
from sandfort.toolbox import process  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
SESSIONS_SPEC_PATH = "/v1/sandboxes/{sandbox_id}/toolbox/process/sessions"
SESSION_SPEC_PATH = SESSIONS_SPEC_PATH + "/{session_id}"
COMMANDS_SPEC_PATH = SESSION_SPEC_PATH + "/commands"

REQUESTED_LINE = "the sandbox was stopped (requested) while this command ran; start it again"
AUTO_STOP_LINE = "the sandbox was stopped (auto_stop) while this command ran; start it again"
NEUTRAL_LINE = "the sandbox stopped while this command ran"
LIMIT_LINE = SANDBOX_DIED_MESSAGE.decode()


# --- fixtures ---------------------------------------------------------------------


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'contract.db'}"
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


async def add_key(app: FastAPI, org_id: str, scopes: frozenset[Scope]) -> str:
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
async def key(app: FastAPI, org_id: str) -> str:
    return await add_key(app, org_id, FULL_ACCESS)


@pytest.fixture
def driver(app: FastAPI) -> FakeDriver:
    fake = app.state.driver
    assert isinstance(fake, FakeDriver)
    return fake


@dataclass
class Gate:
    """A scripted exec stream: one chunk, wait for ``release``, then the death line and exit."""

    release: asyncio.Event = field(default_factory=asyncio.Event)
    abandoned: bool = False


@pytest.fixture
def gate(driver: FakeDriver, monkeypatch: pytest.MonkeyPatch) -> Gate:
    scripted = Gate()
    plain_stream = driver.exec_stream

    async def stream(ref: str, request: ExecRequest) -> AsyncIterator[ExecEvent]:
        if request.argv[0] != "sh":
            async for event in plain_stream(ref, request):
                yield event
            return
        yield OutputChunk("stdout", b"partial\n")
        try:
            await scripted.release.wait()
        except asyncio.CancelledError:
            scripted.abandoned = True
            raise
        yield OutputChunk("stderr", SANDBOX_DIED_MESSAGE)
        yield ExitEvent(137, sandbox_stopped=True)

    monkeypatch.setattr(driver, "exec_stream", stream)
    return scripted


# --- helpers ----------------------------------------------------------------------


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def send(
    client: httpx.AsyncClient, method: str, path: str, key: str, *, status: int, **kwargs: Any
) -> dict[str, Any]:
    response = await client.request(method, path, headers=auth(key), **kwargs)
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    return body


async def create_sandbox(client: httpx.AsyncClient, key: str) -> str:
    body = await send(client, "POST", BASE, key, status=201, json={})
    sandbox_id: str = body["data"]["id"]
    return sandbox_id


def sessions_path(sandbox_id: str, *parts: str) -> str:
    return "/".join([f"{BASE}/{sandbox_id}/toolbox/process/sessions", *parts])


async def create_session(client: httpx.AsyncClient, key: str, sandbox_id: str) -> str:
    body = await send(client, "POST", sessions_path(sandbox_id), key, status=201, json={})
    session_id: str = body["data"]["id"]
    return session_id


async def start_async(client: httpx.AsyncClient, key: str, sandbox_id: str, session_id: str) -> str:
    body = await send(
        client,
        "POST",
        sessions_path(sandbox_id, session_id, "commands") + "?async=true",
        key,
        status=202,
        json={"command": "sleep 3600"},
    )
    command_id: str = body["data"]["command"]["id"]
    return command_id


async def wait_finished(client: httpx.AsyncClient, key: str, path: str) -> dict[str, Any]:
    for _ in range(300):
        data: dict[str, Any] = (await send(client, "GET", path, key, status=200))["data"]
        if data["state"] != "running":
            return data
        await asyncio.sleep(0.01)
    raise AssertionError("command never finished")


async def audit_actions(app: FastAPI, org_id: str) -> list[str]:
    async with UnitOfWork(app.state.session_factory) as uow:
        events = await uow.audit.list(org_id, limit=500)
    return [event.action for event in events]


async def set_sandbox(app: FastAPI, org_id: str, sandbox_id: str, **changes: Any) -> None:
    async with UnitOfWork(app.state.session_factory) as uow:
        row = await uow.sandboxes.get(org_id, sandbox_id)
        assert row is not None
        await uow.sandboxes.update(
            org_id, row.model_copy(update=changes), expected_version=row.version
        )
        await uow.commit()


@dataclass(frozen=True)
class Running:
    sandbox_id: str
    command_path: str


async def start_running(client: httpx.AsyncClient, key: str) -> Running:
    sandbox_id = await create_sandbox(client, key)
    session_id = await create_session(client, key, sandbox_id)
    command_id = await start_async(client, key, sandbox_id, session_id)
    return Running(sandbox_id, sessions_path(sandbox_id, session_id, "commands", command_id))


async def death_line(client: httpx.AsyncClient, key: str, run: Running) -> str:
    """The text of the last log line once the command has finished."""
    await wait_finished(client, key, run.command_path)
    page = (await send(client, "GET", run.command_path + "/logs", key, status=200))["data"]
    assert page["complete"] is True
    assert [e["stream"] for e in page["events"]] == ["stdout", "stderr"]
    line: str = page["events"][-1]["line"]
    return line


# --- 1: the spec lists 202 for the async shape ------------------------------------


def commands_responses(spec: dict[str, Any]) -> dict[str, Any]:
    responses: dict[str, Any] = spec["paths"][COMMANDS_SPEC_PATH]["post"]["responses"]
    return responses


def test_exported_spec_lists_200_and_202_with_one_response_model(app: FastAPI) -> None:
    responses = commands_responses(build_document(app))

    assert {"200", "202"} <= set(responses)
    ref_200 = responses["200"]["content"]["application/json"]["schema"]
    ref_202 = responses["202"]["content"]["application/json"]["schema"]
    assert ref_200 == ref_202
    assert "async" in responses["202"]["description"].lower()
    assert "mode" in responses["202"]["description"]


async def test_the_live_openapi_json_lists_both_statuses(client: httpx.AsyncClient) -> None:
    spec = (await client.get("/openapi.json")).json()

    assert {"200", "202"} <= set(commands_responses(spec))


async def test_the_sync_shape_still_answers_200_and_the_async_shape_202(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    session_id = await create_session(client, key, sandbox_id)
    path = sessions_path(sandbox_id, session_id, "commands")

    sync = await send(client, "POST", path, key, status=200, json={"command": "true"})
    started = await send(
        client, "POST", path, key, status=202, json={"command": "true", "mode": "async"}
    )

    assert sync["data"]["mode"] == "sync"
    assert started["data"]["mode"] == "async"


# --- 2: the stop line follows the cause -------------------------------------------


async def test_a_requested_stop_says_it_was_requested(
    client: httpx.AsyncClient, key: str, gate: Gate
) -> None:
    run = await start_running(client, key)
    await send(client, "POST", f"{BASE}/{run.sandbox_id}/stop", key, status=200)

    gate.release.set()

    assert await death_line(client, key, run) == REQUESTED_LINE


async def test_an_auto_stop_names_its_cause(
    app: FastAPI, org_id: str, client: httpx.AsyncClient, key: str, gate: Gate
) -> None:
    run = await start_running(client, key)
    await set_sandbox(
        app, org_id, run.sandbox_id, state=SandboxState.STOPPED, stop_cause="auto_stop"
    )

    gate.release.set()

    assert await death_line(client, key, run) == AUTO_STOP_LINE


@pytest.mark.parametrize("cause", ["oom_killed", "container_exited"])
async def test_resource_and_main_process_causes_keep_the_driver_wording(
    app: FastAPI, org_id: str, client: httpx.AsyncClient, key: str, gate: Gate, cause: str
) -> None:
    run = await start_running(client, key)
    await set_sandbox(app, org_id, run.sandbox_id, state=SandboxState.STOPPED, stop_cause=cause)

    gate.release.set()

    assert await death_line(client, key, run) == LIMIT_LINE


async def test_an_unknown_cause_gets_the_neutral_line(
    app: FastAPI, org_id: str, client: httpx.AsyncClient, key: str, gate: Gate
) -> None:
    run = await start_running(client, key)
    await set_sandbox(app, org_id, run.sandbox_id, state=SandboxState.STOPPED, stop_cause=None)

    gate.release.set()

    assert await death_line(client, key, run) == NEUTRAL_LINE


async def test_a_death_while_the_sandbox_still_reads_started_keeps_the_driver_wording(
    client: httpx.AsyncClient, key: str, gate: Gate
) -> None:
    run = await start_running(client, key)

    gate.release.set()

    assert await death_line(client, key, run) == LIMIT_LINE


async def test_the_reworded_line_reaches_followers_and_keeps_offsets_exact(
    client: httpx.AsyncClient, key: str, gate: Gate
) -> None:
    run = await start_running(client, key)
    await send(client, "POST", f"{BASE}/{run.sandbox_id}/stop", key, status=200)
    gate.release.set()
    await wait_finished(client, key, run.command_path)

    response = await client.get(run.command_path + "/logs/follow", headers=auth(key))

    assert REQUESTED_LINE in response.text
    assert LIMIT_LINE not in response.text
    status = (await send(client, "GET", run.command_path, key, status=200))["data"]
    assert status["stderr_bytes"] == len(REQUESTED_LINE.encode())


async def test_a_sync_command_cut_short_by_a_requested_stop_is_reworded(
    app: FastAPI, org_id: str, client: httpx.AsyncClient, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    sandbox_id = await create_sandbox(client, key)
    session_id = await create_session(client, key, sandbox_id)

    async def stopped_mid_command(*args: Any, **kwargs: Any) -> ExecResult:
        await set_sandbox(
            app, org_id, sandbox_id, state=SandboxState.STOPPED, stop_cause="requested"
        )
        return ExecResult(
            exit_code=137, stderr=b"warn\n" + SANDBOX_DIED_MESSAGE, sandbox_stopped=True
        )

    monkeypatch.setattr(process, "execute", stopped_mid_command)

    body = await send(
        client,
        "POST",
        sessions_path(sandbox_id, session_id, "commands"),
        key,
        status=200,
        json={"command": "sleep 3600"},
    )

    assert body["data"]["result"]["stderr"] == f"warn\n{REQUESTED_LINE}"


# --- 3: deleting a session --------------------------------------------------------


async def test_delete_frees_the_session_and_a_second_delete_is_404(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    session_id = await create_session(client, key, sandbox_id)
    other = await create_session(client, key, sandbox_id)

    deleted = await send(client, "DELETE", sessions_path(sandbox_id, session_id), key, status=200)

    assert deleted["data"]["id"] == session_id
    assert deleted["data"]["state"] == "closed"
    await send(client, "GET", sessions_path(sandbox_id, session_id), key, status=404)
    listing = await send(client, "GET", sessions_path(sandbox_id), key, status=200)
    assert [item["id"] for item in listing["data"]] == [other]
    again = await send(client, "DELETE", sessions_path(sandbox_id, session_id), key, status=404)
    assert again["error"]["code"] == "NOT_FOUND"


async def test_deleting_an_unknown_session_or_one_of_another_sandbox_is_404(
    client: httpx.AsyncClient, key: str
) -> None:
    first = await create_sandbox(client, key)
    second = await create_sandbox(client, key)
    session_id = await create_session(client, key, first)

    await send(client, "DELETE", sessions_path(first, "ses_nope"), key, status=404)
    await send(client, "DELETE", sessions_path(second, session_id), key, status=404)
    await send(client, "GET", sessions_path(first, session_id), key, status=200)


async def test_deleting_a_session_kills_its_running_commands(
    client: httpx.AsyncClient, key: str, gate: Gate
) -> None:
    sandbox_id = await create_sandbox(client, key)
    session_id = await create_session(client, key, sandbox_id)
    command_id = await start_async(client, key, sandbox_id, session_id)
    command_path = sessions_path(sandbox_id, session_id, "commands", command_id)

    await send(client, "DELETE", sessions_path(sandbox_id, session_id), key, status=200)

    assert gate.abandoned is True
    await send(client, "GET", command_path, key, status=404)
    await send(client, "GET", command_path + "/logs", key, status=404)
    await send(
        client,
        "POST",
        sessions_path(sandbox_id, session_id, "commands"),
        key,
        status=404,
        json={"command": "true"},
    )


async def test_other_sessions_keep_their_commands(
    client: httpx.AsyncClient, key: str, gate: Gate
) -> None:
    sandbox_id = await create_sandbox(client, key)
    doomed = await create_session(client, key, sandbox_id)
    kept = await create_session(client, key, sandbox_id)
    kept_command = await start_async(client, key, sandbox_id, kept)

    await send(client, "DELETE", sessions_path(sandbox_id, doomed), key, status=200)

    status = await send(
        client, "GET", sessions_path(sandbox_id, kept, "commands", kept_command), key, status=200
    )
    assert status["data"]["state"] == "running"
    assert gate.abandoned is False
    gate.release.set()


async def test_a_session_of_a_stopped_sandbox_can_be_deleted(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    session_id = await create_session(client, key, sandbox_id)
    await send(client, "POST", f"{BASE}/{sandbox_id}/stop", key, status=200)

    await send(client, "DELETE", sessions_path(sandbox_id, session_id), key, status=200)

    await send(client, "GET", sessions_path(sandbox_id, session_id), key, status=404)


async def test_delete_is_audited_like_other_toolbox_writes(
    app: FastAPI, org_id: str, client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    session_id = await create_session(client, key, sandbox_id)

    await send(client, "DELETE", sessions_path(sandbox_id, session_id), key, status=200)

    actions = await audit_actions(app, org_id)
    assert "toolbox.session.create" in actions
    assert "toolbox.session.delete" in actions


async def test_delete_needs_the_toolbox_scope(
    app: FastAPI, org_id: str, client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    session_id = await create_session(client, key, sandbox_id)
    reader = await add_key(app, org_id, frozenset({Scope.SANDBOXES_READ}))

    await send(client, "DELETE", sessions_path(sandbox_id, session_id), reader, status=403)

    await send(client, "GET", sessions_path(sandbox_id, session_id), key, status=200)


def test_the_spec_lists_the_delete_operation(app: FastAPI) -> None:
    operation = build_document(app)["paths"][SESSION_SPEC_PATH]["delete"]

    assert {"200", "404"} <= set(operation["responses"])


# --- 4: Idempotency-Key on session create -----------------------------------------


async def post_session(
    client: httpx.AsyncClient, key: str, sandbox_id: str, idem: str | None, **payload: Any
) -> httpx.Response:
    headers = auth(key) if idem is None else {**auth(key), "Idempotency-Key": idem}
    return await client.post(sessions_path(sandbox_id), headers=headers, json=payload)


async def test_the_same_key_and_body_replays_the_first_session(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)

    first = await post_session(client, key, sandbox_id, "k-1", cwd="/work")
    second = await post_session(client, key, sandbox_id, "k-1", cwd="/work")

    assert (first.status_code, second.status_code) == (201, 201)
    assert second.json()["data"] == first.json()["data"]
    assert second.headers.get("Idempotent-Replayed") == "true"
    assert "Idempotent-Replayed" not in first.headers
    listing = await send(client, "GET", sessions_path(sandbox_id), key, status=200)
    assert len(listing["data"]) == 1


async def test_the_same_key_with_another_body_is_a_mismatch(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    await post_session(client, key, sandbox_id, "k-2", cwd="/work")

    clash = await post_session(client, key, sandbox_id, "k-2", cwd="/other")

    assert clash.status_code == 422
    assert clash.json()["error"]["code"] == IdempotencyMismatch.code
    listing = await send(client, "GET", sessions_path(sandbox_id), key, status=200)
    assert len(listing["data"]) == 1


async def test_a_key_belongs_to_one_sandbox(client: httpx.AsyncClient, key: str) -> None:
    first = await create_sandbox(client, key)
    second = await create_sandbox(client, key)

    one = await post_session(client, key, first, "k-3")
    two = await post_session(client, key, second, "k-3")

    assert (one.status_code, two.status_code) == (201, 201)
    assert one.json()["data"]["id"] != two.json()["data"]["id"]
    assert two.json()["data"]["sandbox_id"] == second


async def test_without_the_header_every_call_creates_a_session(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)

    await post_session(client, key, sandbox_id, None)
    await post_session(client, key, sandbox_id, None)

    listing = await send(client, "GET", sessions_path(sandbox_id), key, status=200)
    assert len(listing["data"]) == 2


async def test_a_failed_create_does_not_keep_the_key(client: httpx.AsyncClient, key: str) -> None:
    sandbox_id = await create_sandbox(client, key)

    bad = await post_session(client, key, sandbox_id, "k-4", cwd="relative")
    good = await post_session(client, key, sandbox_id, "k-4", cwd="/work")

    assert bad.status_code == 422
    assert good.status_code == 201
    assert "Idempotent-Replayed" not in good.headers


async def test_an_empty_key_is_refused(client: httpx.AsyncClient, key: str) -> None:
    sandbox_id = await create_sandbox(client, key)

    refused = await post_session(client, key, sandbox_id, "")

    assert refused.status_code == 422
    assert refused.json()["error"]["code"] == "VALIDATION_ERROR"


def test_the_spec_declares_the_header_on_session_create(app: FastAPI) -> None:
    operation = build_document(app)["paths"][SESSIONS_SPEC_PATH]["post"]

    names = [param["name"] for param in operation["parameters"]]
    assert "Idempotency-Key" in names


# --- SDK: delete_session and the create key ---------------------------------------

SDK_BASE = "http://sandfort.test"
SDK_KEY = "sf_test_key"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SESSION_ID = "ses_1"
SESSION_URL = f"/v1/sandboxes/{SID}/toolbox/process/sessions"
SESSION = {
    "id": SESSION_ID,
    "sandbox_id": SID,
    "cwd": "/w",
    "env": {},
    "state": "active",
    "created_at": "2026-11-11T12:00:00Z",
}
SANDBOX = {
    "id": SID,
    "name": "demo",
    "state": "started",
    "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
    "network": {"block_all": False},
}


def envelope(data: object) -> dict[str, object]:
    return {"success": True, "data": data, "error": None, "meta": None}


async def call(fn: Any, *args: Any, **kwargs: Any) -> Any:
    result = fn(*args, **kwargs)
    return await result if inspect.isawaitable(result) else result


@pytest.fixture
def api() -> Any:
    with respx.mock(base_url=SDK_BASE, assert_all_called=False) as router:
        router.get(f"/v1/sandboxes/{SID}").respond(200, json=envelope(SANDBOX))
        yield router


@pytest.fixture(params=["sync", "async"])
async def sdk_sandbox(request: pytest.FixtureRequest, api: Any) -> Any:
    sync = request.param == "sync"
    sdk_client = Client(SDK_BASE, SDK_KEY) if sync else AsyncClient(SDK_BASE, SDK_KEY)
    yield await call(sdk_client.get, SID)
    await call(sdk_client.close if sync else sdk_client.aclose)


async def test_sdk_delete_session_sends_delete_and_returns_the_closed_session(
    api: Any, sdk_sandbox: Any
) -> None:
    route = api.delete(f"{SESSION_URL}/{SESSION_ID}").respond(
        200, json=envelope({**SESSION, "state": "closed"})
    )

    info = await call(sdk_sandbox.process.delete_session, SESSION_ID)

    assert route.called
    assert (info.id, info.state) == (SESSION_ID, "closed")


async def test_sdk_delete_session_of_an_unknown_session_raises_not_found(
    api: Any, sdk_sandbox: Any
) -> None:
    error = {"code": "NOT_FOUND", "message": "session ses_9 not found", "details": {}}
    api.delete(f"{SESSION_URL}/ses_9").respond(
        404, json={"success": False, "data": None, "error": error, "meta": None}
    )

    with pytest.raises(NotFound):
        await call(sdk_sandbox.process.delete_session, "ses_9")


async def test_sdk_delete_session_refuses_an_empty_id(api: Any, sdk_sandbox: Any) -> None:
    with pytest.raises(ValueError):
        await call(sdk_sandbox.process.delete_session, "")


async def test_sdk_create_session_sends_the_idempotency_key(api: Any, sdk_sandbox: Any) -> None:
    route = api.post(SESSION_URL).respond(201, json=envelope(SESSION))

    await call(sdk_sandbox.process.create_session, cwd="/w", idempotency_key="k-sdk")

    assert route.calls.last.request.headers["Idempotency-Key"] == "k-sdk"
    assert json.loads(route.calls.last.request.content) == {"cwd": "/w"}


async def test_sdk_create_session_without_a_key_sends_no_header(api: Any, sdk_sandbox: Any) -> None:
    route = api.post(SESSION_URL).respond(201, json=envelope(SESSION))

    await call(sdk_sandbox.process.create_session)

    assert "Idempotency-Key" not in route.calls.last.request.headers
