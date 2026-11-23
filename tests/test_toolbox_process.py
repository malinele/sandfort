"""API tests for ``/v1/sandboxes/{id}/toolbox/process``: FakeDriver, temp SQLite, httpx.

Daemon-free. The router is mounted by the fixture; the exec handler of the FakeDriver is
replaced per test so output, exit codes and timeouts are fully scripted.
"""

import asyncio
import io
import tarfile
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api import dead_sandbox
from sandfort.api.app import create_app
from sandfort.api.routes.toolbox import process as process_routes
from sandfort.api.schemas.toolbox_process import (
    ExecuteResponse,
    derive_stop_reason,
    execute_response,
)
from sandfort.api.wiring import RECONCILER_ATTR
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.drivers.base import ExecRequest, ExecResult, InstanceInfo
from sandfort.drivers.errors import DriverError
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.toolbox import code_run

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'toolbox.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(driver="fake", database_url=url, api_key_pepper=PEPPER)
    application = create_app(settings)
    application.include_router(process_routes.router)
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


@pytest.fixture
def calls(driver: FakeDriver) -> list[ExecRequest]:
    """Every exec request the driver receives, answered with a plain success."""
    seen: list[ExecRequest] = []

    def handler(env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        seen.append(request)
        return ExecResult(exit_code=0)

    driver.exec_handler = handler
    return seen


async def add_org(app: FastAPI, slug: str) -> str:
    org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)
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
async def org_id(app: FastAPI) -> str:
    return await add_org(app, "acme")


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await add_key(app, org_id, FULL_ACCESS)


async def send(
    client: httpx.AsyncClient, method: str, path: str, key: str, *, status: int, **kwargs: Any
) -> dict[str, Any]:
    response = await client.request(
        method, path, headers={"Authorization": f"Bearer {key}"}, **kwargs
    )
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    assert body["success"] is (status < 400)
    return body


async def create_sandbox(client: httpx.AsyncClient, key: str) -> str:
    body = await send(client, "POST", BASE, key, status=201, json={})
    sandbox_id: str = body["data"]["id"]
    return sandbox_id


def process_path(sandbox_id: str, action: str) -> str:
    return f"{BASE}/{sandbox_id}/toolbox/process/{action}"


async def read_uploaded(driver: FakeDriver, ref: str, path: str) -> str:
    payload = b"".join([chunk async for chunk in driver.get_archive(ref, path)])
    with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
        [member] = archive.getmembers()
        handle = archive.extractfile(member)
        assert handle is not None
        return handle.read().decode()


# --- execute ----------------------------------------------------------------------


async def test_execute_returns_demuxed_output_and_exit_code(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    seen: list[ExecRequest] = []

    def handler(env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        seen.append(request)
        return ExecResult(exit_code=3, stdout=b"to-out\n", stderr=b"to-err\n", duration_ms=7)

    driver.exec_handler = handler
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "POST",
        process_path(sandbox_id, "execute"),
        key,
        status=200,
        json={"command": "make test", "cwd": "/work", "env": {"CI": "1"}, "stdin": "in"},
    )

    assert body["data"] == {
        "exit_code": 3,
        "stdout": "to-out\n",
        "stderr": "to-err\n",
        "timed_out": False,
        "truncated": False,
        "duration_ms": 7,
        "sandbox_stopped": False,
        "stop_reason": None,
    }
    [request] = seen
    assert list(request.argv) == ["sh", "-c", "make test"]
    assert request.cwd == "/work"
    assert request.env == {"CI": "1"}
    assert request.stdin == b"in"


async def test_execute_accepts_argv_with_default_driver_handler(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "POST",
        process_path(sandbox_id, "execute"),
        key,
        status=200,
        json={"argv": ["echo", "hello", "world"]},
    )

    assert body["data"]["exit_code"] == 0
    assert body["data"]["stdout"] == "hello world\n"


async def test_execute_requires_exactly_one_of_command_or_argv(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    path = process_path(sandbox_id, "execute")

    neither = await send(client, "POST", path, key, status=422, json={})
    both = await send(client, "POST", path, key, status=422, json={"command": "a", "argv": ["a"]})

    assert neither["error"]["code"] == "VALIDATION_ERROR"
    assert both["error"]["code"] == "VALIDATION_ERROR"


async def test_execute_rejects_reserved_env_names(
    client: httpx.AsyncClient, key: str, calls: list[ExecRequest]
) -> None:
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "POST",
        process_path(sandbox_id, "execute"),
        key,
        status=422,
        json={"command": "env", "env": {"SANDFORT_SECRET": "x"}},
    )

    assert body["error"]["code"] == "UNPROCESSABLE"
    assert calls == []


async def test_execute_caps_output_size_at_one_mebibyte(
    client: httpx.AsyncClient, key: str, calls: list[ExecRequest]
) -> None:
    sandbox_id = await create_sandbox(client, key)

    await send(
        client, "POST", process_path(sandbox_id, "execute"), key, status=200, json={"command": "x"}
    )

    assert calls[0].max_output_bytes == 1024 * 1024


# --- guards -----------------------------------------------------------------------


async def test_execute_on_stopped_sandbox_is_conflict(
    client: httpx.AsyncClient, key: str, calls: list[ExecRequest]
) -> None:
    sandbox_id = await create_sandbox(client, key)
    await send(client, "POST", f"{BASE}/{sandbox_id}/stop", key, status=200)

    body = await send(
        client, "POST", process_path(sandbox_id, "execute"), key, status=409, json={"command": "ls"}
    )

    assert body["error"]["code"] == "CONFLICT"
    assert body["error"]["details"] == {
        "reason": "no_container",
        "state": "stopped",
        "stop_cause": "requested",
    }
    assert calls == []


async def test_execute_from_another_org_is_not_found(
    app: FastAPI, client: httpx.AsyncClient, key: str, calls: list[ExecRequest]
) -> None:
    sandbox_id = await create_sandbox(client, key)
    other_key = await add_key(app, await add_org(app, "globex"), FULL_ACCESS)

    body = await send(
        client,
        "POST",
        process_path(sandbox_id, "execute"),
        other_key,
        status=404,
        json={"command": "ls"},
    )

    assert body["error"]["code"] == "NOT_FOUND"
    assert calls == []


async def test_execute_without_toolbox_scope_is_forbidden(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str, calls: list[ExecRequest]
) -> None:
    sandbox_id = await create_sandbox(client, key)
    read_only = await add_key(app, org_id, frozenset({Scope.SANDBOXES_READ}))

    body = await send(
        client,
        "POST",
        process_path(sandbox_id, "execute"),
        read_only,
        status=403,
        json={"command": "ls"},
    )

    assert body["error"]["code"] == "FORBIDDEN"
    assert calls == []


# --- timeout ----------------------------------------------------------------------


async def test_timeout_is_reported_as_timed_out(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    seen: list[ExecRequest] = []

    def handler(env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        seen.append(request)
        return ExecResult(exit_code=124, stdout=b"partial", timed_out=True)

    driver.exec_handler = handler
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "POST",
        process_path(sandbox_id, "execute"),
        key,
        status=200,
        json={"command": "sleep 100", "timeout_s": 2},
    )

    assert body["data"]["timed_out"] is True
    assert body["data"]["exit_code"] == 124
    assert body["data"]["stdout"] == "partial"
    assert seen[0].timeout_s == 2.0


# --- reconciler kick --------------------------------------------------------------


@pytest.fixture
def kicks(app: FastAPI, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every ``Reconciler.kick`` made through the app state (the real loop is not running)."""
    seen: list[str] = []
    reconciler = getattr(app.state, RECONCILER_ATTR)
    monkeypatch.setattr(reconciler, "kick", lambda: seen.append("kick"))
    return seen


FAST_SETTLE_TIMEOUT_S = 0.15
FAST_SETTLE_POLL_S = 0.02
LATE_EXIT_DELAY_S = 0.06


@pytest.fixture(autouse=True)
def fast_settle(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shrink the wait for the runtime to report a dead instance (5 s by default)."""
    monkeypatch.setattr(dead_sandbox, "SETTLE_TIMEOUT_S", FAST_SETTLE_TIMEOUT_S)
    monkeypatch.setattr(dead_sandbox, "SETTLE_POLL_INTERVAL_S", FAST_SETTLE_POLL_S)


async def sandbox_state(client: httpx.AsyncClient, key: str, sandbox_id: str) -> str:
    body = await send(client, "GET", f"{BASE}/{sandbox_id}", key, status=200)
    state: str = body["data"]["state"]
    return state


async def test_execute_kicks_the_reconciler_when_the_sandbox_died(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, kicks: list[str]
) -> None:
    def handler(env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        return ExecResult(exit_code=137, stderr=b"the sandbox stopped", sandbox_stopped=True)

    driver.exec_handler = handler
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "POST",
        process_path(sandbox_id, "execute"),
        key,
        status=200,
        json={"command": "stress"},
    )

    assert kicks == ["kick"]
    assert body["data"] == {
        "exit_code": 137,
        "stdout": "",
        "stderr": "the sandbox stopped",
        "timed_out": False,
        "truncated": False,
        "duration_ms": 0,
        "sandbox_stopped": True,
        "stop_reason": "sandbox_stopped",
    }


async def test_code_run_reports_sandbox_stopped_in_the_response(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, kicks: list[str]
) -> None:
    def handler(env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        if request.argv[0] == "python3":
            return ExecResult(exit_code=137, sandbox_stopped=True)
        return ExecResult(exit_code=0)

    driver.exec_handler = handler
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "POST",
        process_path(sandbox_id, "code-run"),
        key,
        status=200,
        json={"language": "python", "code": "print(1)"},
    )

    assert body["data"]["exit_code"] == 137
    assert body["data"]["sandbox_stopped"] is True


async def test_execute_reports_sandbox_stopped_false_for_a_failed_command(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    driver.exec_handler = lambda env, request: ExecResult(exit_code=137)
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "POST",
        process_path(sandbox_id, "execute"),
        key,
        status=200,
        json={"command": "kill -9 $$"},
    )

    assert body["data"]["exit_code"] == 137
    assert body["data"]["sandbox_stopped"] is False
    assert body["data"]["stop_reason"] == "killed"


# --- stop_reason ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (ExecResult(exit_code=0), None),
        (ExecResult(exit_code=1), None),
        (ExecResult(exit_code=124), None),  # a command's own 124 is not a timeout
        (ExecResult(exit_code=137), "killed"),
        (ExecResult(exit_code=124, timed_out=True), "timeout"),
        (ExecResult(exit_code=137, truncated=True), "output_limit"),
        (ExecResult(exit_code=0, truncated=True), "output_limit"),
        (ExecResult(exit_code=137, sandbox_stopped=True), "sandbox_stopped"),
    ],
)
def test_stop_reason_is_derived_from_the_result_flags(
    result: ExecResult, expected: str | None
) -> None:
    assert execute_response(result).stop_reason == expected


@pytest.mark.parametrize(
    ("flags", "expected"),
    [
        ({"timed_out": True, "truncated": True, "sandbox_stopped": True}, "timeout"),
        ({"timed_out": True, "truncated": True}, "timeout"),
        ({"timed_out": True, "sandbox_stopped": True}, "timeout"),
        ({"truncated": True, "sandbox_stopped": True}, "output_limit"),
    ],
)
def test_stop_reason_precedence_is_timeout_then_output_limit_then_sandbox_stopped(
    flags: dict[str, bool], expected: str
) -> None:
    assert execute_response(ExecResult(exit_code=137, **flags)).stop_reason == expected


def test_stop_reason_ignores_the_output_text() -> None:
    result = ExecResult(exit_code=0, stderr=b"the command was stopped after 5 s (timeout)")

    assert execute_response(result).stop_reason is None


def test_stop_reason_is_derived_even_when_a_caller_passes_one() -> None:
    response = ExecuteResponse(
        exit_code=0,
        stdout="",
        stderr="",
        timed_out=True,
        truncated=False,
        duration_ms=1,
        stop_reason="bogus",
    )

    assert response.stop_reason == "timeout"


def test_derive_stop_reason_is_null_for_a_normal_exit() -> None:
    reason = derive_stop_reason(
        exit_code=0, timed_out=False, truncated=False, sandbox_stopped=False
    )

    assert reason is None


async def test_timeout_reports_stop_reason_timeout(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    driver.exec_handler = lambda env, request: ExecResult(exit_code=124, timed_out=True)
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "POST",
        process_path(sandbox_id, "execute"),
        key,
        status=200,
        json={"command": "sleep 100", "timeout_s": 1},
    )

    assert (body["data"]["exit_code"], body["data"]["stop_reason"]) == (124, "timeout")


async def test_code_run_reports_stop_reason_output_limit(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    def handler(env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        if request.argv[0] == "python3":
            return ExecResult(exit_code=137, truncated=True)
        return ExecResult(exit_code=0)

    driver.exec_handler = handler
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "POST",
        process_path(sandbox_id, "code-run"),
        key,
        status=200,
        json={"language": "python", "code": "print(1)"},
    )

    assert body["data"]["stop_reason"] == "output_limit"


async def test_execute_marks_the_row_stopped_when_the_container_is_not_running(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, kicks: list[str]
) -> None:
    sandbox_id = await create_sandbox(client, key)
    [instance] = await driver.list_managed()
    driver.kill_instance(instance.ref, vanish=False)  # the row still says started

    body = await send(
        client,
        "POST",
        process_path(sandbox_id, "execute"),
        key,
        status=409,
        json={"command": "ls"},
    )

    assert kicks == []  # settled before the response, nothing left for the reconciler
    assert body["error"]["code"] == "CONFLICT"
    assert "is not running" in body["error"]["message"]
    assert await sandbox_state(client, key, sandbox_id) == "stopped"


async def test_code_run_kicks_the_reconciler_when_the_sandbox_died(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, kicks: list[str]
) -> None:
    def handler(env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        if request.argv[0] == "python3":
            return ExecResult(exit_code=137, sandbox_stopped=True)
        return ExecResult(exit_code=0)

    driver.exec_handler = handler
    sandbox_id = await create_sandbox(client, key)

    await send(
        client,
        "POST",
        process_path(sandbox_id, "code-run"),
        key,
        status=200,
        json={"language": "python", "code": "print(1)"},
    )

    assert kicks == ["kick"]


async def test_plain_exit_137_and_other_failures_do_not_kick(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, kicks: list[str]
) -> None:
    def handler(env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        return ExecResult(exit_code=137, stderr=b"Killed\n")  # a container-tier OOM: no marker

    driver.exec_handler = handler
    sandbox_id = await create_sandbox(client, key)
    path = process_path(sandbox_id, "execute")

    oom = await send(client, "POST", path, key, status=200, json={"command": "hog"})
    invalid = await send(
        client, "POST", path, key, status=422, json={"command": "env", "env": {"SANDFORT_X": "1"}}
    )

    assert oom["data"]["exit_code"] == 137
    assert invalid["error"]["code"] == "UNPROCESSABLE"
    assert kicks == []


FAST_FIRST_DELAY_S = 0.05
FAST_SECOND_DELAY_S = 0.1
PAST_BOTH_DELAYS_S = 0.4


@pytest.fixture
def fast_delays(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_routes, "RECHECK_KICK_FIRST_DELAY_S", FAST_FIRST_DELAY_S)
    monkeypatch.setattr(process_routes, "RECHECK_KICK_SECOND_DELAY_S", FAST_SECOND_DELAY_S)


def test_recheck_kick_delays_default_to_1_5_and_5_seconds() -> None:
    assert process_routes.RECHECK_KICK_FIRST_DELAY_S == 1.5
    assert process_routes.RECHECK_KICK_SECOND_DELAY_S == 5.0


@pytest.mark.usefixtures("fast_delays")
async def test_a_dead_sandbox_result_schedules_kicks_at_the_configured_delays(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, kicks: list[str]
) -> None:
    def handler(env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        return ExecResult(exit_code=137, sandbox_stopped=True)

    driver.exec_handler = handler
    sandbox_id = await create_sandbox(client, key)

    await send(
        client, "POST", process_path(sandbox_id, "execute"), key, status=200, json={"command": "x"}
    )

    assert kicks == ["kick"]  # the immediate kick; the response did not wait for the others
    await asyncio.sleep(PAST_BOTH_DELAYS_S)
    assert kicks == ["kick", "kick", "kick"]


@pytest.mark.usefixtures("fast_delays")
async def test_a_not_running_conflict_schedules_kicks_at_the_configured_delays(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    kicks: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox_id = await create_sandbox(client, key)
    [instance] = await driver.list_managed()
    driver.kill_instance(instance.ref, vanish=False)

    async def broken_inspect(ref: str) -> InstanceInfo:
        raise RuntimeError("runtime unreachable")  # settling fails, so the kicks take over

    monkeypatch.setattr(driver, "inspect", broken_inspect)

    await send(
        client, "POST", process_path(sandbox_id, "execute"), key, status=409, json={"command": "ls"}
    )

    assert kicks == ["kick"]
    await asyncio.sleep(PAST_BOTH_DELAYS_S)
    assert kicks == ["kick", "kick", "kick"]


@pytest.mark.usefixtures("fast_delays")
async def test_a_code_run_dead_sandbox_result_schedules_the_delayed_kicks(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, kicks: list[str]
) -> None:
    def handler(env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        if request.argv[0] == "python3":
            return ExecResult(exit_code=137, sandbox_stopped=True)
        return ExecResult(exit_code=0)

    driver.exec_handler = handler
    sandbox_id = await create_sandbox(client, key)

    await send(
        client,
        "POST",
        process_path(sandbox_id, "code-run"),
        key,
        status=200,
        json={"language": "python", "code": "print(1)"},
    )
    await asyncio.sleep(PAST_BOTH_DELAYS_S)

    assert kicks == ["kick", "kick", "kick"]


@pytest.mark.usefixtures("fast_delays")
async def test_a_normal_result_schedules_no_kicks(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, kicks: list[str]
) -> None:
    def handler(env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        return ExecResult(exit_code=0, stdout=b"ok\n")

    driver.exec_handler = handler
    sandbox_id = await create_sandbox(client, key)

    await send(
        client, "POST", process_path(sandbox_id, "execute"), key, status=200, json={"command": "x"}
    )
    await asyncio.sleep(PAST_BOTH_DELAYS_S)

    assert kicks == []


@pytest.mark.usefixtures("fast_delays")
async def test_delayed_kicks_without_a_reconciler_are_not_scheduled(
    app: FastAPI, client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    def handler(env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        return ExecResult(exit_code=137, sandbox_stopped=True)

    driver.exec_handler = handler
    sandbox_id = await create_sandbox(client, key)
    delattr(app.state, RECONCILER_ATTR)

    body = await send(
        client, "POST", process_path(sandbox_id, "execute"), key, status=200, json={"command": "x"}
    )
    await asyncio.sleep(PAST_BOTH_DELAYS_S)  # a stray timer would raise here

    assert body["data"]["exit_code"] == 137


async def test_execute_without_a_reconciler_on_the_app_state_still_answers(
    app: FastAPI, client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    def handler(env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        return ExecResult(exit_code=137, sandbox_stopped=True)

    driver.exec_handler = handler
    sandbox_id = await create_sandbox(client, key)
    delattr(app.state, RECONCILER_ATTR)

    body = await send(
        client, "POST", process_path(sandbox_id, "execute"), key, status=200, json={"command": "x"}
    )

    assert body["data"]["exit_code"] == 137


# --- settling the row before the response ---------------------------------------------

DEAD_ROUTES = [
    pytest.param("execute", {"command": "stress"}, id="execute"),
    pytest.param("code-run", {"language": "python", "code": "print(1)"}, id="code-run"),
]


def dying_handler(on_exec: Any) -> Any:
    """An exec handler that reports a dead sandbox for ``stress`` and python, after ``on_exec``."""

    def handler(env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        if request.argv[-1] != "stress" and request.argv[0] != "python3":
            return ExecResult(exit_code=0)
        on_exec()
        return ExecResult(exit_code=137, sandbox_stopped=True)

    return handler


async def post_dying(
    client: httpx.AsyncClient, key: str, sandbox_id: str, route: str, payload: dict[str, Any]
) -> dict[str, Any]:
    body = await send(
        client, "POST", process_path(sandbox_id, route), key, status=200, json=payload
    )
    data: dict[str, Any] = body["data"]
    assert data["exit_code"] == 137
    assert data["sandbox_stopped"] is True
    return data


@pytest.mark.parametrize(("route", "payload"), DEAD_ROUTES)
async def test_a_dead_sandbox_is_stopped_before_the_response_when_the_instance_exited(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    kicks: list[str],
    route: str,
    payload: dict[str, Any],
) -> None:
    sandbox_id = await create_sandbox(client, key)
    [instance] = await driver.list_managed()
    driver.exec_handler = dying_handler(lambda: driver.kill_instance(instance.ref, vanish=False))

    await post_dying(client, key, sandbox_id, route, payload)

    assert await sandbox_state(client, key, sandbox_id) == "stopped"
    assert kicks == []


@pytest.mark.parametrize(("route", "payload"), DEAD_ROUTES)
async def test_a_dead_sandbox_whose_instance_vanished_is_stopped_before_the_response(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    kicks: list[str],
    route: str,
    payload: dict[str, Any],
) -> None:
    sandbox_id = await create_sandbox(client, key)
    [instance] = await driver.list_managed()
    driver.exec_handler = dying_handler(lambda: driver.kill_instance(instance.ref, vanish=True))

    await post_dying(client, key, sandbox_id, route, payload)

    assert await sandbox_state(client, key, sandbox_id) == "stopped"
    assert kicks == []


@pytest.mark.parametrize(("route", "payload"), DEAD_ROUTES)
async def test_a_dead_sandbox_waits_while_the_instance_still_reports_running(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    kicks: list[str],
    route: str,
    payload: dict[str, Any],
) -> None:
    sandbox_id = await create_sandbox(client, key)
    [instance] = await driver.list_managed()

    def exit_soon() -> None:
        asyncio.get_running_loop().call_later(
            LATE_EXIT_DELAY_S, lambda: driver.kill_instance(instance.ref, vanish=False)
        )

    driver.exec_handler = dying_handler(exit_soon)

    await post_dying(client, key, sandbox_id, route, payload)

    assert await sandbox_state(client, key, sandbox_id) == "stopped"
    assert kicks == []


@pytest.mark.parametrize(("route", "payload"), DEAD_ROUTES)
async def test_a_dead_sandbox_that_never_settles_falls_back_to_the_kicks(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    kicks: list[str],
    route: str,
    payload: dict[str, Any],
) -> None:
    sandbox_id = await create_sandbox(client, key)
    driver.exec_handler = dying_handler(lambda: None)  # the instance keeps reporting running

    data = await post_dying(client, key, sandbox_id, route, payload)

    assert data["exit_code"] == 137
    assert await sandbox_state(client, key, sandbox_id) == "started"
    assert kicks == ["kick"]


@pytest.mark.parametrize(("route", "payload"), DEAD_ROUTES)
async def test_a_dead_sandbox_without_a_reconciler_answers_unchanged(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    route: str,
    payload: dict[str, Any],
) -> None:
    sandbox_id = await create_sandbox(client, key)
    [instance] = await driver.list_managed()
    driver.exec_handler = dying_handler(lambda: driver.kill_instance(instance.ref, vanish=False))
    delattr(app.state, RECONCILER_ATTR)

    await post_dying(client, key, sandbox_id, route, payload)

    assert await sandbox_state(client, key, sandbox_id) == "started"


@pytest.mark.parametrize(("route", "payload"), DEAD_ROUTES)
async def test_a_dead_sandbox_whose_inspect_raises_falls_back_to_the_kicks(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    kicks: list[str],
    monkeypatch: pytest.MonkeyPatch,
    route: str,
    payload: dict[str, Any],
) -> None:
    sandbox_id = await create_sandbox(client, key)
    driver.exec_handler = dying_handler(lambda: None)

    async def broken_inspect(ref: str) -> InstanceInfo:
        raise RuntimeError("runtime unreachable")

    monkeypatch.setattr(driver, "inspect", broken_inspect)

    await post_dying(client, key, sandbox_id, route, payload)

    assert await sandbox_state(client, key, sandbox_id) == "started"
    assert kicks == ["kick"]


# --- code run ---------------------------------------------------------------------


async def test_code_run_uploads_and_executes_python_source(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    seen: list[ExecRequest] = []

    def handler(env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        seen.append(request)
        if request.argv[0] == "python3":
            return ExecResult(exit_code=0, stdout=b"42\n")
        return ExecResult(exit_code=0)

    driver.exec_handler = handler
    sandbox_id = await create_sandbox(client, key)
    source = "print(6 * 7)\n"

    body = await send(
        client,
        "POST",
        process_path(sandbox_id, "code-run"),
        key,
        status=200,
        json={"language": "python", "code": source, "argv": ["--flag"], "env": {"A": "b"}},
    )

    assert body["data"]["stdout"] == "42\n"
    assert body["data"]["exit_code"] == 0
    run, cleanup = seen
    script = run.argv[3]
    run_dir = script.rsplit("/", 1)[0]
    assert run.cwd is None
    assert run_dir.startswith("/tmp/.sandfort-run-") and script == f"{run_dir}/main.py"
    assert list(run.argv) == ["python3", "-c", code_run.PYTHON_LOADER, script, "--flag"]
    assert run.env == {"A": "b"}
    assert list(cleanup.argv) == ["rm", "-rf", run_dir]
    [instance] = await driver.list_managed()
    assert await read_uploaded(driver, instance.ref, script) == source


async def test_code_run_route_forwards_cwd_to_the_exec(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    seen: list[ExecRequest] = []

    def handler(env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        seen.append(request)
        return ExecResult(exit_code=0)

    driver.exec_handler = handler
    sandbox_id = await create_sandbox(client, key)

    await send(
        client,
        "POST",
        process_path(sandbox_id, "code-run"),
        key,
        status=200,
        json={"language": "python", "code": "print(1)\n", "cwd": "/work"},
    )

    run, _cleanup = seen
    assert run.cwd == "/work"
    assert run.argv[:3] == ["python3", "-c", code_run.PYTHON_LOADER]
    assert run.argv[3].endswith("/main.py")


class RecordingDriver:
    """Just enough of a driver for ``run_code``: records the upload and every exec."""

    def __init__(self, *, fail_run: bool = False) -> None:
        self.fail_run = fail_run
        self.uploads: list[tuple[str, bytes]] = []
        self.execs: list[ExecRequest] = []

    async def put_archive(self, ref: str, dest_path: str, data: AsyncIterator[bytes]) -> None:
        self.uploads.append((dest_path, b"".join([chunk async for chunk in data])))

    async def exec(self, ref: str, request: ExecRequest) -> ExecResult:
        self.execs.append(request)
        if self.fail_run and request.argv[0] != "rm":
            raise DriverError("exec failed")
        return ExecResult(exit_code=0)


async def run_recorded(driver: RecordingDriver, **kwargs: Any) -> ExecResult:
    sandbox: Any = SimpleNamespace(driver_ref="ref-1")
    recorder: Any = driver
    return await code_run.run_code(recorder, sandbox, "python", "print(1)\n", **kwargs)


def uploaded_members(driver: RecordingDriver) -> list[tarfile.TarInfo]:
    [(dest, payload)] = driver.uploads
    assert dest == "/tmp"
    with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
        return archive.getmembers()


async def test_code_run_tar_holds_a_private_dir_and_main_file() -> None:
    driver = RecordingDriver()

    await run_recorded(driver)

    directory, script = uploaded_members(driver)
    assert directory.isdir() and directory.mode == 0o700
    assert directory.name.startswith(".sandfort-run-")
    assert script.isfile() and script.name == f"{directory.name}/main.py"


async def test_code_run_without_cwd_passes_none_and_the_absolute_script_path() -> None:
    driver = RecordingDriver()

    await run_recorded(driver, argv=["x"])

    [directory, _] = uploaded_members(driver)
    run, cleanup = driver.execs
    script = PurePosixPath(run.argv[3])
    assert run.cwd is None
    loader = ["python3", "-c", code_run.PYTHON_LOADER]
    assert list(run.argv) == [*loader, f"/tmp/{directory.name}/main.py", "x"]
    assert script.is_absolute() and script.stem == "main" and script.suffix == ".py"
    assert script.parent == PurePosixPath(f"/tmp/{directory.name}")
    assert list(cleanup.argv) == ["rm", "-rf", f"/tmp/{directory.name}"]


async def test_code_run_with_an_explicit_cwd_passes_the_absolute_path() -> None:
    driver = RecordingDriver()

    await run_recorded(driver, cwd="/work")

    [directory, _] = uploaded_members(driver)
    run, cleanup = driver.execs
    loader = ["python3", "-c", code_run.PYTHON_LOADER]
    assert list(run.argv) == [*loader, f"/tmp/{directory.name}/main.py"]
    assert run.cwd == "/work"
    assert list(cleanup.argv) == ["rm", "-rf", f"/tmp/{directory.name}"]


async def test_code_run_removes_the_run_dir_even_when_the_exec_fails() -> None:
    driver = RecordingDriver(fail_run=True)

    with pytest.raises(DriverError):
        await run_recorded(driver)

    [directory, _] = uploaded_members(driver)
    cleanup = driver.execs[-1]
    assert list(cleanup.argv) == ["rm", "-rf", f"/tmp/{directory.name}"]


async def test_code_run_with_reserved_env_name_runs_nothing(
    client: httpx.AsyncClient, key: str, calls: list[ExecRequest]
) -> None:
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "POST",
        process_path(sandbox_id, "code-run"),
        key,
        status=422,
        json={"language": "bash", "code": "true", "env": {"SANDFORT_X": "1"}},
    )

    assert body["error"]["code"] == "UNPROCESSABLE"
    assert calls == []


# --- client disconnect ------------------------------------------------------------

FAST_DISCONNECT_POLL_S = 0.01
PROMPT_RETURN_S = 1.0


class FakeRequest:
    """Just enough of ``Request``: ``is_disconnected`` flips after ``disconnect_after`` polls."""

    def __init__(self, disconnect_after: int | None) -> None:
        self.disconnect_after = disconnect_after
        self.polls = 0

    async def is_disconnected(self) -> bool:
        self.polls += 1
        return self.disconnect_after is not None and self.polls > self.disconnect_after


class BlockingExec:
    """A driver call that blocks until cancelled and records that it was."""

    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.cancelled = False

    async def __call__(self) -> ExecResult:
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        raise AssertionError("unreachable")


@pytest.fixture
def fast_disconnect_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_routes, "DISCONNECT_POLL_INTERVAL_S", FAST_DISCONNECT_POLL_S)


def test_disconnect_poll_interval_defaults_to_half_a_second() -> None:
    assert process_routes.DISCONNECT_POLL_INTERVAL_S == 0.5


@pytest.mark.usefixtures("fast_disconnect_poll")
async def test_a_disconnected_client_cancels_the_exec_and_the_handler_returns(
    driver: FakeDriver, caplog: pytest.LogCaptureFixture
) -> None:
    blocking = BlockingExec()
    request: Any = FakeRequest(disconnect_after=2)
    sandbox: Any = type("Sbx", (), {"id": "sbx_gone", "driver_ref": None})()
    caplog.set_level("INFO", logger=process_routes.logger.name)

    outcome = await asyncio.wait_for(
        process_routes._run_until_disconnect(request, driver, sandbox, blocking()),
        timeout=PROMPT_RETURN_S,
    )

    assert blocking.started.is_set()
    assert blocking.cancelled is True
    assert outcome.result.exit_code == process_routes.CLIENT_GONE_EXIT_CODE
    assert outcome.stop_reason is None
    assert any(
        "client disconnected; exec cancelled" in record.getMessage()
        and "sbx_gone" in record.getMessage()
        for record in caplog.records
    )


@pytest.mark.usefixtures("fast_disconnect_poll")
async def test_a_connected_client_gets_the_result_and_the_watcher_is_cancelled(
    driver: FakeDriver,
) -> None:
    request = FakeRequest(disconnect_after=None)
    sandbox: Any = type("Sbx", (), {"id": "sbx_here", "driver_ref": None})()

    async def finishes_after_a_few_polls() -> ExecResult:
        while request.polls < 3:
            await asyncio.sleep(FAST_DISCONNECT_POLL_S)
        return ExecResult(exit_code=0, stdout=b"done")

    outcome = await process_routes._run_until_disconnect(
        request,  # type: ignore[arg-type]
        driver,
        sandbox,
        finishes_after_a_few_polls(),
    )
    polls_at_return = request.polls
    await asyncio.sleep(FAST_DISCONNECT_POLL_S * 10)

    assert outcome == process_routes.ExecOutcome(ExecResult(exit_code=0, stdout=b"done"))
    assert request.polls == polls_at_return  # the watcher stopped polling


@pytest.mark.usefixtures("fast_disconnect_poll")
async def test_an_exec_error_reaches_a_connected_client_unchanged(driver: FakeDriver) -> None:
    request = FakeRequest(disconnect_after=None)
    sandbox: Any = type("Sbx", (), {"id": "sbx_err", "driver_ref": None})()

    async def fails() -> ExecResult:
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        await process_routes._run_until_disconnect(
            request,  # type: ignore[arg-type]
            driver,
            sandbox,
            fails(),
        )
