"""A bare SIGKILL result on a sandbox deleted or reset meanwhile also reports why.

The driver cannot always tell an exec cut short by a delete or reset from a plain SIGKILL: the
result is exit 137 with empty stderr and ``sandbox_stopped`` false. The process routes run the
same row check for such a result as for a ``sandbox_stopped`` one. A named reason wins and the
row is neither settled nor reconciled; with no reason the bare kill stays ``killed``.
"""

from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
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
    KILLED_EXIT_CODE,
    STOP_REASON_KILLED,
    STOP_REASON_SANDBOX_DELETED,
    STOP_REASON_SANDBOX_RESET,
    STOP_REASON_TIMEOUT,
)
from sandfort.api.wiring import RECONCILER_ATTR
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import SandboxState
from sandfort.drivers.base import ExecRequest, ExecResult
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
DELETED_LINE = "the sandbox was deleted while running this command"
RESET_LINE = "the sandbox was reset while running this command"
NEW_REF = "fake-replacement-container"
BARE_KILL = ExecResult(exit_code=KILLED_EXIT_CODE, stdout=b"partial")

ROUTES = [
    pytest.param("execute", {"command": "stress"}, id="execute"),
    pytest.param("code-run", {"language": "python", "code": "print(1)"}, id="code-run"),
]

RowChange = Callable[[], Awaitable[None]]


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'killed_gone.db'}"
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


@pytest.fixture(autouse=True)
def fast_settle(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dead_sandbox, "SETTLE_TIMEOUT_S", 0.1)
    monkeypatch.setattr(dead_sandbox, "SETTLE_POLL_INTERVAL_S", 0.02)


@pytest.fixture
def kicks(app: FastAPI, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    seen: list[str] = []
    reconciler = getattr(app.state, RECONCILER_ATTR)
    monkeypatch.setattr(reconciler, "kick", lambda: seen.append("kick"))
    return seen


@pytest.fixture
def settles(app: FastAPI, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    seen: list[str] = []
    reconciler = getattr(app.state, RECONCILER_ATTR)
    original = reconciler.mark_stopped_unexpectedly

    async def spy(row: Any) -> bool:
        seen.append(row.id)
        return bool(await original(row))

    monkeypatch.setattr(reconciler, "mark_stopped_unexpectedly", spy)
    return seen


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
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


async def send(
    client: httpx.AsyncClient, method: str, path: str, key: str, **kwargs: Any
) -> dict[str, Any]:
    response = await client.request(
        method, path, headers={"Authorization": f"Bearer {key}"}, **kwargs
    )
    assert response.status_code < 300, response.text
    data: dict[str, Any] = response.json()["data"]
    return data


async def create_sandbox(client: httpx.AsyncClient, key: str) -> str:
    data = await send(client, "POST", BASE, key, json={})
    sandbox_id: str = data["id"]
    return sandbox_id


def change_row(app: FastAPI, org_id: str, sandbox_id: str, **changes: Any) -> RowChange:
    """A coroutine factory that writes ``changes`` on the row, as a delete or a reset would."""

    async def apply() -> None:
        async with UnitOfWork(app.state.session_factory) as uow:
            row = await uow.sandboxes.get(org_id, sandbox_id)
            assert row is not None
            await uow.sandboxes.update(
                org_id, row.model_copy(update=changes), expected_version=row.version
            )
            await uow.commit()

    return apply


async def no_change() -> None:
    return None


def end_with(
    driver: FakeDriver, monkeypatch: pytest.MonkeyPatch, change: RowChange, result: ExecResult
) -> None:
    """The user's command writes ``change`` on the row, then ends with exactly ``result``."""
    original = driver.exec

    async def exec_(ref: str, request: ExecRequest) -> ExecResult:
        if request.argv[-1] != "stress" and request.argv[0] != "python3":
            return await original(ref, request)
        await change()
        return result

    monkeypatch.setattr(driver, "exec", exec_)


async def run(
    client: httpx.AsyncClient, key: str, sandbox_id: str, route: str, payload: dict[str, Any]
) -> dict[str, Any]:
    return await send(
        client, "POST", f"{BASE}/{sandbox_id}/toolbox/process/{route}", key, json=payload
    )


async def row_state(app: FastAPI, org_id: str, sandbox_id: str) -> SandboxState:
    async with UnitOfWork(app.state.session_factory) as uow:
        row = await uow.sandboxes.get(org_id, sandbox_id)
    assert row is not None
    return row.state


@pytest.mark.parametrize(("route", "payload"), ROUTES)
async def test_a_bare_kill_on_a_deleted_row_reports_sandbox_deleted(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
    kicks: list[str],
    settles: list[str],
    route: str,
    payload: dict[str, Any],
) -> None:
    sandbox_id = await create_sandbox(client, key)
    change = change_row(app, org_id, sandbox_id, state=SandboxState.DESTROYING)
    end_with(driver, monkeypatch, change, BARE_KILL)

    data = await run(client, key, sandbox_id, route, payload)

    assert data["stop_reason"] == STOP_REASON_SANDBOX_DELETED
    assert data["stderr"] == DELETED_LINE
    assert data["exit_code"] == KILLED_EXIT_CODE
    assert data["stdout"] == "partial"
    assert (kicks, settles) == ([], [])
    assert await row_state(app, org_id, sandbox_id) is SandboxState.DESTROYING


@pytest.mark.parametrize(("route", "payload"), ROUTES)
async def test_a_bare_kill_on_a_row_with_a_new_driver_ref_reports_sandbox_reset(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
    kicks: list[str],
    settles: list[str],
    route: str,
    payload: dict[str, Any],
) -> None:
    sandbox_id = await create_sandbox(client, key)
    change = change_row(app, org_id, sandbox_id, driver_ref=NEW_REF)
    end_with(driver, monkeypatch, change, BARE_KILL)

    data = await run(client, key, sandbox_id, route, payload)

    assert data["stop_reason"] == STOP_REASON_SANDBOX_RESET
    assert data["stderr"] == RESET_LINE
    assert data["exit_code"] == KILLED_EXIT_CODE
    assert (kicks, settles) == ([], [])
    assert await row_state(app, org_id, sandbox_id) is SandboxState.STARTED


async def test_a_bare_kill_keeps_its_own_stderr_before_the_reason_line(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox_id = await create_sandbox(client, key)
    change = change_row(app, org_id, sandbox_id, state=SandboxState.DESTROYED)
    result = ExecResult(exit_code=KILLED_EXIT_CODE, stderr=b"Killed")
    end_with(driver, monkeypatch, change, result)

    data = await run(client, key, sandbox_id, "execute", {"command": "stress"})

    assert data["stderr"] == f"Killed\n{DELETED_LINE}"
    assert data["stop_reason"] == STOP_REASON_SANDBOX_DELETED


@pytest.mark.parametrize(("route", "payload"), ROUTES)
async def test_a_bare_kill_on_an_unchanged_started_row_stays_killed(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
    kicks: list[str],
    settles: list[str],
    route: str,
    payload: dict[str, Any],
) -> None:
    sandbox_id = await create_sandbox(client, key)
    end_with(driver, monkeypatch, no_change, BARE_KILL)

    data = await run(client, key, sandbox_id, route, payload)

    assert data["stop_reason"] == STOP_REASON_KILLED
    assert data["stderr"] == ""  # no line added
    assert data["sandbox_stopped"] is False
    assert (kicks, settles) == ([], [])
    assert await row_state(app, org_id, sandbox_id) is SandboxState.STARTED


async def test_a_timed_out_result_is_not_checked_against_the_row(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
    kicks: list[str],
    settles: list[str],
) -> None:
    sandbox_id = await create_sandbox(client, key)
    change = change_row(app, org_id, sandbox_id, state=SandboxState.DESTROYING)
    result = ExecResult(exit_code=KILLED_EXIT_CODE, timed_out=True)
    end_with(driver, monkeypatch, change, result)
    checked: list[str] = []
    original = process_routes._gone_reason

    async def spy(request: Any, sandbox: Any) -> str | None:
        checked.append(sandbox.id)
        return await original(request, sandbox)

    monkeypatch.setattr(process_routes, "_gone_reason", spy)

    data = await run(client, key, sandbox_id, "execute", {"command": "stress"})

    assert data["stop_reason"] == STOP_REASON_TIMEOUT
    assert data["stderr"] == ""
    assert data["timed_out"] is True
    assert checked == []
    assert (kicks, settles) == ([], [])
