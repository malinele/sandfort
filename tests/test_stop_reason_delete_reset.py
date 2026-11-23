"""A sandbox deleted or reset under a synchronous exec or code run reports why it stopped.

The driver only sees its container die and says so with an OOM hint (``SANDBOX_DIED_MESSAGE``).
The process routes re-read the row: destroying/destroyed means ``sandbox_deleted``, a changed
``driver_ref`` means ``sandbox_reset``. Neither is settled nor reconciled. Exit code 137 and
``sandbox_stopped`` stay as they were.
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
    STOP_REASON_SANDBOX_DELETED,
    STOP_REASON_SANDBOX_RESET,
    STOP_REASON_SANDBOX_STOPPED,
    execute_response,
)
from sandfort.api.wiring import RECONCILER_ATTR
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import SandboxState
from sandfort.drivers.base import ExecRequest, ExecResult
from sandfort.drivers.docker.exec import SANDBOX_DIED_MESSAGE
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
OOM_TEXT = "a resource limit was hit"
DELETED_LINE = "the sandbox was deleted while running this command"
RESET_LINE = "the sandbox was reset while running this command"
NEW_REF = "fake-replacement-container"

ROUTES = [
    pytest.param("execute", {"command": "stress"}, id="execute"),
    pytest.param("code-run", {"language": "python", "code": "print(1)"}, id="code-run"),
]

RowChange = Callable[[], Awaitable[None]]


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'stop_reason.db'}"
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


def die_after(driver: FakeDriver, monkeypatch: pytest.MonkeyPatch, change: RowChange) -> None:
    """The user's command writes ``change`` on the row, then dies as the Docker driver reports."""
    original = driver.exec

    async def exec_(ref: str, request: ExecRequest) -> ExecResult:
        if request.argv[-1] != "stress" and request.argv[0] != "python3":
            return await original(ref, request)
        await change()
        return ExecResult(
            exit_code=137, stdout=b"partial", stderr=SANDBOX_DIED_MESSAGE, sandbox_stopped=True
        )

    monkeypatch.setattr(driver, "exec", exec_)


async def run_dying(
    client: httpx.AsyncClient, key: str, sandbox_id: str, route: str, payload: dict[str, Any]
) -> dict[str, Any]:
    path = f"{BASE}/{sandbox_id}/toolbox/process/{route}"
    data = await send(client, "POST", path, key, json=payload)
    assert data["exit_code"] == 137  # kept, so existing clients keep working
    assert data["sandbox_stopped"] is True
    assert data["stdout"] == "partial"
    return data


async def row_state(app: FastAPI, org_id: str, sandbox_id: str) -> SandboxState:
    async with UnitOfWork(app.state.session_factory) as uow:
        row = await uow.sandboxes.get(org_id, sandbox_id)
    assert row is not None
    return row.state


# --- deleted ------------------------------------------------------------------------------


@pytest.mark.parametrize("state", [SandboxState.DESTROYING, SandboxState.DESTROYED])
@pytest.mark.parametrize(("route", "payload"), ROUTES)
async def test_a_sandbox_deleted_under_the_command_reports_sandbox_deleted(
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
    state: SandboxState,
) -> None:
    sandbox_id = await create_sandbox(client, key)
    die_after(driver, monkeypatch, change_row(app, org_id, sandbox_id, state=state))

    data = await run_dying(client, key, sandbox_id, route, payload)

    assert data["stop_reason"] == STOP_REASON_SANDBOX_DELETED
    assert data["stderr"] == DELETED_LINE
    assert OOM_TEXT not in data["stderr"]
    assert (kicks, settles) == ([], [])
    assert await row_state(app, org_id, sandbox_id) is state  # not settled to stopped


# --- reset --------------------------------------------------------------------------------


@pytest.mark.parametrize(("route", "payload"), ROUTES)
async def test_a_sandbox_reset_under_the_command_reports_sandbox_reset(
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
    die_after(driver, monkeypatch, change_row(app, org_id, sandbox_id, driver_ref=NEW_REF))

    data = await run_dying(client, key, sandbox_id, route, payload)

    assert data["stop_reason"] == STOP_REASON_SANDBOX_RESET
    assert data["stderr"] == RESET_LINE
    assert OOM_TEXT not in data["stderr"]
    assert (kicks, settles) == ([], [])
    assert await row_state(app, org_id, sandbox_id) is SandboxState.STARTED


async def test_a_deleted_row_wins_over_a_changed_driver_ref(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
    kicks: list[str],
) -> None:
    sandbox_id = await create_sandbox(client, key)
    change = change_row(app, org_id, sandbox_id, state=SandboxState.DESTROYING, driver_ref=NEW_REF)
    die_after(driver, monkeypatch, change)

    data = await run_dying(client, key, sandbox_id, "execute", {"command": "stress"})

    assert data["stop_reason"] == STOP_REASON_SANDBOX_DELETED
    assert data["stderr"] == DELETED_LINE


# --- unexplained death: today's answer --------------------------------------------------------


@pytest.mark.parametrize(("route", "payload"), ROUTES)
async def test_an_unchanged_started_row_keeps_sandbox_stopped_and_the_driver_message(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
    kicks: list[str],
    route: str,
    payload: dict[str, Any],
) -> None:
    sandbox_id = await create_sandbox(client, key)
    die_after(driver, monkeypatch, no_change)

    data = await run_dying(client, key, sandbox_id, route, payload)

    assert data["stop_reason"] == STOP_REASON_SANDBOX_STOPPED
    assert data["stderr"] == SANDBOX_DIED_MESSAGE.decode()
    assert kicks == ["kick"]  # the fake instance still runs, so settling falls back to kicks


async def test_a_failed_re_read_keeps_todays_answer(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
    kicks: list[str],
) -> None:
    sandbox_id = await create_sandbox(client, key)
    die_after(driver, monkeypatch, change_row(app, org_id, sandbox_id, driver_ref=NEW_REF))

    def broken_uow(request: Any) -> Any:
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(process_routes, "get_uow", broken_uow)  # route Depends keep the original

    data = await run_dying(client, key, sandbox_id, "execute", {"command": "stress"})

    assert data["stop_reason"] == STOP_REASON_SANDBOX_STOPPED
    assert data["stderr"] == SANDBOX_DIED_MESSAGE.decode()
    assert kicks == ["kick"]


# --- unit: stderr rewrite and the response override ------------------------------------------


def test_the_death_line_is_replaced_in_place_and_other_output_is_kept() -> None:
    stderr = b"warn\n" + SANDBOX_DIED_MESSAGE + b"\ntail"
    result = ExecResult(exit_code=137, stderr=stderr, sandbox_stopped=True)

    explained = process_routes._explain_gone(result, STOP_REASON_SANDBOX_RESET)

    assert explained.stderr == b"warn\n" + RESET_LINE.encode() + b"\ntail"
    assert (explained.exit_code, explained.sandbox_stopped) == (137, True)


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        (b"", DELETED_LINE.encode()),
        (b"boom", b"boom\n" + DELETED_LINE.encode()),
        (b"boom\n", b"boom\n" + DELETED_LINE.encode()),
    ],
)
def test_without_a_death_line_the_reason_line_is_appended(stderr: bytes, expected: bytes) -> None:
    result = ExecResult(exit_code=137, stderr=stderr, sandbox_stopped=True)

    explained = process_routes._explain_gone(result, STOP_REASON_SANDBOX_DELETED)

    assert explained.stderr == expected


@pytest.mark.parametrize("reason", [STOP_REASON_SANDBOX_DELETED, STOP_REASON_SANDBOX_RESET])
def test_the_response_builder_reports_an_explicit_stop_reason(reason: str) -> None:
    result = ExecResult(exit_code=137, sandbox_stopped=True)

    response = execute_response(result, stop_reason=reason)

    assert response.stop_reason == reason
    assert (response.exit_code, response.sandbox_stopped) == (137, True)


def test_an_explicit_reason_survives_revalidation_of_the_response() -> None:
    response = execute_response(
        ExecResult(exit_code=137, sandbox_stopped=True), stop_reason=STOP_REASON_SANDBOX_RESET
    )

    again = type(response).model_validate(response.model_dump())  # as FastAPI does on return

    assert again.stop_reason == STOP_REASON_SANDBOX_RESET


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (ExecResult(exit_code=137, truncated=True, sandbox_stopped=True), "output_limit"),
        (ExecResult(exit_code=124, timed_out=True), "timeout"),
        (ExecResult(exit_code=137), "killed"),
        (ExecResult(exit_code=0), None),
    ],
)
def test_an_override_never_replaces_another_derived_reason(
    result: ExecResult, expected: str | None
) -> None:
    response = execute_response(result, stop_reason=STOP_REASON_SANDBOX_DELETED)

    assert response.stop_reason == expected
