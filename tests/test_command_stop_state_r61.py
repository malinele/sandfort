"""Round 61: an async command ended by a sandbox stop reads ``killed`` with a stop cause.

A command the sandbox stop cut short used to read ``exited`` / 137, like a command that sent
itself SIGKILL. Now it reads state ``killed``, ``exit_code`` null and ``stop_cause``
``sandbox_stopped`` (also on the final SSE ``exit`` event and the log page). Commands that ended
on their own, died under a limit while the sandbox kept running, or were killed through the kill
route keep their earlier answer, with ``stop_cause`` null.

Daemon-free: temp SQLite, ``httpx.ASGITransport``, ``FakeDriver`` with a scripted exec stream.
"""

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
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
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.drivers.base import ExecEvent, ExecRequest, ExitEvent, OutputChunk
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.toolbox.sessions import SessionService

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
STOP_CAUSE = "sandbox_stopped"


# --- fixtures ---------------------------------------------------------------------


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'stop-state.db'}"
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
async def key(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=FULL_ACCESS,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


@dataclass
class Gate:
    """A scripted exec stream: emits one chunk, waits for ``release``, then ends as told."""

    exit_event: ExitEvent = field(default_factory=lambda: ExitEvent(137, sandbox_stopped=True))
    release: asyncio.Event = field(default_factory=asyncio.Event)
    abandoned: bool = False


@pytest.fixture
def gate(app: FastAPI, monkeypatch: pytest.MonkeyPatch) -> Gate:
    driver = app.state.driver
    assert isinstance(driver, FakeDriver)
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
        yield scripted.exit_event

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


@dataclass(frozen=True)
class Running:
    sandbox_id: str
    path: str  # the command's status path


async def start_running(client: httpx.AsyncClient, key: str) -> Running:
    created = await send(client, "POST", BASE, key, status=201, json={})
    sandbox_id: str = created["data"]["id"]
    sessions = f"{BASE}/{sandbox_id}/toolbox/process/sessions"
    session = await send(client, "POST", sessions, key, status=201, json={})
    session_path = f"{sessions}/{session['data']['id']}"
    started = await send(
        client,
        "POST",
        f"{session_path}/commands?async=true",
        key,
        status=202,
        json={"command": "sleep 3600"},
    )
    assert started["data"]["command"]["state"] == "running"
    assert started["data"]["command"].get("stop_cause") is None
    return Running(sandbox_id, f"{session_path}/commands/{started['data']['command']['id']}")


async def wait_finished(client: httpx.AsyncClient, key: str, path: str) -> dict[str, Any]:
    for _ in range(300):
        data: dict[str, Any] = (await send(client, "GET", path, key, status=200))["data"]
        if data["state"] != "running":
            return data
        await asyncio.sleep(0.01)
    raise AssertionError("command never finished")


async def stop_sandbox(client: httpx.AsyncClient, key: str, sandbox_id: str) -> None:
    await send(client, "POST", f"{BASE}/{sandbox_id}/stop", key, status=200)


def parse_sse(text: str) -> list[dict[str, str]]:
    frames = []
    for block in text.split("\n\n"):
        if block.strip() and not block.startswith(":"):
            frames.append(dict(line.split(": ", 1) for line in block.split("\n")))
    return frames


async def final_exit_event(client: httpx.AsyncClient, key: str, path: str) -> dict[str, Any]:
    response = await client.get(path + "/logs/follow", headers=auth(key))
    frames = parse_sse(response.text)
    assert frames[-1]["event"] == "exit"
    final: dict[str, Any] = json.loads(frames[-1]["data"])
    return final


# --- a stop ends the command ------------------------------------------------------


async def test_sandbox_stop_reads_killed_without_exit_code_and_names_the_cause(
    client: httpx.AsyncClient, key: str, gate: Gate
) -> None:
    run = await start_running(client, key)
    await stop_sandbox(client, key, run.sandbox_id)

    gate.release.set()
    status = await wait_finished(client, key, run.path)

    assert (status["state"], status["exit_code"]) == ("killed", None)
    assert status["stop_cause"] == STOP_CAUSE
    assert status["finished_at"] is not None
    assert status["stdout_bytes"] == len(b"partial\n")


async def test_the_stop_answer_is_stable_on_later_reads_and_in_the_log_page(
    client: httpx.AsyncClient, key: str, gate: Gate
) -> None:
    run = await start_running(client, key)
    await stop_sandbox(client, key, run.sandbox_id)
    gate.release.set()
    await wait_finished(client, key, run.path)

    again = (await send(client, "GET", run.path, key, status=200))["data"]
    page = (await send(client, "GET", run.path + "/logs", key, status=200))["data"]

    assert (again["state"], again["exit_code"], again["stop_cause"]) == ("killed", None, STOP_CAUSE)
    assert (page["state"], page["exit_code"], page["complete"]) == ("killed", None, True)
    assert page["stop_cause"] == STOP_CAUSE


async def test_follow_stream_ends_with_an_exit_event_that_carries_the_stop_cause(
    client: httpx.AsyncClient, key: str, gate: Gate
) -> None:
    run = await start_running(client, key)
    await stop_sandbox(client, key, run.sandbox_id)
    gate.release.set()
    await wait_finished(client, key, run.path)

    final = await final_exit_event(client, key, run.path)

    assert (final["state"], final["exit_code"], final["stop_cause"]) == ("killed", None, STOP_CAUSE)


async def test_a_follower_attached_before_the_stop_gets_the_cause_on_its_exit_event(
    client: httpx.AsyncClient, key: str, gate: Gate
) -> None:
    run = await start_running(client, key)
    follower = asyncio.create_task(final_exit_event(client, key, run.path))
    await asyncio.sleep(0.05)
    await stop_sandbox(client, key, run.sandbox_id)
    gate.release.set()

    final = await asyncio.wait_for(follower, 5)

    assert (final["state"], final["exit_code"], final["stop_cause"]) == ("killed", None, STOP_CAUSE)


# --- everything else keeps today's answer -----------------------------------------


async def test_a_command_that_sigkills_itself_still_reads_exited_137(
    client: httpx.AsyncClient, key: str, gate: Gate
) -> None:
    gate.exit_event = ExitEvent(137)
    run = await start_running(client, key)

    gate.release.set()
    status = await wait_finished(client, key, run.path)

    assert (status["state"], status["exit_code"]) == ("exited", 137)
    assert status.get("stop_cause") is None
    final = await final_exit_event(client, key, run.path)
    assert (final["state"], final["exit_code"], final.get("stop_cause")) == ("exited", 137, None)


async def test_a_death_under_a_limit_while_the_sandbox_keeps_running_stays_exited(
    client: httpx.AsyncClient, key: str, gate: Gate
) -> None:
    run = await start_running(client, key)  # driver reports sandbox_stopped, the row stays started

    gate.release.set()
    status = await wait_finished(client, key, run.path)

    assert (status["state"], status["exit_code"]) == ("exited", 137)
    assert status.get("stop_cause") is None


async def test_a_command_that_ended_before_the_stop_keeps_its_exit_code(
    client: httpx.AsyncClient, key: str, gate: Gate
) -> None:
    gate.exit_event = ExitEvent(0)
    run = await start_running(client, key)
    gate.release.set()
    before = await wait_finished(client, key, run.path)

    await stop_sandbox(client, key, run.sandbox_id)
    after = (await send(client, "GET", run.path, key, status=200))["data"]

    assert (before["state"], before["exit_code"]) == ("exited", 0)
    assert (after["state"], after["exit_code"]) == ("exited", 0)
    assert after.get("stop_cause") is None


async def test_the_kill_route_still_reads_killed_without_a_stop_cause(
    client: httpx.AsyncClient, key: str, gate: Gate
) -> None:
    run = await start_running(client, key)

    killed = await send(client, "POST", run.path + "/kill", key, status=200)

    assert gate.abandoned is True
    assert (killed["data"]["state"], killed["data"]["exit_code"]) == ("killed", None)
    assert killed["data"].get("stop_cause") is None
    status = (await send(client, "GET", run.path, key, status=200))["data"]
    assert (status["state"], status["exit_code"], status.get("stop_cause")) == (
        "killed",
        None,
        None,
    )


async def test_a_kill_after_a_stop_ended_the_command_keeps_the_stop_answer(
    client: httpx.AsyncClient, key: str, gate: Gate
) -> None:
    run = await start_running(client, key)
    await stop_sandbox(client, key, run.sandbox_id)
    gate.release.set()
    await wait_finished(client, key, run.path)
    await send(client, "POST", f"{BASE}/{run.sandbox_id}/start", key, status=200)

    again = await send(client, "POST", run.path + "/kill", key, status=200)

    assert (again["data"]["state"], again["data"]["exit_code"]) == ("killed", None)
    assert again["data"]["stop_cause"] == STOP_CAUSE


# --- the kill wins the finish update ----------------------------------------------


@dataclass
class FinishHold:
    """Holds the first ``_finish`` call (the pump's) until released; later calls pass through."""

    entered: asyncio.Event = field(default_factory=asyncio.Event)
    proceed: asyncio.Event = field(default_factory=asyncio.Event)
    calls: int = 0


@pytest.fixture
def finish_hold(monkeypatch: pytest.MonkeyPatch) -> FinishHold:
    hold = FinishHold()
    original = SessionService._finish

    async def held(self: SessionService, *args: Any, **kwargs: Any) -> Any:
        hold.calls += 1
        if hold.calls == 1:
            hold.entered.set()
            await hold.proceed.wait()
        return await original(self, *args, **kwargs)

    monkeypatch.setattr(SessionService, "_finish", held)
    return hold


async def test_a_user_kill_that_wins_the_finish_update_carries_no_stop_cause(
    client: httpx.AsyncClient, key: str, gate: Gate, finish_hold: FinishHold
) -> None:
    run = await start_running(client, key)
    await stop_sandbox(client, key, run.sandbox_id)
    gate.release.set()
    await asyncio.wait_for(finish_hold.entered.wait(), 5)  # the pump sits inside its finish
    await send(client, "POST", f"{BASE}/{run.sandbox_id}/start", key, status=200)

    killed = await send(client, "POST", run.path + "/kill", key, status=200)

    assert (killed["data"]["state"], killed["data"]["exit_code"]) == ("killed", None)
    assert killed["data"].get("stop_cause") is None
    status = (await send(client, "GET", run.path, key, status=200))["data"]
    assert (status["state"], status.get("stop_cause")) == ("killed", None)
    final = await final_exit_event(client, key, run.path)
    assert (final["state"], final.get("stop_cause")) == ("killed", None)


async def test_the_stop_still_wins_when_the_finish_runs_to_completion_after_a_pause(
    client: httpx.AsyncClient, key: str, gate: Gate, finish_hold: FinishHold
) -> None:
    run = await start_running(client, key)
    await stop_sandbox(client, key, run.sandbox_id)
    gate.release.set()
    await asyncio.wait_for(finish_hold.entered.wait(), 5)

    finish_hold.proceed.set()
    status = await wait_finished(client, key, run.path)

    assert (status["state"], status["exit_code"]) == ("killed", None)
    assert status["stop_cause"] == STOP_CAUSE


# --- additive schema --------------------------------------------------------------


async def test_stop_cause_is_an_optional_additive_field_in_the_openapi_schema(
    client: httpx.AsyncClient,
) -> None:
    spec = (await client.get("/openapi.json")).json()
    schemas = spec["components"]["schemas"]
    carriers = [
        schema
        for schema in schemas.values()
        if "stop_cause" in schema.get("properties", {}) and "exit_code" in schema["properties"]
    ]

    assert carriers, "no command schema carries stop_cause"
    for schema in carriers:
        assert "stop_cause" not in schema.get("required", [])
