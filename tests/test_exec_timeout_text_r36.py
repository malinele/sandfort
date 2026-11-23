"""The driver's timeout note starts on its own line and names no client parameter; exec and
code-run on a sandbox the caller or auto-stop stopped mid-run say so instead of a limit.

The stop half reuses the DB-backed app and helpers of ``test_stop_reason_delete_reset``.
"""

from typing import Any

import httpx
import pytest
from fastapi import FastAPI

import test_stop_reason_delete_reset as base
from sandfort.api.openapi import build_document
from sandfort.domain.sandbox import ERROR_CONTAINER_EXITED, SandboxState
from sandfort.drivers.base import ExecRequest, ExecResult, OutputChunk
from sandfort.drivers.docker.exec import (
    SANDBOX_DIED_MESSAGE,
    SANDBOX_STOPPED_MESSAGE,
    timeout_message,
    with_timeout_note,
)
from sandfort.drivers.fake import FakeDriver, timed_out_result

TIMEOUT_S = 3.0
TIMED_OUT_EXIT_CODE = 124

app = base.app
client = base.client
driver = base.driver
fast_settle = base.fast_settle
kicks = base.kicks
settles = base.settles
org_id = base.org_id
key = base.key

STOPPED_LINE = SANDBOX_STOPPED_MESSAGE.decode()
ROUTES = base.ROUTES


def timed_out_driver(stderr: bytes) -> FakeDriver:
    return FakeDriver(
        exec_handler=lambda env, request: timed_out_result(request, stderr=stderr),
    )


def test_partial_stderr_without_a_newline_gets_the_note_on_its_own_line() -> None:
    assert with_timeout_note(b"nonl", TIMEOUT_S) == b"nonl\n" + timeout_message(TIMEOUT_S)


def test_stderr_ending_in_a_newline_gets_no_extra_blank_line() -> None:
    assert with_timeout_note(b"line\n", TIMEOUT_S) == b"line\n" + timeout_message(TIMEOUT_S)


def test_empty_stderr_gets_no_leading_blank_line() -> None:
    assert with_timeout_note(b"", TIMEOUT_S) == timeout_message(TIMEOUT_S)


def test_a_note_already_present_is_not_added_again() -> None:
    once = with_timeout_note(b"nonl", TIMEOUT_S)

    assert with_timeout_note(once, TIMEOUT_S) == once


def test_the_note_names_no_parameter_and_keeps_the_token_and_maximum() -> None:
    note = timeout_message(TIMEOUT_S)

    assert b"timeout_s" not in note
    assert note == b"the command was stopped after 3 s (timeout); allow more time, up to 3600 s"


async def test_a_scripted_fake_timeout_puts_the_note_on_its_own_line() -> None:
    driver = timed_out_driver(b"nonl")
    ref = driver.plant_instance("sbx_text", "org_text")

    result = await driver.exec(ref, ExecRequest(argv=["x"], timeout_s=TIMEOUT_S))

    assert (result.exit_code, result.timed_out) == (TIMED_OUT_EXIT_CODE, True)
    assert result.stderr == b"nonl\n" + timeout_message(TIMEOUT_S)


async def test_a_scripted_fake_timeout_streams_the_note_without_a_blank_line() -> None:
    driver = timed_out_driver(b"")
    ref = driver.plant_instance("sbx_text", "org_text")
    request = ExecRequest(argv=["x"], timeout_s=TIMEOUT_S)

    events = [e async for e in driver.exec_stream(ref, request)]

    assert events[0] == OutputChunk("stderr", timeout_message(TIMEOUT_S))


# --- a sandbox stopped under the command ------------------------------------------------------


def bare_kill_after(driver: FakeDriver, monkeypatch: pytest.MonkeyPatch, change: Any) -> None:
    """The user's command writes ``change`` on the row, then ends with a plain SIGKILL (runc)."""
    original = driver.exec

    async def exec_(ref: str, request: ExecRequest) -> ExecResult:
        if request.argv[-1] != "stress" and request.argv[0] != "python3":
            return await original(ref, request)
        await change()
        return ExecResult(exit_code=137, stdout=b"partial", stderr=b"warn")

    monkeypatch.setattr(driver, "exec", exec_)


@pytest.mark.parametrize("state", [SandboxState.STOPPING, SandboxState.STOPPED])
@pytest.mark.parametrize(("route", "payload"), ROUTES)
async def test_a_sandbox_stopped_under_the_command_says_it_was_stopped(
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
    sandbox_id = await base.create_sandbox(client, key)
    base.die_after(driver, monkeypatch, base.change_row(app, org_id, sandbox_id, state=state))

    data = await base.run_dying(client, key, sandbox_id, route, payload)

    assert data["stop_reason"] == "sandbox_stopped"
    assert data["stderr"] == STOPPED_LINE
    assert STOPPED_LINE == "the sandbox was stopped while the command was running; start it again"
    assert "resource limit" not in data["stderr"]
    assert (kicks, settles) == ([], [])  # a stop on purpose is neither settled nor reconciled
    assert await base.row_state(app, org_id, sandbox_id) is state


@pytest.mark.parametrize(("route", "payload"), ROUTES)
async def test_a_plain_kill_from_a_stop_is_reported_as_stopped(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
    route: str,
    payload: dict[str, Any],
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    stopping = base.change_row(app, org_id, sandbox_id, state=SandboxState.STOPPING)
    bare_kill_after(driver, monkeypatch, stopping)

    data = await base.run_dying(client, key, sandbox_id, route, payload)

    assert data["stop_reason"] == "sandbox_stopped"
    assert data["stderr"] == f"warn\n{STOPPED_LINE}"


@pytest.mark.parametrize(("route", "payload"), ROUTES)
async def test_a_death_on_a_started_row_keeps_the_limit_wording(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
    route: str,
    payload: dict[str, Any],
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    base.die_after(driver, monkeypatch, base.no_change)

    data = await base.run_dying(client, key, sandbox_id, route, payload)

    assert data["stop_reason"] == "sandbox_stopped"
    assert data["stderr"] == SANDBOX_DIED_MESSAGE.decode()
    assert STOPPED_LINE not in data["stderr"]


async def test_a_death_the_reconciler_already_settled_keeps_the_limit_wording(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    settled = base.change_row(
        app, org_id, sandbox_id, state=SandboxState.STOPPED, error_code=ERROR_CONTAINER_EXITED
    )
    base.die_after(driver, monkeypatch, settled)

    data = await base.run_dying(client, key, sandbox_id, "execute", {"command": "stress"})

    assert data["stop_reason"] == "sandbox_stopped"
    assert data["stderr"] == SANDBOX_DIED_MESSAGE.decode()


async def test_a_plain_kill_on_a_started_row_stays_killed(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    bare_kill_after(driver, monkeypatch, base.no_change)
    path = f"{base.BASE}/{sandbox_id}/toolbox/process/execute"

    data = await base.send(client, "POST", path, key, json={"command": "stress"})

    assert (data["stop_reason"], data["sandbox_stopped"]) == ("killed", False)
    assert data["stderr"] == "warn"


def test_the_openapi_stop_reason_text_names_a_stop_and_a_limit() -> None:
    description = build_document()["info"]["description"]
    line = next(row for row in description.splitlines() if row.startswith("- `sandbox_stopped`"))

    assert "auto-stop" in line
    assert "resource limit" in line
