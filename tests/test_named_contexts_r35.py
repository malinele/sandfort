"""Round 35: named code contexts (idempotent create, ``?name=``, SDK ``ensure``) and the
hard-kill message that names the caller's limit. FakeDriver plus the scripted sandbox shell of
``test_code_contexts_api``; the SDK half uses ``httpx.MockTransport``."""

import asyncio
import json
import sys
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

import test_code_contexts_api as base
from sandfort.api.routes.toolbox import code_contexts as code_context_routes
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.sandbox import ERROR_CONTAINER_EXITED, SandboxState
from sandfort.drivers.base import ExecRequest, ExecResult
from sandfort.drivers.docker.exec import SANDBOX_DIED_MESSAGE, timeout_message
from sandfort.drivers.errors import DriverConflict, DriverError, DriverNotFound, DriverTimeout
from sandfort.errors import Conflict
from sandfort.toolbox import code_context_stream, code_contexts, stop_wording
from test_code_contexts_api import SandboxShell

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

from sandfort_sdk._transport import AsyncTransport, SyncTransport, client_kwargs  # noqa: E402
from sandfort_sdk.code_contexts import AsyncCodeContexts, CodeContexts  # noqa: E402

app = base.app
client = base.client
driver = base.driver
shell = base.shell
org_id = base.org_id
key = base.key
quick_interrupt_wait = base.quick_interrupt_wait

NAME = "analysis.v1"


async def create_named(
    client: httpx.AsyncClient, key: str, sandbox_id: str, name: str, *, status: int, **extra: Any
) -> dict[str, Any]:
    body = await base.send(
        client,
        "POST",
        base.contexts_path(sandbox_id),
        key,
        status=status,
        json={"name": name, **extra},
    )
    data: dict[str, Any] = body["data"]
    return data


async def listed(
    client: httpx.AsyncClient, key: str, sandbox_id: str, query: str = ""
) -> list[dict[str, Any]]:
    path = base.contexts_path(sandbox_id) + query
    data: list[dict[str, Any]] = (await base.send(client, "GET", path, key, status=200))["data"]
    return data


def restart_kills_the_kernels(shell: SandboxShell) -> None:
    """A stop ends every kernel process; ``/tmp`` keeps their directories but none is live."""
    shell.alive.clear()
    shell.ready.clear()


async def restart(
    client: httpx.AsyncClient, key: str, sandbox_id: str, shell: SandboxShell
) -> None:
    await base.send(client, "POST", f"{base.BASE}/{sandbox_id}/stop", key, status=200)
    restart_kills_the_kernels(shell)
    await base.send(client, "POST", f"{base.BASE}/{sandbox_id}/start", key, status=200)


# --- create with a name -----------------------------------------------------------------


async def test_a_named_create_returns_the_name_and_the_list_shows_it(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    unnamed = await base.create_context(client, key, sandbox_id)

    created = await create_named(client, key, sandbox_id, NAME, status=201, cwd="/data")

    assert created["name"] == NAME
    assert created["cwd"] == "/data"
    items = {item["id"]: item for item in await listed(client, key, sandbox_id)}
    assert items[created["id"]] == {
        "id": created["id"],
        "language": "python",
        "cwd": "/data",
        "name": NAME,
    }
    assert "name" not in items[unnamed]  # an unnamed context carries no name


async def test_the_name_is_stored_in_the_context_directory(
    client: httpx.AsyncClient, key: str, driver: Any, shell: SandboxShell
) -> None:
    sandbox_id = await base.create_sandbox(client, key)

    created = await create_named(client, key, sandbox_id, NAME, status=201)

    directory = code_contexts.context_dir(created["id"])
    stored = await base.read_uploaded(driver, f"{directory}/{code_contexts.NAME_FILE}")
    assert stored == NAME


async def test_a_second_create_with_the_same_name_returns_the_same_context(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    first = await create_named(client, key, sandbox_id, NAME, status=201)

    again = await create_named(client, key, sandbox_id, NAME, status=200, cwd="/elsewhere")

    assert again == first  # cwd is not compared; the live context is returned as it is
    assert len(shell.starts) == 1
    assert len(await listed(client, key, sandbox_id)) == 1


async def test_a_new_name_creates_a_new_context(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    first = await create_named(client, key, sandbox_id, NAME, status=201)

    other = await create_named(client, key, sandbox_id, "other", status=201)

    assert other["id"] != first["id"]
    assert len(shell.starts) == 2


async def test_two_concurrent_creates_with_one_name_start_one_kernel(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    headers = {"Authorization": f"Bearer {key}"}
    path = base.contexts_path(sandbox_id)

    responses = await asyncio.gather(
        *(client.post(path, headers=headers, json={"name": NAME}) for _ in range(2))
    )

    assert sorted(r.status_code for r in responses) == [200, 201]
    assert len({r.json()["data"]["id"] for r in responses}) == 1
    assert len(shell.starts) == 1


@pytest.mark.parametrize("name", ["", "-lead", "has space", "a/b", "x" * 64])
async def test_an_invalid_name_is_unprocessable(
    client: httpx.AsyncClient, key: str, shell: SandboxShell, name: str
) -> None:
    sandbox_id = await base.create_sandbox(client, key)

    body = await base.send(
        client, "POST", base.contexts_path(sandbox_id), key, status=422, json={"name": name}
    )

    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert shell.starts == []


async def test_a_named_create_is_audited_with_its_name(
    app: Any, client: httpx.AsyncClient, org_id: str, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await base.create_sandbox(client, key)

    await create_named(client, key, sandbox_id, NAME, status=201)
    await create_named(client, key, sandbox_id, NAME, status=200)

    events = [
        e for e in await base.audit_rows(app, org_id) if e.action == "toolbox.code_contexts.create"
    ]
    assert [e.details["name"] for e in events] == [NAME, NAME]


# --- lookup by name ---------------------------------------------------------------------


async def test_the_list_filters_by_name(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    wanted = await create_named(client, key, sandbox_id, NAME, status=201)
    await create_named(client, key, sandbox_id, "other", status=201)
    await base.create_context(client, key, sandbox_id)

    found = await listed(client, key, sandbox_id, f"?name={NAME}")
    missing = await listed(client, key, sandbox_id, "?name=nobody")

    assert [item["id"] for item in found] == [wanted["id"]]
    assert missing == []


async def test_an_invalid_name_filter_is_unprocessable(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await base.create_sandbox(client, key)

    path = base.contexts_path(sandbox_id) + "?name=a%2Fb"
    body = await base.send(client, "GET", path, key, status=422)

    assert body["error"]["code"] == "VALIDATION_ERROR"


async def test_a_name_file_that_is_not_a_valid_name_reads_as_unnamed(
    client: httpx.AsyncClient, key: str, driver: Any, shell: SandboxShell
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    created = await create_named(client, key, sandbox_id, NAME, status=201)
    [instance] = await driver.list_managed()
    path = f"{code_contexts.context_dir(created['id'])}/{code_contexts.NAME_FILE}"
    driver._instances[instance.ref].files[path] = b"bad name\n"  # rewritten inside the sandbox

    [item] = await listed(client, key, sandbox_id)

    assert "name" not in item


def fail_name_reads(monkeypatch: pytest.MonkeyPatch, driver: Any, error: DriverError) -> None:
    """Make every read of a context's name file raise ``error``; other reads are untouched."""
    original = driver.get_archive

    def get_archive(ref: str, path: str) -> AsyncIterator[bytes]:
        if path.endswith(f"/{code_contexts.NAME_FILE}"):

            async def failing() -> AsyncIterator[bytes]:
                raise error
                yield b""  # makes this an async generator

            return failing()
        result: AsyncIterator[bytes] = original(ref, path)
        return result

    monkeypatch.setattr(driver, "get_archive", get_archive)


async def test_a_transient_name_read_error_makes_ensure_fail_without_a_duplicate(
    client: httpx.AsyncClient,
    key: str,
    driver: Any,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    first = await create_named(client, key, sandbox_id, NAME, status=201)
    fail_name_reads(monkeypatch, driver, DriverTimeout("the daemon did not answer"))

    body = await base.send(
        client, "POST", base.contexts_path(sandbox_id), key, status=504, json={"name": NAME}
    )

    assert body["error"]["code"] == "DRIVER_TIMEOUT"
    assert len(shell.starts) == 1  # no second context was started
    monkeypatch.undo()
    assert [item["id"] for item in await listed(client, key, sandbox_id)] == [first["id"]]


async def test_a_transient_name_read_error_fails_the_name_filter_too(
    client: httpx.AsyncClient,
    key: str,
    driver: Any,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    await create_named(client, key, sandbox_id, NAME, status=201)
    fail_name_reads(monkeypatch, driver, DriverError("daemon outage"))

    path = base.contexts_path(sandbox_id) + f"?name={NAME}"
    response = await client.get(path, headers={"Authorization": f"Bearer {key}"})

    assert response.status_code >= 500


async def test_a_not_found_name_read_still_means_unnamed(
    client: httpx.AsyncClient,
    key: str,
    driver: Any,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    unnamed = await base.create_context(client, key, sandbox_id)
    fail_name_reads(monkeypatch, driver, DriverNotFound("no such path"))

    items = await listed(client, key, sandbox_id)
    created = await create_named(client, key, sandbox_id, NAME, status=201)

    assert [item["id"] for item in items] == [unnamed]
    assert "name" not in items[0]
    assert created["id"] != unnamed
    assert len(shell.starts) == 2


async def test_the_existing_name_reply_carries_the_existing_cwd(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    first = await create_named(client, key, sandbox_id, NAME, status=201, cwd="/data")

    again = await create_named(client, key, sandbox_id, NAME, status=200, cwd="/elsewhere")

    assert first["cwd"] == "/data"
    assert again["cwd"] == "/data"  # the request's cwd is ignored


# --- the run body -----------------------------------------------------------------------


@pytest.mark.parametrize("suffix", ["run", "run/stream"])
async def test_the_run_body_rejects_an_unknown_field(
    client: httpx.AsyncClient, key: str, shell: SandboxShell, suffix: str
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    context_id = await base.create_context(client, key, sandbox_id)

    path = base.contexts_path(sandbox_id, context_id, *suffix.split("/"))
    body = await base.send(client, "POST", path, key, status=422, json={"code": "1", "timeout": 5})

    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert "timeout" in json.dumps(body["error"])
    assert shell.runs == []


# --- after a restart --------------------------------------------------------------------


async def test_after_a_restart_the_same_create_starts_a_new_context_with_the_name(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    before = await create_named(client, key, sandbox_id, NAME, status=201)

    await restart(client, key, sandbox_id, shell)
    gone = await listed(client, key, sandbox_id, f"?name={NAME}")
    after = await create_named(client, key, sandbox_id, NAME, status=201)

    assert gone == []
    assert after["id"] != before["id"]
    assert after["name"] == NAME
    assert [item["id"] for item in await listed(client, key, sandbox_id, f"?name={NAME}")] == [
        after["id"]
    ]


# --- the hard-kill message ---------------------------------------------------------------


async def stuck_run(
    client: httpx.AsyncClient, key: str, shell: SandboxShell, *, kernel_answers: bool
) -> dict[str, Any]:
    sandbox_id = await base.create_sandbox(client, key)
    context_id = await base.create_context(client, key, sandbox_id)
    exec_timeout = 3 + code_contexts.EXEC_MARGIN_S
    stderr = b"partial\n" + timeout_message(exec_timeout)  # what the Docker driver writes
    shell.cell_result = ExecResult(exit_code=124, stderr=stderr, timed_out=True)
    shell.idle = kernel_answers
    path = base.contexts_path(sandbox_id, context_id, "run")
    body = await base.send(
        client, "POST", path, key, status=200, json={"code": "native()", "timeout_s": 3}
    )
    data: dict[str, Any] = body["data"]
    return data


async def test_the_hard_kill_message_names_the_callers_limit(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    data = await stuck_run(client, key, shell, kernel_answers=False)

    assert data["stop_reason"] == "context_lost"
    limit_line = (
        "the cell exceeded its 3 s limit and the kernel did not stop when interrupted; "
        "its state is lost"
    )
    assert data["stderr"] == f"partial\n{limit_line}\n{code_contexts.STOPPED_MESSAGE}"
    assert "8 s" not in data["stderr"]


async def test_a_kernel_that_answers_keeps_the_drivers_line_and_the_context(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    data = await stuck_run(client, key, shell, kernel_answers=True)

    assert data["stop_reason"] == "timeout"
    assert data["stderr"].endswith(code_contexts.INTERRUPTED_MESSAGE)
    assert shell.kills == []


def test_the_hard_kill_line_leaves_stderr_without_the_deadline_line_alone() -> None:
    stderr = b"partial\nthe command was stopped after 5 s (timeout)"

    assert code_contexts._hard_kill_line(stderr, 8.0, 3.0) == stderr


# --- a run cut short by a stop is reported as stopped, not as a limit -------------------


class DownAfterClient:
    """The shell until the client exec ran; then the interrupt and probe scripts fail ``error``."""

    def __init__(self, shell: SandboxShell, error: DriverError) -> None:
        self.shell = shell
        self.error = error
        self.down = False

    def __call__(self, env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        argv = list(request.argv)
        if self.down and argv[:2] == ["sh", "-c"]:
            if argv[2] in (code_contexts._INTERRUPT_SCRIPT, code_contexts._PROBE_SCRIPT):
                raise self.error
        result = self.shell(env, request)
        if argv[0] == "python3":
            self.down = True
        return result


@dataclass(frozen=True)
class RowEdit:
    """What the sandbox row says once the cell's client exec has ended.

    ``arm`` makes the driver write ``changes`` on the row right after the client exec, so the
    route reads them when it decides the wording of a death: a ``stopping``/``stopped`` row
    without ``error_code`` is a stop by the caller or auto-stop, anything else a death.
    """

    app: FastAPI
    org_id: str
    monkeypatch: pytest.MonkeyPatch
    changes: Mapping[str, Any]

    def arm(self, driver: base.FakeDriver, sandbox_id: str) -> None:
        original = driver.exec
        write = self._writer(sandbox_id)

        async def exec_(ref: str, request: ExecRequest) -> ExecResult:
            result = await original(ref, request)
            if request.argv[0] == "python3":
                await write()
            return result

        self.monkeypatch.setattr(driver, "exec", exec_)

    def raise_on_client_exec(
        self, driver: base.FakeDriver, sandbox_id: str, error: DriverError
    ) -> None:
        """Make the client exec write ``changes`` on the row and then fail with ``error``."""
        original = driver.exec
        write = self._writer(sandbox_id)

        async def exec_(ref: str, request: ExecRequest) -> ExecResult:
            if request.argv[0] == "python3":
                await write()
                raise error
            return await original(ref, request)

        self.monkeypatch.setattr(driver, "exec", exec_)

    def _writer(self, sandbox_id: str) -> Callable[[], Awaitable[None]]:
        async def write() -> None:
            async with UnitOfWork(self.app.state.session_factory) as uow:
                row = await uow.sandboxes.get(self.org_id, sandbox_id)
                assert row is not None
                updated = row.model_copy(update=dict(self.changes))
                await uow.sandboxes.update(self.org_id, updated, expected_version=row.version)
                await uow.commit()

        return write


STOPPED_LINE = code_contexts.STOPPED_WHILE_RUNNING_MESSAGE
DIED_LINE = stop_wording.CELL_DIED_MESSAGE.decode()
CALLER_STOP_ROWS = [
    pytest.param({"state": SandboxState.STOPPING}, id="stopping"),
    pytest.param({"state": SandboxState.STOPPED}, id="stopped"),
]
DEATH_ROWS = [  # no stop by the caller or auto-stop: the sandbox died under the cell
    pytest.param({}, id="row-still-started"),
    pytest.param(
        {"state": SandboxState.STOPPED, "error_code": ERROR_CONTAINER_EXITED}, id="settled-death"
    ),
]


async def run_cut_by_stop(
    client: httpx.AsyncClient,
    key: str,
    driver: base.FakeDriver,
    shell: SandboxShell,
    error: DriverError,
    cell_result: ExecResult,
    edit: RowEdit | None = None,
) -> dict[str, Any]:
    sandbox_id = await base.create_sandbox(client, key)
    context_id = await base.create_context(client, key, sandbox_id)
    shell.cell_result = cell_result
    driver.exec_handler = DownAfterClient(shell, error)
    if edit is not None:
        edit.arm(driver, sandbox_id)
    path = base.contexts_path(sandbox_id, context_id, "run")
    body = await base.send(
        client, "POST", path, key, status=200, json={"code": "native()", "timeout_s": 3}
    )
    data: dict[str, Any] = body["data"]
    return data


def deadline_result() -> ExecResult:
    stderr = b"partial\n" + timeout_message(3 + code_contexts.EXEC_MARGIN_S)
    return ExecResult(exit_code=124, stderr=stderr, timed_out=True)


@pytest.mark.parametrize("changes", CALLER_STOP_ROWS)
async def test_a_deadline_run_on_a_sandbox_the_caller_stopped_says_it_was_stopped(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: base.FakeDriver,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
    changes: dict[str, Any],
) -> None:
    error = DriverConflict("container sbx is not running")
    edit = RowEdit(app, org_id, monkeypatch, changes)

    data = await run_cut_by_stop(client, key, driver, shell, error, deadline_result(), edit)

    assert data["stop_reason"] == "sandbox_stopped"
    assert (data["timed_out"], data["sandbox_stopped"]) == (False, True)
    assert data["stderr"] == f"partial\n{STOPPED_LINE}\n"
    assert "limit" not in data["stderr"]
    assert shell.kills == []  # nothing was discarded: the sandbox itself is down


@pytest.mark.parametrize("changes", DEATH_ROWS)
async def test_a_deadline_run_on_a_sandbox_that_died_keeps_the_died_wording(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: base.FakeDriver,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
    changes: dict[str, Any],
) -> None:
    error = DriverConflict("container sbx is not running")
    edit = RowEdit(app, org_id, monkeypatch, changes)

    data = await run_cut_by_stop(client, key, driver, shell, error, deadline_result(), edit)

    assert data["stop_reason"] == "sandbox_stopped"
    assert (data["timed_out"], data["sandbox_stopped"]) == (False, True)
    assert data["stderr"] == f"partial\n{DIED_LINE}\n"
    assert "was stopped while" not in data["stderr"]
    assert shell.kills == []


async def test_a_deadline_run_on_a_vanished_container_says_the_container_is_gone(
    client: httpx.AsyncClient, key: str, driver: base.FakeDriver, shell: SandboxShell
) -> None:
    error = DriverNotFound("No such container: sbx")

    data = await run_cut_by_stop(client, key, driver, shell, error, deadline_result())

    assert data["stop_reason"] == "sandbox_stopped"
    assert data["stderr"] == f"partial\n{code_contexts.CONTAINER_GONE_MESSAGE}\n"


@pytest.mark.parametrize("changes", CALLER_STOP_ROWS)
async def test_a_sandbox_death_result_is_reworded_when_the_caller_stopped_the_sandbox(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: base.FakeDriver,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
    changes: dict[str, Any],
) -> None:
    died = ExecResult(exit_code=137, stderr=SANDBOX_DIED_MESSAGE, sandbox_stopped=True)
    error = DriverConflict("container sbx is not running")
    edit = RowEdit(app, org_id, monkeypatch, changes)

    data = await run_cut_by_stop(client, key, driver, shell, error, died, edit)

    assert data["stop_reason"] == "sandbox_stopped"
    assert data["stderr"] == f"{STOPPED_LINE}\n"
    assert "resource limit" not in data["stderr"]


@pytest.mark.parametrize("changes", DEATH_ROWS)
async def test_an_oom_style_death_during_a_run_reports_the_died_wording(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: base.FakeDriver,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
    changes: dict[str, Any],
) -> None:
    died = ExecResult(exit_code=137, stderr=SANDBOX_DIED_MESSAGE, sandbox_stopped=True)
    error = DriverConflict("container sbx is not running")
    edit = RowEdit(app, org_id, monkeypatch, changes)

    data = await run_cut_by_stop(client, key, driver, shell, error, died, edit)

    assert data["stop_reason"] == "sandbox_stopped"
    assert data["stderr"] == f"{DIED_LINE}\n"
    assert "was stopped while" not in data["stderr"]


def sse_events(text: str) -> list[tuple[str, dict[str, Any]]]:
    """The (event, data) pairs of an event stream; comment frames are skipped."""
    events: list[tuple[str, dict[str, Any]]] = []
    for block in text.split("\n\n"):
        if block.strip() and not block.startswith(":"):
            fields = dict(line.split(": ", 1) for line in block.splitlines())
            events.append((fields["event"], json.loads(fields["data"])))
    return events


async def stream_death(
    client: httpx.AsyncClient,
    key: str,
    shell: SandboxShell,
    driver: base.FakeDriver | None = None,
    edit: RowEdit | None = None,
    cell_stderr: bytes = b"partial\n" + SANDBOX_DIED_MESSAGE,
) -> tuple[str, dict[str, Any]]:
    """Stream a cell whose sandbox died under it; the joined stderr events and the result."""
    stderr, result = await stream_death_events(client, key, shell, driver, edit, cell_stderr)
    return "".join(data["data"] for data in stderr), result


async def stream_death_events(
    client: httpx.AsyncClient,
    key: str,
    shell: SandboxShell,
    driver: base.FakeDriver | None,
    edit: RowEdit | None,
    cell_stderr: bytes,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Stream a cell that wrote ``cell_stderr`` before its sandbox stopped under it.

    Returns the data of each ``stderr`` event in order and the ``result`` event's data.
    """
    sandbox_id = await base.create_sandbox(client, key)
    context_id = await base.create_context(client, key, sandbox_id)
    shell.cell_result = ExecResult(exit_code=137, stderr=cell_stderr, sandbox_stopped=True)
    if edit is not None and driver is not None:
        edit.arm(driver, sandbox_id)
    response = await client.post(
        base.contexts_path(sandbox_id, context_id, "run", "stream"),
        headers={"Authorization": f"Bearer {key}"},
        json={"code": "native()", "timeout_s": 3},
    )
    assert response.status_code == 200, response.text
    events = sse_events(response.text)
    assert events[-1][0] == "result"
    assert [name for name, _ in events].count("result") == 1
    return [data for name, data in events if name == "stderr"], events[-1][1]


@pytest.mark.parametrize("changes", CALLER_STOP_ROWS)
async def test_the_streamed_stderr_of_a_stopped_sandbox_matches_the_result(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: base.FakeDriver,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
    changes: dict[str, Any],
) -> None:
    driver.exec_handler = DownAfterClient(shell, DriverConflict("container sbx is not running"))
    edit = RowEdit(app, org_id, monkeypatch, changes)

    streamed, result = await stream_death(client, key, shell, driver, edit)

    assert result["stop_reason"] == "sandbox_stopped"
    assert result["stderr"] == f"partial\n{STOPPED_LINE}\n"
    assert streamed == result["stderr"]
    assert "resource limit" not in streamed


@pytest.mark.parametrize("changes", DEATH_ROWS)
async def test_the_streamed_stderr_of_an_oom_style_death_matches_the_result(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: base.FakeDriver,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
    changes: dict[str, Any],
) -> None:
    driver.exec_handler = DownAfterClient(shell, DriverConflict("container sbx is not running"))
    edit = RowEdit(app, org_id, monkeypatch, changes)

    streamed, result = await stream_death(client, key, shell, driver, edit)

    assert result["stop_reason"] == "sandbox_stopped"
    assert result["stderr"] == f"partial\n{DIED_LINE}\n"
    assert streamed == result["stderr"]
    assert "was stopped while" not in streamed


async def test_the_streamed_stderr_of_a_limit_death_keeps_the_limit_line(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    streamed, result = await stream_death(client, key, shell)  # the probe still answers

    assert result["stop_reason"] == "sandbox_stopped"
    assert result["stderr"] == "partial\n" + DIED_LINE
    assert streamed == result["stderr"]


async def stream_stuck(
    client: httpx.AsyncClient, key: str, shell: SandboxShell, *, kernel_answers: bool
) -> tuple[list[str], dict[str, Any]]:
    """``stuck_run`` through the stream: each ``stderr`` event's text and the ``result``."""
    sandbox_id = await base.create_sandbox(client, key)
    context_id = await base.create_context(client, key, sandbox_id)
    shell.cell_result = deadline_result()
    shell.idle = kernel_answers
    response = await client.post(
        base.contexts_path(sandbox_id, context_id, "run", "stream"),
        headers={"Authorization": f"Bearer {key}"},
        json={"code": "native()", "timeout_s": 3},
    )
    assert response.status_code == 200, response.text
    events = sse_events(response.text)
    assert events[-1][0] == "result"
    assert [name for name, _ in events].count("result") == 1
    return [data["data"] for name, data in events if name == "stderr"], events[-1][1]


async def test_a_streamed_hard_kill_never_streams_the_deadline_sentence(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    chunks, result = await stream_stuck(client, key, shell, kernel_answers=False)

    assert (result["stop_reason"], result["exit_code"]) == ("context_lost", 124)
    assert "".join(chunks) == result["stderr"]
    assert result["stderr"].startswith("partial\nthe cell exceeded its 3 s limit")
    assert not [chunk for chunk in chunks if "allow more time" in chunk or "8 s" in chunk]


async def test_a_streamed_stuck_cell_whose_kernel_answers_matches_the_result(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    chunks, result = await stream_stuck(client, key, shell, kernel_answers=True)

    assert result["stop_reason"] == "timeout"
    assert "".join(chunks) == result["stderr"]
    assert result["stderr"].endswith(code_contexts.INTERRUPTED_MESSAGE)
    assert shell.kills == []


async def test_a_streamed_deadline_run_on_a_vanished_container_matches_the_result(
    client: httpx.AsyncClient, key: str, driver: base.FakeDriver, shell: SandboxShell
) -> None:
    driver.exec_handler = DownAfterClient(shell, DriverNotFound("No such container: sbx"))

    chunks, result = await stream_stuck(client, key, shell, kernel_answers=True)

    assert result["stop_reason"] == "sandbox_stopped"
    assert result["stderr"] == f"partial\n{code_contexts.CONTAINER_GONE_MESSAGE}\n"
    assert "".join(chunks) == result["stderr"]  # the dropped deadline line was never streamed
    assert not [chunk for chunk in chunks if "allow more time" in chunk]


def test_held_stderr_that_the_result_does_not_extend_is_not_sent() -> None:
    events = code_context_stream.RunEvents()
    events.emit("stderr", {"data": "partial\n"})
    events.hold()

    code_context_stream._send_stderr_tail(events, {"stderr": "other\n"})

    assert events.stderr_sent() == "partial\n"


def test_unheld_stderr_that_the_result_does_not_extend_is_not_sent() -> None:
    events = code_context_stream.RunEvents()
    events.emit("stderr", {"data": "partial\n"})

    code_context_stream._send_stderr_tail(events, {"stderr": "other\n"})

    assert events.stderr_sent() == "partial\n"


@pytest.mark.parametrize("held", [True, False], ids=["held", "nothing-held"])
def test_the_unsent_tail_of_the_result_stderr_is_sent_held_or_not(held: bool) -> None:
    events = code_context_stream.RunEvents()
    events.emit("stderr", {"data": "partial\n"})
    if held:
        events.hold()

    code_context_stream._send_stderr_tail(events, {"stderr": f"partial\n{DELETED_CELL_LINE}\n"})

    assert events.stderr_sent() == f"partial\n{DELETED_CELL_LINE}\n"


def test_a_result_stderr_equal_to_what_was_sent_sends_no_empty_chunk() -> None:
    events = code_context_stream.RunEvents()
    events.emit("stderr", {"data": "partial\n"})

    code_context_stream._send_stderr_tail(events, {"stderr": "partial\n"})

    assert events._stderr_sent == ["partial\n"]


async def test_an_unrelated_probe_failure_keeps_the_context_and_the_timeout(
    client: httpx.AsyncClient, key: str, driver: base.FakeDriver, shell: SandboxShell
) -> None:
    data = await run_cut_by_stop(
        client, key, driver, shell, DriverTimeout("daemon is slow"), deadline_result()
    )

    assert data["stop_reason"] == "timeout"
    assert data["stderr"].endswith(code_contexts.UNCONFIRMED_MESSAGE)


def stop_check(answer: str | None, asked: list[str | None]) -> code_context_stream.StopCheck:
    async def check() -> str | None:
        asked.append(answer)
        return answer

    return check


@pytest.mark.parametrize(
    ("error", "reason", "message"),
    [
        pytest.param(
            DriverConflict("container sbx is not running"),
            "sandbox_stopped",
            STOPPED_LINE,
            id="stop",
        ),
        pytest.param(DriverConflict("container sbx is not running"), None, DIED_LINE, id="died"),
        pytest.param(
            DriverNotFound("No such container: sbx"),
            "sandbox_stopped",
            code_contexts.CONTAINER_GONE_MESSAGE,
            id="gone",
        ),
    ],
)
async def test_the_stream_error_event_for_a_stopped_sandbox_carries_the_stop_reason(
    error: DriverError, reason: str | None, message: str
) -> None:
    async def finish(events: code_context_stream.RunEvents) -> dict[str, Any]:
        raise error

    asked: list[str | None] = []
    check = stop_check(reason, asked)
    events = [event async for event in code_context_stream.stream_run(finish, check)]

    assert events == [
        ("error", {"code": Conflict.code, "message": message, "stop_reason": "sandbox_stopped"})
    ]
    assert len(asked) == (0 if isinstance(error, DriverNotFound) else 1)  # gone: no row needed


async def test_the_stream_error_event_without_a_stop_check_keeps_the_drivers_line() -> None:
    async def finish(events: code_context_stream.RunEvents) -> dict[str, Any]:
        raise DriverConflict("container sbx is not running")

    events = [event async for event in code_context_stream.stream_run(finish)]

    assert events == [
        ("error", {"code": Conflict.code, "message": DIED_LINE, "stop_reason": "sandbox_stopped"})
    ]


async def stream_with_failing_exec(
    client: httpx.AsyncClient, key: str, driver: base.FakeDriver, edit: RowEdit
) -> list[tuple[str, dict[str, Any]]]:
    """Stream a cell whose client exec writes the row edit, then raises the not-running conflict."""
    sandbox_id = await base.create_sandbox(client, key)
    context_id = await base.create_context(client, key, sandbox_id)
    edit.raise_on_client_exec(driver, sandbox_id, DriverConflict("container sbx is not running"))
    response = await client.post(
        base.contexts_path(sandbox_id, context_id, "run", "stream"),
        headers={"Authorization": f"Bearer {key}"},
        json={"code": "native()", "timeout_s": 3},
    )
    assert response.status_code == 200, response.text
    return sse_events(response.text)


@pytest.mark.parametrize("changes", CALLER_STOP_ROWS)
async def test_a_streamed_exec_conflict_on_a_sandbox_the_caller_stopped_says_it_was_stopped(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: base.FakeDriver,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
    changes: dict[str, Any],
) -> None:
    edit = RowEdit(app, org_id, monkeypatch, changes)

    events = await stream_with_failing_exec(client, key, driver, edit)

    assert events[-1] == (
        "error",
        {"code": Conflict.code, "message": STOPPED_LINE, "stop_reason": "sandbox_stopped"},
    )


@pytest.mark.parametrize("changes", DEATH_ROWS)
async def test_a_streamed_exec_conflict_on_a_sandbox_that_died_keeps_the_drivers_line(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: base.FakeDriver,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
    changes: dict[str, Any],
) -> None:
    edit = RowEdit(app, org_id, monkeypatch, changes)

    events = await stream_with_failing_exec(client, key, driver, edit)

    name, data = events[-1]
    assert name == "error"
    assert data == {"code": Conflict.code, "message": DIED_LINE, "stop_reason": "sandbox_stopped"}
    assert "was stopped while" not in data["message"]


# --- a cell run ended by a delete, a reset or a vanished container -------------------------

DELETED_CELL_LINE = "the sandbox was deleted while the cell was running"
RESET_CELL_LINE = (
    "the sandbox was reset while the cell was running; the context is gone, "
    "create or ensure a new one"
)
GONE_LINE = code_contexts.CONTAINER_GONE_MESSAGE
DELETE_ROW = {"state": SandboxState.DESTROYING}
RESET_ROW = {"driver_ref": "ctr_replaced_by_reset"}
ENDINGS = [  # (probe error, row edit, stop reason, the line stderr ends with)
    pytest.param(
        DriverConflict("container sbx is not running"),
        DELETE_ROW,
        "sandbox_deleted",
        DELETED_CELL_LINE,
        id="deleted",
    ),
    pytest.param(
        DriverConflict("container sbx is not running"),
        RESET_ROW,
        "sandbox_reset",
        RESET_CELL_LINE,
        id="reset",
    ),
    pytest.param(
        DriverNotFound("No such container: sbx"),
        DELETE_ROW,
        "sandbox_deleted",
        GONE_LINE,
        id="gone-deleted",
    ),
    pytest.param(
        DriverNotFound("No such container: sbx"),
        RESET_ROW,
        "sandbox_reset",
        GONE_LINE,
        id="gone-reset",
    ),
]
ALL_ENDING_LINES = (DELETED_CELL_LINE, RESET_CELL_LINE, GONE_LINE, STOPPED_LINE, DIED_LINE)


def assert_one_ending_line(stderr: str, line: str) -> None:
    assert stderr.count(line) == 1
    assert [other for other in ALL_ENDING_LINES if other != line and other in stderr] == []


@pytest.mark.parametrize(("error", "changes", "reason", "line"), ENDINGS)
async def test_a_cell_run_ended_by_a_delete_reset_or_vanished_container_names_it_once(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: base.FakeDriver,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
    error: DriverError,
    changes: dict[str, Any],
    reason: str,
    line: str,
) -> None:
    died = ExecResult(
        exit_code=137, stderr=b"partial\n" + SANDBOX_DIED_MESSAGE, sandbox_stopped=True
    )
    edit = RowEdit(app, org_id, monkeypatch, changes)

    data = await run_cut_by_stop(client, key, driver, shell, error, died, edit)

    assert data["stop_reason"] == reason
    assert data["sandbox_stopped"] is True
    assert data["stderr"] == f"partial\n{line}\n"
    assert_one_ending_line(data["stderr"], line)


@pytest.mark.parametrize(("error", "changes", "reason", "line"), ENDINGS)
async def test_a_streamed_cell_ended_by_a_delete_reset_or_vanished_container_names_it_once(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: base.FakeDriver,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
    error: DriverError,
    changes: dict[str, Any],
    reason: str,
    line: str,
) -> None:
    driver.exec_handler = DownAfterClient(shell, error)
    edit = RowEdit(app, org_id, monkeypatch, changes)

    streamed, result = await stream_death(client, key, shell, driver, edit)

    assert result["stop_reason"] == reason
    assert result["stderr"] == f"partial\n{line}\n"
    assert streamed == result["stderr"]
    assert_one_ending_line(streamed, line)


NO_DEATH_LINE_ENDINGS = [  # the container went away without the driver's death line
    *ENDINGS,
    *(
        pytest.param(
            DriverConflict("container sbx is not running"),
            {"state": state},
            "sandbox_stopped",
            STOPPED_LINE,
            id=f"stop-{state.value}",
        )
        for state in (SandboxState.STOPPING, SandboxState.STOPPED)
    ),
]


@pytest.mark.parametrize(("error", "changes", "reason", "line"), NO_DEATH_LINE_ENDINGS)
async def test_a_streamed_cell_ended_without_the_death_line_streams_the_gone_sentence_last(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: base.FakeDriver,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
    error: DriverError,
    changes: dict[str, Any],
    reason: str,
    line: str,
) -> None:
    driver.exec_handler = DownAfterClient(shell, error)
    edit = RowEdit(app, org_id, monkeypatch, changes)

    chunks, result = await stream_death_events(client, key, shell, driver, edit, b"partial\n")

    assert result["stop_reason"] == reason
    assert result["sandbox_stopped"] is True
    assert result["stderr"] == f"partial\n{line}\n"
    assert chunks, "no stderr chunk was streamed"
    assert line in chunks[-1]["data"]
    assert "".join(chunk["data"] for chunk in chunks) == result["stderr"]
    assert_one_ending_line("".join(chunk["data"] for chunk in chunks), line)


async def test_a_vanished_container_with_the_row_still_started_names_it_once(
    client: httpx.AsyncClient, key: str, driver: base.FakeDriver, shell: SandboxShell
) -> None:
    driver.exec_handler = DownAfterClient(shell, DriverNotFound("No such container: sbx"))

    streamed, result = await stream_death(client, key, shell, driver)

    assert result["stop_reason"] == "sandbox_stopped"
    assert result["stderr"] == f"partial\n{GONE_LINE}\n"
    assert streamed == result["stderr"]


@pytest.mark.parametrize(
    ("changes", "line"),
    [
        pytest.param(DELETE_ROW, DELETED_CELL_LINE, id="deleted"),
        pytest.param(RESET_ROW, RESET_CELL_LINE, id="reset"),
    ],
)
async def test_a_streamed_exec_conflict_on_a_deleted_or_reset_sandbox_names_it_once(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: base.FakeDriver,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
    changes: dict[str, Any],
    line: str,
) -> None:
    edit = RowEdit(app, org_id, monkeypatch, changes)

    events = await stream_with_failing_exec(client, key, driver, edit)

    name, data = events[-1]
    assert name == "error"
    assert data == {"code": Conflict.code, "message": line, "stop_reason": "sandbox_stopped"}
    assert_one_ending_line(data["message"], line)
    assert "cell" in data["message"]
    assert "resource limit" not in data["message"]
    assert [event for event in events if event[0] == "error"] == [events[-1]]


@pytest.mark.parametrize(
    ("reason", "line"),
    [
        pytest.param("sandbox_deleted", DELETED_CELL_LINE, id="deleted"),
        pytest.param("sandbox_reset", RESET_CELL_LINE, id="reset"),
        pytest.param("sandbox_stopped", STOPPED_LINE, id="stopped"),
        pytest.param("something_else", DIED_LINE, id="unknown-reason"),
    ],
)
async def test_the_stream_error_event_maps_the_rows_stop_reason_through_the_cell_lines(
    reason: str, line: str
) -> None:
    async def finish(events: code_context_stream.RunEvents) -> dict[str, Any]:
        raise DriverConflict("container sbx is not running")

    asked: list[str | None] = []
    stream = code_context_stream.stream_run(
        finish, stop_check(reason, asked), code_context_routes.CELL_GONE_MESSAGES
    )
    events = [event async for event in stream]

    assert events == [
        ("error", {"code": Conflict.code, "message": line, "stop_reason": "sandbox_stopped"})
    ]
    assert asked == [reason]


@pytest.mark.parametrize(
    ("reason", "line"),
    [
        pytest.param("sandbox_stopped", STOPPED_LINE, id="stopped"),
        pytest.param("sandbox_deleted", DIED_LINE, id="deleted-has-no-default-line"),
        pytest.param("sandbox_reset", DIED_LINE, id="reset-has-no-default-line"),
        pytest.param("something_else", DIED_LINE, id="unknown-reason"),
        pytest.param(None, DIED_LINE, id="no-reason"),
    ],
)
async def test_the_stream_error_event_without_a_mapping_uses_the_default_gone_lines(
    reason: str | None, line: str
) -> None:
    async def finish(events: code_context_stream.RunEvents) -> dict[str, Any]:
        raise DriverConflict("container sbx is not running")

    asked: list[str | None] = []
    stream = code_context_stream.stream_run(finish, stop_check(reason, asked))
    events = [event async for event in stream]

    assert events == [
        ("error", {"code": Conflict.code, "message": line, "stop_reason": "sandbox_stopped"})
    ]
    assert asked == [reason]


async def test_the_stream_error_event_for_another_driver_failure_stays_generic() -> None:
    async def finish(events: code_context_stream.RunEvents) -> dict[str, Any]:
        raise DriverError("the daemon went away")

    events = [event async for event in code_context_stream.stream_run(finish)]

    assert events == [
        ("error", {"code": "INTERNAL", "message": code_context_stream.FAILED_MESSAGE})
    ]


# --- SDK ensure -------------------------------------------------------------------------

SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
BASE_URL = "http://sandfort.test"
SDK_KEY = "sf_test_key"
TIMEOUT_S = 30.0
CONTEXTS = f"/v1/sandboxes/{SID}/toolbox/code-contexts"


class FakeServer:
    """The create and list routes: a named create returns the live context of that name."""

    def __init__(self) -> None:
        self.live: dict[str, dict[str, Any]] = {}  # id -> context payload
        self.bodies: list[dict[str, Any]] = []
        self.counter = 0

    def restart(self) -> None:
        self.live.clear()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.url.path == CONTEXTS
        if request.method == "GET":
            return self._envelope(list(self.live.values()), 200)
        body: dict[str, Any] = json.loads(request.content)
        self.bodies.append(body)
        name = body.get("name")
        for context in self.live.values():
            if name is not None and context.get("name") == name:
                return self._envelope(context, 200)
        self.counter += 1
        context = {"id": f"ctx_{self.counter:016x}", "language": "python", "cwd": "/work"}
        if name is not None:
            context["name"] = name
        self.live[context["id"]] = context
        return self._envelope(context, 201)

    @staticmethod
    def _envelope(data: Any, status: int) -> httpx.Response:
        return httpx.Response(status, json={"success": True, "data": data, "meta": None})


def sync_contexts(server: FakeServer) -> CodeContexts:
    transport = SyncTransport(BASE_URL, SDK_KEY, TIMEOUT_S, max_retries=0)
    transport._http.close()
    transport._http = httpx.Client(
        transport=httpx.MockTransport(server), **client_kwargs(BASE_URL, SDK_KEY, TIMEOUT_S)
    )
    return CodeContexts(SID, transport)


def async_contexts(server: FakeServer) -> AsyncCodeContexts:
    transport = AsyncTransport(BASE_URL, SDK_KEY, TIMEOUT_S, max_retries=0)
    transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(server), **client_kwargs(BASE_URL, SDK_KEY, TIMEOUT_S)
    )
    return AsyncCodeContexts(SID, transport)


def test_sdk_create_passes_the_name_and_the_context_carries_it() -> None:
    server = FakeServer()

    context = sync_contexts(server).create("/data", name=NAME)

    assert server.bodies == [{"language": "python", "cwd": "/data", "name": NAME}]
    assert context.name == NAME
    assert NAME in repr(context)


def test_sdk_create_without_a_name_sends_none_and_reads_none() -> None:
    server = FakeServer()

    context = sync_contexts(server).create()

    assert server.bodies == [{"language": "python"}]
    assert context.name is None


def test_sdk_ensure_returns_the_live_context_then_a_new_one_after_a_restart() -> None:
    server = FakeServer()
    contexts = sync_contexts(server)

    first = contexts.ensure(NAME)
    same = contexts.ensure(NAME, cwd="/ignored")
    server.restart()
    after = contexts.ensure(NAME)

    assert same.id == first.id
    assert after.id != first.id
    assert after.name == NAME
    assert server.bodies[0] == {"language": "python", "name": NAME}
    assert [c.name for c in contexts.list()] == [NAME]


async def test_async_sdk_ensure_returns_the_live_context_then_a_new_one_after_a_restart() -> None:
    server = FakeServer()
    contexts = async_contexts(server)

    first = await contexts.ensure(NAME, language="python")
    same = await contexts.ensure(NAME)
    server.restart()
    after = await contexts.ensure(NAME)

    assert same.id == first.id
    assert after.id != first.id
    assert after.name == NAME
    assert NAME in repr(after)
    assert [c.name for c in await contexts.list()] == [NAME]


async def test_async_sdk_create_passes_the_name() -> None:
    server = FakeServer()

    context = await async_contexts(server).create(name=NAME)

    assert server.bodies == [{"language": "python", "name": NAME}]
    assert context.name == NAME
