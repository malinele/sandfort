"""API tests for ``/v1/sandboxes/{id}/toolbox/code-contexts``: FakeDriver, temp SQLite, httpx.

Daemon-free. ``SandboxShell`` stands in for the sandbox: it answers the ``sh -c`` scripts the
platform execs (start, ready, list, delete, probe) and the client exec of a run, so the routes
are tested end to end up to the driver. The kernel itself is tested in ``test_code_contexts``.
"""

import asyncio
import io
import json
import re
import tarfile
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.routes.toolbox import code_contexts as routes
from sandfort.api.routes.toolbox import process as process_routes
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import AuditEvent
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import Sandbox
from sandfort.drivers.base import ExecRequest, ExecResult
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.toolbox import code_contexts

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
DEFAULT_CWD = "/workspace"
UNKNOWN_ID = "ctx_0123456789abcdef"
CONTEXT_ID = re.compile(r"ctx_[0-9a-f]{16}")
AUDIT_ACTIONS = {
    "toolbox.code_contexts.create",
    "toolbox.code_contexts.run",
    "toolbox.code_contexts.delete",
}
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})


def _script_of(request: ExecRequest) -> str:
    argv = list(request.argv)
    return argv[2] if argv[:2] == ["sh", "-c"] else ""


class SandboxShell:
    """A scripted sandbox: tracks which kernels were started and answers the platform's execs."""

    def __init__(self) -> None:
        self.has_python = True
        self.kernel_starts = True
        self.kernel_hangs = False  # the kernel process runs but never creates its socket
        self.alive: set[str] = set()  # context directories whose kernel process is running
        self.kills: list[str] = []  # directories the kill script ran against
        self.log = b""
        self.ready: dict[str, str] = {}  # context directory -> the kernel's working directory
        self.requests: list[ExecRequest] = []
        self.cell_result = ExecResult(exit_code=0)
        self.idle = True  # the kernel reports its cell done once interrupted (no busy marker)
        self.interrupts: list[str] = []  # directories the interrupt script signalled
        self.interrupt_args: list[list[str]] = []  # the cell number argument of each interrupt
        self.idle_args: list[list[str]] = []  # the cell number argument of each idle check
        self.outcome: dict[str, Any] | None = None  # the client's trailer, keyed by its token

    def scripts(self) -> list[str]:
        """The platform scripts execed so far, in order."""
        return [_script_of(r) for r in self.requests if _script_of(r)]

    @property
    def starts(self) -> list[ExecRequest]:
        return [r for r in self.requests if _script_of(r) == code_contexts._START_SCRIPT]

    @property
    def runs(self) -> list[ExecRequest]:
        return [r for r in self.requests if r.argv[0] == "python3"]

    def __call__(self, env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        self.requests.append(request)
        argv = list(request.argv)
        if argv[:2] == ["sh", "-c"]:
            return self._script(argv[2], argv[4:], request)
        if argv[0] == "python3":
            if self.outcome is None:
                return self.cell_result
            line = f"{argv[5]} {json.dumps(self.outcome)}\n".encode()
            stdout = self.cell_result.stdout + code_contexts.OUTCOME_MARK + line
            return replace(self.cell_result, stdout=stdout)
        if argv[:2] == ["rm", "-rf"]:
            self.ready.pop(argv[2], None)
        return ExecResult(exit_code=0)

    def _script(self, script: str, args: list[str], request: ExecRequest) -> ExecResult:
        if script.startswith("command -v python3"):
            return ExecResult(exit_code=0 if self.has_python else 1)
        if script == code_contexts._START_SCRIPT:
            if self.kernel_starts:
                self.alive.add(args[0])
                if not self.kernel_hangs:
                    self.ready[args[0]] = request.cwd or DEFAULT_CWD
            return ExecResult(exit_code=0)
        if script == code_contexts._READY_SCRIPT:
            cwd = self.ready.get(args[0])
            if cwd is None:
                return ExecResult(exit_code=1)
            return ExecResult(exit_code=0, stdout=cwd.encode())
        if script == code_contexts._LIST_SCRIPT:
            prefix = code_contexts.UPLOAD_DIR + "/" + code_contexts.DIR_PREFIX
            lines = [f"{d.removeprefix(prefix)}\t{cwd}\n" for d, cwd in self.ready.items()]
            return ExecResult(exit_code=0, stdout="".join(lines).encode())
        if script == code_contexts._KILL_SCRIPT:
            self.kills.append(args[0])
            self.alive.discard(args[0])
            return ExecResult(exit_code=0)
        if script == code_contexts._DELETE_SCRIPT:
            self.alive.discard(args[0])
            if self.ready.pop(args[0], None) is None:
                return ExecResult(exit_code=code_contexts._NOT_FOUND_EXIT_CODE)
            return ExecResult(exit_code=0)
        if script == code_contexts._INTERRUPT_SCRIPT:
            if args[0] not in self.ready:
                return ExecResult(exit_code=code_contexts._NOT_FOUND_EXIT_CODE)
            if args[0] not in self.alive:
                return ExecResult(exit_code=1)
            if len(args) > 2 and args[2] and self.idle:  # asked to skip a kernel with no cell
                return ExecResult(exit_code=code_contexts.NOT_RUNNING_CELL_EXIT_CODE)
            self.interrupts.append(args[0])
            self.interrupt_args.append(args[1:])
            return ExecResult(exit_code=0)
        if script == code_contexts._IDLE_SCRIPT:
            self.idle_args.append(args[1:])
            return ExecResult(exit_code=0 if self.idle else 1)
        if script.startswith("tail"):
            return ExecResult(exit_code=0, stdout=self.log)
        assert script == code_contexts._PROBE_SCRIPT, script
        return ExecResult(exit_code=0 if args[0] in self.ready else 1)


@pytest.fixture(autouse=True)
def quick_interrupt_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    """A kernel that never reports idle must not make a test wait the full 2 s."""
    monkeypatch.setattr(code_contexts, "INTERRUPT_WAIT_S", 0.2)
    monkeypatch.setattr(code_contexts, "INTERRUPT_POLL_S", 0.01)


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'code_contexts.db'}"
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
def driver(app: FastAPI) -> FakeDriver:
    fake = app.state.driver
    assert isinstance(fake, FakeDriver)
    return fake


@pytest.fixture
def shell(driver: FakeDriver) -> SandboxShell:
    scripted = SandboxShell()
    driver.exec_handler = scripted
    return scripted


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


def contexts_path(sandbox_id: str, *parts: str) -> str:
    return "/".join([f"{BASE}/{sandbox_id}/toolbox/code-contexts", *parts])


async def create_context(
    client: httpx.AsyncClient, key: str, sandbox_id: str, **payload: Any
) -> str:
    body = await send(client, "POST", contexts_path(sandbox_id), key, status=201, json=payload)
    context_id: str = body["data"]["id"]
    return context_id


async def read_uploaded(driver: FakeDriver, path: str) -> str:
    [instance] = await driver.list_managed()
    payload = b"".join([chunk async for chunk in driver.get_archive(instance.ref, path)])
    with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
        [member] = archive.getmembers()
        handle = archive.extractfile(member)
        assert handle is not None
        return handle.read().decode()


async def audit_rows(app: FastAPI, org_id: str) -> list[AuditEvent]:
    async with UnitOfWork(app.state.session_factory) as uow:
        return list(await uow.audit.list(org_id, limit=200))


def every_route(sandbox_id: str, context_id: str) -> list[tuple[str, str, dict[str, Any]]]:
    """One call per route, for the guard tests."""
    return [
        ("POST", contexts_path(sandbox_id), {"json": {}}),
        ("GET", contexts_path(sandbox_id), {}),
        ("DELETE", contexts_path(sandbox_id, context_id), {}),
        ("POST", contexts_path(sandbox_id, context_id, "run"), {"json": {"code": "1"}}),
        ("POST", contexts_path(sandbox_id, context_id, "interrupt"), {}),
    ]


# --- create -----------------------------------------------------------------------------


async def test_create_uploads_the_kernel_and_client_and_starts_the_kernel(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)

    body = await send(client, "POST", contexts_path(sandbox_id), key, status=201, json={})

    data = body["data"]
    assert CONTEXT_ID.fullmatch(data["id"])
    assert data["language"] == "python"
    assert data["cwd"] == DEFAULT_CWD
    directory = code_contexts.context_dir(data["id"])
    assert await read_uploaded(driver, f"{directory}/kernel.py") == code_contexts.KERNEL_SOURCE
    assert await read_uploaded(driver, f"{directory}/client.py") == code_contexts.CLIENT_SOURCE
    [start] = shell.starts
    assert list(start.argv) == ["sh", "-c", code_contexts._START_SCRIPT, "sh", directory]
    assert start.cwd is None


async def test_create_starts_the_kernel_in_the_requested_directory(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client, "POST", contexts_path(sandbox_id), key, status=201, json={"cwd": "/data"}
    )

    assert body["data"]["cwd"] == "/data"
    assert shell.starts[0].cwd == "/data"


async def test_create_without_python3_is_a_conflict(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    shell.has_python = False
    sandbox_id = await create_sandbox(client, key)

    body = await send(client, "POST", contexts_path(sandbox_id), key, status=409, json={})

    assert body["error"]["code"] == "CONFLICT"
    assert body["error"]["details"]["reason"] == "operation_failed"
    assert "python3" in body["error"]["message"]
    assert shell.starts == []


async def test_a_kernel_that_never_comes_up_is_a_conflict_and_is_cleaned_up(
    client: httpx.AsyncClient,
    key: str,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(code_contexts, "READY_TIMEOUT_S", 0.3)
    monkeypatch.setattr(code_contexts, "READY_POLL_S", 0.05)
    shell.kernel_starts = False
    shell.log = b"setsid: not found"
    sandbox_id = await create_sandbox(client, key)

    body = await send(client, "POST", contexts_path(sandbox_id), key, status=409, json={})

    assert body["error"]["details"]["reason"] == "operation_failed"
    assert "setsid: not found" in body["error"]["message"]
    [start] = shell.starts
    directory = start.argv[4]
    assert ["rm", "-rf", directory] in [list(r.argv) for r in shell.requests]


async def test_a_kernel_that_started_but_never_got_ready_is_killed_before_the_cleanup(
    client: httpx.AsyncClient,
    key: str,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(code_contexts, "READY_TIMEOUT_S", 0.3)
    monkeypatch.setattr(code_contexts, "READY_POLL_S", 0.05)
    shell.kernel_hangs = True
    sandbox_id = await create_sandbox(client, key)

    await send(client, "POST", contexts_path(sandbox_id), key, status=409, json={})

    [start] = shell.starts
    directory = start.argv[4]
    assert shell.kills == [directory]
    assert shell.alive == set()  # the kernel process is gone, not just its directory
    commands = [list(r.argv) for r in shell.requests]
    kill = ["sh", "-c", code_contexts._KILL_SCRIPT, "sh", directory]
    assert commands.index(kill) < commands.index(["rm", "-rf", directory])


async def test_create_with_another_language_is_unprocessable(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client, "POST", contexts_path(sandbox_id), key, status=422, json={"language": "bash"}
    )

    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert shell.starts == []


# --- run --------------------------------------------------------------------------------


async def test_run_execs_the_client_against_the_socket_with_the_uploaded_cell(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    shell.cell_result = ExecResult(exit_code=0, stdout=b"2\n", duration_ms=9)

    body = await send(
        client,
        "POST",
        contexts_path(sandbox_id, context_id, "run"),
        key,
        status=200,
        json={"code": "print(x + 1)", "timeout_s": 12},
    )

    assert body["data"] == {
        "exit_code": 0,
        "stdout": "2\n",
        "stderr": "",
        "timed_out": False,
        "truncated": False,
        "duration_ms": 9,
        "sandbox_stopped": False,
        "stop_reason": None,
        "result": None,
        "error": None,
    }
    [run] = shell.runs
    directory = code_contexts.context_dir(context_id)
    python, client_file, socket_file, cell_file, timeout, token, cell_number = run.argv
    assert python == "python3"
    assert re.fullmatch(r"[1-9][0-9]*", cell_number)  # the number the kernel marks its cell with
    assert run.max_output_bytes == code_contexts.CLIENT_OUTPUT_LIMIT  # room kept for the trailer
    assert client_file == f"{directory}/client.py"
    assert socket_file == f"{directory}/kernel.sock"
    assert re.fullmatch(rf"{re.escape(directory)}/cell-[0-9a-f]{{32}}\.py", cell_file)
    assert float(timeout) == 12.0
    assert re.fullmatch(r"[0-9a-f]{32}", token)  # keys the client's outcome trailer
    assert run.timeout_s == 12.0 + code_contexts.EXEC_MARGIN_S
    assert await read_uploaded(driver, cell_file) == "print(x + 1)"
    assert list(shell.requests[-1].argv) == ["rm", "-rf", cell_file]


async def test_run_passes_a_raised_cell_through_with_exit_code_one(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    traceback_text = 'Traceback (most recent call last):\n  File "<cell-1>", line 1\nNameError: x\n'
    shell.cell_result = ExecResult(exit_code=1, stderr=traceback_text.encode())

    body = await send(
        client,
        "POST",
        contexts_path(sandbox_id, context_id, "run"),
        key,
        status=200,
        json={"code": "x"},
    )

    assert body["data"]["exit_code"] == 1
    assert body["data"]["stderr"] == traceback_text
    assert body["data"]["timed_out"] is False
    assert body["data"]["stop_reason"] is None


async def run_once(client: httpx.AsyncClient, key: str, code: str = "x") -> dict[str, Any]:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    path = contexts_path(sandbox_id, context_id, "run")
    body = await send(client, "POST", path, key, status=200, json={"code": code})
    data: dict[str, Any] = body["data"]
    return data


async def test_run_answers_the_trailing_expression_as_result_and_keeps_stdout(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    shell.cell_result = ExecResult(exit_code=0, stdout=b"a\n5\n")
    shell.outcome = {"x": 0, "r": "5", "err": None, "lost": False}

    data = await run_once(client, key, "print('a')\n5")

    assert data["stdout"] == "a\n5\n"  # the trailer is gone, the printed repr stays
    assert data["result"] == "5"
    assert data["error"] is None
    assert data["stop_reason"] is None


async def test_run_answers_a_null_result_for_an_assignment(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    shell.outcome = {"x": 0, "r": None, "err": None, "lost": False}

    data = await run_once(client, key, "x = 1")

    assert (data["stdout"], data["result"], data["error"]) == ("", None, None)


async def test_run_answers_a_raised_cell_as_a_structured_error(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    traceback_text = "Traceback (most recent call last):\nZeroDivisionError: division by zero\n"
    shell.cell_result = ExecResult(exit_code=1, stderr=traceback_text.encode())
    error = {"type": "ZeroDivisionError", "message": "division by zero"}
    shell.outcome = {"x": 1, "r": None, "err": error, "lost": False}

    data = await run_once(client, key, "1 / 0")

    assert data["exit_code"] == 1
    assert data["error"] == error
    assert data["result"] is None
    assert data["stderr"] == traceback_text
    assert data["stop_reason"] is None


async def test_a_kernel_lost_during_the_run_answers_context_lost(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    lost_line = b"the context kernel closed the connection; its state is lost\n"
    shell.cell_result = ExecResult(exit_code=1, stdout=b"started\n", stderr=lost_line)
    shell.outcome = {"x": 1, "r": None, "err": None, "lost": True}

    data = await run_once(client, key)

    assert data["stop_reason"] == "context_lost"
    assert data["exit_code"] == 1  # exit codes stay as before
    assert data["timed_out"] is False
    assert data["stdout"] == "started\n"
    assert (data["result"], data["error"]) == (None, None)


async def test_a_run_without_an_outcome_trailer_answers_null_fields(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    """A client uploaded before the trailer existed: same response as before, fields null."""
    shell.cell_result = ExecResult(exit_code=1, stderr=b"boom\n")

    data = await run_once(client, key)

    assert (data["exit_code"], data["stop_reason"]) == (1, None)
    assert (data["result"], data["error"]) == (None, None)


async def test_run_reports_a_kernel_timeout_as_timed_out(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    shell.cell_result = ExecResult(exit_code=124, stderr=b"TimeoutError: cell exceeded 1 s\n")

    body = await send(
        client,
        "POST",
        contexts_path(sandbox_id, context_id, "run"),
        key,
        status=200,
        json={"code": "while True: pass", "timeout_s": 1},
    )

    assert body["data"]["exit_code"] == 124
    assert body["data"]["timed_out"] is True
    assert body["data"]["stop_reason"] == "timeout"
    assert shell.ready  # the context is still there


async def test_a_kernel_timeout_keeps_the_context(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    shell.cell_result = ExecResult(exit_code=124, stderr=b"TimeoutError: cell exceeded 1 s\n")

    await send(
        client,
        "POST",
        contexts_path(sandbox_id, context_id, "run"),
        key,
        status=200,
        json={"code": "x", "timeout_s": 1},
    )

    assert shell.kills == []
    assert len(shell.alive) == 1


async def test_an_exec_timeout_kills_the_kernel_and_removes_the_context(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    directory = code_contexts.context_dir(context_id)
    shell.cell_result = ExecResult(exit_code=137, stderr=b"partial", timed_out=True)
    shell.idle = False  # the interrupt gets no answer from the kernel
    path = contexts_path(sandbox_id, context_id)

    body = await send(
        client,
        "POST",
        path + "/run",
        key,
        status=200,
        json={"code": "native_call()", "timeout_s": 2},
    )

    data = body["data"]
    assert data["timed_out"] is True
    assert data["stop_reason"] == "context_lost"  # the context was removed
    assert data["stderr"] == "partial\n" + code_contexts.STOPPED_MESSAGE
    assert data["stderr"].count("\n") == 2  # the partial line plus exactly one added line
    assert shell.kills == [directory]
    assert shell.alive == set()
    listed = await send(client, "GET", contexts_path(sandbox_id), key, status=200)
    later = await send(client, "POST", path + "/run", key, status=404, json={"code": "1"})
    deleted = await send(client, "DELETE", path, key, status=404)
    assert listed["data"] == []
    assert later["error"]["code"] == deleted["error"]["code"] == "NOT_FOUND"
    assert len(shell.runs) == 1  # the later run never reached the client


async def test_an_exec_timeout_without_stderr_adds_just_the_stop_line(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    shell.cell_result = ExecResult(exit_code=137, timed_out=True)
    shell.idle = False

    body = await send(
        client,
        "POST",
        contexts_path(sandbox_id, context_id, "run"),
        key,
        status=200,
        json={"code": "x", "timeout_s": 1},
    )

    assert body["data"]["stderr"] == code_contexts.STOPPED_MESSAGE


@pytest.mark.parametrize(
    ("requested", "alarm"), [(1, 1.0), (3000, 3000.0), (3596, 3595.0), (3600, 3595.0)]
)
async def test_the_cell_alarm_leaves_room_for_the_exec_margin(
    client: httpx.AsyncClient, key: str, shell: SandboxShell, requested: int, alarm: float
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)

    await send(
        client,
        "POST",
        contexts_path(sandbox_id, context_id, "run"),
        key,
        status=200,
        json={"code": "1", "timeout_s": requested},
    )

    [run] = shell.runs
    assert float(run.argv[4]) == alarm
    assert run.timeout_s == alarm + code_contexts.EXEC_MARGIN_S
    assert run.timeout_s <= code_contexts.MAX_TIMEOUT_S


async def test_run_in_an_unknown_context_is_not_found(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)

    for context_id in (UNKNOWN_ID, "ctx_nope"):
        body = await send(
            client,
            "POST",
            contexts_path(sandbox_id, context_id, "run"),
            key,
            status=404,
            json={"code": "1"},
        )
        assert body["error"]["code"] == "NOT_FOUND"
    assert shell.runs == []


async def test_run_with_another_language_is_unprocessable(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)

    body = await send(
        client,
        "POST",
        contexts_path(sandbox_id, context_id, "run"),
        key,
        status=422,
        json={"language": "javascript", "code": "1"},
    )

    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert shell.runs == []


# --- parallel runs on one context ---------------------------------------------------------

WAIT_DEADLINE_S = 10.0


@dataclass
class SlowKernel:
    """The kernel exec of the fake sandbox: it takes ``delay_s``, or waits for ``release``."""

    hold: bool = False
    delay_s: float = 0.0
    events: list[str] = field(default_factory=list)
    started: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)


def slow_kernel(
    monkeypatch: pytest.MonkeyPatch, driver: FakeDriver, *, hold: bool = False, delay_s: float = 0.0
) -> SlowKernel:
    """Make every client exec (``python3 ...``) slow; the cell timeout names the run in events."""
    kernel = SlowKernel(hold=hold, delay_s=delay_s)
    original = driver.exec

    async def exec_(ref: str, request: ExecRequest) -> ExecResult:
        if request.argv[0] != "python3":
            return await original(ref, request)
        name = request.argv[4]  # the cell timeout
        kernel.events.append(f"start {name}")
        kernel.started.set()
        if kernel.hold:
            await asyncio.wait_for(kernel.release.wait(), WAIT_DEADLINE_S)
        else:
            await asyncio.sleep(kernel.delay_s)
        result = await original(ref, request)
        kernel.events.append(f"end {name}")
        return result

    monkeypatch.setattr(driver, "exec", exec_)
    return kernel


def run_cell(
    client: httpx.AsyncClient, key: str, run_path: str, *, timeout_s: int, status: int = 200
) -> asyncio.Task[dict[str, Any]]:
    call = send(
        client, "POST", run_path, key, status=status, json={"code": "x", "timeout_s": timeout_s}
    )
    return asyncio.create_task(call)


async def wait_for_users(lock_key: tuple[str, str], users: int) -> None:
    """Wait until ``users`` runs hold or wait for the context's lock."""

    async def poll() -> None:
        while lock_key not in routes._RUN_LOCKS or routes._RUN_LOCKS[lock_key].users < users:
            await asyncio.sleep(0.01)

    await asyncio.wait_for(poll(), WAIT_DEADLINE_S)


async def test_two_concurrent_runs_on_one_context_complete_one_after_the_other(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    kernel = slow_kernel(monkeypatch, driver, delay_s=0.2)
    run_path = contexts_path(sandbox_id, context_id, "run")

    first = run_cell(client, key, run_path, timeout_s=30)
    await asyncio.wait_for(kernel.started.wait(), WAIT_DEADLINE_S)
    second = run_cell(client, key, run_path, timeout_s=31)
    first_body, second_body = await asyncio.gather(first, second)

    assert first_body["data"]["exit_code"] == second_body["data"]["exit_code"] == 0
    assert first_body["data"]["timed_out"] is second_body["data"]["timed_out"] is False
    assert kernel.events == ["start 30.0", "end 30.0", "start 31.0", "end 31.0"]  # no overlap
    assert routes._RUN_LOCKS == {}


async def test_a_waiter_whose_timeout_passes_gets_124_and_the_context_survives(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    kernel = slow_kernel(monkeypatch, driver, hold=True)
    run_path = contexts_path(sandbox_id, context_id, "run")

    first = run_cell(client, key, run_path, timeout_s=30)
    await asyncio.wait_for(kernel.started.wait(), WAIT_DEADLINE_S)
    waiter = await send(
        client, "POST", run_path, key, status=200, json={"code": "x", "timeout_s": 1}
    )

    data = waiter["data"]
    assert data["exit_code"] == routes.BUSY_EXIT_CODE == 124
    assert data["timed_out"] is True
    assert data["stop_reason"] == "queue_timeout"
    assert data["result"] is None and data["error"] is None
    assert data["stderr"] == routes.BUSY_MESSAGE.decode()
    assert data["stderr"].count("\n") == 1
    assert "another run on this context was still executing" in data["stderr"]
    assert len(routes._RUN_LOCKS) == 1  # the holder still has its entry
    kernel.release.set()
    holder = await first
    assert holder["data"]["exit_code"] == 0
    assert shell.kills == []
    assert len(shell.alive) == 1
    assert len(shell.runs) == 1  # the waiter never reached the client
    listed = await send(client, "GET", contexts_path(sandbox_id), key, status=200)
    assert [item["id"] for item in listed["data"]] == [context_id]
    assert routes._RUN_LOCKS == {}


async def test_only_the_run_whose_own_cell_timed_out_discards_the_context(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    directory = code_contexts.context_dir(context_id)
    kernel = slow_kernel(monkeypatch, driver, hold=True)
    shell.cell_result = ExecResult(exit_code=137, timed_out=True)
    shell.idle = False
    run_path = contexts_path(sandbox_id, context_id, "run")

    holder = run_cell(client, key, run_path, timeout_s=30)
    await asyncio.wait_for(kernel.started.wait(), WAIT_DEADLINE_S)
    waiter = run_cell(client, key, run_path, timeout_s=30, status=404)
    await wait_for_users((sandbox_id, context_id), 2)
    kernel.release.set()
    holder_body, waiter_body = await asyncio.gather(holder, waiter)

    assert holder_body["data"]["timed_out"] is True
    assert holder_body["data"]["stop_reason"] == "context_lost"
    assert holder_body["data"]["stderr"] == code_contexts.STOPPED_MESSAGE
    assert waiter_body["error"]["code"] == "NOT_FOUND"  # it ran after the discard
    assert shell.kills == [directory]
    assert len(shell.runs) == 1
    assert routes._RUN_LOCKS == {}


async def test_runs_on_different_contexts_do_not_wait_for_each_other(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox_id = await create_sandbox(client, key)
    first_id = await create_context(client, key, sandbox_id)
    second_id = await create_context(client, key, sandbox_id)
    kernel = slow_kernel(monkeypatch, driver, hold=True)

    first = run_cell(client, key, contexts_path(sandbox_id, first_id, "run"), timeout_s=30)
    await asyncio.wait_for(kernel.started.wait(), WAIT_DEADLINE_S)
    kernel.started.clear()
    second = run_cell(client, key, contexts_path(sandbox_id, second_id, "run"), timeout_s=31)
    await asyncio.wait_for(kernel.started.wait(), WAIT_DEADLINE_S)  # started while the first held
    kernel.release.set()
    await asyncio.gather(first, second)

    assert kernel.events[:2] == ["start 30.0", "start 31.0"]
    assert routes._RUN_LOCKS == {}


async def test_a_run_on_an_unknown_context_leaves_no_lock_behind(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)

    await send(
        client,
        "POST",
        contexts_path(sandbox_id, UNKNOWN_ID, "run"),
        key,
        status=404,
        json={"code": "1"},
    )

    assert routes._RUN_LOCKS == {}


# --- list and delete --------------------------------------------------------------------


async def test_list_returns_the_live_contexts(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    empty = await send(client, "GET", contexts_path(sandbox_id), key, status=200)
    first = await create_context(client, key, sandbox_id)
    second = await create_context(client, key, sandbox_id, cwd="/data")

    body = await send(client, "GET", contexts_path(sandbox_id), key, status=200)

    assert empty["data"] == []
    listed = {item["id"]: item for item in body["data"]}
    assert set(listed) == {first, second}
    assert listed[first] == {"id": first, "language": "python", "cwd": DEFAULT_CWD}
    assert listed[second]["cwd"] == "/data"


async def test_delete_removes_the_context_and_a_second_delete_is_not_found(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    path = contexts_path(sandbox_id, context_id)

    deleted = await send(client, "DELETE", path, key, status=200)
    listed = await send(client, "GET", contexts_path(sandbox_id), key, status=200)
    again = await send(client, "DELETE", path, key, status=404)
    run = await send(client, "POST", path + "/run", key, status=404, json={"code": "1"})

    assert deleted["data"] == {"id": context_id, "deleted": True}
    assert listed["data"] == []
    assert again["error"]["code"] == "NOT_FOUND"
    assert run["error"]["code"] == "NOT_FOUND"


async def test_delete_of_an_unknown_context_is_not_found(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)

    body = await send(client, "DELETE", contexts_path(sandbox_id, UNKNOWN_ID), key, status=404)

    assert body["error"]["code"] == "NOT_FOUND"


# --- interrupt --------------------------------------------------------------------------


def interrupt_path(sandbox_id: str, context_id: str) -> str:
    return contexts_path(sandbox_id, context_id, "interrupt")


async def test_interrupt_signals_the_kernel_and_answers_true(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    shell.idle = False  # a cell is running (an interrupt between cells answers false)

    body = await send(client, "POST", interrupt_path(sandbox_id, context_id), key, status=200)

    assert body["data"] == {"id": context_id, "interrupted": True}
    assert shell.interrupts == [code_contexts.context_dir(context_id)]
    assert shell.kills == []  # an interrupt never stops the kernel
    assert shell.interrupt_args == [["", "1"]]  # no cell named: whichever one runs is stopped
    listed = await send(client, "GET", contexts_path(sandbox_id), key, status=200)
    assert [item["id"] for item in listed["data"]] == [context_id]


async def test_interrupt_of_a_context_without_a_live_kernel_answers_false(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    shell.alive.clear()  # the directory is there, the kernel process is not

    body = await send(client, "POST", interrupt_path(sandbox_id, context_id), key, status=200)

    assert body["data"] == {"id": context_id, "interrupted": False}
    assert shell.interrupts == []


@pytest.mark.parametrize("context_id", [UNKNOWN_ID, "not-a-context"])
async def test_interrupt_of_an_unknown_context_is_not_found(
    client: httpx.AsyncClient, key: str, shell: SandboxShell, context_id: str
) -> None:
    sandbox_id = await create_sandbox(client, key)

    body = await send(client, "POST", interrupt_path(sandbox_id, context_id), key, status=404)

    assert body["error"]["code"] == "NOT_FOUND"
    assert shell.interrupts == []


async def test_interrupt_is_audited(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)

    await send(client, "POST", interrupt_path(sandbox_id, context_id), key, status=200)

    [event] = [
        e for e in await audit_rows(app, org_id) if e.action == "toolbox.code_contexts.interrupt"
    ]
    assert event.target_type == "sandbox"
    assert event.target_id == sandbox_id
    assert event.details == {"context_id": context_id}


class FakeRequest:
    """Just enough of ``Request``: ``is_disconnected`` flips after ``disconnect_after`` polls."""

    def __init__(self, disconnect_after: int) -> None:
        self.disconnect_after = disconnect_after
        self.polls = 0

    async def is_disconnected(self) -> bool:
        self.polls += 1
        return self.polls > self.disconnect_after


async def stored_sandbox(app: FastAPI, org_id: str, sandbox_id: str) -> Sandbox:
    async with UnitOfWork(app.state.session_factory) as uow:
        sandbox = await uow.sandboxes.get(org_id, sandbox_id)
    assert sandbox is not None
    return sandbox


def record_lock_state_at_interrupt(
    monkeypatch: pytest.MonkeyPatch, lock_key: tuple[str, str]
) -> list[bool]:
    """For each interrupt helper call: was the context's lock still registered at that time?"""
    seen: list[bool] = []
    original = code_contexts.interrupt_context

    async def spy(*args: Any, **kwargs: Any) -> bool:
        seen.append(lock_key in routes._RUN_LOCKS)
        return await original(*args, **kwargs)

    monkeypatch.setattr(code_contexts, "interrupt_context", spy)
    return seen


async def test_a_run_whose_client_went_away_interrupts_its_cell_before_the_lock_is_released(
    app: FastAPI,
    client: httpx.AsyncClient,
    org_id: str,
    key: str,
    driver: FakeDriver,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    sandbox = await stored_sandbox(app, org_id, sandbox_id)
    kernel = slow_kernel(monkeypatch, driver, hold=True)
    monkeypatch.setattr(process_routes, "DISCONNECT_POLL_INTERVAL_S", 0.01)
    seen = record_lock_state_at_interrupt(monkeypatch, (sandbox_id, context_id))
    request: Any = FakeRequest(disconnect_after=3)

    turn = routes._run_in_turn(driver, sandbox, context_id, "while True: pass", 30.0)
    call = routes._exec_of(turn, [])
    outcome = await asyncio.wait_for(
        process_routes._run_until_disconnect(request, driver, sandbox, call), WAIT_DEADLINE_S
    )

    assert kernel.started.is_set()
    assert outcome.result.exit_code == process_routes.CLIENT_GONE_EXIT_CODE
    assert shell.interrupts == [code_contexts.context_dir(context_id)]
    assert seen == [True]
    scripts = shell.scripts()
    assert scripts.index(code_contexts._INTERRUPT_SCRIPT) < scripts.index(
        code_contexts._IDLE_SCRIPT
    )  # the cell is interrupted, then waited for
    assert shell.kills == []
    assert routes._RUN_LOCKS == {}


async def test_the_next_run_does_not_queue_behind_a_cancelled_one(
    app: FastAPI,
    client: httpx.AsyncClient,
    org_id: str,
    key: str,
    driver: FakeDriver,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    sandbox = await stored_sandbox(app, org_id, sandbox_id)
    kernel = slow_kernel(monkeypatch, driver, hold=True)
    first = asyncio.create_task(routes._run_in_turn(driver, sandbox, context_id, "x", 30.0))
    await asyncio.wait_for(kernel.started.wait(), WAIT_DEADLINE_S)
    second = asyncio.create_task(routes._run_in_turn(driver, sandbox, context_id, "y", 30.0))
    await wait_for_users((sandbox_id, context_id), 2)

    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    kernel.release.set()
    turn = await asyncio.wait_for(second, WAIT_DEADLINE_S)

    assert turn.result.exit_code == 0 and not turn.result.timed_out
    assert turn.stop_reason is None
    assert shell.interrupts == [code_contexts.context_dir(context_id)]  # before the second ran
    assert shell.kills == []  # no stuck-cell discard for the run behind it
    assert routes._RUN_LOCKS == {}


async def test_a_waiter_that_is_cancelled_does_not_interrupt_the_running_cell(
    app: FastAPI,
    client: httpx.AsyncClient,
    org_id: str,
    key: str,
    driver: FakeDriver,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    sandbox = await stored_sandbox(app, org_id, sandbox_id)
    kernel = slow_kernel(monkeypatch, driver, hold=True)
    holder = asyncio.create_task(routes._run_in_turn(driver, sandbox, context_id, "x", 30.0))
    await asyncio.wait_for(kernel.started.wait(), WAIT_DEADLINE_S)
    waiter = asyncio.create_task(routes._run_in_turn(driver, sandbox, context_id, "y", 30.0))
    await wait_for_users((sandbox_id, context_id), 2)

    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    kernel.release.set()
    await asyncio.wait_for(holder, WAIT_DEADLINE_S)

    assert shell.interrupts == []  # the holder's own cell was never cut short
    assert routes._RUN_LOCKS == {}


async def test_a_run_that_hit_the_output_limit_interrupts_its_cell(
    client: httpx.AsyncClient, key: str, shell: SandboxShell, monkeypatch: pytest.MonkeyPatch
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    shell.cell_result = ExecResult(exit_code=137, stdout=b"x" * 10, truncated=True)
    seen = record_lock_state_at_interrupt(monkeypatch, (sandbox_id, context_id))

    body = await send(
        client,
        "POST",
        contexts_path(sandbox_id, context_id, "run"),
        key,
        status=200,
        json={"code": "while True: print('x')"},
    )

    assert body["data"]["stop_reason"] == "output_limit"
    assert shell.interrupts == [code_contexts.context_dir(context_id)]
    assert seen == [True]  # interrupted while the run still held the context
    assert code_contexts._IDLE_SCRIPT in shell.scripts()  # and waited for the cell to end
    assert shell.kills == []
    assert routes._RUN_LOCKS == {}


async def test_a_run_that_hit_the_output_limit_interrupts_only_its_own_cell_number(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    shell.cell_result = ExecResult(exit_code=137, stdout=b"x" * 10, truncated=True)

    await send(
        client,
        "POST",
        contexts_path(sandbox_id, context_id, "run"),
        key,
        status=200,
        json={"code": "while True: print('x')"},
    )

    [run] = shell.runs
    cell_number = run.argv[6]  # the number the client hands to the kernel
    assert shell.interrupt_args == [[cell_number]]  # the interrupt names that cell ...
    assert shell.idle_args == [[cell_number]]  # ... and so does the wait for it to end


async def test_two_runs_get_two_cell_numbers_and_their_interrupts_follow_them(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    shell.cell_result = ExecResult(exit_code=137, truncated=True)
    path = contexts_path(sandbox_id, context_id, "run")

    for code in ("while True: print(1)", "while True: print(2)"):
        await send(client, "POST", path, key, status=200, json={"code": code})

    numbers = [int(r.argv[6]) for r in shell.runs]
    assert numbers[0] < numbers[1]
    assert shell.interrupt_args == [[str(n)] for n in numbers]


async def test_the_exec_timeout_interrupt_names_the_runs_cell(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    shell.cell_result = ExecResult(exit_code=137, timed_out=True)

    await send(
        client,
        "POST",
        contexts_path(sandbox_id, context_id, "run"),
        key,
        status=200,
        json={"code": "native()"},
    )

    [run] = shell.runs
    assert shell.interrupt_args == [[run.argv[6]]]
    assert shell.idle_args == [[run.argv[6]]]
    assert shell.kills == []  # the kernel answered, so the context was kept


async def test_a_run_that_ended_normally_is_not_interrupted(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)

    await send(
        client,
        "POST",
        contexts_path(sandbox_id, context_id, "run"),
        key,
        status=200,
        json={"code": "1"},
    )

    assert shell.interrupts == []
    assert code_contexts._INTERRUPT_SCRIPT not in shell.scripts()


async def test_a_failing_interrupt_is_logged_and_never_breaks_the_answer(
    client: httpx.AsyncClient,
    key: str,
    shell: SandboxShell,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    shell.cell_result = ExecResult(exit_code=137, truncated=True)

    async def broken(*args: Any, **kwargs: Any) -> bool:
        raise RuntimeError("the sandbox went away")

    monkeypatch.setattr(code_contexts, "interrupt_context", broken)
    caplog.set_level("ERROR", logger=routes.logger.name)

    body = await send(
        client,
        "POST",
        contexts_path(sandbox_id, context_id, "run"),
        key,
        status=200,
        json={"code": "x"},
    )

    assert body["data"]["stop_reason"] == "output_limit"
    assert any("could not interrupt code context" in r.getMessage() for r in caplog.records)
    assert routes._RUN_LOCKS == {}


# --- the stuck-cell rule interrupts first -----------------------------------------------


async def test_the_stuck_cell_path_interrupts_and_waits_before_it_discards(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    directory = code_contexts.context_dir(context_id)
    shell.cell_result = ExecResult(exit_code=137, timed_out=True)
    shell.idle = False

    body = await send(
        client,
        "POST",
        contexts_path(sandbox_id, context_id, "run"),
        key,
        status=200,
        json={"code": "native_call()", "timeout_s": 1},
    )

    assert body["data"]["stderr"] == code_contexts.STOPPED_MESSAGE
    assert shell.interrupts == [directory]
    assert shell.kills == [directory]
    scripts = shell.scripts()
    assert scripts.index(code_contexts._INTERRUPT_SCRIPT) < scripts.index(
        code_contexts._IDLE_SCRIPT
    )
    assert scripts.index(code_contexts._IDLE_SCRIPT) < scripts.index(code_contexts._KILL_SCRIPT)


async def test_a_stuck_cell_the_kernel_finishes_after_the_interrupt_keeps_the_context(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    shell.cell_result = ExecResult(exit_code=137, stderr=b"partial", timed_out=True)
    path = contexts_path(sandbox_id, context_id)

    body = await send(
        client, "POST", path + "/run", key, status=200, json={"code": "slow()", "timeout_s": 1}
    )

    data = body["data"]
    assert data["timed_out"] is True
    assert data["stop_reason"] == "timeout"
    assert data["stderr"] == "partial\n" + code_contexts.INTERRUPTED_MESSAGE
    assert shell.interrupts == [code_contexts.context_dir(context_id)]
    assert shell.kills == []
    shell.cell_result = ExecResult(exit_code=0, stdout=b"2\n")
    later = await send(client, "POST", path + "/run", key, status=200, json={"code": "1 + 1"})
    assert later["data"]["stdout"] == "2\n"


async def test_a_stuck_cell_without_a_live_kernel_is_discarded_without_waiting(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    directory = code_contexts.context_dir(context_id)
    shell.cell_result = ExecResult(exit_code=137, timed_out=True)
    shell.alive.clear()  # the kernel process is gone, the directory is still there

    body = await send(
        client,
        "POST",
        contexts_path(sandbox_id, context_id, "run"),
        key,
        status=200,
        json={"code": "x", "timeout_s": 1},
    )

    assert body["data"]["stderr"] == code_contexts.STOPPED_MESSAGE
    assert shell.interrupts == []
    assert code_contexts._IDLE_SCRIPT not in shell.scripts()
    assert shell.kills == [directory]


# --- audit ------------------------------------------------------------------------------


async def test_every_mutating_call_is_audited_and_reads_are_not(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    secret = "print('code-secret-value-c0de')"

    context_id = await create_context(client, key, sandbox_id)
    await send(client, "GET", contexts_path(sandbox_id), key, status=200)
    await send(
        client,
        "POST",
        contexts_path(sandbox_id, context_id, "run"),
        key,
        status=200,
        json={"code": secret},
    )
    await send(client, "DELETE", contexts_path(sandbox_id, context_id), key, status=200)

    events = [e for e in await audit_rows(app, org_id) if e.action in AUDIT_ACTIONS]
    assert sorted(e.action for e in events) == sorted(AUDIT_ACTIONS)
    assert sorted(e.action for e in events) == [
        "toolbox.code_contexts.create",
        "toolbox.code_contexts.delete",
        "toolbox.code_contexts.run",
    ]  # the literal names, for tests/audit_coverage_table_r96.py
    for event in events:
        assert event.target_id == sandbox_id
        assert event.target_type == "sandbox"
    [run_event] = [e for e in events if e.action.endswith(".run")]
    assert run_event.details["context_id"] == context_id
    assert "code-secret-value-c0de" not in str(run_event.details)  # the code is digested
    assert set(run_event.details["code"]) == {"sha256", "length"}


# --- guards -----------------------------------------------------------------------------


async def test_the_routes_require_the_toolbox_scope(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    read_only = await add_key(app, org_id, frozenset({Scope.SANDBOXES_READ}))
    before = len(shell.requests)

    for method, path, kwargs in every_route(sandbox_id, context_id):
        body = await send(client, method, path, read_only, status=403, **kwargs)
        assert body["error"]["code"] == "FORBIDDEN"

    assert len(shell.requests) == before


async def test_another_orgs_sandbox_is_not_found(
    app: FastAPI, client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    other = await add_key(app, await add_org(app, "globex"), FULL_ACCESS)
    before = len(shell.requests)

    for method, path, kwargs in every_route(sandbox_id, context_id):
        body = await send(client, method, path, other, status=404, **kwargs)
        assert body["error"]["code"] == "NOT_FOUND"

    assert len(shell.requests) == before


async def test_a_stopped_sandbox_answers_conflict_no_container(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await create_sandbox(client, key)
    context_id = await create_context(client, key, sandbox_id)
    await send(client, "POST", f"{BASE}/{sandbox_id}/stop", key, status=200)
    before = len(shell.requests)

    for method, path, kwargs in every_route(sandbox_id, context_id):
        body = await send(client, method, path, key, status=409, **kwargs)
        assert body["error"]["details"]["reason"] == "no_container"

    assert len(shell.requests) == before
