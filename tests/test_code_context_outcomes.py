"""Machine-readable outcomes of code-context runs: ``result``, ``error`` and the stop reasons.

The kernel and client sources run for real in local ``python3`` subprocesses (as in
``test_code_contexts.py``); the client gets a per-run token, ends its stdout with the outcome
trailer, and ``split_outcome`` turns that back into the cell's own stdout plus the outcome.
The response model and the generated OpenAPI document are checked without a sandbox.
"""

import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from sandfort.api.openapi import build_document
from sandfort.api.schemas import toolbox_process
from sandfort.api.schemas.toolbox_process import (
    CellErrorResponse,
    ContextRunResponse,
    ExecuteResponse,
    context_run_response,
)
from sandfort.drivers.base import ExecResult
from sandfort.toolbox import code_contexts
from sandfort.toolbox.code_contexts import (
    OUTCOME_MARK,
    CellError,
    ClientOutcome,
    split_outcome,
)

READY_DEADLINE_S = 10.0
RUN_DEADLINE_S = 30.0
BUSY_DEADLINE_S = 10.0
MAX_SOCKET_PATH = 100
RUN_PATH = "/v1/sandboxes/{sandbox_id}/toolbox/code-contexts/{context_id}/run"
EXECUTE_PATH = "/v1/sandboxes/{sandbox_id}/toolbox/process/execute"


@dataclass(frozen=True)
class Run:
    exit_code: int
    stdout: bytes  # the cell's own stdout, trailer removed
    stderr: str
    outcome: ClientOutcome | None


class Kernel:
    """A real kernel process; cells go through the real client with a per-run token."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.socket = directory / code_contexts.SOCKET_FILE
        (directory / code_contexts.KERNEL_FILE).write_text(code_contexts.KERNEL_SOURCE)
        (directory / code_contexts.CLIENT_FILE).write_text(code_contexts.CLIENT_SOURCE)
        self.log = (directory / "kernel.log").open("wb")
        self.process = subprocess.Popen(
            [sys.executable, str(directory / code_contexts.KERNEL_FILE), str(directory)],
            stdin=subprocess.DEVNULL,
            stdout=self.log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self._cells = 0

    def wait_ready(self) -> None:
        deadline = time.monotonic() + READY_DEADLINE_S
        while not self.socket.exists():
            assert self.process.poll() is None, (self.directory / "kernel.log").read_text()
            assert time.monotonic() < deadline, "the kernel never created its socket"
            time.sleep(0.05)

    def start(
        self, code: str, token: str | None, *, timeout_s: str = "10", seq: int | None = None
    ) -> subprocess.Popen[bytes]:
        """Start a cell through the client; ``seq`` is the cell number it hands to the kernel."""
        self._cells += 1
        cell = self.directory / f"cell-{self._cells}.py"
        cell.write_text(code)
        client = str(self.directory / code_contexts.CLIENT_FILE)
        argv = [sys.executable, client, str(self.socket), str(cell), timeout_s]
        if token is not None or seq is not None:
            argv.append(token or "")
        if seq is not None:
            argv.append(str(seq))
        return subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def run(self, code: str, *, timeout_s: str = "10") -> Run:
        token = uuid.uuid4().hex
        return finish(self.start(code, token, timeout_s=timeout_s), token)

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGKILL)
        self.process.wait()
        self.log.close()


def finish(client: subprocess.Popen[bytes], token: str) -> Run:
    stdout, stderr = client.communicate(timeout=RUN_DEADLINE_S)
    own, outcome = split_outcome(stdout, token)
    return Run(client.returncode, own, stderr.decode(), outcome)


@pytest.fixture
def kernel() -> Iterator[Kernel]:
    directory = Path(tempfile.mkdtemp(prefix="sfo-"))
    if len(str(directory / "kernel.sock.tmp")) > MAX_SOCKET_PATH:
        shutil.rmtree(directory, ignore_errors=True)
        pytest.skip("the temp directory path is too long for a unix socket")
    started = Kernel(directory)
    try:
        started.wait_ready()
        yield started
    finally:
        started.close()
        shutil.rmtree(directory, ignore_errors=True)


def wait_busy(kernel: Kernel) -> None:
    deadline = time.monotonic() + BUSY_DEADLINE_S
    while not (kernel.directory / "kernel.busy").exists():
        assert time.monotonic() < deadline, "the cell never started"
        time.sleep(0.02)


# --- result and error from the real kernel ------------------------------------------------


def test_a_trailing_expression_fills_result_and_stdout_is_unchanged(kernel: Kernel) -> None:
    run = kernel.run("print('a')\n5")

    assert run.exit_code == 0
    assert run.stdout == b"a\n5\n"  # still printed, as in a notebook; no trailer left
    assert run.outcome == ClientOutcome(status=0, result="5", error=None, lost=False)


def test_an_assignment_gives_a_null_result(kernel: Kernel) -> None:
    run = kernel.run("x = 1")

    assert run.stdout == b""
    assert run.outcome == ClientOutcome(status=0, result=None, error=None, lost=False)


def test_a_trailing_none_gives_a_null_result(kernel: Kernel) -> None:
    run = kernel.run("print('side effect')\nNone")

    assert run.stdout == b"side effect\n"
    assert run.outcome is not None and run.outcome.result is None


def test_the_result_is_the_repr(kernel: Kernel) -> None:
    kernel.run("x = 41")

    run = kernel.run("{'k': x + 1, 's': 'šđ'}")

    assert run.outcome is not None
    assert run.outcome.result == "{'k': 42, 's': 'šđ'}"
    assert run.stdout.decode() == "{'k': 42, 's': 'šđ'}\n"


def test_a_raising_cell_gives_error_and_a_null_result(kernel: Kernel) -> None:
    run = kernel.run("print('before')\n1 / 0")

    assert run.exit_code == 1
    assert run.stdout == b"before\n"
    assert "ZeroDivisionError" in run.stderr  # the traceback stays on stderr
    error = CellError(type="ZeroDivisionError", message="division by zero")
    assert run.outcome == ClientOutcome(status=1, result=None, error=error, lost=False)


@pytest.mark.parametrize(
    ("code", "kind", "message"),
    [
        ("raise ValueError('bad input')", "ValueError", "bad input"),
        ("raise KeyError('k')", "KeyError", "'k'"),
        ("raise SystemExit(3)", "SystemExit", "3"),
        ("x = (", "SyntaxError", "'(' was never closed (<cell>, line 1)"),
    ],
)
def test_the_error_names_the_exception_class_and_message(
    kernel: Kernel, code: str, kind: str, message: str
) -> None:
    run = kernel.run(code)

    assert run.outcome is not None
    assert run.outcome.error == CellError(type=kind, message=message)
    assert run.outcome.result is None


def test_a_kernel_timeout_reports_a_timeout_error(kernel: Kernel) -> None:
    run = kernel.run("import time\ntime.sleep(60)", timeout_s="1")

    assert run.exit_code == code_contexts.TIMED_OUT_EXIT_CODE
    assert run.outcome is not None
    assert run.outcome.error == CellError(type="TimeoutError", message="cell exceeded 1 s")
    assert run.outcome.lost is False


def test_the_state_survives_an_error_and_later_results_are_clean(kernel: Kernel) -> None:
    kernel.run("n = 2")
    kernel.run("raise RuntimeError('x')")

    run = kernel.run("n * 3")

    assert run.outcome == ClientOutcome(status=0, result="6", error=None, lost=False)


# --- a lost kernel ------------------------------------------------------------------------


def test_a_kernel_killed_during_a_run_reports_lost(kernel: Kernel) -> None:
    token = uuid.uuid4().hex
    client = kernel.start("import time\ntime.sleep(30)", token)
    wait_busy(kernel)

    kernel.process.kill()
    run = finish(client, token)

    assert run.exit_code == 1  # unchanged exit code
    assert "its state is lost" in run.stderr
    assert run.outcome == ClientOutcome(status=1, result=None, error=None, lost=True)
    response = context_run_response(
        ExecResult(exit_code=run.exit_code, stdout=run.stdout),
        stop_reason=toolbox_process.CONTEXT_STOP_REASON_CONTEXT_LOST,
    )
    assert response.stop_reason == "context_lost"


def test_a_context_deleted_during_a_run_reports_lost(kernel: Kernel) -> None:
    """Delete kills the kernel and removes the directory; the trailer does not need it."""
    token = uuid.uuid4().hex
    client = kernel.start("print('started')\nimport time\ntime.sleep(30)", token)
    assert client.stdout is not None
    first = client.stdout.readline()  # the cell is running once its first line arrived

    kernel.process.kill()
    shutil.rmtree(kernel.directory, ignore_errors=True)
    run = finish(client, token)

    assert first == b"started\n"
    assert run.stdout == b""  # the rest of stdout was only the trailer
    assert run.exit_code == 1
    assert run.outcome is not None and run.outcome.lost is True


def test_an_unreachable_kernel_reports_lost(tmp_path: Path) -> None:
    token = uuid.uuid4().hex
    cell = tmp_path / "cell.py"
    cell.write_text("1")
    client = tmp_path / code_contexts.CLIENT_FILE
    client.write_text(code_contexts.CLIENT_SOURCE)
    argv = [sys.executable, str(client), str(tmp_path / "none.sock"), str(cell), "5", token]

    completed = subprocess.run(argv, capture_output=True, timeout=RUN_DEADLINE_S, check=False)
    stdout, outcome = split_outcome(completed.stdout, token)

    assert completed.returncode == 1
    assert stdout == b""
    assert outcome is not None and outcome.lost is True


def test_without_a_token_the_client_writes_no_trailer(kernel: Kernel) -> None:
    """The argv of a platform that predates the trailer: stdout is exactly the cell's."""
    client = kernel.start("print('a')\n5", None)
    stdout, _ = client.communicate(timeout=RUN_DEADLINE_S)

    assert client.returncode == 0
    assert stdout == b"a\n5\n"


# --- split_outcome ------------------------------------------------------------------------


def trailer(token: str, body: str) -> bytes:
    return OUTCOME_MARK + token.encode() + b" " + body.encode() + b"\n"


def test_split_keeps_stdout_without_a_marker() -> None:
    assert split_outcome(b"plain\n", "t" * 32) == (b"plain\n", None)


def test_split_ignores_a_trailer_for_another_token() -> None:
    stdout = b"x\n" + trailer("a" * 32, '{"x": 0, "r": "1", "err": null, "lost": false}')

    assert split_outcome(stdout, "b" * 32) == (stdout, None)


@pytest.mark.parametrize(
    "body",
    [
        "not json",
        "[1]",
        '{"x": "0", "r": null, "err": null, "lost": false}',
        '{"x": true, "r": null, "err": null, "lost": false}',
        '{"x": 0, "r": 5, "err": null, "lost": false}',
        '{"x": 0, "r": null, "err": {"type": 1, "message": ""}, "lost": false}',
        '{"x": 0, "r": null, "err": "boom", "lost": false}',
        '{"x": 0, "r": null, "err": null}',
    ],
)
def test_a_malformed_trailer_leaves_stdout_unchanged(body: str) -> None:
    token = "c" * 32
    stdout = b"out\n" + trailer(token, body)

    assert split_outcome(stdout, token) == (stdout, None)


def test_only_the_last_marker_counts() -> None:
    token = "d" * 32
    first = trailer(token, '{"x": 0, "r": "fake", "err": null, "lost": false}')
    last = trailer(token, '{"x": 1, "r": null, "err": null, "lost": true}')

    stdout, outcome = split_outcome(b"a" + first + b"b" + last, token)

    assert stdout == b"a" + first + b"b"
    assert outcome == ClientOutcome(status=1, result=None, error=None, lost=True)


# --- the response model -------------------------------------------------------------------


def test_queue_timeout_refines_a_timeout() -> None:
    busy = ExecResult(exit_code=124, stderr=b"busy\n", timed_out=True)

    reason = toolbox_process.CONTEXT_STOP_REASON_QUEUE_TIMEOUT
    response = context_run_response(busy, stop_reason=reason)
    again = ContextRunResponse.model_validate(response.model_dump())

    assert response.stop_reason == again.stop_reason == "queue_timeout"
    assert (response.exit_code, response.timed_out) == (124, True)


def test_context_lost_is_kept_on_a_plain_exit() -> None:
    lost = ExecResult(exit_code=1, stderr=b"the context kernel closed the connection\n")

    reason = toolbox_process.CONTEXT_STOP_REASON_CONTEXT_LOST
    response = context_run_response(lost, stop_reason=reason)

    assert response.stop_reason == "context_lost"
    assert response.exit_code == 1


@pytest.mark.parametrize(
    ("result", "given", "expected"),
    [
        (ExecResult(exit_code=0), "queue_timeout", None),  # not a timeout: derived wins
        (ExecResult(exit_code=124, timed_out=True), "context_lost", "context_lost"),  # removed
        (ExecResult(exit_code=137, truncated=True), "context_lost", "output_limit"),
        (ExecResult(exit_code=137, sandbox_stopped=True), "context_lost", "sandbox_stopped"),
        (ExecResult(exit_code=137, sandbox_stopped=True), "sandbox_deleted", "sandbox_deleted"),
        (ExecResult(exit_code=0), "nonsense", None),
    ],
)
def test_other_stop_reasons_keep_their_meaning(
    result: ExecResult, given: str, expected: str | None
) -> None:
    assert context_run_response(result, stop_reason=given).stop_reason == expected


@pytest.mark.parametrize("given", ["queue_timeout", "context_lost"])
def test_the_execute_response_never_carries_the_context_reasons(given: str) -> None:
    timed_out = ExecuteResponse(
        exit_code=124,
        stdout="",
        stderr="",
        timed_out=True,
        truncated=False,
        duration_ms=0,
        stop_reason=given,
    )

    assert timed_out.stop_reason == "timeout"


def test_the_response_carries_result_and_error() -> None:
    error = CellErrorResponse(type="ValueError", message="bad")

    response = context_run_response(ExecResult(exit_code=1, stdout=b"a\n"), error=error)

    dumped = response.model_dump()
    assert dumped["result"] is None
    assert dumped["error"] == {"type": "ValueError", "message": "bad"}
    assert dumped["stdout"] == "a\n"


# --- OpenAPI ------------------------------------------------------------------------------


def resolve(document: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    while "$ref" in schema:
        name = schema["$ref"].rsplit("/", 1)[-1]
        schema = document["components"]["schemas"][name]
    return schema


def response_data(document: dict[str, Any], path: str) -> dict[str, Any]:
    """The ``data`` schema of the 200 envelope of ``POST path``."""
    content = document["paths"][path]["post"]["responses"]["200"]["content"]
    envelope = resolve(document, content["application/json"]["schema"])
    return nullable_ref(document, envelope["properties"]["data"])


def nullable_ref(document: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    if "$ref" in schema:
        return resolve(document, schema)
    [ref] = [option for option in schema["anyOf"] if "$ref" in option]
    return resolve(document, ref)


def test_the_spec_documents_result_error_and_the_new_stop_reasons() -> None:
    properties = response_data(build_document(), RUN_PATH)["properties"]

    assert {"result", "error", "stop_reason", "stdout"} <= set(properties)
    assert {"type": "string"} in properties["result"]["anyOf"]
    error = nullable_ref(build_document(), properties["error"])
    assert set(error["properties"]) == {"type", "message"}
    assert set(error["required"]) == {"type", "message"}
    description = properties["stop_reason"]["description"]
    assert "'queue_timeout'" in description and "'context_lost'" in description


def test_the_execute_route_keeps_the_plain_execute_response() -> None:
    properties = response_data(build_document(), EXECUTE_PATH)["properties"]

    assert "result" not in properties
    assert "queue_timeout" not in properties["stop_reason"]["description"]
