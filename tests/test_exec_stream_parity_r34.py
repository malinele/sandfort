"""Streamed and plain runs agree: the stop reasons of ``exec_stream`` and of code-context runs.

The fake driver (like Firecracker) replays a buffered exec as a stream; the stream must keep every
flag of the buffered result, and the streaming module must add nothing the plain run lacks.
"""

import json
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sandfort.domain.sandbox import Sandbox
from sandfort.drivers.base import ExecRequest, ExecResult, ExitEvent, OutputChunk
from sandfort.drivers.fake import FakeDriver, timed_out_result
from sandfort.toolbox import code_context_stream, code_contexts
from sandfort.toolbox.code_context_stream import RunEvents, streaming_runner

NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
CONTEXT_ID = "ctx_0123456789abcdef"
CELL_TIMEOUT_S = 3.0
OUTCOME = {"x": 0, "r": "42", "err": None, "lost": False}
TIMED_OUT_EXIT_CODE = 124


class CellScript:
    """Answers the platform's ``sh -c`` execs and the client exec of one scripted cell."""

    def __init__(self, *, timed_out: bool) -> None:
        self.timed_out = timed_out

    def __call__(self, env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        if request.argv[0] != "python3":
            return ExecResult(exit_code=0)
        if self.timed_out:
            return timed_out_result(request, stdout=b"tick\n")
        line = f"{request.argv[5]} {json.dumps(OUTCOME)}\n".encode()
        return ExecResult(exit_code=0, stdout=b"hi\n" + code_contexts.OUTCOME_MARK + line)


def running_sandbox(driver: FakeDriver) -> Sandbox:
    ref = driver.plant_instance("sbx_parity", "org_parity")
    return Sandbox(
        id="sbx_parity",
        org_id="org_parity",
        name="parity",
        image_ref="fake-image",
        driver="fake",
        driver_ref=ref,
        created_at=NOW,
        updated_at=NOW,
    )


@pytest.fixture(autouse=True)
def quick_waits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(code_contexts, "INTERRUPT_WAIT_S", 0.2)
    monkeypatch.setattr(code_contexts, "INTERRUPT_POLL_S", 0.01)


async def plain_and_streamed(
    *, timed_out: bool
) -> tuple[code_contexts.ContextRun, code_contexts.ContextRun]:
    driver = FakeDriver(exec_handler=CellScript(timed_out=timed_out))
    sandbox = running_sandbox(driver)

    async def run(runner: code_contexts.RunExec | None) -> code_contexts.ContextRun:
        done = await code_contexts.run_in_context(
            driver, sandbox, CONTEXT_ID, "1", timeout_s=CELL_TIMEOUT_S, cell=1, runner=runner
        )
        return replace(done, exec_result=replace(done.exec_result, duration_ms=0))

    plain = await run(None)
    streamed = await run(streaming_runner(driver, sandbox, RunEvents()))
    return plain, streamed


async def test_a_streamed_exec_keeps_the_sandbox_stopped_flag() -> None:
    stopped = ExecResult(exit_code=137, stderr=b"gone\n", sandbox_stopped=True)
    driver = FakeDriver(exec_handler=lambda env, request: stopped)
    ref = driver.plant_instance("sbx_parity", "org_parity")

    events = [e async for e in driver.exec_stream(ref, ExecRequest(argv=["x"]))]

    assert events == [
        OutputChunk("stderr", b"gone\n"),
        ExitEvent(137, timed_out=False, truncated=False, sandbox_stopped=True),
    ]


async def test_a_streamed_exec_keeps_the_timeout_and_truncation_flags() -> None:
    cut = ExecResult(exit_code=124, timed_out=True, truncated=True)
    driver = FakeDriver(exec_handler=lambda env, request: cut)
    ref = driver.plant_instance("sbx_parity", "org_parity")

    events = [e async for e in driver.exec_stream(ref, ExecRequest(argv=["x"]))]

    assert events == [ExitEvent(124, timed_out=True, truncated=True, sandbox_stopped=False)]


async def test_a_streamed_run_of_a_normal_cell_equals_the_plain_run() -> None:
    plain, streamed = await plain_and_streamed(timed_out=False)

    assert streamed == plain
    assert (plain.exec_result.stdout, plain.result) == (b"hi\n", "42")


async def test_a_streamed_run_of_a_timed_out_cell_equals_the_plain_run() -> None:
    plain, streamed = await plain_and_streamed(timed_out=True)

    assert streamed == plain
    assert plain.exec_result.timed_out is True
    # the driver's one timeout line, not a second one added by the streaming module
    assert plain.exec_result.stderr.count(b"(timeout)") == 1


def test_the_streaming_module_does_not_import_the_docker_driver() -> None:
    source = Path(code_context_stream.__file__).read_text(encoding="utf-8")

    assert "drivers.docker" not in source
