"""Round-34 code contexts: a slow or failed probe never kills a healthy kernel.

After an exec deadline the stuck cell is settled with a probe of the kernel. The probe is
three-valued: alive, dead (the "no live kernel" exit code, the probe not timed out) or unknown (the
probe timed out, any other exit code, or a ``DriverError`` from the probe or the idle check).
Unknown is treated like alive: the context is kept and the run is a plain ``timeout``. A discard
that raises ``DriverError`` keeps the context as well; ``context_lost`` means it was removed.
"""

from typing import Any

import httpx
import pytest

import test_code_contexts_api as base
from sandfort.drivers.base import ExecRequest, ExecResult
from sandfort.drivers.errors import DriverError
from sandfort.toolbox import code_contexts
from test_code_context_r33b import EXEC_TIMEOUT_EXIT_CODE, stuck_run
from test_code_contexts_api import SandboxShell

# The fixtures of the API tests, reused under their own names.
app = base.app
client = base.client
driver = base.driver
org_id = base.org_id
key = base.key
quick_interrupt_wait = base.quick_interrupt_wait


class ProbeShell(SandboxShell):
    """The scripted sandbox with a probe that can time out or fail, and a discard that can fail."""

    def __init__(self) -> None:
        super().__init__()
        self.probe_result: ExecResult | None = None  # replaces the interrupt script's answer
        self.probe_error: DriverError | None = None
        self.idle_error: DriverError | None = None
        self.kill_error: DriverError | None = None

    def _script(self, script: str, args: list[str], request: ExecRequest) -> ExecResult:
        if script == code_contexts._INTERRUPT_SCRIPT:
            if self.probe_error is not None:
                raise self.probe_error
            if self.probe_result is not None:
                return self.probe_result
        if script == code_contexts._IDLE_SCRIPT and self.idle_error is not None:
            raise self.idle_error
        if script == code_contexts._KILL_SCRIPT and self.kill_error is not None:
            raise self.kill_error
        return super()._script(script, args, request)


@pytest.fixture
def shell(driver: Any) -> ProbeShell:
    scripted = ProbeShell()
    driver.exec_handler = scripted
    return scripted


def assert_plain_timeout(data: dict[str, Any], shell: ProbeShell) -> None:
    """The run is a ``timeout`` with the unconfirmed-state message; the context still exists."""
    assert data["stop_reason"] == "timeout"
    assert data["exit_code"] == EXEC_TIMEOUT_EXIT_CODE
    assert data["timed_out"] is True
    assert data["stderr"] == "partial\n" + code_contexts.UNCONFIRMED_MESSAGE
    assert shell.kills == []
    assert len(shell.alive) == 1
    assert len(shell.ready) == 1


async def test_a_probe_that_timed_out_keeps_the_context(
    client: httpx.AsyncClient, key: str, shell: ProbeShell
) -> None:
    shell.probe_result = ExecResult(exit_code=EXEC_TIMEOUT_EXIT_CODE, timed_out=True)

    data, _, _ = await stuck_run(client, key, shell, kernel_answers=False)

    assert_plain_timeout(data, shell)


async def test_a_probe_with_an_unexpected_exit_code_keeps_the_context(
    client: httpx.AsyncClient, key: str, shell: ProbeShell
) -> None:
    shell.probe_result = ExecResult(exit_code=137)

    data, _, _ = await stuck_run(client, key, shell, kernel_answers=False)

    assert_plain_timeout(data, shell)


async def test_a_probe_that_raises_driver_error_keeps_the_context(
    client: httpx.AsyncClient, key: str, shell: ProbeShell
) -> None:
    shell.probe_error = DriverError("the sandbox is busy")

    data, _, _ = await stuck_run(client, key, shell, kernel_answers=False)

    assert_plain_timeout(data, shell)


async def test_an_idle_check_that_raises_driver_error_keeps_the_context(
    client: httpx.AsyncClient, key: str, shell: ProbeShell
) -> None:
    shell.idle_error = DriverError("the sandbox is busy")

    data, _, _ = await stuck_run(client, key, shell, kernel_answers=False)

    assert_plain_timeout(data, shell)


async def test_a_probe_that_reports_no_live_kernel_is_context_lost(
    client: httpx.AsyncClient, key: str, shell: ProbeShell
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    context_id = await base.create_context(client, key, sandbox_id)
    shell.cell_result = ExecResult(
        exit_code=EXEC_TIMEOUT_EXIT_CODE, stderr=b"partial", timed_out=True
    )
    shell.alive.clear()  # the kernel process is gone, the directory is still there

    body = await base.send(
        client,
        "POST",
        base.contexts_path(sandbox_id, context_id, "run"),
        key,
        status=200,
        json={"code": "native_call()", "timeout_s": 1},
    )

    data = body["data"]
    assert (data["stop_reason"], data["exit_code"]) == ("context_lost", EXEC_TIMEOUT_EXIT_CODE)
    assert data["stderr"] == "partial\n" + code_contexts.STOPPED_MESSAGE
    assert shell.kills == [code_contexts.context_dir(context_id)]
    assert shell.ready == {}


async def test_a_discard_that_raises_driver_error_keeps_the_context(
    client: httpx.AsyncClient,
    key: str,
    shell: ProbeShell,
    caplog: pytest.LogCaptureFixture,
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    context_id = await base.create_context(client, key, sandbox_id)
    shell.cell_result = ExecResult(
        exit_code=EXEC_TIMEOUT_EXIT_CODE, stderr=b"partial", timed_out=True
    )
    shell.alive.clear()  # the probe reports no live kernel, so the context is discarded
    shell.kill_error = DriverError("the sandbox is busy")

    with caplog.at_level("WARNING", logger=code_contexts.logger.name):
        body = await base.send(
            client,
            "POST",
            base.contexts_path(sandbox_id, context_id, "run"),
            key,
            status=200,
            json={"code": "native_call()", "timeout_s": 1},
        )

    data = body["data"]
    assert data["stop_reason"] == "timeout"
    assert data["exit_code"] == EXEC_TIMEOUT_EXIT_CODE
    assert data["stderr"] == "partial\n" + code_contexts.INTERRUPTED_MESSAGE
    assert list(shell.ready) == [code_contexts.context_dir(context_id)]
    assert any("discarding the code context failed" in r.message for r in caplog.records)
