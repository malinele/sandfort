"""Round-33 code contexts: a run that ends with the context removed reports ``context_lost``.

A cell stuck in native code outlives the exec deadline; the kernel is sent an interrupt and given
2 s. A kernel that stays silent is stopped and the context removed: the run answers
``stop_reason`` ``context_lost`` with exit code 124 and the stderr line, so a client does not retry
into a 404. A cell timeout, and an exec timeout the kernel survived, stay ``timeout``. The sandbox
is scripted by ``SandboxShell`` of ``test_code_contexts_api``.
"""

from typing import Any

import httpx

import test_code_contexts_api as base
from sandfort.drivers.base import ExecResult
from sandfort.toolbox import code_contexts
from test_code_contexts_api import SandboxShell

# The fixtures of the API tests, reused under their own names.
app = base.app
client = base.client
driver = base.driver
shell = base.shell
org_id = base.org_id
key = base.key
quick_interrupt_wait = base.quick_interrupt_wait

EXEC_TIMEOUT_EXIT_CODE = 124


async def stuck_run(
    client: httpx.AsyncClient, key: str, shell: SandboxShell, *, kernel_answers: bool
) -> tuple[dict[str, Any], str, str]:
    """Run a cell whose exec deadline passes; the response data, the sandbox and context ids."""
    sandbox_id = await base.create_sandbox(client, key)
    context_id = await base.create_context(client, key, sandbox_id)
    shell.cell_result = ExecResult(
        exit_code=EXEC_TIMEOUT_EXIT_CODE, stderr=b"partial", timed_out=True
    )
    shell.idle = kernel_answers  # a silent kernel never reports its cell done after the interrupt
    body = await base.send(
        client,
        "POST",
        base.contexts_path(sandbox_id, context_id, "run"),
        key,
        status=200,
        json={"code": "native_call()", "timeout_s": 1},
    )
    data: dict[str, Any] = body["data"]
    return data, sandbox_id, context_id


async def test_a_removed_stuck_context_reports_context_lost_with_exit_124(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    data, _, context_id = await stuck_run(client, key, shell, kernel_answers=False)

    assert data["stop_reason"] == "context_lost"
    assert data["exit_code"] == EXEC_TIMEOUT_EXIT_CODE
    assert data["timed_out"] is True
    assert data["error"] is None
    assert data["stderr"] == "partial\n" + code_contexts.STOPPED_MESSAGE
    assert shell.kills == [code_contexts.context_dir(context_id)]


async def test_a_stuck_context_without_a_live_kernel_reports_context_lost(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    context_id = await base.create_context(client, key, sandbox_id)
    shell.cell_result = ExecResult(exit_code=EXEC_TIMEOUT_EXIT_CODE, timed_out=True)
    shell.alive.clear()  # the kernel process is gone, the directory is still there

    body = await base.send(
        client,
        "POST",
        base.contexts_path(sandbox_id, context_id, "run"),
        key,
        status=200,
        json={"code": "x", "timeout_s": 1},
    )

    data = body["data"]
    assert (data["stop_reason"], data["exit_code"]) == ("context_lost", EXEC_TIMEOUT_EXIT_CODE)
    assert data["stderr"] == code_contexts.STOPPED_MESSAGE


async def test_the_removed_context_is_a_404_for_the_next_run(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    _, sandbox_id, context_id = await stuck_run(client, key, shell, kernel_answers=False)

    later = await base.send(
        client,
        "POST",
        base.contexts_path(sandbox_id, context_id, "run"),
        key,
        status=404,
        json={"code": "1"},
    )

    assert later["error"]["code"] == "NOT_FOUND"


async def test_an_exec_timeout_the_kernel_survives_stays_timeout(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    data, _, _ = await stuck_run(client, key, shell, kernel_answers=True)

    assert data["stop_reason"] == "timeout"
    assert data["exit_code"] == EXEC_TIMEOUT_EXIT_CODE
    assert data["stderr"] == "partial\n" + code_contexts.INTERRUPTED_MESSAGE
    assert shell.kills == []
    assert len(shell.alive) == 1


async def test_an_ordinary_cell_timeout_stays_timeout(
    client: httpx.AsyncClient, key: str, shell: SandboxShell
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    context_id = await base.create_context(client, key, sandbox_id)
    shell.cell_result = ExecResult(exit_code=EXEC_TIMEOUT_EXIT_CODE, stderr=b"TimeoutError\n")

    body = await base.send(
        client,
        "POST",
        base.contexts_path(sandbox_id, context_id, "run"),
        key,
        status=200,
        json={"code": "while True: pass", "timeout_s": 1},
    )

    data = body["data"]
    assert (data["stop_reason"], data["exit_code"], data["timed_out"]) == ("timeout", 124, True)
    assert shell.kills == []
    assert len(shell.alive) == 1
