"""Round-34: a cancelled streamed run finishes its interrupt before the producer returns.

``_run_until_disconnect`` cancels its exec task when it is itself cancelled; the exec task is
then awaited (shielded), so the cell interrupt and the per-context lock release are done by the
time the helper, and with it the stream's producer, returns. The second part covers the stderr
line after an exec deadline: a kernel confirmed alive keeps the interrupted message; a probe whose
answer is unknown should say the state could not be confirmed.
"""

import asyncio
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

import test_code_context_probe_r34 as probe
import test_code_contexts_api as base
from sandfort.api.routes.toolbox import code_contexts as routes
from sandfort.drivers.base import ExecResult
from sandfort.toolbox import code_context_stream, code_contexts
from test_code_context_probe_r34 import ProbeShell
from test_code_context_r33b import EXEC_TIMEOUT_EXIT_CODE, stuck_run

# The fixtures of the API tests, reused under their own names.
app = base.app
client = base.client
driver = base.driver
org_id = base.org_id
key = base.key
quick_interrupt_wait = base.quick_interrupt_wait
shell = probe.shell

SANDBOX_ID = "sbx_streamcancel"
CONTEXT_ID = "ctx_0123456789abcdef"
INTERRUPT_TAKES_S = 0.05  # the interrupt is still running for a while after the cancellation
DEADLINE_S = 5.0
UNCONFIRMED = (
    "the cell exceeded its time limit; the kernel state could not be confirmed, "
    "so the context was kept\n"
)


class HangingKernel:
    """``run_in_context`` that never answers, and an ``_interrupt_cell`` that takes a while."""

    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.interrupted: list[int] = []

    async def run_in_context(self, *_args: Any, **_kwargs: Any) -> code_contexts.ContextRun:
        self.started.set()
        await asyncio.Event().wait()  # cancelled together with the producer
        raise AssertionError("unreachable")

    async def interrupt_cell(
        self, _driver: Any, _sandbox: Any, _context_id: str, cell: int
    ) -> None:
        await asyncio.sleep(INTERRUPT_TAKES_S)
        self.interrupted.append(cell)


@pytest.fixture
def kernel(monkeypatch: pytest.MonkeyPatch) -> HangingKernel:
    fake = HangingKernel()
    monkeypatch.setattr(code_contexts, "run_in_context", fake.run_in_context)
    monkeypatch.setattr(routes, "_interrupt_cell", fake.interrupt_cell)
    return fake


async def connected() -> bool:
    return False  # the client stays connected: only the cancellation ends the run


async def test_a_cancelled_producer_returns_with_the_lock_free_and_the_cell_interrupted(
    kernel: HangingKernel,
) -> None:
    request: Any = SimpleNamespace(is_disconnected=connected)
    sandbox: Any = SimpleNamespace(id=SANDBOX_ID)
    no_driver: Any = None  # the faked kernel never reaches the driver

    async def finish(events: code_context_stream.RunEvents) -> dict[str, Any]:
        finished: list[routes._Turn] = []
        turn = routes._run_in_turn(no_driver, sandbox, CONTEXT_ID, "1", 1.0)
        call = routes._exec_of(turn, finished)
        await routes._run_until_disconnect(request, no_driver, sandbox, call)
        return {}

    events = code_context_stream.RunEvents()
    producer = asyncio.ensure_future(code_context_stream._produce(events, finish))
    await asyncio.wait_for(kernel.started.wait(), DEADLINE_S)
    assert (SANDBOX_ID, CONTEXT_ID) in routes._RUN_LOCKS  # the run holds the context's lock

    producer.cancel()
    await asyncio.wait_for(asyncio.wait({producer}), DEADLINE_S)

    assert producer.cancelled()
    assert routes._RUN_LOCKS == {}  # released before the producer returned, no polling
    assert len(kernel.interrupted) == 1


async def test_a_kernel_confirmed_alive_keeps_the_interrupted_message(
    client: httpx.AsyncClient, key: str, shell: ProbeShell
) -> None:
    data, _, _ = await stuck_run(client, key, shell, kernel_answers=True)

    assert (data["stop_reason"], data["exit_code"]) == ("timeout", EXEC_TIMEOUT_EXIT_CODE)
    assert data["stderr"] == "partial\n" + code_contexts.INTERRUPTED_MESSAGE
    assert shell.kills == []


async def test_an_unknown_probe_state_says_the_state_was_not_confirmed(
    client: httpx.AsyncClient, key: str, shell: ProbeShell
) -> None:
    shell.probe_result = ExecResult(exit_code=EXEC_TIMEOUT_EXIT_CODE, timed_out=True)

    data, _, _ = await stuck_run(client, key, shell, kernel_answers=False)

    assert (data["stop_reason"], data["exit_code"]) == ("timeout", EXEC_TIMEOUT_EXIT_CODE)
    assert data["stderr"] == "partial\n" + UNCONFIRMED
    assert shell.kills == []
    assert len(shell.alive) == 1
