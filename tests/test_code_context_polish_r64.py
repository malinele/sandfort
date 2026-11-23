"""Round 64: polish found by a data-scientist persona using a code context as a notebook.

* cell wording: the output-limit and sandbox-death sentences of a cell run say "cell", and a
  death says the context and its variables are gone (exec keeps its "command" wording);
* ``\\r`` progress updates (tqdm style) are streamed as they arrive, byte-exact;
* the interrupt answers ``interrupted: false`` when no cell is running.

FakeDriver plus the scripted shells of ``test_code_contexts_api`` and
``test_code_context_stream_r34``; the interrupt script runs against a stand-in ``/proc``.
"""

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

import test_code_context_stream_r34 as streamed
import test_code_contexts_api as base
from sandfort.api.routes.toolbox import code_contexts as code_context_routes
from sandfort.drivers.base import ExecEvent, ExecRequest, ExecResult, ExitEvent
from sandfort.drivers.docker.exec import SANDBOX_DIED_MESSAGE, output_cap_message
from sandfort.drivers.errors import DriverConflict
from sandfort.drivers.fake import FakeDriver
from sandfort.toolbox import code_context_stream, code_contexts, stop_wording
from test_code_context_interrupt import ready_sleeper
from test_code_contexts import context_with_pid, register, script_in, stop

app = base.app
client = base.client
driver = base.driver
shell = base.shell
org_id = base.org_id
key = base.key
quick_interrupt_wait = base.quick_interrupt_wait
session = streamed.session
stream_app = streamed.app
quick_waits = streamed.quick_waits

LIMIT = code_contexts.CLIENT_OUTPUT_LIMIT
LOST_HINT = "the context and its variables are gone; start the sandbox and ensure the context again"
CELL_LIMIT_LINE = f"the cell was stopped because its output exceeded the limit of {LIMIT} bytes"
CELL_DIED_LINE = (
    "the sandbox stopped while running this cell "
    f"(a resource limit was hit or its main process ended); {LOST_HINT}"
)


# --- the wording helpers ------------------------------------------------------------------


def test_the_output_limit_sentence_of_a_cell_says_cell() -> None:
    reworded = stop_wording.cell_reword(b"partial\n" + output_cap_message(LIMIT))

    assert reworded == b"partial\n" + CELL_LIMIT_LINE.encode()


def test_the_death_line_of_a_cell_says_cell_and_that_the_state_is_gone() -> None:
    reworded = stop_wording.cell_reword(b"partial\n" + SANDBOX_DIED_MESSAGE + b"\n")

    assert reworded == f"partial\n{CELL_DIED_LINE}\n".encode()
    assert b"command" not in reworded


def test_other_cell_stderr_is_left_alone() -> None:
    text = b"Traceback...\nthe command in your own message stays\n"

    assert stop_wording.cell_reword(text) == text


def test_exec_keeps_its_command_wording() -> None:
    assert b"this command" in SANDBOX_DIED_MESSAGE
    assert b"the command was stopped" in output_cap_message(LIMIT)
    assert stop_wording.reword(SANDBOX_DIED_MESSAGE, None) == SANDBOX_DIED_MESSAGE


def test_the_cell_death_line_has_no_driver_sentence_left() -> None:
    assert SANDBOX_DIED_MESSAGE not in stop_wording.CELL_DIED_MESSAGE
    assert stop_wording.CELL_DIED_MESSAGE.decode() == CELL_DIED_LINE


# --- a run: output limit and death ---------------------------------------------------------


async def run_cell(
    client: httpx.AsyncClient, key: str, shell: base.SandboxShell, result: ExecResult
) -> dict[str, Any]:
    sandbox_id = await base.create_sandbox(client, key)
    context_id = await base.create_context(client, key, sandbox_id)
    shell.cell_result = result
    path = base.contexts_path(sandbox_id, context_id, "run")
    body = await base.send(client, "POST", path, key, status=200, json={"code": "go()"})
    data: dict[str, Any] = body["data"]
    return data


async def test_a_run_that_hit_the_output_limit_says_the_cell_was_stopped(
    client: httpx.AsyncClient, key: str, shell: base.SandboxShell
) -> None:
    cut = ExecResult(
        exit_code=137, stdout=b"x" * 10, stderr=output_cap_message(LIMIT), truncated=True
    )

    data = await run_cell(client, key, shell, cut)

    assert data["stop_reason"] == "output_limit"
    assert data["stderr"] == CELL_LIMIT_LINE
    assert "command" not in data["stderr"]


async def test_a_sandbox_that_died_under_a_cell_says_the_context_is_gone(
    client: httpx.AsyncClient, key: str, shell: base.SandboxShell
) -> None:
    died = ExecResult(
        exit_code=137, stderr=b"partial\n" + SANDBOX_DIED_MESSAGE, sandbox_stopped=True
    )

    data = await run_cell(client, key, shell, died)

    assert data["stop_reason"] == "sandbox_stopped"
    assert data["stderr"] == f"partial\n{CELL_DIED_LINE}"
    assert "command" not in data["stderr"]


async def test_a_container_that_ran_out_of_memory_under_a_cell_says_the_context_is_gone(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, shell: base.SandboxShell
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    context_id = await base.create_context(client, key, sandbox_id)
    [instance] = await driver.list_managed()

    def handler(env: Any, request: ExecRequest) -> ExecResult:
        if request.argv[0] != "python3":
            return shell(env, request)
        driver.kill_instance(instance.ref, vanish=False, oom=True)
        return ExecResult(exit_code=137, stderr=SANDBOX_DIED_MESSAGE, sandbox_stopped=True)

    driver.exec_handler = handler
    path = base.contexts_path(sandbox_id, context_id, "run")

    body = await base.send(client, "POST", path, key, status=200, json={"code": "go()"})

    data = body["data"]
    assert data["stop_reason"] == "oom_killed"
    assert "ran out of memory" in data["stderr"]
    assert data["stderr"].rstrip("\n").endswith(LOST_HINT)
    assert "command" not in data["stderr"]


async def test_the_exec_route_keeps_the_command_wording(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    died = ExecResult(exit_code=137, stderr=SANDBOX_DIED_MESSAGE, sandbox_stopped=True)
    driver.exec_handler = lambda env, request: died

    body = await base.send(
        client,
        "POST",
        f"{base.BASE}/{sandbox_id}/toolbox/process/execute",
        key,
        status=200,
        json={"command": "stress"},
    )

    stderr = body["data"]["stderr"]
    assert "this command" in stderr
    assert "cell" not in stderr
    assert "context" not in stderr


async def test_the_error_event_of_a_streamed_death_uses_the_cell_wording() -> None:
    async def finish(events: code_context_stream.RunEvents) -> dict[str, Any]:
        raise DriverConflict("container sbx is not running")

    events = [event async for event in code_context_stream.stream_run(finish)]

    [(name, data)] = events
    assert name == "error"
    assert data["message"] == CELL_DIED_LINE


async def test_the_streamed_output_limit_notice_is_worded_for_the_cell(
    session: streamed.Session,
) -> None:
    notice = output_cap_message(LIMIT)

    _, events = await session.stream(
        lambda token: [
            streamed.out(b"x" * 100),
            streamed.err(b"warn"),
            streamed.err(notice),
            ExitEvent(137, truncated=True),
        ]
    )

    result = events[-1][1]
    assert result["stop_reason"] == "output_limit"
    assert result["stderr"] == f"warn\n{CELL_LIMIT_LINE}"
    assert streamed.joined(events, "stderr") == result["stderr"]
    assert "command" not in streamed.joined(events, "stderr")


# --- \r flushes a stream chunk ----------------------------------------------------------------


def stdout_chunks(events: streamed.Events) -> list[str]:
    return [data["data"] for name, data in events if name == "stdout"]


async def test_progress_updates_separated_by_carriage_returns_arrive_one_by_one(
    session: streamed.Session,
) -> None:
    chunks = [streamed.out(b"10%\r"), streamed.out(b"50%\r"), streamed.out(b"100%\n")]

    _, events = await session.stream(lambda token: streamed.done(token, *chunks))

    assert stdout_chunks(events) == ["10%\r", "50%\r", "100%\n"]
    assert events[-1][1]["stdout"] == "10%\r50%\r100%\n"  # not converted, byte for byte


async def test_one_chunk_with_several_carriage_returns_is_cut_after_the_last_one(
    session: streamed.Session,
) -> None:
    _, events = await session.stream(
        lambda token: streamed.done(token, streamed.out(b"a\rb\rc"), streamed.out(b"d\n"))
    )

    assert stdout_chunks(events) == ["a\rb\r", "cd\n"]
    assert events[-1][1]["stdout"] == "a\rb\rcd\n"


async def test_a_carriage_return_line_feed_pair_is_kept_whole(
    session: streamed.Session,
) -> None:
    chunks = [streamed.out(b"row\r"), streamed.out(b"\nnext\r\n")]

    _, events = await session.stream(lambda token: streamed.done(token, *chunks))

    assert "".join(stdout_chunks(events)) == "row\r\nnext\r\n"
    assert events[-1][1]["stdout"] == "row\r\nnext\r\n"


@pytest.mark.parametrize("cut", [1, len(code_contexts.OUTCOME_MARK) + 3, -1])
async def test_the_trailer_still_never_appears_after_a_carriage_return(
    session: streamed.Session, cut: int
) -> None:
    def script(token: str) -> list[ExecEvent]:
        line = streamed.trailer(token)
        pieces = [streamed.out(b"p\r"), streamed.out(line[:cut]), streamed.out(line[cut:])]
        return [*pieces, ExitEvent(0)]

    response, events = await session.stream(script)

    assert stdout_chunks(events) == ["p\r"]
    assert "sandfort-outcome" not in response.text
    assert events[-1][1]["result"] == "42"


def test_the_trailer_filter_releases_up_to_the_last_carriage_return() -> None:
    hold = code_context_stream.TrailerFilter("tok")

    assert hold.feed(b"a\rb") == b"a\r"
    assert hold.feed(b"c") == b""
    assert hold.finish() == b"bc"


def test_the_trailer_filter_still_holds_a_line_without_a_break() -> None:
    hold = code_context_stream.TrailerFilter("tok")

    assert hold.feed(b"no break yet") == b""
    assert hold.finish() == b"no break yet"


# --- the interrupt between cells -----------------------------------------------------------------


def interrupt_path(sandbox_id: str, context_id: str) -> str:
    return base.contexts_path(sandbox_id, context_id, "interrupt")


async def test_an_interrupt_between_cells_answers_false_and_signals_nothing(
    client: httpx.AsyncClient, key: str, shell: base.SandboxShell
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    context_id = await base.create_context(client, key, sandbox_id)
    shell.idle = True  # no cell is running

    body = await base.send(client, "POST", interrupt_path(sandbox_id, context_id), key, status=200)

    assert body["data"] == {"id": context_id, "interrupted": False}
    assert shell.interrupts == []
    assert shell.kills == []


async def test_an_interrupt_of_a_running_cell_answers_true(
    client: httpx.AsyncClient, key: str, shell: base.SandboxShell
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    context_id = await base.create_context(client, key, sandbox_id)
    shell.idle = False  # a cell is running

    body = await base.send(client, "POST", interrupt_path(sandbox_id, context_id), key, status=200)

    assert body["data"] == {"id": context_id, "interrupted": True}
    assert shell.interrupts == [code_contexts.context_dir(context_id)]


async def test_an_interrupt_of_an_unknown_context_is_still_not_found(
    client: httpx.AsyncClient, key: str, shell: base.SandboxShell
) -> None:
    sandbox_id = await base.create_sandbox(client, key)

    await base.send(
        client, "POST", interrupt_path(sandbox_id, base.UNKNOWN_ID), key, status=404
    )


def test_the_route_and_the_sdk_describe_the_idle_answer() -> None:
    text = code_context_routes._INTERRUPT_DESCRIPTION
    sdk = (
        Path(__file__).resolve().parents[1]
        / "sdk/python/src/sandfort_sdk/code_contexts.py"
    ).read_text()

    assert "no cell is running" in text
    assert re.search(r"False when no cell is running", sdk)
    assert "between cells it does nothing" not in text


@pytest.fixture
def proc(tmp_path: Path) -> Path:
    root = tmp_path / "proc"
    root.mkdir()
    return root


def test_the_interrupt_script_skips_an_idle_kernel_when_asked(tmp_path: Path, proc: Path) -> None:
    kernel = ready_sleeper()
    try:
        directory = context_with_pid(tmp_path, str(kernel.pid))
        register(proc, kernel, ["python3", f"{directory}/kernel.py", str(directory)])

        result = script_in(proc, code_contexts._INTERRUPT_SCRIPT, str(directory), "", "1")

        assert result.returncode == code_contexts.NOT_RUNNING_CELL_EXIT_CODE
        assert kernel.poll() is None  # nothing was signalled
    finally:
        stop(kernel)


def test_the_interrupt_script_signals_a_busy_kernel_when_asked(tmp_path: Path, proc: Path) -> None:
    kernel = ready_sleeper()
    try:
        directory = context_with_pid(tmp_path, str(kernel.pid))
        (directory / "kernel.busy").write_text("7")
        register(proc, kernel, ["python3", f"{directory}/kernel.py", str(directory)])

        result = script_in(proc, code_contexts._INTERRUPT_SCRIPT, str(directory), "", "1")

        assert result.returncode == 0
        assert kernel.wait(timeout=10) != 0  # SIGINT ended the sleeper
    finally:
        stop(kernel)


def test_the_interrupt_script_without_the_flag_signals_an_idle_kernel_as_before(
    tmp_path: Path, proc: Path
) -> None:
    kernel = ready_sleeper()
    try:
        directory = context_with_pid(tmp_path, str(kernel.pid))
        register(proc, kernel, ["python3", f"{directory}/kernel.py", str(directory)])

        result = script_in(proc, code_contexts._INTERRUPT_SCRIPT, str(directory))

        assert result.returncode == 0
        assert kernel.wait(timeout=10) != 0
    finally:
        stop(kernel)


def test_the_interrupt_script_of_a_dead_kernel_still_answers_one_with_the_flag(
    tmp_path: Path, proc: Path
) -> None:
    directory = context_with_pid(tmp_path, "99999999")

    result = script_in(proc, code_contexts._INTERRUPT_SCRIPT, str(directory), "", "1")

    assert result.returncode == 1


# --- the guide ---------------------------------------------------------------------------

GUIDE = Path(__file__).resolve().parents[1] / "docs/connect-guide.md"


@pytest.fixture
def guide_lines() -> Iterator[list[str]]:
    yield GUIDE.read_text().splitlines()


def test_the_guide_gives_the_measured_pandas_install_time(guide_lines: list[str]) -> None:
    pandas = [line for line in guide_lines if "pip install" in line and "pandas" in line]

    assert pandas
    assert not any("about 25 s" in line for line in guide_lines)
    assert any("about a minute on the shared beta" in line for line in guide_lines)


def test_the_guide_explains_the_memory_overrun_and_the_recovery(guide_lines: list[str]) -> None:
    text = "\n".join(guide_lines)

    assert "memory overrun in a cell stops the whole sandbox on the `gvisor` tier" in text
    assert "all of its contexts" in text
    assert "check `created`" in text
    assert "reload the data from files" in text
