"""Interrupting a code-context cell: the kernel's SIGINT handler and the interrupt scripts.

The kernel tests run a real local ``python3`` kernel (see ``test_code_contexts``) and send it
SIGINT directly; the script tests run the ``sh -c`` scripts against a stand-in ``/proc``. The
route and the auto-interrupt paths are covered in ``test_code_contexts_api``.
"""

import os
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from sandfort.toolbox import code_contexts
from test_code_contexts import (
    MAX_SOCKET_PATH,
    RUN_DEADLINE_S,
    Kernel,
    Outcome,
    context_with_pid,
    register,
    run_cell,
    script_in,
    sleeper,
    stop,
)

BUSY_DEADLINE_S = 10.0
SETTLE_S = 0.3
READY_DEADLINE_S = 30.0
READY_SLEEPER_CODE = "import time; print('ready', flush=True); time.sleep(60)"


# --- the handler, in this process (no bound socket needed) --------------------------------


@pytest.fixture
def handler_scope(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Any]]:
    """The kernel source as a module with its SIGINT handler installed in this process."""
    monkeypatch.setitem(sys.modules, "__main__", sys.modules["__main__"])
    scope: dict[str, Any] = {"__name__": "kernel_under_test", "__file__": "kernel.py"}
    exec(compile(code_contexts.KERNEL_SOURCE, "kernel.py", "exec"), scope)
    previous = signal.signal(signal.SIGINT, scope["on_interrupt"])
    try:
        yield scope
    finally:
        signal.signal(signal.SIGINT, previous)


def interrupt_once_running(scope: dict[str, Any]) -> threading.Thread:
    """A thread that sends this process SIGINT as soon as the kernel reports a running cell."""

    def fire() -> None:
        deadline = time.monotonic() + BUSY_DEADLINE_S
        while not scope["STATE"]["running"] and time.monotonic() < deadline:
            time.sleep(0.01)
        os.kill(os.getpid(), signal.SIGINT)

    thread = threading.Thread(target=fire, daemon=True)
    thread.start()
    return thread


def test_the_handler_interrupts_the_running_cell_and_the_next_cell_sees_the_state(
    handler_scope: dict[str, Any],
) -> None:
    namespace = handler_scope["new_main"]()
    run_cell(handler_scope, namespace, "x = 41")
    thread = interrupt_once_running(handler_scope)

    result = run_cell(handler_scope, namespace, "while True:\n    pass")
    thread.join(timeout=RUN_DEADLINE_S)

    assert result.exit_code == 1
    lines = result.stderr.splitlines()
    assert lines[0] == "Traceback (most recent call last):"
    assert lines[-1] == "KeyboardInterrupt"
    assert "kernel.py" not in result.stderr
    assert handler_scope["STATE"]["running"] is False
    assert run_cell(handler_scope, namespace, "print(x + 1)") == Outcome(0, "42\n", "")


def test_the_handler_ignores_a_signal_between_cells(handler_scope: dict[str, Any]) -> None:
    namespace = handler_scope["new_main"]()
    run_cell(handler_scope, namespace, "y = 'kept'")

    os.kill(os.getpid(), signal.SIGINT)  # would raise KeyboardInterrupt here if it were live
    time.sleep(0.05)

    assert run_cell(handler_scope, namespace, "print(y)") == Outcome(0, "kept\n", "")


def test_the_busy_marker_exists_only_while_a_cell_runs(
    handler_scope: dict[str, Any], tmp_path: Path
) -> None:
    marker = tmp_path / "kernel.busy"
    handler_scope["STATE"]["busy_path"] = str(marker)
    namespace = handler_scope["new_main"]()

    code = f"import os\nprint(os.path.exists({str(marker)!r}))"

    during = run_cell(handler_scope, namespace, code)

    assert during.stdout == "True\n"
    assert not marker.exists()


@pytest.fixture
def live_kernel() -> Iterator[Kernel]:
    directory = Path(tempfile.mkdtemp(prefix="sfk-"))
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


def start_cell(kernel: Kernel, code: str) -> subprocess.Popen[bytes]:
    """Start a cell through the client without waiting for it."""
    cell = kernel.directory / "interrupt-cell.py"
    cell.write_text(code)
    return subprocess.Popen(
        [
            sys.executable,
            str(kernel.directory / code_contexts.CLIENT_FILE),
            str(kernel.socket),
            str(cell),
            "30",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def wait_until_busy(kernel: Kernel) -> None:
    busy = kernel.directory / "kernel.busy"
    deadline = time.monotonic() + BUSY_DEADLINE_S
    while not busy.exists():
        assert time.monotonic() < deadline, "the kernel never started the cell"
        time.sleep(0.02)


def interrupt(kernel: Kernel) -> None:
    os.kill(kernel.process.pid, signal.SIGINT)


def test_an_interrupt_ends_a_running_cell_with_keyboard_interrupt_and_keeps_the_state(
    live_kernel: Kernel,
) -> None:
    live_kernel.run("x = 41")
    cell = start_cell(live_kernel, "while True:\n    pass")
    try:
        wait_until_busy(live_kernel)

        interrupt(live_kernel)
        stdout, stderr = cell.communicate(timeout=RUN_DEADLINE_S)
    finally:
        cell.kill()
        cell.wait()

    assert cell.returncode == 1
    assert stdout == b""
    lines = stderr.decode().splitlines()
    assert lines[0] == "Traceback (most recent call last):"
    assert lines[-1] == "KeyboardInterrupt"
    assert "kernel.py" not in stderr.decode()
    assert not (live_kernel.directory / "kernel.busy").exists()
    follow_up = live_kernel.run("print(x + 1)")
    assert (follow_up.exit_code, follow_up.stdout) == (0, "42\n")


def test_an_interrupt_between_cells_is_a_no_op_and_the_kernel_stays_up(
    live_kernel: Kernel,
) -> None:
    live_kernel.run("y = 'kept'")

    interrupt(live_kernel)
    interrupt(live_kernel)
    time.sleep(SETTLE_S)

    assert live_kernel.process.poll() is None
    follow_up = live_kernel.run("print(y)")  # the stray interrupts do not hit the next cell
    assert (follow_up.exit_code, follow_up.stdout, follow_up.stderr) == (0, "kept\n", "")


def test_an_interrupt_before_the_first_cell_is_a_no_op(live_kernel: Kernel) -> None:
    interrupt(live_kernel)
    time.sleep(SETTLE_S)

    assert live_kernel.process.poll() is None
    assert live_kernel.run("print(1)").stdout == "1\n"


def test_a_cell_can_catch_the_interrupt_and_the_kernel_goes_on(live_kernel: Kernel) -> None:
    code = "try:\n    while True:\n        pass\nexcept KeyboardInterrupt:\n    print('caught')"
    cell = start_cell(live_kernel, code)
    try:
        wait_until_busy(live_kernel)
        interrupt(live_kernel)
        stdout, _ = cell.communicate(timeout=RUN_DEADLINE_S)
    finally:
        cell.kill()
        cell.wait()

    assert (cell.returncode, stdout) == (0, b"caught\n")
    assert live_kernel.run("print(2)").stdout == "2\n"


# --- the scripts, against a stand-in /proc ------------------------------------------------


@pytest.fixture
def proc(tmp_path: Path) -> Path:
    root = tmp_path / "proc"
    root.mkdir()
    return root


def ready_sleeper() -> subprocess.Popen[bytes]:
    """A sleeper that has finished interpreter start-up and is about to sleep.

    A SIGINT that lands while a fresh interpreter is still importing (slow under load) can be
    swallowed by the start-up code, leaving a process that never dies. Tests that assert the
    sleeper ends on SIGINT must therefore signal it only after it reports ready.

    Diagnosis of the earlier flake: the SIGINT landed before the fresh interpreter had installed
    its default SIGINT handler, so it never became a KeyboardInterrupt and the sleeper lived on.
    """
    process = subprocess.Popen([sys.executable, "-c", READY_SLEEPER_CODE], stdout=subprocess.PIPE)
    assert process.stdout is not None
    try:
        readable, _, _ = select.select([process.stdout], [], [], READY_DEADLINE_S)
        assert readable, "the sleeper never reported ready"
        assert process.stdout.readline() == b"ready\n"
    except BaseException:
        stop(process)
        raise
    finally:
        process.stdout.close()
    return process


def test_the_interrupt_script_signals_the_process_whose_cmdline_names_the_directory(
    tmp_path: Path, proc: Path
) -> None:
    kernel = ready_sleeper()
    try:
        directory = context_with_pid(tmp_path, str(kernel.pid))
        register(proc, kernel, ["python3", f"{directory}/kernel.py", str(directory)])

        result = script_in(proc, code_contexts._INTERRUPT_SCRIPT, str(directory))

        assert result.returncode == 0
        assert kernel.wait(timeout=RUN_DEADLINE_S) != 0  # SIGINT ended the sleeper
        assert directory.exists()  # an interrupt removes nothing
    finally:
        stop(kernel)


def test_the_interrupt_script_never_signals_an_unrelated_process_that_reuses_the_pid(
    tmp_path: Path, proc: Path
) -> None:
    other = sleeper()
    try:
        register(proc, other, ["/usr/bin/sleeper", "--unrelated"])
        directory = context_with_pid(tmp_path, str(other.pid))

        result = script_in(proc, code_contexts._INTERRUPT_SCRIPT, str(directory))
        time.sleep(SETTLE_S)

        assert result.returncode == 1
        assert other.poll() is None
    finally:
        stop(other)


@pytest.mark.parametrize("pid_text", ["", "abc", "../self", "99999999", "1 2"])
def test_the_interrupt_script_ignores_a_pid_file_that_is_not_a_live_pid(
    tmp_path: Path, proc: Path, pid_text: str
) -> None:
    directory = context_with_pid(tmp_path, pid_text)

    result = script_in(proc, code_contexts._INTERRUPT_SCRIPT, str(directory))

    assert result.returncode == 1


def test_the_interrupt_script_of_a_missing_directory_exits_44(tmp_path: Path, proc: Path) -> None:
    result = script_in(proc, code_contexts._INTERRUPT_SCRIPT, str(tmp_path / "missing"))

    assert result.returncode == code_contexts._NOT_FOUND_EXIT_CODE


def test_the_idle_script_follows_the_busy_marker(tmp_path: Path) -> None:
    def idle() -> int:
        return subprocess.run(
            ["sh", "-c", code_contexts._IDLE_SCRIPT, "sh", str(tmp_path)],
            timeout=RUN_DEADLINE_S,
            check=False,
        ).returncode

    assert idle() == 0
    (tmp_path / "kernel.busy").write_text("")
    assert idle() == 1
    (tmp_path / "kernel.busy").unlink()
    assert idle() == 0


def test_the_idle_script_with_a_number_only_waits_for_that_cell(tmp_path: Path) -> None:
    def idle(*cell: str) -> int:
        return script_in(tmp_path, code_contexts._IDLE_SCRIPT, str(tmp_path), *cell).returncode

    assert (idle(), idle("7")) == (0, 0)  # no marker: idle
    (tmp_path / "kernel.busy").write_text("7")
    assert idle() == 1  # a cell runs
    assert idle("7") == 1  # that very cell
    assert idle("8") == 0  # another cell: the one waited for is not running


def test_the_interrupt_script_writes_the_target_before_signalling(
    tmp_path: Path, proc: Path
) -> None:
    kernel = ready_sleeper()
    try:
        directory = context_with_pid(tmp_path, str(kernel.pid))
        register(proc, kernel, ["python3", f"{directory}/kernel.py", str(directory)])

        result = script_in(proc, code_contexts._INTERRUPT_SCRIPT, str(directory), "123")

        assert result.returncode == 0
        assert (directory / "kernel.interrupt").read_text() == "123"
        assert not (directory / "kernel.interrupt.tmp").exists()
        assert kernel.wait(timeout=RUN_DEADLINE_S) != 0  # SIGINT ended the sleeper
    finally:
        stop(kernel)


def test_an_interrupt_without_a_number_removes_a_stale_target(tmp_path: Path, proc: Path) -> None:
    kernel = sleeper()
    try:
        directory = context_with_pid(tmp_path, str(kernel.pid))
        register(proc, kernel, ["python3", f"{directory}/kernel.py", str(directory)])
        (directory / "kernel.interrupt").write_text("99")

        result = script_in(proc, code_contexts._INTERRUPT_SCRIPT, str(directory))

        assert result.returncode == 0
        assert not (directory / "kernel.interrupt").exists()
    finally:
        stop(kernel)


# The pid check: a process naming the directory without being the kernel is never signalled.
OTHER_COMMANDS = [
    ["python3", "{d}/client.py", "{d}/kernel.sock", "{d}/cell-1.py", "5", "token"],
    ["sh", "-c", "probe script", "sh", "{d}"],
    ["tail", "-c", "100", "{d}/kernel.log"],
    ["python3", "{d}2/kernel.py", "{d}2"],
]


@pytest.mark.parametrize("command", OTHER_COMMANDS, ids=["client", "shell", "tail", "sibling"])
@pytest.mark.parametrize("script", ["_INTERRUPT_SCRIPT", "_KILL_SCRIPT"])
def test_a_process_naming_the_directory_but_not_the_kernel_script_is_never_signalled(
    tmp_path: Path, proc: Path, command: list[str], script: str
) -> None:
    other = sleeper()
    try:
        directory = context_with_pid(tmp_path, str(other.pid))
        register(proc, other, [part.format(d=directory) for part in command])

        result = script_in(proc, getattr(code_contexts, script), str(directory))
        time.sleep(SETTLE_S)

        assert result.returncode == (1 if script == "_INTERRUPT_SCRIPT" else 0)
        assert other.poll() is None
    finally:
        stop(other)
