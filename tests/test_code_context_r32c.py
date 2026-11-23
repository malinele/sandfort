"""Round-32 code-context fixes: the cwd is importable, and the spawn hint reaches stderr.

The kernel and client sources run for real in local ``python3`` subprocesses, as in
``test_code_context_outcomes.py``; the kernel starts inside a working directory of its own.
"""

import json
import os
import shutil
import signal
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from sandfort.toolbox import code_contexts
from test_code_context_outcomes import MAX_SOCKET_PATH, Kernel

SPAWN_TIMEOUT_S = "2"
HINT_PREFIX = "hint: functions defined in cells are not importable by spawn/forkserver children"
SPAWN_CHILD_CELL = (
    "import multiprocessing, time\n"
    "child = multiprocessing.get_context('spawn').Process(target=time.sleep, args=(60,))\n"
    "child.start()\n"
    "time.sleep(30)\n"  # the child is alive when the alarm fires
)
MODULE_NAME = "r32c_helper"


class Live:
    """A running kernel plus the working directory it was started in."""

    def __init__(self, kernel: Kernel, work: Path) -> None:
        self.kernel, self.work = kernel, work


def kill_group(kernel: Kernel) -> None:
    """Kill the kernel's whole process group: a spawn child a cell left behind goes with it."""
    try:
        os.killpg(kernel.process.pid, signal.SIGKILL)
    except OSError:
        pass  # already gone


@pytest.fixture
def live(monkeypatch: pytest.MonkeyPatch) -> Iterator[Live]:
    directory = Path(tempfile.mkdtemp(prefix="sfc-"))
    work = Path(tempfile.mkdtemp(prefix="sfw-"))
    if len(str(directory / "kernel.sock.tmp")) > MAX_SOCKET_PATH:
        shutil.rmtree(directory, ignore_errors=True)
        shutil.rmtree(work, ignore_errors=True)
        pytest.skip("the temp directory path is too long for a unix socket")
    (work / f"{MODULE_NAME}.py").write_text("VALUE = 42\n")
    monkeypatch.chdir(work)  # the kernel inherits it, like a context created with this cwd
    started = Kernel(directory)
    try:
        started.wait_ready()
        yield Live(started, work)
    finally:
        kill_group(started)
        started.close()
        shutil.rmtree(directory, ignore_errors=True)
        shutil.rmtree(work, ignore_errors=True)


def test_a_module_file_in_the_kernel_cwd_imports_from_a_cell(live: Live) -> None:
    run = live.kernel.run(f"import {MODULE_NAME}\n{MODULE_NAME}.VALUE")

    assert run.exit_code == 0, run.stderr
    assert run.outcome is not None and run.outcome.result == "42"


def test_the_cwd_leads_sys_path_and_the_kernel_directory_is_not_on_it(live: Live) -> None:
    run = live.kernel.run("import json, sys\nprint(json.dumps(sys.path))")

    assert run.exit_code == 0, run.stderr
    path = json.loads(run.stdout.decode())
    assert os.path.realpath(path[0]) == os.path.realpath(live.work)
    private = os.path.realpath(live.kernel.directory)
    assert all(os.path.realpath(entry or ".") != private for entry in path)


def test_the_kernels_own_file_is_not_importable_from_a_cell(live: Live) -> None:
    stem = code_contexts.KERNEL_FILE.removesuffix(".py")

    run = live.kernel.run(f"import {stem}")

    assert run.exit_code == 1
    assert run.outcome is not None and run.outcome.error is not None
    assert run.outcome.error.type == "ModuleNotFoundError"


def test_a_stopped_cell_with_live_spawn_children_has_the_hint_in_both_places(live: Live) -> None:
    run = live.kernel.run(SPAWN_CHILD_CELL, timeout_s=SPAWN_TIMEOUT_S)

    assert run.exit_code == code_contexts.TIMED_OUT_EXIT_CODE
    assert run.outcome is not None and run.outcome.error is not None
    first, hint = run.outcome.error.message.split("\n")
    assert first == f"cell exceeded {SPAWN_TIMEOUT_S} s"
    assert hint.startswith(HINT_PREFIX)
    lines = run.stderr.splitlines()
    assert lines[-1] == hint
    assert lines[-2].startswith("TimeoutError")  # the traceback comes right before it


@pytest.mark.parametrize(
    ("code", "timeout_s"),
    [("raise ValueError('boom')", "10"), ("import multiprocessing, time\ntime.sleep(30)", "1")],
)
def test_a_cell_error_without_spawn_children_has_no_hint_on_stderr(
    live: Live, code: str, timeout_s: str
) -> None:
    run = live.kernel.run(code, timeout_s=timeout_s)

    assert run.exit_code != 0
    assert run.outcome is not None and run.outcome.error is not None
    assert "hint:" not in run.outcome.error.message
    assert "hint:" not in run.stderr
