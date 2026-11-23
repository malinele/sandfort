"""Code-context kernel and client, run for real in a local ``python3`` subprocess (daemon-free).

The kernel and client sources are the module constants that ``create_context`` uploads into a
sandbox. Here they are written to a temp directory and started the same way: the kernel binds
``kernel.sock`` in it, and every cell goes through the client, one process per cell.
"""

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from sandfort.errors import NotFound
from sandfort.toolbox import code_contexts

READY_DEADLINE_S = 10.0
CELL_TIMEOUT_S = 10
RUN_DEADLINE_S = 30.0
MAX_SOCKET_PATH = 100


@dataclass(frozen=True)
class Outcome:
    exit_code: int
    stdout: str
    stderr: str


class Kernel:
    """A kernel process plus a helper that runs cells through the client file."""

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

    def run(self, code: str, *, timeout_s: float = CELL_TIMEOUT_S) -> Outcome:
        self._cells += 1
        cell = self.directory / f"cell-{self._cells}.py"
        cell.write_text(code)
        completed = subprocess.run(
            [
                sys.executable,
                str(self.directory / code_contexts.CLIENT_FILE),
                str(self.socket),
                str(cell),
                str(timeout_s),
            ],
            capture_output=True,
            timeout=RUN_DEADLINE_S,
            check=False,
        )
        return Outcome(completed.returncode, completed.stdout.decode(), completed.stderr.decode())

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGKILL)
        self.process.wait()
        self.log.close()


@pytest.fixture
def kernel() -> Iterator[Kernel]:
    directory = Path(tempfile.mkdtemp(prefix="sfk-"))
    # unix socket paths are limited to about 100 bytes (the staging name is the longest)
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


def test_a_variable_survives_into_the_next_cell(kernel: Kernel) -> None:
    first = kernel.run("x = 1")
    second = kernel.run("print(x + 1)")

    assert first == Outcome(0, "", "")
    assert second == Outcome(0, "2\n", "")


def test_imports_and_functions_survive(kernel: Kernel) -> None:
    kernel.run("import math\ndef area(r):\n    return math.pi * r * r")

    result = kernel.run("print(round(area(1), 2))")

    assert result == Outcome(0, "3.14\n", "")


def test_a_trailing_expression_prints_its_repr(kernel: Kernel) -> None:
    kernel.run("x = 41")

    assert kernel.run("x + 1").stdout == "42\n"
    assert kernel.run("'text'").stdout == "'text'\n"
    assert kernel.run("[1, 2]\nNone").stdout == ""


def test_the_last_value_is_kept_as_underscore(kernel: Kernel) -> None:
    kernel.run("6 * 7")

    assert kernel.run("print(_)").stdout == "42\n"


def test_stdout_and_stderr_stay_apart(kernel: Kernel) -> None:
    result = kernel.run("import sys\nprint('to-out')\nprint('to-err', file=sys.stderr)")

    assert result == Outcome(0, "to-out\n", "to-err\n")


def test_an_exception_exits_one_with_a_short_traceback_and_keeps_the_state(
    kernel: Kernel,
) -> None:
    kernel.run("kept = 'still here'")

    failed = kernel.run("def boom():\n    return 1 / 0\nboom()")
    later = kernel.run("print(kept)")

    assert failed.exit_code == 1
    assert failed.stdout == ""
    assert 'File "<cell-2>", line 2, in boom' in failed.stderr
    assert "ZeroDivisionError" in failed.stderr
    assert code_contexts.KERNEL_FILE not in failed.stderr  # no kernel frames
    assert later == Outcome(0, "still here\n", "")


def test_a_syntax_error_exits_one_and_names_the_cell(kernel: Kernel) -> None:
    result = kernel.run("x = (")

    assert result.exit_code == 1
    assert "<cell>" in result.stderr
    assert "SyntaxError" in result.stderr
    assert kernel.run("print('alive')").stdout == "alive\n"


def test_sys_exit_in_a_cell_does_not_kill_the_kernel(kernel: Kernel) -> None:
    kernel.run("n = 5")

    result = kernel.run("raise SystemExit(3)")

    assert result.exit_code == 1
    assert "SystemExit" in result.stderr
    assert kernel.run("print(n)").stdout == "5\n"


def test_a_timeout_exits_124_and_keeps_the_state(kernel: Kernel) -> None:
    started = time.monotonic()

    result = kernel.run("kept = 7\nimport time\ntime.sleep(60)", timeout_s=1)
    elapsed = time.monotonic() - started
    later = kernel.run("print(kept)")

    assert result.exit_code == code_contexts.TIMED_OUT_EXIT_CODE
    assert "TimeoutError" in result.stderr
    assert elapsed < RUN_DEADLINE_S
    assert later == Outcome(0, "7\n", "")


def test_a_busy_loop_is_interrupted_by_the_timeout(kernel: Kernel) -> None:
    result = kernel.run("while True:\n    pass", timeout_s=1)

    assert result.exit_code == code_contexts.TIMED_OUT_EXIT_CODE
    assert kernel.run("print('after')").stdout == "after\n"


def test_a_cell_that_catches_the_timeout_ends_normally(kernel: Kernel) -> None:
    code = "import time\ntry:\n    time.sleep(60)\nexcept TimeoutError:\n    print('caught')"

    result = kernel.run(code, timeout_s=1)

    assert result == Outcome(0, "caught\n", "")


def test_cells_run_in_the_main_module_without_the_kernels_own_names(kernel: Kernel) -> None:
    code = "import sys\nprint(sys.modules['__main__'].__dict__ is globals(), 'serve' in globals())"

    assert kernel.run(code) == Outcome(0, "True False\n", "")


def test_a_function_defined_in_a_cell_can_be_pickled(kernel: Kernel) -> None:
    kernel.run("import pickle\ndef f(x):\n    return x + 1")

    result = kernel.run("print(pickle.loads(pickle.dumps(f))(41))")

    assert result == Outcome(0, "42\n", "")


def test_a_timeout_traceback_shows_no_kernel_frame(kernel: Kernel) -> None:
    result = kernel.run("import time\ntime.sleep(60)", timeout_s=1)

    assert result.exit_code == code_contexts.TIMED_OUT_EXIT_CODE
    assert "TimeoutError" in result.stderr
    assert code_contexts.KERNEL_FILE not in result.stderr


def test_non_ascii_output_round_trips(kernel: Kernel) -> None:
    assert kernel.run("print('šđčćž ✓')").stdout == "šđčćž ✓\n"


def test_the_client_reports_a_missing_kernel(tmp_path: Path) -> None:
    cell = tmp_path / "cell.py"
    cell.write_text("print(1)")
    client = tmp_path / code_contexts.CLIENT_FILE
    client.write_text(code_contexts.CLIENT_SOURCE)

    completed = subprocess.run(
        [sys.executable, str(client), str(tmp_path / "none.sock"), str(cell), "5"],
        capture_output=True,
        timeout=RUN_DEADLINE_S,
        check=False,
    )

    assert completed.returncode == 1
    assert b"cannot reach the context kernel" in completed.stderr


def test_the_client_reports_a_kernel_that_dies_mid_cell(kernel: Kernel) -> None:
    kernel.run("keep = 1")

    result = kernel.run("import os\nos._exit(0)")

    assert result.exit_code == 1
    assert "its state is lost" in result.stderr


@pytest.mark.parametrize("bad", ["", "ctx_", "ctx_XYZ", "../etc", "ctx_0123456789abcdef/../x"])
def test_an_id_of_another_shape_is_never_a_directory(bad: str) -> None:
    with pytest.raises(NotFound):
        code_contexts._checked_dir(bad)


def test_the_directory_is_named_after_the_id() -> None:
    assert code_contexts.context_dir("ctx_0123456789abcdef") == (
        "/tmp/.sandfort-ctx-ctx_0123456789abcdef"
    )


@pytest.mark.skipif(shutil.which("setsid") is None, reason="needs the setsid command (Linux)")
def test_the_shell_scripts_start_list_and_delete_a_real_kernel() -> None:
    """The ``sh -c`` scripts the platform execs, run against a real directory in ``/tmp``."""
    context_id = f"ctx_{os.urandom(8).hex()}"
    directory = Path(code_contexts.context_dir(context_id))
    directory.mkdir(mode=0o700)
    (directory / code_contexts.KERNEL_FILE).write_text(code_contexts.KERNEL_SOURCE)

    def sh(script: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", "-c", script, "sh", str(directory)],
            capture_output=True,
            text=True,
            timeout=RUN_DEADLINE_S,
            check=False,
        )

    try:
        assert sh(code_contexts._START_SCRIPT).returncode == 0
        deadline = time.monotonic() + READY_DEADLINE_S
        ready = sh(code_contexts._READY_SCRIPT)
        while ready.returncode != 0 and time.monotonic() < deadline:
            time.sleep(0.1)
            ready = sh(code_contexts._READY_SCRIPT)
        assert ready.returncode == 0, (directory / "kernel.log").read_text()
        assert ready.stdout.strip() == os.getcwd()
        assert f"{context_id}\t{os.getcwd()}" in sh(code_contexts._LIST_SCRIPT).stdout.splitlines()

        assert sh(code_contexts._DELETE_SCRIPT).returncode == 0

        assert not directory.exists()
        assert context_id not in sh(code_contexts._LIST_SCRIPT).stdout
        assert sh(code_contexts._DELETE_SCRIPT).returncode == code_contexts._NOT_FOUND_EXIT_CODE
    finally:
        shutil.rmtree(directory, ignore_errors=True)


# --- the kernel's functions over a socketpair (no bound socket needed) --------------------


@pytest.fixture
def kernel_scope(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """The kernel source executed as a plain module; ``__main__`` is restored afterwards."""
    monkeypatch.setitem(sys.modules, "__main__", sys.modules["__main__"])
    scope: dict[str, Any] = {"__name__": "kernel_under_test", "__file__": "kernel.py"}
    exec(compile(code_contexts.KERNEL_SOURCE, "kernel.py", "exec"), scope)
    return scope


def run_cell(scope: dict[str, Any], namespace: dict[str, Any], code: str) -> Outcome:
    near, far = socket.socketpair()
    with near, far:
        near.sendall(json.dumps({"code": code, "timeout_s": 5}).encode() + b"\n")
        scope["handle"](namespace, far)
        far.shutdown(socket.SHUT_WR)
        frames = [json.loads(line) for line in near.makefile("rb")]
    out = "".join(f["d"] for f in frames if f.get("s") == "o")
    err = "".join(f["d"] for f in frames if f.get("s") == "e")
    [status] = [f["x"] for f in frames if "x" in f]
    return Outcome(status, out, err)


def test_new_main_installs_a_main_module_whose_dict_is_the_cell_namespace(
    kernel_scope: dict[str, Any],
) -> None:
    namespace = kernel_scope["new_main"]()

    assert sys.modules["__main__"].__dict__ is namespace
    assert namespace["__name__"] == "__main__"
    assert "serve" not in namespace  # the kernel's own code lives elsewhere


def test_a_cell_function_pickles_by_reference_to_the_main_module(
    kernel_scope: dict[str, Any],
) -> None:
    namespace = kernel_scope["new_main"]()
    code = "import pickle\ndef f(x):\n    return x + 1\nprint(pickle.loads(pickle.dumps(f))(41))"

    assert run_cell(kernel_scope, namespace, code) == Outcome(0, "42\n", "")


def test_cell_errors_are_printed_without_kernel_frames_or_a_second_traceback(
    kernel_scope: dict[str, Any],
) -> None:
    namespace = kernel_scope["new_main"]()

    result = run_cell(kernel_scope, namespace, "def boom():\n    return 1 / 0\nboom()")

    assert result.exit_code == 1
    assert 'File "<cell-1>", line 3, in <module>' in result.stderr
    assert 'File "<cell-1>", line 2, in boom' in result.stderr
    assert "kernel.py" not in result.stderr
    assert "TypeError" not in result.stderr
    assert result.stderr.count("Traceback (most recent call last)") == 1


def reply_frame(scope: dict[str, Any], namespace: dict[str, Any], code: str) -> dict[str, Any]:
    near, far = socket.socketpair()
    with near, far:
        near.sendall(json.dumps({"code": code, "timeout_s": 5}).encode() + b"\n")
        scope["handle"](namespace, far)
        far.shutdown(socket.SHUT_WR)
        frames = [json.loads(line) for line in near.makefile("rb")]
    [reply] = [f for f in frames if "x" in f]
    return dict(reply)


def test_the_reply_frame_adds_result_and_error_next_to_the_status(
    kernel_scope: dict[str, Any],
) -> None:
    namespace = kernel_scope["new_main"]()

    value = reply_frame(kernel_scope, namespace, "x = 2\nx * 21")
    none = reply_frame(kernel_scope, namespace, "y = 1")
    raised = reply_frame(kernel_scope, namespace, "raise LookupError('gone')")

    assert value == {"x": 0, "r": "42", "err": None}
    assert none == {"x": 0, "r": None, "err": None}
    assert raised == {"x": 1, "r": None, "err": {"type": "LookupError", "message": "gone"}}


def test_a_syntax_error_in_a_cell_has_no_kernel_frame(kernel_scope: dict[str, Any]) -> None:
    namespace = kernel_scope["new_main"]()

    result = run_cell(kernel_scope, namespace, "x = (")

    assert result.exit_code == 1
    assert "SyntaxError" in result.stderr
    assert "kernel.py" not in result.stderr


# --- the shell scripts and a stale pid file ------------------------------------------------
# The scripts read /proc/<pid>/cmdline; these tests point that path at a stand-in directory.


def sleeper() -> subprocess.Popen[bytes]:
    return subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])


@pytest.fixture
def short_dir() -> Iterator[Path]:
    """A short directory path, so a unix socket inside it stays within the path limit."""
    directory = Path(tempfile.mkdtemp(prefix="sfk-"))
    try:
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def script_in(
    proc: Path, script: str, *args: str, tmp_root: Path | None = None
) -> subprocess.CompletedProcess[str]:
    """Run ``script`` with /proc (and, when given, the /tmp context glob) redirected."""
    patched = script.replace("/proc/", f"{proc}/")
    if tmp_root is not None:
        patched = patched.replace("/tmp/.sandfort-ctx-", f"{tmp_root}/.sandfort-ctx-")
    return subprocess.run(
        ["sh", "-c", patched, "sh", *args],
        capture_output=True,
        text=True,
        timeout=RUN_DEADLINE_S,
        check=False,
    )


def register(proc: Path, process: subprocess.Popen[bytes], argv: list[str]) -> None:
    """Make ``process`` look like ``argv`` in the stand-in /proc."""
    entry = proc / str(process.pid)
    entry.mkdir(parents=True)
    (entry / "cmdline").write_bytes(b"".join(a.encode() + b"\0" for a in argv))


def context_with_pid(tmp_path: Path, pid: str) -> Path:
    directory = tmp_path / ".sandfort-ctx-ctx_0123456789abcdef"
    directory.mkdir()
    (directory / "kernel.pid").write_text(pid)
    return directory


def bound_socket(path: Path) -> socket.socket:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(str(path))
    except OSError as error:
        sock.close()
        pytest.skip(f"cannot bind a unix socket here: {error}")
    return sock


def stop(*processes: subprocess.Popen[bytes]) -> None:
    for process in processes:
        process.kill()
        process.wait()


@pytest.fixture
def proc(tmp_path: Path) -> Path:
    root = tmp_path / "proc"
    root.mkdir()
    return root


def test_delete_does_not_kill_an_unrelated_process_that_reuses_the_pid(
    tmp_path: Path, proc: Path
) -> None:
    other = sleeper()
    try:
        register(proc, other, ["/usr/bin/sleeper", "--unrelated"])
        directory = context_with_pid(tmp_path, str(other.pid))

        result = script_in(proc, code_contexts._DELETE_SCRIPT, str(directory))

        assert result.returncode == 0
        assert not directory.exists()  # only the directory is removed
        assert other.poll() is None
    finally:
        stop(other)


def test_delete_kills_the_process_whose_cmdline_names_the_directory(
    tmp_path: Path, proc: Path
) -> None:
    kernel = sleeper()
    try:
        directory = context_with_pid(tmp_path, str(kernel.pid))
        register(proc, kernel, ["python3", f"{directory}/kernel.py", str(directory)])

        result = script_in(proc, code_contexts._DELETE_SCRIPT, str(directory))

        assert result.returncode == 0
        assert kernel.wait(timeout=RUN_DEADLINE_S) == -signal.SIGKILL
        assert not directory.exists()
    finally:
        stop(kernel)


@pytest.mark.parametrize("pid_text", ["", "abc", "../self", "99999999", "1 2"])
def test_delete_ignores_a_pid_file_that_is_not_a_live_pid(
    tmp_path: Path, proc: Path, pid_text: str
) -> None:
    directory = context_with_pid(tmp_path, pid_text)

    result = script_in(proc, code_contexts._DELETE_SCRIPT, str(directory))

    assert result.returncode == 0
    assert not directory.exists()


def test_delete_of_a_missing_directory_exits_44(tmp_path: Path, proc: Path) -> None:
    result = script_in(proc, code_contexts._DELETE_SCRIPT, str(tmp_path / "gone"))

    assert result.returncode == code_contexts._NOT_FOUND_EXIT_CODE


def test_the_kill_script_stops_the_kernel_and_keeps_the_directory(
    tmp_path: Path, proc: Path
) -> None:
    kernel, other = sleeper(), sleeper()
    try:
        directory = context_with_pid(tmp_path, str(kernel.pid))
        register(proc, kernel, ["python3", f"{directory}/kernel.py", str(directory)])
        register(proc, other, ["python3", "unrelated.py"])

        assert script_in(proc, code_contexts._KILL_SCRIPT, str(directory)).returncode == 0
        assert kernel.wait(timeout=RUN_DEADLINE_S) == -signal.SIGKILL
        assert directory.exists()

        (directory / "kernel.pid").write_text(str(other.pid))
        assert script_in(proc, code_contexts._KILL_SCRIPT, str(directory)).returncode == 0
        assert other.poll() is None  # not that context's kernel
    finally:
        stop(kernel, other)


def test_probe_reports_a_live_kernel_and_not_a_stale_pid(short_dir: Path, proc: Path) -> None:
    kernel, other = sleeper(), sleeper()
    try:
        directory = context_with_pid(short_dir, str(kernel.pid))
        register(proc, kernel, ["python3", f"{directory}/kernel.py", str(directory)])
        register(proc, other, ["python3", "unrelated.py"])
        with bound_socket(directory / code_contexts.SOCKET_FILE):
            probe = code_contexts._PROBE_SCRIPT
            assert script_in(proc, probe, str(directory)).returncode == 0

            (directory / "kernel.pid").write_text(str(other.pid))
            assert script_in(proc, probe, str(directory)).returncode != 0
    finally:
        stop(kernel, other)


def test_list_omits_a_context_whose_pid_belongs_to_another_process(
    short_dir: Path, proc: Path
) -> None:
    live, stale = sleeper(), sleeper()
    context_ids = [f"ctx_{os.urandom(8).hex()}" for _ in range(2)]
    directories = [short_dir / f"{code_contexts.DIR_PREFIX}{i}" for i in context_ids]
    sockets: list[socket.socket] = []
    try:
        for directory in directories:
            directory.mkdir(mode=0o700)
            (directory / "kernel.cwd").write_text("/work")
        (directories[0] / "kernel.pid").write_text(str(live.pid))
        (directories[1] / "kernel.pid").write_text(str(stale.pid))
        register(proc, live, ["python3", f"{directories[0]}/kernel.py", str(directories[0])])
        register(proc, stale, ["python3", "unrelated.py"])
        sockets = [bound_socket(d / code_contexts.SOCKET_FILE) for d in directories]

        result = script_in(proc, code_contexts._LIST_SCRIPT, tmp_root=short_dir)
        listed = result.stdout.splitlines()

        assert f"{context_ids[0]}\t/work" in listed
        assert all(not line.startswith(context_ids[1]) for line in listed)
    finally:
        for sock in sockets:
            sock.close()
        for directory in directories:
            shutil.rmtree(directory, ignore_errors=True)
        stop(live, stale)
