"""Round-31 code-context fixes: buffered cell output, the output-limit notice, the spawn hint.

The live tests run a real local kernel and the real client (as in ``test_code_context_outcomes``);
the in-process tests run the kernel source as a module and call its ``handle`` over a socketpair
(as in ``test_code_context_r30n``); the notice tests drive ``run_in_context`` with a stub driver.
"""

import asyncio
import json
import os
import shutil
import signal
import socket
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sandfort.domain.sandbox import Sandbox
from sandfort.drivers.base import ExecRequest, ExecResult, SandboxDriver
from sandfort.drivers.docker.exec import output_cap_message
from sandfort.toolbox import code_contexts
from test_code_context_outcomes import MAX_SOCKET_PATH, RUN_DEADLINE_S, Kernel, finish, wait_busy

CHATTY_LINES = 20_000
CHATTY_BOUND_S = 2.0  # a plain program prints these lines in well under 0.1 s
CAPPED_BYTES = 2 * 1024 * 1024  # where the stand-in for the driver cap kills the client
CAP_DEADLINE_S = 10.0
IDLE_DEADLINE_S = 10.0
WORKER_DEADLINE_S = 20.0
SPAWN_TIMEOUT_S = "4"
HINT = "functions defined in cells are not importable by spawn/forkserver children"
SPAWN_POOL_CELL = (
    "import multiprocessing\n"
    "def square(x):\n"
    "    return x * x\n"
    "pool = multiprocessing.get_context({method!r}).Pool(2)\n"
    "pool.map(square, range(4))\n"
)
CONTEXT_ID = "ctx_0123456789abcdef"


# --- a live kernel -------------------------------------------------------------------------


@pytest.fixture
def live() -> Iterator[Kernel]:
    directory = Path(tempfile.mkdtemp(prefix="sfb-"))
    if len(str(directory / "kernel.sock.tmp")) > MAX_SOCKET_PATH:
        shutil.rmtree(directory, ignore_errors=True)
        pytest.skip("the temp directory path is too long for a unix socket")
    started = Kernel(directory)
    try:
        started.wait_ready()
        yield started
    finally:
        kill_group(started)
        started.close()
        shutil.rmtree(directory, ignore_errors=True)


def kill_group(kernel: Kernel) -> None:
    """Kill the kernel's whole process group: pool workers a cell left behind go with it."""
    try:
        os.killpg(kernel.process.pid, signal.SIGKILL)
    except OSError:
        pass  # already gone


def wait_idle(kernel: Kernel) -> None:
    deadline = time.monotonic() + IDLE_DEADLINE_S
    while (kernel.directory / "kernel.busy").exists():
        assert time.monotonic() < deadline, "the cell never ended"
        time.sleep(0.02)


def wait_for_lost_tasks(kernel: Kernel) -> None:
    """Wait until the four pool workers that could not load ``square`` have died (their log)."""
    deadline = time.monotonic() + WORKER_DEADLINE_S
    log = kernel.directory / "kernel.log"
    while log.read_text(errors="replace").count("AttributeError") < 4:
        assert time.monotonic() < deadline, log.read_text(errors="replace")
        time.sleep(0.05)


def test_twenty_thousand_printed_lines_finish_fast_and_in_order(live: Kernel) -> None:
    started = time.monotonic()
    run = live.run(f"for i in range({CHATTY_LINES}):\n    print(i)")
    elapsed = time.monotonic() - started

    assert run.exit_code == 0, run.stderr
    assert run.stdout.decode().splitlines() == [str(i) for i in range(CHATTY_LINES)]
    assert elapsed < CHATTY_BOUND_S


def test_interleaved_stdout_and_stderr_writes_keep_their_order_per_stream(live: Kernel) -> None:
    code = (
        "import sys\n"
        "for i in range(3000):\n"
        "    print('o%d' % i)\n"
        "    print('e%d' % i, file=sys.stderr)\n"
        "    if i % 1000 == 0:\n"
        "        sys.stdout.write('x' * 70000 + '\\n')\n"  # larger than one chunk
    )

    run = live.run(code)

    assert run.exit_code == 0, run.stderr
    expected_out: list[str] = []
    for i in range(3000):
        expected_out.append(f"o{i}")
        if i % 1000 == 0:
            expected_out.append("x" * 70000)
    assert run.stdout.decode().splitlines() == expected_out
    assert run.stderr.splitlines() == [f"e{i}" for i in range(3000)]


def test_output_without_a_newline_and_the_trailing_value_arrive_whole(live: Kernel) -> None:
    run = live.run("import sys\nsys.stdout.write('a')\nsys.stderr.write('b')\n41 + 1")

    assert run.stdout == b"a42\n"
    assert run.stderr == "b"
    assert run.outcome is not None and run.outcome.result == "42"


def test_the_output_cap_still_stops_a_cell_that_prints_forever(live: Kernel) -> None:
    client = live.start("while True:\n    print('y' * 99)", uuid.uuid4().hex, timeout_s="60")
    wait_busy(live)
    assert client.stdout is not None
    received = 0
    deadline = time.monotonic() + CAP_DEADLINE_S
    while received < CAPPED_BYTES:  # the driver counts the bytes and kills at its cap
        assert time.monotonic() < deadline, "the output never reached the cap"
        chunk = client.stdout.read1(65536)
        assert chunk, "the client ended before the cap"
        received += len(chunk)
    client.kill()  # what the driver does at the cap
    client.communicate(timeout=RUN_DEADLINE_S)

    os.kill(live.process.pid, signal.SIGINT)  # the output_limit run interrupts its cell
    wait_idle(live)

    after = live.run("1 + 1")
    assert after.outcome is not None and after.outcome.result == "2"  # state kept, kernel free


@pytest.mark.parametrize("method", ["spawn", "forkserver"])
def test_a_spawn_pool_cell_that_times_out_carries_the_hint(live: Kernel, method: str) -> None:
    run = live.run(SPAWN_POOL_CELL.format(method=method), timeout_s=SPAWN_TIMEOUT_S)

    assert run.exit_code == code_contexts.TIMED_OUT_EXIT_CODE
    assert run.outcome is not None and run.outcome.error is not None
    assert run.outcome.error.type == "TimeoutError"
    first, hint = run.outcome.error.message.split("\n")
    assert first == f"cell exceeded {SPAWN_TIMEOUT_S} s"
    assert HINT in hint and "fork" in hint


def test_a_spawn_pool_cell_that_is_interrupted_carries_the_hint(live: Kernel) -> None:
    token = uuid.uuid4().hex
    client = live.start(SPAWN_POOL_CELL.format(method="spawn"), token, timeout_s="60")
    wait_busy(live)
    wait_for_lost_tasks(live)

    os.kill(live.process.pid, signal.SIGINT)
    run = finish(client, token)

    assert run.outcome is not None and run.outcome.error is not None
    assert run.outcome.error.type == "KeyboardInterrupt"
    assert HINT in run.outcome.error.message


@pytest.mark.parametrize(
    "code",
    ["import time\ntime.sleep(30)", "import multiprocessing, time\ntime.sleep(30)"],
)
def test_a_plain_sleep_that_times_out_has_no_hint(live: Kernel, code: str) -> None:
    run = live.run(code, timeout_s="1")

    assert run.exit_code == code_contexts.TIMED_OUT_EXIT_CODE
    assert run.outcome is not None and run.outcome.error is not None
    assert run.outcome.error.message == "cell exceeded 1 s"


def test_a_plain_interrupted_cell_has_no_hint(live: Kernel) -> None:
    token = uuid.uuid4().hex
    client = live.start("import multiprocessing, time\ntime.sleep(30)", token, timeout_s="60")
    wait_busy(live)

    os.kill(live.process.pid, signal.SIGINT)
    run = finish(client, token)

    assert run.outcome is not None and run.outcome.error is not None
    assert (run.outcome.error.type, run.outcome.error.message) == ("KeyboardInterrupt", "")


# --- the kernel in this process: how writes become frames ----------------------------------


@pytest.fixture
def scope(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[dict[str, Any]]:
    monkeypatch.setitem(sys.modules, "__main__", sys.modules["__main__"])
    kernel: dict[str, Any] = {"__name__": "kernel_under_test", "__file__": "kernel.py"}
    exec(compile(code_contexts.KERNEL_SOURCE, "kernel.py", "exec"), kernel)
    kernel["STATE"]["busy_path"] = str(tmp_path / "kernel.busy")
    previous = signal.signal(signal.SIGINT, kernel["on_interrupt"])
    try:
        yield kernel
    finally:
        signal.signal(signal.SIGINT, previous)
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT})


def frames_of(
    kernel: dict[str, Any],
    code: str,
    *,
    timeout_s: int = 5,
    namespace: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    lines: list[bytes] = []
    near, far = socket.socketpair()
    with near, far:
        near.sendall(json.dumps({"code": code, "timeout_s": timeout_s}).encode() + b"\n")
        reader = threading.Thread(target=lambda: lines.extend(near.makefile("rb")), daemon=True)
        reader.start()
        kernel["handle"](kernel["new_main"]() if namespace is None else namespace, far)
        far.shutdown(socket.SHUT_WR)
        reader.join(timeout=RUN_DEADLINE_S)
    return [json.loads(line) for line in lines]


def texts(frames: list[dict[str, Any]], tag: str) -> list[str]:
    return [f["d"] for f in frames if f.get("s") == tag]


def test_many_short_prints_become_few_frames(scope: dict[str, Any]) -> None:
    frames = frames_of(scope, f"for i in range({CHATTY_LINES}):\n    print(i)")

    out = texts(frames, "o")
    assert "".join(out) == "".join(f"{i}\n" for i in range(CHATTY_LINES))
    assert len(out) < CHATTY_LINES // 100
    assert frames[-1] == {"x": 0, "r": None, "err": None}  # the reply comes after all output


def test_an_explicit_flush_sends_what_was_written(scope: dict[str, Any]) -> None:
    code = "import sys\nsys.stdout.write('a')\nsys.stdout.flush()\nn = sys.stdout.write('b')"

    assert texts(frames_of(scope, code), "o") == ["a", "b"]


def test_collected_output_goes_out_while_the_cell_still_runs(scope: dict[str, Any]) -> None:
    code = (
        "import sys, time\n"
        "sys.stdout.write('a')\n"
        f"time.sleep({scope['FLUSH_S']} * 8)\n"  # the flusher thread sends 'a' meanwhile
        "n = sys.stdout.write('b')"
    )

    assert texts(frames_of(scope, code), "o") == ["a", "b"]


def test_the_flusher_thread_ends_with_the_cell(scope: dict[str, Any]) -> None:
    before = threading.active_count()

    frames_of(scope, "x = 1")

    assert threading.active_count() == before


def test_a_large_write_is_sent_at_once(scope: dict[str, Any]) -> None:
    size = scope["FLUSH_CHARS"]
    code = f"import sys\nsys.stdout.write('z' * {size})\nn = sys.stdout.write('tail')"

    assert texts(frames_of(scope, code), "o") == ["z" * size, "tail"]


def test_a_frame_is_sent_with_sigint_and_sigalrm_held(scope: dict[str, Any]) -> None:
    held: list[bool] = []

    class Conn:
        def sendall(self, data: bytes) -> None:
            mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
            held.append({signal.SIGINT, signal.SIGALRM} <= mask)

    scope["send"](Conn(), {"s": "o", "d": "x"})

    assert held == [True]
    assert signal.SIGALRM not in signal.pthread_sigmask(signal.SIG_BLOCK, set())


def test_in_process_a_live_spawn_child_at_the_timeout_adds_the_hint(scope: dict[str, Any]) -> None:
    namespace = scope["new_main"]()
    code = (
        "import multiprocessing, time\n"
        "child = multiprocessing.get_context('spawn').Process(target=time.sleep, args=(60,))\n"
        "child.start()\n"
        "time.sleep(30)\n"  # the child is alive when the alarm fires
    )
    try:
        frames = frames_of(scope, code, timeout_s=2, namespace=namespace)
    finally:
        child = namespace.get("child")
        if child is not None and child.pid is not None:
            child.kill()
            child.join()

    reply = frames[-1]
    assert reply["x"] == code_contexts.TIMED_OUT_EXIT_CODE, (reply, child.exitcode, frames)
    assert reply["err"] == {
        "type": "TimeoutError",
        "message": f"cell exceeded 2 s\n{scope['SPAWN_HINT']}",
    }


def test_in_process_a_plain_sleep_that_times_out_has_no_hint(scope: dict[str, Any]) -> None:
    code = "import multiprocessing, time\ntime.sleep(30)"

    reply = frames_of(scope, code, timeout_s=1)[-1]

    assert reply["err"] == {"type": "TimeoutError", "message": "cell exceeded 1 s"}


def test_the_hint_names_both_ways_out(scope: dict[str, Any]) -> None:
    hint = scope["SPAWN_HINT"]

    assert HINT in hint and "fork" in hint and "module file" in hint and "\n" not in hint


# --- the output-limit notice ---------------------------------------------------------------


class CappedDriver:
    """Answers the platform's scripts with success, and the client exec as one stopped at the
    output cap: ``stderr`` followed by the driver's notice."""

    def __init__(self, stderr: bytes) -> None:
        self.stderr = stderr

    async def exec(self, ref: str, request: ExecRequest) -> ExecResult:
        if request.argv[0] != "python3":
            return ExecResult(exit_code=0)
        stderr = self.stderr + output_cap_message(request.max_output_bytes)
        return ExecResult(exit_code=137, stdout=b"x" * 10, stderr=stderr, truncated=True)

    async def put_archive(self, ref: str, dest_path: str, data: AsyncIterator[bytes]) -> None:
        async for _ in data:
            pass


def capped_run(stderr: bytes) -> ExecResult:
    driver = cast(SandboxDriver, CappedDriver(stderr))
    sandbox = cast(Sandbox, SimpleNamespace(driver_ref="ref", state=None))
    coroutine = code_contexts.run_in_context(driver, sandbox, CONTEXT_ID, "print(1)", timeout_s=5)
    return asyncio.run(coroutine).exec_result


@pytest.mark.parametrize(
    ("stderr", "before"),
    [
        (b"a partial line", b"a partial line\n"),
        (b"a whole line\n", b"a whole line\n"),
        (b"", b""),
    ],
)
def test_the_limit_notice_starts_on_its_own_line(stderr: bytes, before: bytes) -> None:
    notice = output_cap_message(code_contexts.CLIENT_OUTPUT_LIMIT)

    result = capped_run(stderr)

    assert result.truncated
    assert result.stderr == before + notice
