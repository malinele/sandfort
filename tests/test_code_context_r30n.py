"""Round-30 review findings for code contexts: interrupt and outcome edge cases.

The in-process tests run the kernel source as a module (as in ``test_code_contexts``) and call
its ``handle`` over a socketpair; the others use a real local kernel and the real client (as in
``test_code_context_outcomes``) and the ``sh -c`` scripts against a stand-in ``/proc``.
"""

import json
import os
import shutil
import signal
import socket
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from sandfort.toolbox import code_contexts
from sandfort.toolbox.code_contexts import OUTCOME_MARK, CellError, split_outcome
from sandfort.toolbox.process import MAX_OUTPUT_BYTES
from test_code_context_outcomes import MAX_SOCKET_PATH, RUN_DEADLINE_S, Kernel, finish, wait_busy

SETTLE_S = 0.3
TOKEN = "a" * 32
OTHER_TOKEN = "b" * 32
INTERRUPTED = CellError(type="KeyboardInterrupt", message="")
CUT_MARK = "... [truncated]"


# --- the kernel as a module, in this process ----------------------------------------------


@pytest.fixture
def scope(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[dict[str, Any]]:
    """The kernel source as a module, its SIGINT handler installed in this process."""
    monkeypatch.setitem(sys.modules, "__main__", sys.modules["__main__"])
    kernel: dict[str, Any] = {"__name__": "kernel_under_test", "__file__": "kernel.py"}
    exec(compile(code_contexts.KERNEL_SOURCE, "kernel.py", "exec"), kernel)
    kernel["STATE"]["busy_path"] = str(tmp_path / "kernel.busy")
    previous = signal.signal(signal.SIGINT, kernel["on_interrupt"])
    try:
        yield kernel
    finally:
        signal.signal(signal.SIGINT, previous)
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT})  # whatever a test left


def frames_of(
    kernel: dict[str, Any], namespace: dict[str, Any], code: str, *, seq: int | None = None
) -> list[dict[str, Any]]:
    """Every frame the kernel's ``handle`` sends for one request."""
    request: dict[str, Any] = {"code": code, "timeout_s": 5}
    if seq is not None:
        request["seq"] = seq
    lines: list[bytes] = []
    near, far = socket.socketpair()
    with near, far:
        near.sendall(json.dumps(request).encode() + b"\n")
        # read while the kernel writes: its large outputs would fill the socket buffer
        reader = threading.Thread(target=lambda: lines.extend(near.makefile("rb")), daemon=True)
        reader.start()
        kernel["handle"](namespace, far)
        far.shutdown(socket.SHUT_WR)
        reader.join(timeout=RUN_DEADLINE_S)
    return [json.loads(line) for line in lines]


def reply_of(frames: list[dict[str, Any]]) -> dict[str, Any]:
    [reply] = [f for f in frames if "x" in f]
    return dict(reply)


def sigint_blocked() -> bool:
    return signal.SIGINT in signal.pthread_sigmask(signal.SIG_BLOCK, set())  # reads the mask


class SignalProbe:
    """The ``signal`` module as the kernel sees it, noting what happens around a cell."""

    def __init__(self, *, interrupt_when_the_alarm_is_cleared: bool = False) -> None:
        self.interrupt_on_clear = interrupt_when_the_alarm_is_cleared
        self.sent = 0
        self.sigint_blocked_at_handler_swap: list[bool] = []

    def __getattr__(self, name: str) -> Any:
        return getattr(signal, name)

    def signal(self, signum: int, handler: Any) -> Any:
        self.sigint_blocked_at_handler_swap.append(sigint_blocked())
        return signal.signal(signum, handler)

    def alarm(self, seconds: int) -> int:
        if seconds == 0 and self.interrupt_on_clear and not self.sent:
            self.sent += 1
            os.kill(os.getpid(), signal.SIGINT)  # right after the cell's code returned
        return signal.alarm(seconds)


def test_a_sigint_right_after_the_cell_returned_still_gets_a_normal_reply(
    scope: dict[str, Any], tmp_path: Path
) -> None:
    probe = SignalProbe(interrupt_when_the_alarm_is_cleared=True)
    scope["signal"] = probe
    namespace = scope["new_main"]()
    stdout, alarm_handler = sys.stdout, signal.getsignal(signal.SIGALRM)

    frames = frames_of(scope, namespace, "x = 1\nx + 41")
    time.sleep(0.05)

    assert probe.sent == 1
    assert reply_of(frames) == {"x": 0, "r": "42", "err": None}  # not an error of a finished cell
    assert not any(f.get("s") == "e" for f in frames)
    assert scope["STATE"]["running"] is False
    assert not (tmp_path / "kernel.busy").exists()
    assert (sys.stdout, signal.getsignal(signal.SIGALRM)) == (stdout, alarm_handler)
    assert not sigint_blocked()


class LateInterruptProbe(SignalProbe):
    """Raises KeyboardInterrupt from the first SIGINT mask call after the cell's execute."""

    def __init__(self) -> None:
        super().__init__()
        self.executed = False
        self.raised = 0

    def pthread_sigmask(self, how: int, mask: Any) -> Any:
        if self.executed and not self.raised:
            self.raised += 1
            raise KeyboardInterrupt()  # the SIGINT that lands before the mask takes effect
        return signal.pthread_sigmask(how, mask)


def test_a_late_sigint_never_leaves_a_pending_alarm_or_the_old_handler_unrestored(
    scope: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    probe = LateInterruptProbe()
    real_execute = scope["execute"]

    def execute_then_flag(namespace: dict[str, Any], code: str) -> Any:
        result = real_execute(namespace, code)
        probe.executed = True  # from here on, the next mask call is interrupted
        return result

    def previous_handler(signum: int, frame: Any) -> None:
        raise AssertionError("the cell's alarm must never fire")

    monkeypatch.setitem(scope, "signal", probe)
    monkeypatch.setitem(scope, "execute", execute_then_flag)
    signal.signal(signal.SIGALRM, previous_handler)
    near, far = socket.socketpair()
    try:
        with near, far:
            status, result, error = scope["run_cell"](scope["new_main"](), far, "x = 1\nx + 41", 5)
    finally:
        pending = signal.alarm(0)  # also cancels a leaked alarm so it cannot kill the test run
        restored = signal.signal(signal.SIGALRM, signal.SIG_DFL)

    assert probe.raised == 1
    assert (status, result) == (1, None)  # the interrupt is reported like any interrupted cell
    assert error is not None
    assert pending == 0  # no alarm stays pending after run_cell
    assert restored is previous_handler  # the SIGALRM handler from before the cell is back
    assert scope["STATE"]["running"] is False


def test_sigint_is_blocked_from_the_end_of_the_cell_until_the_reply_is_sent(
    scope: dict[str, Any],
) -> None:
    probe = SignalProbe()
    scope["signal"] = probe

    frames_of(scope, scope["new_main"](), "1 / 0")

    # run_cell swaps the SIGALRM handler twice: on entry (not blocked) and in its cleanup
    assert probe.sigint_blocked_at_handler_swap == [False, True]
    assert not sigint_blocked()  # handle undid the block once the reply was sent


def test_handle_always_sends_a_reply_even_when_run_cell_raises_keyboard_interrupt(
    scope: dict[str, Any],
) -> None:
    def stray(*args: Any, **kwargs: Any) -> None:
        raise KeyboardInterrupt()

    scope["run_cell"] = stray

    frames = frames_of(scope, scope["new_main"](), "1")

    assert reply_of(frames) == {"x": 1, "r": None, "err": None}  # not the cell's interrupt
    assert any(f.get("s") == "e" and "KeyboardInterrupt" in f["d"] for f in frames)
    assert not sigint_blocked()


def test_a_keyboard_interrupt_of_the_cell_itself_is_reported_as_its_interrupt(
    scope: dict[str, Any],
) -> None:
    def interrupted(*args: Any, **kwargs: Any) -> None:
        scope["STATE"]["interrupted"] = True
        raise KeyboardInterrupt()

    scope["run_cell"] = interrupted

    reply = reply_of(frames_of(scope, scope["new_main"](), "1"))

    assert reply == {"x": 1, "r": None, "err": {"type": "KeyboardInterrupt", "message": ""}}


# --- which cell an interrupt is for (handler called directly) ------------------------------


def aim(scope: dict[str, Any], tmp_path: Path, number: int | None) -> None:
    """Deliver an interrupt to the handler, naming cell ``number`` (none: unnamed)."""
    target = tmp_path / "kernel.interrupt"
    scope["STATE"]["interrupt_path"] = str(target)
    target.unlink(missing_ok=True)
    if number is not None:
        target.write_text(str(number))
    try:
        scope["on_interrupt"](signal.SIGINT, None)
    finally:
        assert not target.exists()  # the handler consumes the target


def test_an_interrupt_naming_another_running_cell_is_ignored(
    scope: dict[str, Any], tmp_path: Path
) -> None:
    state = scope["STATE"]
    state.update(running=True, seq=5)

    aim(scope, tmp_path, 4)

    assert state["running"] is True and state["skip"] is None
    with pytest.raises(KeyboardInterrupt):
        aim(scope, tmp_path, 5)
    assert state["running"] is False and state["interrupted"] is True


def test_an_interrupt_naming_a_cell_that_has_not_begun_is_kept_for_that_cell(
    scope: dict[str, Any], tmp_path: Path
) -> None:
    state = scope["STATE"]
    state["seq"] = 5

    aim(scope, tmp_path, 9)  # between cells: nothing to raise, but cell 9 is now refused
    aim(scope, tmp_path, 3)  # a past cell is not remembered

    assert state["skip"] == 9
    with pytest.raises(KeyboardInterrupt):
        scope["begin"](9)
    assert state["skip"] is None and state["interrupted"] is True
    scope["set_running"](False)  # the cleanup run_cell does


# --- result and error text are bounded -----------------------------------------------------


def test_a_long_result_repr_is_cut_with_a_marker_but_printed_in_full(
    scope: dict[str, Any],
) -> None:
    limit = scope["RESULT_MAX_CHARS"]
    assert (limit, scope["CUT_MARK"]) == (4096, CUT_MARK)  # the values the tests below assume

    frames = frames_of(scope, scope["new_main"](), "'x' * 100000")

    result = reply_of(frames)["r"]
    assert len(result) == limit and result.endswith(CUT_MARK)
    assert result.startswith("'xxx")
    printed = "".join(f["d"] for f in frames if f.get("s") == "o")
    assert printed == repr("x" * 100000) + "\n"  # stdout is the cell's own: nothing cut there


def test_a_long_error_message_is_cut_too(scope: dict[str, Any]) -> None:
    reply = reply_of(frames_of(scope, scope["new_main"](), "raise ValueError('y' * 100000)"))

    assert reply["err"]["type"] == "ValueError"
    assert len(reply["err"]["message"]) == scope["RESULT_MAX_CHARS"]
    assert reply["err"]["message"].endswith(CUT_MARK)


def test_the_reserve_covers_the_longest_trailer(scope: dict[str, Any]) -> None:
    """Worst case: every character of text escapes to 6 bytes, for the result and the error."""
    longest = 2 * 6 * scope["RESULT_MAX_CHARS"] + 1024  # +1024: type name, mark, token, keys

    assert longest <= code_contexts.TRAILER_RESERVE_BYTES
    reserve = code_contexts.TRAILER_RESERVE_BYTES
    assert code_contexts.CLIENT_OUTPUT_LIMIT == MAX_OUTPUT_BYTES - reserve


# --- a real kernel and the real client -----------------------------------------------------


@pytest.fixture
def live() -> Iterator[Kernel]:
    directory = Path(tempfile.mkdtemp(prefix="sfr-"))
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


def interrupt(kernel: Kernel, cell: int | None) -> None:
    """What the interrupt script does: write the target (when a cell is named), send SIGINT."""
    target = kernel.directory / "kernel.interrupt"
    if cell is not None:
        target.write_text(str(cell))
    os.kill(kernel.process.pid, signal.SIGINT)
    deadline = time.monotonic() + RUN_DEADLINE_S
    while cell is not None and target.exists():  # the handler consumes it
        assert time.monotonic() < deadline, "the kernel never read the interrupt"
        time.sleep(0.01)


def test_the_busy_marker_holds_the_number_of_the_running_cell(live: Kernel) -> None:
    client = live.start("import time\ntime.sleep(30)", TOKEN, timeout_s="30", seq=12)
    try:
        wait_busy(live)
        assert (live.directory / "kernel.busy").read_text() == "12"
        interrupt(live, 12)
        run = finish(client, TOKEN)
    finally:
        client.kill()
        client.wait()

    assert run.outcome is not None and run.outcome.error == INTERRUPTED
    assert not (live.directory / "kernel.busy").exists()


def test_an_interrupt_for_cell_n_does_not_stop_cell_n_plus_one(live: Kernel) -> None:
    assert finish(live.start("x = 1", TOKEN, seq=11), TOKEN).exit_code == 0
    second = live.start("while True:\n    pass", OTHER_TOKEN, timeout_s="30", seq=12)
    try:
        wait_busy(live)

        interrupt(live, 11)  # meant for the cell that has long finished
        time.sleep(SETTLE_S)
        still_running = second.poll() is None
        interrupt(live, 12)
        run = finish(second, OTHER_TOKEN)
    finally:
        second.kill()
        second.wait()

    assert still_running
    assert run.exit_code == 1
    assert run.outcome is not None and run.outcome.error == INTERRUPTED


def test_an_interrupt_without_a_number_still_stops_whichever_cell_runs(live: Kernel) -> None:
    client = live.start("while True:\n    pass", TOKEN, timeout_s="30", seq=7)
    try:
        wait_busy(live)
        interrupt(live, None)
        run = finish(client, TOKEN)
    finally:
        client.kill()
        client.wait()

    assert run.outcome is not None and run.outcome.error == INTERRUPTED


def test_a_cancel_before_the_cell_starts_makes_the_kernel_skip_the_cell(live: Kernel) -> None:
    flag = live.directory / "ran"
    code = f"open({str(flag)!r}, 'w').close()"
    interrupt(live, 21)  # the kernel is idle: recorded for the cell that is about to come

    skipped = finish(live.start(code, TOKEN, seq=21), TOKEN)

    assert not flag.exists()  # the code never ran
    assert skipped.exit_code == 1
    assert skipped.outcome is not None and skipped.outcome.error == INTERRUPTED
    assert "KeyboardInterrupt" in skipped.stderr
    assert not (live.directory / "kernel.busy").exists()
    after = finish(live.start(code, OTHER_TOKEN, seq=22), OTHER_TOKEN)
    assert after.exit_code == 0 and flag.exists()  # the next cell is not affected


def test_a_cancel_for_a_cell_that_never_came_does_not_skip_a_later_one(live: Kernel) -> None:
    interrupt(live, 30)  # cell 30 never reaches the kernel

    first = finish(live.start("print('ran')", TOKEN, seq=31), TOKEN)
    again = finish(live.start("print('ran again')", OTHER_TOKEN, seq=30), OTHER_TOKEN)

    assert (first.exit_code, first.stdout) == (0, b"ran\n")
    assert (again.exit_code, again.stdout) == (0, b"ran again\n")


def test_stdout_near_the_limit_keeps_the_result_and_fits_the_exec_cap(live: Kernel) -> None:
    printed = code_contexts.CLIENT_OUTPUT_LIMIT - 20_000
    code = f"import sys\nsys.stdout.write('a' * {printed})\n'r' * 15000"
    client = live.start(code, TOKEN)

    raw, _ = client.communicate(timeout=RUN_DEADLINE_S)
    stdout, outcome = split_outcome(raw, TOKEN)

    assert len(raw) <= MAX_OUTPUT_BYTES  # the trailer did not push the exec over its cap
    assert len(stdout) == printed + len(repr("r" * 15000)) + 1
    assert outcome is not None and outcome.result is not None
    assert len(outcome.result) == 4096 and outcome.result.endswith(CUT_MARK)


@pytest.mark.parametrize(
    "code",
    ["'\\U0001F600' * 100000", "raise ValueError('\\x00' * 100000)"],
    ids=["result", "error"],
)
def test_the_longest_real_trailer_fits_in_the_reserve(live: Kernel, code: str) -> None:
    client = live.start(code, TOKEN)

    raw, _ = client.communicate(timeout=RUN_DEADLINE_S)

    at = raw.rfind(OUTCOME_MARK + TOKEN.encode())
    assert at >= 0
    assert len(raw) - at <= code_contexts.TRAILER_RESERVE_BYTES
    assert split_outcome(raw, TOKEN)[1] is not None


# --- trailers cut short --------------------------------------------------------------------

FULL_TRAILER = (
    OUTCOME_MARK + OTHER_TOKEN.encode() + b' {"x": 0, "r": "42", "err": null, "lost": false}\n'
)


@pytest.mark.parametrize("cut", range(1, len(FULL_TRAILER)))
def test_a_trailer_cut_short_is_removed_from_stdout(cut: int) -> None:
    stdout = b"out\n" + FULL_TRAILER[:cut]

    assert split_outcome(stdout, OTHER_TOKEN) == (b"out\n", None)


def test_cell_numbers_do_not_go_backwards() -> None:
    numbers = [code_contexts.new_cell_number() for _ in range(100)]

    assert numbers == sorted(numbers) and numbers[0] > 0
