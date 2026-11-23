"""Docker exec unit tests: demux + cap logic and the exec flow over a fake docker-py client."""

import socket
import struct
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from sandfort.drivers.base import ExecRequest, ExitEvent, OutputChunk
from sandfort.drivers.docker import exec as exec_module
from sandfort.drivers.docker.demux import STDERR, STDOUT, FrameDemuxer, OutputCaps
from sandfort.drivers.docker.exec import (
    COMMAND_NOT_FOUND_MESSAGE,
    DEATH_POLL_INTERVAL_S,
    DEATH_POLL_WINDOW_S,
    EXEC_WRAPPER,
    MISSING_CWD_MESSAGE,
    SANDBOX_DIED_EXIT_CODE,
    SANDBOX_DIED_MESSAGE,
    SUSPECT_DEATH_EXIT_CODES,
    TIMED_OUT_EXIT_CODE,
    TIMEOUT_MESSAGE_TEMPLATE,
    WRAPPER_ARG0,
    exec_run,
    exec_stream,
    output_cap_message,
    rewrite_sandbox_death,
    timeout_message,
)
from sandfort.drivers.errors import DriverError, DriverNotFound


def frame(kind: int, payload: bytes) -> bytes:
    return struct.pack(">BxxxI", kind, len(payload)) + payload


# --- FrameDemuxer ---------------------------------------------------------------------


def test_demux_separates_stdout_and_stderr_frames() -> None:
    data = frame(1, b"out") + frame(2, b"err")

    assert FrameDemuxer().feed(data) == [(STDOUT, b"out"), (STDERR, b"err")]


def test_demux_handles_header_split_across_feeds() -> None:
    data = frame(1, b"hello")
    demuxer = FrameDemuxer()

    assert demuxer.feed(data[:3]) == []
    assert demuxer.feed(data[3:10]) == [(STDOUT, b"he")]
    assert demuxer.feed(data[10:]) == [(STDOUT, b"llo")]


def test_demux_emits_partial_payload_as_it_arrives() -> None:
    data = frame(2, b"abcdef")
    demuxer = FrameDemuxer()

    first = demuxer.feed(data[:11])
    second = demuxer.feed(data[11:])

    assert b"".join(chunk for _, chunk in first + second) == b"abcdef"
    assert all(stream == STDERR for stream, _ in first + second)


def test_demux_drops_unknown_streams_and_empty_frames() -> None:
    data = frame(0, b"stdin-echo") + frame(1, b"") + frame(1, b"ok")

    assert FrameDemuxer().feed(data) == [(STDOUT, b"ok")]


def test_demux_handles_many_frames_in_one_feed() -> None:
    data = b"".join(frame(1, bytes([i])) for i in range(50))

    assert FrameDemuxer().feed(data) == [(STDOUT, bytes([i])) for i in range(50)]


# --- OutputCaps -----------------------------------------------------------------------


def test_caps_pass_data_under_the_limit() -> None:
    caps = OutputCaps(10)

    assert caps.admit(STDOUT, b"12345") == b"12345"
    assert caps.truncated is False


def test_caps_exactly_at_limit_is_not_truncated() -> None:
    caps = OutputCaps(5)

    assert caps.admit(STDOUT, b"12345") == b"12345"
    assert caps.truncated is False


def test_caps_cut_at_limit_and_flag_truncation() -> None:
    caps = OutputCaps(5)

    assert caps.admit(STDOUT, b"123") == b"123"
    assert caps.admit(STDOUT, b"45678") == b"45"
    assert caps.admit(STDOUT, b"more") == b""
    assert caps.truncated is True


def test_caps_are_tracked_per_stream() -> None:
    caps = OutputCaps(4)

    assert caps.admit(STDOUT, b"1234") == b"1234"
    assert caps.admit(STDERR, b"abcd") == b"abcd"
    assert caps.truncated is False


def test_caps_with_zero_limit_drop_everything() -> None:
    caps = OutputCaps(0)

    assert caps.admit(STDERR, b"x") == b""
    assert caps.truncated is True


# --- exec flow over a fake client -----------------------------------------------------


class FakeApi:
    def __init__(self, sock: socket.socket, exit_code: int = 0) -> None:
        self.sock = sock
        self.exit_code = exit_code
        self.created: list[dict[str, Any]] = []

    def exec_create(self, container: str, **kwargs: Any) -> dict[str, str]:
        self.created.append(kwargs)
        return {"Id": f"exec{len(self.created)}"}

    def exec_start(self, exec_id: str, **kwargs: Any) -> Any:
        return self.sock if kwargs.get("socket") else b""

    def exec_inspect(self, exec_id: str) -> dict[str, Any]:
        return {"Running": False, "ExitCode": self.exit_code}


class FakeClient:
    def __init__(self, api: FakeApi) -> None:
        self.api = api


@pytest.fixture
def pair() -> Iterator[tuple[socket.socket, socket.socket]]:
    ours, theirs = socket.socketpair()
    try:
        yield ours, theirs
    finally:
        ours.close()
        theirs.close()


def kill_calls(api: FakeApi) -> list[dict[str, Any]]:
    return [call for call in api.created if "kill" in call["cmd"][2]]


async def test_exec_run_demuxes_streams_and_reports_exit_code(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(frame(1, b"out") + frame(2, b"err"))
    theirs.close()
    api = FakeApi(ours, exit_code=3)

    result = await exec_run(FakeClient(api), "ref", ExecRequest(argv=["x"], timeout_s=5))

    assert (result.exit_code, result.stdout, result.stderr) == (3, b"out", b"err")
    assert result.timed_out is False
    assert result.truncated is False
    assert kill_calls(api) == []


async def test_exec_wraps_argv_with_pid_file_and_passes_options(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.close()
    api = FakeApi(ours)
    request = ExecRequest(argv=["ls", "-l"], cwd="/w", env={"A": "1"}, user="1000", timeout_s=5)

    await exec_run(FakeClient(api), "ref", request)

    call = api.created[0]
    assert call["cmd"][0:2] == ["sh", "-c"]
    assert call["cmd"][6:] == ["ls", "-l"]
    assert call["cmd"][4].endswith(".pid")
    assert call["cmd"][5] == "/w"
    assert "workdir" not in call
    assert (call["environment"], call["user"]) == ({"A": "1"}, "1000")


async def test_exec_command_line_uses_neutral_arg0_and_positional_pid_file_and_cwd(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.close()
    api = FakeApi(ours)
    request = ExecRequest(argv=["ls"], cwd="/w", timeout_s=5)

    await exec_run(FakeClient(api), "ref", request)

    cmd = api.created[0]["cmd"]
    assert cmd[2] == EXEC_WRAPPER
    assert cmd[3] == WRAPPER_ARG0 == "sandfort"
    assert cmd[4].startswith("/tmp/.sf-exec-") and cmd[4].endswith(".pid")
    assert cmd[5:] == ["/w", "ls"]


async def test_exec_without_cwd_passes_empty_cwd_argument_and_no_workdir(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.close()
    api = FakeApi(ours)

    await exec_run(FakeClient(api), "ref", ExecRequest(argv=["ls"], timeout_s=5))

    call = api.created[0]
    assert call["cmd"][5:] == ["", "ls"]
    assert "workdir" not in call


def test_wrapper_text_contains_both_error_messages() -> None:
    assert COMMAND_NOT_FOUND_MESSAGE == "command not found: "
    assert MISSING_CWD_MESSAGE == "working directory does not exist: "
    assert COMMAND_NOT_FOUND_MESSAGE in EXEC_WRAPPER
    assert MISSING_CWD_MESSAGE in EXEC_WRAPPER
    assert "command -v" in EXEC_WRAPPER


def test_wrapper_text_groups_the_pid_redirection_so_its_failure_is_silenced() -> None:
    assert '{ echo $$ > "$f"; } 2>/dev/null' in EXEC_WRAPPER


# --- the wrapper under a real local sh (no docker) -----------------------------------


def run_wrapper(
    tmp_path: Path, cwd: str, argv: list[str]
) -> tuple[subprocess.CompletedProcess[str], Path]:
    pid_file = tmp_path / ".sf-exec-test.pid"
    result = subprocess.run(
        ["/bin/sh", "-c", EXEC_WRAPPER, WRAPPER_ARG0, str(pid_file), cwd, *argv],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return result, pid_file


def test_wrapper_missing_command_prints_message_without_pid_file_path(tmp_path: Path) -> None:
    result, pid_file = run_wrapper(tmp_path, "", ["nosuchcmd"])

    assert result.returncode == 127
    assert result.stderr == "command not found: nosuchcmd\n"
    assert str(pid_file) not in result.stderr
    assert not pid_file.exists()  # removed by the EXIT trap (see test_exec_pid_cleanup_r64)


def test_wrapper_missing_cwd_prints_message_and_exits_127(tmp_path: Path) -> None:
    result, _ = run_wrapper(tmp_path, "/no/such", ["echo", "hi"])

    assert result.returncode == 127
    assert result.stderr == "working directory does not exist: /no/such\n"
    assert result.stdout == ""


def test_wrapper_text_runs_in_the_foreground_keeps_the_status_and_removes_the_pid_file() -> None:
    assert '"$@"; rc=$?; rm -f "$f"; exit "$rc"' in EXEC_WRAPPER
    assert 'exec "$@"' not in EXEC_WRAPPER


def test_wrapper_runs_command_records_pid_and_removes_it_afterwards(tmp_path: Path) -> None:
    pid_file = tmp_path / ".sf-exec-test.pid"
    # The command reads the pid file itself, proving the pid was written before it ran.
    result, _ = run_wrapper(tmp_path, "", ["cat", str(pid_file)])
    echoed, _ = run_wrapper(tmp_path, "", ["echo", "hi"])

    assert result.returncode == 0
    assert result.stdout.strip().isdigit()
    assert (echoed.returncode, echoed.stdout) == (0, "hi\n")
    assert not pid_file.exists()


def test_wrapper_keeps_the_exit_status_and_still_removes_the_pid_file(tmp_path: Path) -> None:
    result, pid_file = run_wrapper(tmp_path, "", ["sh", "-c", "exit 7"])

    assert result.returncode == 7
    assert not pid_file.exists()


def test_wrapper_passes_stdin_through_to_the_command(tmp_path: Path) -> None:
    pid_file = tmp_path / ".sf-exec-test.pid"

    result = subprocess.run(
        ["/bin/sh", "-c", EXEC_WRAPPER, WRAPPER_ARG0, str(pid_file), "", "cat"],
        input="from stdin\n",
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert (result.returncode, result.stdout) == (0, "from stdin\n")
    assert not pid_file.exists()


def test_wrapper_stays_silent_when_the_pid_file_cannot_be_written(tmp_path: Path) -> None:
    # The redirection fails here, as it does on a full disk.
    pid_file = tmp_path / "no-such-dir" / ".sf-exec-test.pid"

    result = subprocess.run(
        ["/bin/sh", "-c", EXEC_WRAPPER, WRAPPER_ARG0, str(pid_file), "", "echo", "hi"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout == "hi\n"
    assert result.stderr == ""


def test_wrapper_runs_command_in_requested_cwd(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()

    result, _ = run_wrapper(tmp_path, str(work), ["pwd"])

    assert result.returncode == 0
    assert Path(result.stdout.strip()).resolve() == work.resolve()


async def test_timeout_kills_process_and_reports_timed_out(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, _theirs = pair
    api = FakeApi(ours, exit_code=137)
    request = ExecRequest(argv=["sleep", "600"], timeout_s=0.3)

    result = await exec_run(FakeClient(api), "ref", request)

    assert result.timed_out is True
    assert result.exit_code == TIMED_OUT_EXIT_CODE
    assert len(kill_calls(api)) == 1
    assert api.created[1]["cmd"][4] == api.created[0]["cmd"][4]  # same pid file


async def test_output_over_cap_is_truncated_and_kills_process(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(frame(1, b"x" * 100))
    api = FakeApi(ours, exit_code=137)
    request = ExecRequest(argv=["yes"], timeout_s=5, max_output_bytes=10)

    result = await exec_run(FakeClient(api), "ref", request)

    assert result.stdout == b"x" * 10
    assert result.truncated is True
    assert result.timed_out is False
    assert result.exit_code == 137
    assert len(kill_calls(api)) == 1


async def test_output_over_cap_adds_the_limit_message_to_stderr(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(frame(1, b"x" * 100))
    api = FakeApi(ours, exit_code=137)
    request = ExecRequest(argv=["yes"], timeout_s=5, max_output_bytes=10)

    result = await exec_run(FakeClient(api), "ref", request)

    assert result.stderr == (
        b"the command was stopped because its output exceeded the limit of 10 bytes"
    )
    assert result.stderr == output_cap_message(10)
    assert (result.exit_code, result.truncated, result.timed_out) == (137, True, False)


async def test_output_cap_message_follows_the_requests_limit_after_the_command_stderr(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(frame(2, b"err\n") + frame(1, b"x" * 100))
    request = ExecRequest(argv=["yes"], timeout_s=5, max_output_bytes=50)

    result = await exec_run(FakeClient(FakeApi(ours, exit_code=137)), "ref", request)

    assert result.stderr == b"err\n" + output_cap_message(50)
    assert result.stderr.endswith(b"exceeded the limit of 50 bytes")


async def test_no_limit_message_when_the_output_stays_within_the_cap(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(frame(1, b"x" * 10))
    theirs.close()
    request = ExecRequest(argv=["x"], timeout_s=5, max_output_bytes=10)

    result = await exec_run(FakeClient(FakeApi(ours)), "ref", request)

    assert (result.truncated, result.stderr) == (False, b"")


async def test_timeout_adds_the_timeout_line_and_no_limit_message(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, _theirs = pair
    request = ExecRequest(argv=["sleep", "600"], timeout_s=0.3)

    result = await exec_run(FakeClient(FakeApi(ours, exit_code=137)), "ref", request)

    assert (result.timed_out, result.exit_code) == (True, TIMED_OUT_EXIT_CODE)
    assert result.stderr == (
        b"the command was stopped after 0.3 s (timeout); allow more time, up to 3600 s"
    )
    assert result.stderr == timeout_message(0.3)
    assert b"exceeded the limit" not in result.stderr


async def test_timeout_line_follows_the_command_stderr(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(frame(2, b"working\n"))
    request = ExecRequest(argv=["sleep", "600"], timeout_s=0.3)

    result = await exec_run(FakeClient(FakeApi(ours, exit_code=137)), "ref", request)

    assert result.stderr == b"working\n" + timeout_message(0.3)


async def test_timeout_note_starts_on_its_own_line_after_unterminated_stderr(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(frame(2, b"nonl"))
    request = ExecRequest(argv=["sleep", "600"], timeout_s=0.3)

    result = await exec_run(FakeClient(FakeApi(ours, exit_code=137)), "ref", request)

    assert result.stderr == b"nonl\n" + timeout_message(0.3)


def test_timeout_message_prints_whole_seconds_without_a_fraction() -> None:
    assert TIMEOUT_MESSAGE_TEMPLATE.format(timeout_s=60.0) == (
        "the command was stopped after 60 s (timeout); allow more time, up to 3600 s"
    )
    assert timeout_message(5) == (
        b"the command was stopped after 5 s (timeout); allow more time, up to 3600 s"
    )


def test_timeout_message_names_the_api_maximum_timeout() -> None:
    from sandfort.api.schemas.toolbox_process import MAX_TIMEOUT_S

    assert f"up to {MAX_TIMEOUT_S} s" in TIMEOUT_MESSAGE_TEMPLATE


async def test_no_timeout_line_when_the_command_finishes_in_time(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(frame(2, b"err\n"))
    theirs.close()
    request = ExecRequest(argv=["x"], timeout_s=5)

    result = await exec_run(FakeClient(FakeApi(ours, exit_code=1)), "ref", request)

    assert (result.timed_out, result.stderr) == (False, b"err\n")


async def test_stream_ends_with_exactly_one_exit_event(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(frame(1, b"a") + frame(2, b"b"))
    theirs.close()
    client = FakeClient(FakeApi(ours))

    events = [event async for event in exec_stream(client, "ref", ExecRequest(argv=["x"]))]

    assert events[:2] == [OutputChunk(STDOUT, b"a"), OutputChunk(STDERR, b"b")]
    assert isinstance(events[-1], ExitEvent)
    assert sum(isinstance(event, ExitEvent) for event in events) == 1


# --- gVisor sandbox death -------------------------------------------------------------

GVISOR_SANDBOX_ID = "ab" * 32
GVISOR_DEATH = (
    f'waiting on pid 2: waiting on PID 2 in sandbox "{GVISOR_SANDBOX_ID}": '
    'urpc method "containerManager.WaitPID" failed: EOF\n'
).encode()
CLEAN_MESSAGE = (
    b"the sandbox stopped while running this command "
    b"(a resource limit was hit or its main process ended); start it again"
)


async def test_gvisor_sandbox_death_becomes_the_clean_message_with_exit_137(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(frame(1, b"partial\n") + frame(1, GVISOR_DEATH))
    theirs.close()
    api = FakeApi(ours, exit_code=128)

    result = await exec_run(FakeClient(api), "ref", ExecRequest(argv=["x"], timeout_s=5))

    assert SANDBOX_DIED_MESSAGE == CLEAN_MESSAGE
    assert SANDBOX_DIED_EXIT_CODE == 137
    assert (result.exit_code, result.stdout, result.stderr) == (137, b"partial\n", CLEAN_MESSAGE)
    assert GVISOR_SANDBOX_ID.encode() not in result.stdout + result.stderr
    assert (result.timed_out, result.truncated) == (False, False)
    assert result.sandbox_stopped is True


async def test_gvisor_sandbox_death_is_rewritten_on_the_streamed_path(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(frame(2, GVISOR_DEATH) + frame(2, GVISOR_DEATH))
    theirs.close()
    client = FakeClient(FakeApi(ours, exit_code=128))

    events = [event async for event in exec_stream(client, "ref", ExecRequest(argv=["x"]))]

    assert events == [OutputChunk(STDERR, CLEAN_MESSAGE), ExitEvent(137, sandbox_stopped=True)]


def test_rewrite_keeps_lines_before_the_report_and_matches_the_short_form() -> None:
    short = b'out\nwaiting on PID 2 in sandbox "abc": EOF\n'

    chunks, died = rewrite_sandbox_death(STDOUT, short, reported=False)

    assert died is True
    assert chunks == [OutputChunk(STDOUT, b"out\n"), OutputChunk(STDERR, CLEAN_MESSAGE)]


@pytest.mark.parametrize(
    "data",
    [b"hello\n", b"waiting on PID 7\n", b"in sandbox\nwaiting on PID 2\n", b"\x00\xff"],
)
def test_rewrite_passes_ordinary_output_through_unchanged(data: bytes) -> None:
    assert rewrite_sandbox_death(STDOUT, data, reported=False) == (
        [OutputChunk(STDOUT, data)],
        False,
    )
    assert rewrite_sandbox_death(STDERR, b"", reported=False) == ([], False)


async def test_ordinary_output_and_exit_codes_are_untouched(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(frame(1, b"waiting on PID 2\n") + frame(2, b"err"))
    theirs.close()
    api = FakeApi(ours, exit_code=128)

    result = await exec_run(FakeClient(api), "ref", ExecRequest(argv=["x"], timeout_s=5))

    assert (result.exit_code, result.stdout, result.stderr) == (128, b"waiting on PID 2\n", b"err")
    assert result.sandbox_stopped is False


async def test_plain_exit_137_without_the_marker_does_not_report_a_stopped_sandbox(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(frame(2, b"Killed\n"))
    theirs.close()
    api = FakeApi(ours, exit_code=137)  # e.g. a container-tier OOM kill: no gVisor marker

    result = await exec_run(FakeClient(api), "ref", ExecRequest(argv=["x"], timeout_s=5))

    assert (result.exit_code, result.stderr) == (137, b"Killed\n")
    assert result.sandbox_stopped is False


async def test_plain_exit_137_stream_event_is_not_flagged(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.close()
    client = FakeClient(FakeApi(ours, exit_code=137))

    events = [event async for event in exec_stream(client, "ref", ExecRequest(argv=["x"]))]

    assert events == [ExitEvent(137)]
    assert ExitEvent(137).sandbox_stopped is False


async def test_timeout_does_not_report_a_stopped_sandbox(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, _theirs = pair
    request = ExecRequest(argv=["sleep", "600"], timeout_s=0.3)

    result = await exec_run(FakeClient(FakeApi(ours, exit_code=137)), "ref", request)

    assert result.timed_out is True
    assert result.sandbox_stopped is False


async def test_a_death_report_wins_over_the_deadline(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(frame(2, GVISOR_DEATH))  # the stream stays open, so the deadline is hit
    request = ExecRequest(argv=["fork-bomb"], timeout_s=0.3)

    result = await exec_run(FakeClient(FakeApi(ours, exit_code=137)), "ref", request)

    assert result.stderr == CLEAN_MESSAGE
    assert (result.exit_code, result.timed_out, result.sandbox_stopped) == (137, False, True)


async def test_a_death_report_wins_over_the_deadline_on_the_streamed_path(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(frame(2, GVISOR_DEATH))
    client = FakeClient(FakeApi(ours, exit_code=137))
    request = ExecRequest(argv=["fork-bomb"], timeout_s=0.3)

    events = [event async for event in exec_stream(client, "ref", request)]

    assert events == [
        OutputChunk(STDERR, CLEAN_MESSAGE),
        ExitEvent(137, timed_out=False, sandbox_stopped=True),
    ]


async def test_a_plain_timeout_with_ordinary_output_stays_a_timeout(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(frame(1, b"still running\n"))
    request = ExecRequest(argv=["sleep", "600"], timeout_s=0.3)

    result = await exec_run(FakeClient(FakeApi(ours, exit_code=137)), "ref", request)

    assert result.stdout == b"still running\n"
    assert (result.exit_code, result.timed_out, result.sandbox_stopped) == (124, True, False)


# --- Kata (microvm) guest death -------------------------------------------------------

KATA_DEATH = (
    b'Others("failed to handle message handler TaskRequest\n\nCaused by:\n'
    b"    0: start process\n    1: start\n    2: enter process\n    3: exec process\n"
    b"    4: socket err: early eof\n\nStack backtrace:\n"
    b"   0: <anyhow::Error as core::convert::From<ttrpc::error::Error>>::from\n"
)
KATA_BACKTRACE_TAIL = b'   1: containerd_shim_kata_v2::task_service::handler\n")'


def assert_no_shim_text(data: bytes) -> None:
    for fragment in (b"TaskRequest", b"ttrpc", b"early eof", b"backtrace", b"anyhow", b"shim"):
        assert fragment not in data


@pytest.mark.parametrize("kind", [1, 2])
async def test_kata_shim_report_becomes_the_clean_message_with_exit_137(
    pair: tuple[socket.socket, socket.socket], kind: int
) -> None:
    ours, theirs = pair
    theirs.sendall(frame(kind, b"partial\n") + frame(kind, KATA_DEATH))
    theirs.sendall(frame(kind, KATA_BACKTRACE_TAIL))
    theirs.close()
    api = FakeApi(ours, exit_code=128)

    result = await exec_run(FakeClient(api), "ref", ExecRequest(argv=["x"], timeout_s=5))

    kept_out, kept_err = (b"partial\n", b"") if kind == 1 else (b"", b"partial\n")
    assert (result.exit_code, result.stdout, result.stderr) == (
        137,
        kept_out,
        kept_err + CLEAN_MESSAGE,
    )
    assert_no_shim_text(result.stdout + result.stderr)
    assert result.sandbox_stopped is True
    assert (result.timed_out, result.truncated) == (False, False)


async def test_kata_shim_report_is_rewritten_on_the_streamed_path(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(frame(1, KATA_DEATH) + frame(2, KATA_BACKTRACE_TAIL))
    theirs.close()
    client = FakeClient(FakeApi(ours, exit_code=128))

    events = [event async for event in exec_stream(client, "ref", ExecRequest(argv=["x"]))]

    assert events == [OutputChunk(STDERR, CLEAN_MESSAGE), ExitEvent(137, sandbox_stopped=True)]


def test_rewrite_matches_the_kata_ttrpc_and_early_eof_pair() -> None:
    data = b"out\nsocket err: early eof (ttrpc::error::Error)\nmore\n"

    chunks, died = rewrite_sandbox_death(STDERR, data, reported=False)

    assert died is True
    assert chunks == [OutputChunk(STDERR, b"out\n"), OutputChunk(STDERR, CLEAN_MESSAGE)]


@pytest.mark.parametrize(
    "data",
    [b"ttrpc client ready\n", b"read: early eof\n", b"failed to handle message\n"],
)
def test_rewrite_passes_partial_kata_words_through_unchanged(data: bytes) -> None:
    assert rewrite_sandbox_death(STDOUT, data, reported=False) == (
        [OutputChunk(STDOUT, data)],
        False,
    )


class GoneExecApi(FakeApi):
    """The daemon forgot the exec while its result was awaited (a dead Kata guest)."""

    def __init__(self, sock: socket.socket, message: str | DriverNotFound) -> None:
        super().__init__(sock)
        self.message = message

    def exec_inspect(self, exec_id: str) -> dict[str, Any]:
        if isinstance(self.message, DriverNotFound):
            raise self.message
        raise DriverNotFound(self.message, ref="ref")


EXEC_GONE = "No such exec instance: the sandbox container"
REAL_EXEC_ID = "0123456789abcdef" * 4


@pytest.mark.parametrize(
    "raw",
    [
        f"No such exec instance: {REAL_EXEC_ID}",
        f"No such exec instance '{REAL_EXEC_ID}' found in daemon",
    ],
)
async def test_a_real_daemon_exec_id_is_still_a_stopped_sandbox(
    pair: tuple[socket.socket, socket.socket], raw: str
) -> None:
    from sandfort.drivers.docker.client import as_driver_error
    from test_docker_driver_unit import daemon_error

    errors = pytest.importorskip("docker.errors")
    ours, theirs = pair
    theirs.close()
    mapped = as_driver_error(daemon_error(errors.NotFound, 404, raw), ref="ref")
    assert isinstance(mapped, DriverNotFound)
    assert REAL_EXEC_ID not in mapped.message

    result = await exec_run(
        FakeClient(GoneExecApi(ours, mapped)), "ref", ExecRequest(argv=["x"], timeout_s=5)
    )

    assert (result.exit_code, result.sandbox_stopped) == (137, True)


async def test_exec_gone_is_read_from_the_daemon_text_when_the_message_is_fixed(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.close()
    error = DriverNotFound(
        "the object does not exist", ref="ref", daemon_text="No such exec instance: abc"
    )

    result = await exec_run(
        FakeClient(GoneExecApi(ours, error)), "ref", ExecRequest(argv=["x"], timeout_s=5)
    )

    assert (result.exit_code, result.sandbox_stopped) == (137, True)


async def test_exec_instance_gone_while_waiting_is_a_stopped_sandbox(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(frame(1, b"partial\n"))
    theirs.close()
    api = GoneExecApi(ours, EXEC_GONE)

    result = await exec_run(FakeClient(api), "ref", ExecRequest(argv=["x"], timeout_s=5))

    assert (result.exit_code, result.stdout, result.stderr) == (137, b"partial\n", CLEAN_MESSAGE)
    assert result.sandbox_stopped is True
    assert (result.timed_out, result.truncated) == (False, False)
    assert kill_calls(api) == []


async def test_exec_instance_gone_after_a_kata_report_gives_one_message(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(frame(1, KATA_DEATH))
    theirs.close()
    client = FakeClient(GoneExecApi(ours, EXEC_GONE))

    events = [event async for event in exec_stream(client, "ref", ExecRequest(argv=["x"]))]

    assert events == [OutputChunk(STDERR, CLEAN_MESSAGE), ExitEvent(137, sandbox_stopped=True)]


async def test_unrelated_not_found_while_waiting_still_raises(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.close()
    api = GoneExecApi(ours, "No such container: the sandbox container")

    with pytest.raises(DriverNotFound, match="No such container"):
        await exec_run(FakeClient(api), "ref", ExecRequest(argv=["x"], timeout_s=5))


async def test_ordinary_exit_128_is_unchanged(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(frame(1, b"out\n") + frame(2, b"fatal: ttrpc handshake\n"))
    theirs.close()
    api = FakeApi(ours, exit_code=128)

    result = await exec_run(FakeClient(api), "ref", ExecRequest(argv=["x"], timeout_s=5))

    assert (result.exit_code, result.stdout, result.stderr) == (
        128,
        b"out\n",
        b"fatal: ttrpc handshake\n",
    )
    assert result.sandbox_stopped is False


# --- silent guest death: the container state decides --------------------------------------


class InspectApi(FakeApi):
    """A fake whose container inspect reports a runtime and a running flag (or raises)."""

    def __init__(
        self,
        sock: socket.socket,
        exit_code: int,
        runtime: str,
        running: bool,
        error: Exception | None = None,
    ) -> None:
        super().__init__(sock, exit_code)
        self.attrs = {"HostConfig": {"Runtime": runtime}, "State": {"Running": running}}
        self.error = error
        self.inspected: list[str] = []

    def inspect_container(self, ref: str) -> dict[str, Any]:
        self.inspected.append(ref)
        if self.error is not None:
            raise self.error
        return self.attrs


async def run_silent_exit(
    pair: tuple[socket.socket, socket.socket],
    exit_code: int,
    runtime: str,
    running: bool,
    error: Exception | None = None,
) -> tuple[Any, InspectApi]:
    ours, theirs = pair
    theirs.close()
    api = InspectApi(ours, exit_code, runtime, running, error)
    result = await exec_run(FakeClient(api), "ref", ExecRequest(argv=["x"], timeout_s=5))
    return result, api


def test_suspect_exit_codes_are_128_137_and_255() -> None:
    assert SUSPECT_DEATH_EXIT_CODES == frozenset({128, 137, 255})


@pytest.mark.parametrize("runtime", ["kata", "kata-qemu", "runsc"])
@pytest.mark.parametrize("exit_code", [128, 137, 255])
async def test_silent_exit_on_a_stopped_own_kernel_container_is_the_dead_sandbox_result(
    pair: tuple[socket.socket, socket.socket], runtime: str, exit_code: int
) -> None:
    result, api = await run_silent_exit(pair, exit_code, runtime, running=False)

    assert (result.exit_code, result.stdout, result.stderr) == (137, b"", CLEAN_MESSAGE)
    assert result.sandbox_stopped is True
    assert (result.timed_out, result.truncated) == (False, False)
    assert api.inspected == ["ref"]


async def test_silent_death_is_reported_on_the_streamed_path(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.close()
    client = FakeClient(InspectApi(ours, 255, "kata", running=False))

    events = [event async for event in exec_stream(client, "ref", ExecRequest(argv=["x"]))]

    assert events == [OutputChunk(STDERR, CLEAN_MESSAGE), ExitEvent(137, sandbox_stopped=True)]


async def test_silent_exit_255_on_a_running_kata_container_is_unchanged(
    pair: tuple[socket.socket, socket.socket], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exec_module, "_poll_sleep", lambda _seconds: None)

    result, api = await run_silent_exit(pair, 255, "kata", running=True)

    assert (result.exit_code, result.stdout, result.stderr) == (255, b"", b"")
    assert result.sandbox_stopped is False
    assert set(api.inspected) == {"ref"}


@pytest.mark.parametrize("runtime", ["runc", ""])
async def test_silent_exit_255_on_a_runc_container_is_unchanged(
    pair: tuple[socket.socket, socket.socket], runtime: str
) -> None:
    result, _api = await run_silent_exit(pair, 255, runtime, running=False)

    assert (result.exit_code, result.stdout, result.stderr) == (255, b"", b"")
    assert result.sandbox_stopped is False


async def test_an_inspection_error_leaves_the_result_unchanged(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    error = RuntimeError("daemon went away")

    result, api = await run_silent_exit(pair, 255, "kata", running=False, error=error)

    assert (result.exit_code, result.stdout, result.stderr) == (255, b"", b"")
    assert result.sandbox_stopped is False
    assert api.inspected == ["ref"]


async def test_a_client_without_inspect_leaves_the_result_unchanged(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.close()

    result = await exec_run(
        FakeClient(FakeApi(ours, exit_code=255)), "ref", ExecRequest(argv=["x"], timeout_s=5)
    )

    assert (result.exit_code, result.sandbox_stopped) == (255, False)


@pytest.mark.parametrize("exit_code", [0, 1, 2, 127, 130, 139])
async def test_other_exit_codes_never_inspect_the_container(
    pair: tuple[socket.socket, socket.socket], exit_code: int
) -> None:
    result, api = await run_silent_exit(pair, exit_code, "kata", running=False)

    assert (result.exit_code, result.sandbox_stopped) == (exit_code, False)
    assert api.inspected == []


async def test_an_already_reported_death_does_not_inspect_the_container(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(frame(1, KATA_DEATH))
    theirs.close()
    api = InspectApi(ours, 128, "kata", running=False)

    result = await exec_run(FakeClient(api), "ref", ExecRequest(argv=["x"], timeout_s=5))

    assert (result.exit_code, result.stderr) == (137, CLEAN_MESSAGE)
    assert result.sandbox_stopped is True
    assert api.inspected == []


class SequenceApi(InspectApi):
    """Reports the given ``Running`` values on successive inspects; the last one repeats."""

    def __init__(self, sock: socket.socket, exit_code: int, runtime: str, seq: list[bool]) -> None:
        super().__init__(sock, exit_code, runtime, running=seq[0])
        self.seq = seq

    def inspect_container(self, ref: str) -> dict[str, Any]:
        index = min(len(self.inspected), len(self.seq) - 1)
        self.attrs["State"] = {"Running": self.seq[index]}
        return super().inspect_container(ref)


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Replace the poll sleep with a recorder, so the poll window costs no real time."""
    recorded: list[float] = []
    monkeypatch.setattr(exec_module, "_poll_sleep", recorded.append)
    return recorded


def test_the_poll_window_is_three_seconds_in_quarter_second_steps() -> None:
    assert (DEATH_POLL_INTERVAL_S, DEATH_POLL_WINDOW_S) == (0.25, 3.0)


@pytest.mark.parametrize("runtime", ["kata", "kata-qemu", "runsc"])
async def test_a_timeout_on_a_running_vm_container_is_inspected_once_without_sleeping(
    pair: tuple[socket.socket, socket.socket], sleeps: list[float], runtime: str
) -> None:
    ours, _theirs = pair
    api = SequenceApi(ours, 137, runtime, [True])

    result = await exec_run(
        FakeClient(api), "ref", ExecRequest(argv=["sleep", "600"], timeout_s=0.3)
    )

    assert (result.exit_code, result.timed_out, result.sandbox_stopped) == (124, True, False)
    assert (len(api.inspected), sleeps) == (1, [])


@pytest.mark.parametrize("exit_code", sorted(SUSPECT_DEATH_EXIT_CODES))
async def test_a_suspect_exit_code_on_a_running_vm_still_polls_the_whole_window(
    pair: tuple[socket.socket, socket.socket], sleeps: list[float], exit_code: int
) -> None:
    ours, theirs = pair
    theirs.close()
    api = SequenceApi(ours, exit_code, "runsc", [True])

    result = await exec_run(FakeClient(api), "ref", ExecRequest(argv=["x"], timeout_s=5))

    assert (result.sandbox_stopped, result.timed_out) == (False, False)
    assert sum(sleeps) == DEATH_POLL_WINDOW_S
    assert len(api.inspected) == 1 + len(sleeps)


async def test_a_timeout_on_a_stopped_runc_container_is_inspected_once_and_stays_a_timeout(
    pair: tuple[socket.socket, socket.socket], sleeps: list[float]
) -> None:
    ours, _theirs = pair
    api = SequenceApi(ours, 137, "runc", [False])

    result = await exec_run(
        FakeClient(api), "ref", ExecRequest(argv=["sleep", "600"], timeout_s=0.3)
    )

    assert (result.exit_code, result.timed_out, result.sandbox_stopped) == (124, True, False)
    assert (len(api.inspected), sleeps) == (1, [])


@pytest.mark.parametrize("runtime", ["kata", "kata-qemu", "runsc"])
async def test_exit_255_on_a_vm_that_stops_by_the_third_inspect_is_the_dead_sandbox_result(
    pair: tuple[socket.socket, socket.socket], sleeps: list[float], runtime: str
) -> None:
    ours, theirs = pair
    theirs.close()
    api = SequenceApi(ours, 255, runtime, [True, True, False])

    result = await exec_run(FakeClient(api), "ref", ExecRequest(argv=["x"], timeout_s=5))

    assert (result.exit_code, result.stdout, result.stderr) == (137, b"", CLEAN_MESSAGE)
    assert (result.sandbox_stopped, result.timed_out) == (True, False)
    assert (len(api.inspected), sleeps) == (3, [0.25, 0.25])


async def test_a_timeout_does_not_wait_for_a_vm_that_would_stop_on_a_later_inspect(
    pair: tuple[socket.socket, socket.socket], sleeps: list[float]
) -> None:
    ours, _theirs = pair
    api = SequenceApi(ours, 137, "kata", [True, True, False])

    result = await exec_run(
        FakeClient(api), "ref", ExecRequest(argv=["sleep", "600"], timeout_s=0.3)
    )

    assert (result.exit_code, result.timed_out, result.sandbox_stopped) == (124, True, False)
    assert (len(api.inspected), sleeps) == (1, [])


async def test_a_timeout_on_a_stopped_vm_is_the_dead_sandbox_result_without_polling(
    pair: tuple[socket.socket, socket.socket], sleeps: list[float]
) -> None:
    ours, _theirs = pair
    api = SequenceApi(ours, 137, "runsc", [False])

    result = await exec_run(
        FakeClient(api), "ref", ExecRequest(argv=["sleep", "600"], timeout_s=0.3)
    )

    assert (result.exit_code, result.sandbox_stopped, result.timed_out) == (137, True, False)
    assert (len(api.inspected), sleeps) == (1, [])


async def test_a_vm_that_stays_running_is_polled_for_the_whole_window_and_not_dead(
    pair: tuple[socket.socket, socket.socket], sleeps: list[float]
) -> None:
    ours, theirs = pair
    theirs.close()
    api = SequenceApi(ours, 255, "kata", [True])

    result = await exec_run(FakeClient(api), "ref", ExecRequest(argv=["x"], timeout_s=5))

    assert (result.exit_code, result.stdout, result.stderr) == (255, b"", b"")
    assert result.sandbox_stopped is False
    assert sum(sleeps) == DEATH_POLL_WINDOW_S
    assert set(sleeps) == {DEATH_POLL_INTERVAL_S}
    assert len(api.inspected) == 1 + len(sleeps)


async def test_a_runc_container_with_exit_137_is_inspected_once_and_never_polled(
    pair: tuple[socket.socket, socket.socket], sleeps: list[float]
) -> None:
    ours, theirs = pair
    theirs.close()
    api = SequenceApi(ours, 137, "runc", [True])

    result = await exec_run(FakeClient(api), "ref", ExecRequest(argv=["x"], timeout_s=5))

    assert (result.exit_code, result.sandbox_stopped) == (137, False)
    assert (len(api.inspected), sleeps) == (1, [])


async def test_exit_0_never_inspects_or_polls(
    pair: tuple[socket.socket, socket.socket], sleeps: list[float]
) -> None:
    ours, theirs = pair
    theirs.close()
    api = SequenceApi(ours, 0, "kata", [True])

    result = await exec_run(FakeClient(api), "ref", ExecRequest(argv=["x"], timeout_s=5))

    assert (result.exit_code, result.sandbox_stopped) == (0, False)
    assert (api.inspected, sleeps) == ([], [])


@pytest.mark.parametrize("timeout_s", [5, 0.3])
async def test_an_inspection_error_answers_not_dead_without_polling(
    pair: tuple[socket.socket, socket.socket], sleeps: list[float], timeout_s: float
) -> None:
    ours, theirs = pair
    if timeout_s == 5:
        theirs.close()
    api = InspectApi(ours, 255, "kata", running=True, error=RuntimeError("daemon went away"))

    result = await exec_run(FakeClient(api), "ref", ExecRequest(argv=["x"], timeout_s=timeout_s))

    assert result.sandbox_stopped is False
    # no death message; a timed-out run carries only the timeout line
    assert result.stderr == (timeout_message(timeout_s) if result.timed_out else b"")
    assert (api.inspected, sleeps) == (["ref"], [])


class FlakyApi(SequenceApi):
    """The first inspect works; the second one (during the poll) raises."""

    def inspect_container(self, ref: str) -> dict[str, Any]:
        if len(self.inspected) == 1:
            self.inspected.append(ref)
            raise RuntimeError("daemon went away")
        return super().inspect_container(ref)


async def test_an_inspection_error_during_the_poll_answers_not_dead(
    pair: tuple[socket.socket, socket.socket], sleeps: list[float]
) -> None:
    ours, theirs = pair
    theirs.close()
    api = FlakyApi(ours, 255, "kata", [True])

    result = await exec_run(FakeClient(api), "ref", ExecRequest(argv=["x"], timeout_s=5))

    assert (result.exit_code, result.sandbox_stopped, result.stderr) == (255, False, b"")
    assert (len(api.inspected), len(sleeps)) == (2, 1)


async def test_empty_argv_is_rejected(pair: tuple[socket.socket, socket.socket]) -> None:
    with pytest.raises(DriverError):
        await exec_run(FakeClient(FakeApi(pair[0])), "ref", ExecRequest(argv=[]))
