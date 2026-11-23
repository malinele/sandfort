"""R64: the exec pid file is removed on every exit path of the sandbox-side wrapper."""

import socket
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from tests.test_docker_exec import client, remove_all, start_sandbox  # noqa: F401
from tests.test_docker_exec_unit import FakeApi, FakeClient, kill_calls

from sandfort.drivers.base import ExecRequest
from sandfort.drivers.docker import exec as exec_module
from sandfort.drivers.docker.driver import DockerDriver
from sandfort.drivers.docker.exec import EXEC_WRAPPER, WRAPPER_ARG0, exec_run, exec_stream

TRAP = "trap 'rm -f \"$f\"' EXIT"
SHELL_TIMEOUT_S = 30
# Lists pid files other than the listing exec's own (its wrapper is this shell's parent).
OTHER_PID_FILES = (
    'for f in /tmp/.sf-exec-*.pid; do [ -e "$f" ] || continue; '
    '[ "$(cat "$f")" = "$PPID" ] || echo "$f"; done'
)


@pytest.fixture
def pair() -> Iterator[tuple[socket.socket, socket.socket]]:
    ours, theirs = socket.socketpair()
    try:
        yield ours, theirs
    finally:
        ours.close()
        theirs.close()


@pytest.fixture
def driver(client: Any) -> DockerDriver:  # noqa: F811
    from sandfort.config import Settings

    return DockerDriver(Settings(), client=client)


def run_wrapper(tmp_path: Path, cwd: str, argv: list[str]) -> tuple[int, Path]:
    pid_file = tmp_path / ".sf-exec-test.pid"
    result = subprocess.run(
        ["/bin/sh", "-c", EXEC_WRAPPER, WRAPPER_ARG0, str(pid_file), cwd, *argv],
        capture_output=True,
        text=True,
        timeout=SHELL_TIMEOUT_S,
        check=False,
    )
    return result.returncode, pid_file


# --- the wrapper text: the trap is armed right after the pid is written ----------------


def test_wrapper_arms_an_exit_trap_before_any_check_can_fail() -> None:
    pid_written = EXEC_WRAPPER.index('echo $$ > "$f"')
    trap = EXEC_WRAPPER.index(TRAP)
    first_check = EXEC_WRAPPER.index("if [ -n")

    assert pid_written < trap < first_check


def test_wrapper_keeps_its_exit_status_handling() -> None:
    assert '"$@"; rc=$?; rm -f "$f"; exit "$rc"' in EXEC_WRAPPER


# --- the wrapper under a real local sh: every exit path leaves no file -----------------


def test_command_not_found_removes_the_pid_file_and_exits_127(tmp_path: Path) -> None:
    code, pid_file = run_wrapper(tmp_path, "", ["nosuchcmd"])

    assert code == 127
    assert not pid_file.exists()


def test_missing_cwd_removes_the_pid_file_and_exits_127(tmp_path: Path) -> None:
    code, pid_file = run_wrapper(tmp_path, "/no/such", ["echo", "hi"])

    assert code == 127
    assert not pid_file.exists()


def test_normal_and_failing_exits_remove_the_pid_file(tmp_path: Path) -> None:
    ok_code, ok_file = run_wrapper(tmp_path, "", ["true"])
    bad_code, bad_file = run_wrapper(tmp_path, "", ["sh", "-c", "exit 7"])

    assert (ok_code, bad_code) == (0, 7)
    assert not ok_file.exists() and not bad_file.exists()


def test_a_command_ended_by_a_signal_keeps_its_status_and_removes_the_file(
    tmp_path: Path,
) -> None:
    code, pid_file = run_wrapper(tmp_path, "", ["sh", "-c", "kill -TERM $$"])

    assert code == 143
    assert not pid_file.exists()


def test_the_pid_is_still_recorded_while_the_command_runs(tmp_path: Path) -> None:
    pid_file = tmp_path / ".sf-exec-test.pid"
    result = subprocess.run(
        ["/bin/sh", "-c", EXEC_WRAPPER, WRAPPER_ARG0, str(pid_file), "", "cat", str(pid_file)],
        capture_output=True,
        text=True,
        timeout=SHELL_TIMEOUT_S,
        check=False,
    )

    assert result.stdout.strip().isdigit()
    assert not pid_file.exists()


# --- kill, timeout and disconnect: the kill exec removes the file ----------------------


def run_kill_script(pid_file: Path) -> None:
    subprocess.run(
        ["sh", "-c", exec_module._KILL_SCRIPT, "sh", str(pid_file)],
        capture_output=True,
        timeout=SHELL_TIMEOUT_S,
        check=False,
    )


def test_kill_script_removes_the_file_of_a_wrapper_that_already_exited(tmp_path: Path) -> None:
    pid_file = tmp_path / ".sf-exec-gone.pid"
    pid_file.write_text("999999\n")  # no such process

    run_kill_script(pid_file)

    assert not pid_file.exists()


def test_kill_script_removes_an_empty_pid_file(tmp_path: Path) -> None:
    pid_file = tmp_path / ".sf-exec-empty.pid"
    pid_file.write_text("")

    run_kill_script(pid_file)

    assert not pid_file.exists()


def test_kill_script_removes_the_file_before_it_kills() -> None:
    script = exec_module._KILL_SCRIPT

    assert script.index('rm -f "$f"') < script.index('k "$p"')


async def test_timeout_runs_a_kill_exec_on_the_same_pid_file(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, _theirs = pair
    api = FakeApi(ours, exit_code=137)

    await exec_run(FakeClient(api), "ref", ExecRequest(argv=["sleep", "600"], timeout_s=0.3))

    (kill,) = kill_calls(api)
    assert kill["cmd"][2] == exec_module._KILL_SCRIPT
    assert 'rm -f "$f"' in kill["cmd"][2]
    assert kill["cmd"][4] == api.created[0]["cmd"][4]


async def test_output_cap_runs_a_kill_exec_on_the_same_pid_file(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(b"\x01\x00\x00\x00\x00\x00\x00\x64" + b"x" * 100)
    api = FakeApi(ours, exit_code=137)

    await exec_run(
        FakeClient(api), "ref", ExecRequest(argv=["yes"], timeout_s=5, max_output_bytes=10)
    )

    (kill,) = kill_calls(api)
    assert kill["cmd"][4] == api.created[0]["cmd"][4]


async def test_client_disconnect_runs_a_kill_exec_on_the_same_pid_file(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.sendall(b"\x01\x00\x00\x00\x00\x00\x00\x02hi")
    api = FakeApi(ours)
    stream = exec_stream(FakeClient(api), "ref", ExecRequest(argv=["x"], timeout_s=30))

    await anext(stream)
    await stream.aclose()  # the consumer abandons the iterator

    (kill,) = kill_calls(api)
    assert kill["cmd"][4] == api.created[0]["cmd"][4]


async def test_normal_exit_needs_no_extra_round_trip(
    pair: tuple[socket.socket, socket.socket],
) -> None:
    ours, theirs = pair
    theirs.close()
    api = FakeApi(ours, exit_code=127)

    await exec_run(FakeClient(api), "ref", ExecRequest(argv=["nosuchcmd"], timeout_s=5))

    assert len(api.created) == 1  # no kill or cleanup exec when the wrapper cleans up itself
    assert TRAP in api.created[0]["cmd"][2]


# --- real daemon ------------------------------------------------------------------------


@pytest.mark.docker
async def test_missing_command_leaves_no_exec_pid_file_in_the_sandbox(
    client: Any,  # noqa: F811
    driver: DockerDriver,
) -> None:
    created: list[str] = []
    try:
        ref = await start_sandbox(driver, created)

        missing = await driver.exec(ref, ExecRequest(argv=["nosuchcmd"], timeout_s=10))
        listing = await driver.exec(ref, ExecRequest(argv=["sh", "-c", OTHER_PID_FILES]))

        assert missing.exit_code == 127
        assert listing.stdout.decode().strip() == ""
    finally:
        remove_all(client, created)
