"""R64: a PTY session's pid file is removed from the host side when the session closes.

The PTY wrapper ends in ``exec``, so it cannot trap its own exit. ``close`` therefore removes
the file itself: the kill exec already does it for a live process, a plain ``rm`` exec covers
a session whose process ended on its own. The unit tests run those execs on a local ``sh``
against a temporary pid file, so a passing test means the file is really gone.
"""

import asyncio
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from tests.test_docker_exec import client, remove_all, start_sandbox  # noqa: F401

from sandfort.config import Settings
from sandfort.drivers.base import ExecRequest, PtySessionHandle
from sandfort.drivers.docker import exec as exec_module
from sandfort.drivers.docker import pty as pty_module
from sandfort.drivers.docker.driver import DockerDriver
from sandfort.drivers.errors import DriverError

SHELL_TIMEOUT_S = 30
DEAD_PID = 2**31 - 2  # no such process, so the kill script only has to remove the file
# Lists pid files of both kinds, except the listing exec's own (its wrapper is the parent).
LEFTOVER_PID_FILES = (
    'for f in /tmp/.sf-pty-*.pid /tmp/.sf-exec-*.pid; do [ -e "$f" ] || continue; '
    '[ "$(cat "$f")" = "$PPID" ] || echo "$f"; done'
)
CLEANUP_WAIT_S = 10.0
CLEANUP_POLL_S = 0.1


class LocalApi:
    """A docker api whose execs run on the local ``sh``: the sandbox is the host's tmp dir."""

    def __init__(self, sock: socket.socket, *, running: bool, fail_exec: bool = False) -> None:
        self.sock = sock
        self.running = running
        self.fail_exec = fail_exec
        self.created: list[dict[str, Any]] = []

    def exec_create(self, container: str, **kwargs: Any) -> dict[str, str]:
        if self.fail_exec and not kwargs.get("tty"):
            raise RuntimeError("daemon unreachable")
        self.created.append(kwargs)
        return {"Id": f"exec{len(self.created)}"}

    def exec_start(self, exec_id: str, **kwargs: Any) -> Any:
        call = self.created[int(exec_id.removeprefix("exec")) - 1]
        cmd = call["cmd"]
        if call.get("tty"):
            Path(cmd[3]).write_text(f"{DEAD_PID}\n")  # what the wrapper does first
            return self.sock
        subprocess.run(cmd, capture_output=True, timeout=SHELL_TIMEOUT_S, check=False)
        return b""

    def exec_inspect(self, exec_id: str) -> dict[str, Any]:
        return {"Running": self.running, "ExitCode": None if self.running else 0}

    def exec_resize(self, exec_id: str, **kwargs: Any) -> None:
        return None

    def extra_execs(self) -> list[dict[str, Any]]:
        """Every exec besides the terminal itself: kill or cleanup."""
        return [call for call in self.created if not call.get("tty")]


class LocalClient:
    def __init__(self, api: LocalApi) -> None:
        self.api = api


@pytest.fixture
def pair() -> Iterator[tuple[socket.socket, socket.socket]]:
    ours, theirs = socket.socketpair()
    try:
        yield ours, theirs
    finally:
        ours.close()
        theirs.close()


@pytest.fixture
def pid_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(pty_module, "PID_FILE_TEMPLATE", str(tmp_path / ".sf-pty-{run_id}.pid"))
    return tmp_path


def pid_files(directory: Path) -> list[Path]:
    return sorted(directory.glob(".sf-pty-*.pid"))


async def open_session(
    api: LocalApi,
) -> tuple[pty_module.DockerPtyRegistry, PtySessionHandle]:
    registry = pty_module.DockerPtyRegistry()
    handle = await pty_module.create_pty(
        LocalClient(api), registry, "ref", ["sh"], {}, rows=24, cols=80
    )
    return registry, handle


# --- close: the session's process ended on its own ---------------------------------------


async def test_close_after_a_normal_end_removes_the_pid_file(
    pair: tuple[socket.socket, socket.socket], pid_dir: Path
) -> None:
    ours, theirs = pair
    api = LocalApi(ours, running=False)
    registry, handle = await open_session(api)
    assert len(pid_files(pid_dir)) == 1  # the wrapper's exec leaves it behind
    theirs.close()  # the shell exited: EOF on the socket

    await pty_module.close_pty(registry, handle)

    assert pid_files(pid_dir) == []


async def test_close_after_a_normal_end_runs_one_plain_remove_exec(
    pair: tuple[socket.socket, socket.socket], pid_dir: Path
) -> None:
    ours, _theirs = pair
    api = LocalApi(ours, running=False)
    registry, handle = await open_session(api)

    await pty_module.close_pty(registry, handle)

    (cleanup,) = api.extra_execs()
    assert "kill" not in cleanup["cmd"][2]
    assert cleanup["cmd"][-1] == api.created[0]["cmd"][3]


# --- disconnect: the client goes away while the shell is still alive ----------------------


async def test_close_on_client_disconnect_removes_the_pid_file(
    pair: tuple[socket.socket, socket.socket], pid_dir: Path
) -> None:
    ours, _theirs = pair
    api = LocalApi(ours, running=True)
    registry, handle = await open_session(api)

    await pty_module.close_pty(registry, handle)  # what the bridge teardown calls

    assert pid_files(pid_dir) == []


async def test_driver_shutdown_removes_the_pid_files_of_live_sessions(
    pair: tuple[socket.socket, socket.socket], pid_dir: Path
) -> None:
    ours, _theirs = pair
    api = LocalApi(ours, running=True)
    registry, _handle = await open_session(api)

    await pty_module.close_all(registry)

    assert pid_files(pid_dir) == []


# --- kill: a live process tree is killed and the file goes with it -------------------------


async def test_killing_a_live_session_removes_the_file_without_an_extra_exec(
    pair: tuple[socket.socket, socket.socket], pid_dir: Path
) -> None:
    ours, _theirs = pair
    api = LocalApi(ours, running=True)
    registry, handle = await open_session(api)

    await pty_module.close_pty(registry, handle)

    (kill,) = api.extra_execs()  # the kill exec is the only one: it removes the file itself
    assert kill["cmd"][2] == exec_module._KILL_SCRIPT
    assert kill["cmd"][4] == api.created[0]["cmd"][3]
    assert pid_files(pid_dir) == []


async def test_a_session_whose_state_is_unknown_is_killed_and_cleaned(
    pair: tuple[socket.socket, socket.socket], pid_dir: Path
) -> None:
    ours, _theirs = pair
    api = LocalApi(ours, running=False)

    def failing_inspect(exec_id: str) -> dict[str, Any]:
        raise DriverError("inspect failed")

    api.exec_inspect = failing_inspect  # type: ignore[method-assign]
    registry, handle = await open_session(api)

    await pty_module.close_pty(registry, handle)

    (kill,) = api.extra_execs()
    assert kill["cmd"][2] == exec_module._KILL_SCRIPT
    assert pid_files(pid_dir) == []


# --- best effort and idempotence -----------------------------------------------------------


async def test_a_failing_cleanup_exec_does_not_break_close(
    pair: tuple[socket.socket, socket.socket], pid_dir: Path
) -> None:
    ours, _theirs = pair
    api = LocalApi(ours, running=False, fail_exec=True)
    registry, handle = await open_session(api)

    await pty_module.close_pty(registry, handle)  # must not raise

    assert api.extra_execs() == []


async def test_closing_twice_runs_the_cleanup_once(
    pair: tuple[socket.socket, socket.socket], pid_dir: Path
) -> None:
    ours, _theirs = pair
    api = LocalApi(ours, running=False)
    registry, handle = await open_session(api)

    await pty_module.close_pty(registry, handle)
    await pty_module.close_pty(registry, handle)

    assert len(api.extra_execs()) == 1


async def test_a_failed_initial_resize_closes_and_cleans_up(
    pair: tuple[socket.socket, socket.socket], pid_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ours, _theirs = pair
    api = LocalApi(ours, running=False)

    def broken(self: pty_module.DockerPty, rows: int, cols: int) -> None:
        raise DriverError("resize failed")

    monkeypatch.setattr(pty_module.DockerPty, "initial_resize", broken)

    with pytest.raises(DriverError):
        await open_session(api)

    assert pid_files(pid_dir) == []


# --- real daemon ---------------------------------------------------------------------------


async def leftover_pid_files(driver: DockerDriver, ref: str) -> str:
    """The pid files left in /tmp, polled briefly because the cleanup exec is detached."""
    deadline = time.monotonic() + CLEANUP_WAIT_S
    while True:
        listing = await driver.exec(ref, ExecRequest(argv=["sh", "-c", LEFTOVER_PID_FILES]))
        left = listing.stdout.decode().strip()
        if not left or time.monotonic() >= deadline:
            return left
        await asyncio.sleep(CLEANUP_POLL_S)


@pytest.mark.docker
async def test_a_closed_terminal_leaves_no_pty_pid_file_in_the_sandbox(
    client: Any,  # noqa: F811
) -> None:
    driver = DockerDriver(Settings(), client=client)
    created: list[str] = []
    try:
        ref = await start_sandbox(driver, created)

        ended = await driver.create_pty(ref, ["sh"], {}, 24, 80)
        await driver.write_pty(ended, b"exit\n")
        while await driver.read_pty(ended):
            pass  # drain until the shell has ended on its own
        await driver.close_pty(ended)

        killed = await driver.create_pty(ref, ["sh"], {}, 24, 80)
        await driver.write_pty(killed, b"echo up\n")
        await driver.read_pty(killed)
        await driver.close_pty(killed)  # still running: the kill path

        assert await leftover_pid_files(driver, ref) == ""
    finally:
        remove_all(client, created)
