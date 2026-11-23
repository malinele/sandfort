"""Docker implementation of ``PtySessionDriver``: a tty exec attached over the hijacked socket.

The command runs behind the same pid-recording ``sh`` wrapper as ``exec.py``, so ``close`` can
SIGKILL the process tree inside the container. In tty mode the output is not multiplexed, so
bytes go straight from the socket to the caller. Blocking docker-py calls go through
``run_blocking`` (control lane); the socket reads and writes (``read_some``, ``write_all``)
depend on the process and go through ``run_bulk`` (bulk lane). Reads poll the socket with a
short ``select`` timeout, so a waiting reader never pins a worker thread for long and a
cancelled read returns promptly.
"""

import asyncio
import contextlib
import logging
import select
import threading
import time
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

import anyio

from sandfort.drivers.base import PtySessionHandle
from sandfort.drivers.docker import exec as docker_exec
from sandfort.drivers.docker.client import run_blocking, translate_errors
from sandfort.drivers.docker.lanes import run_bulk
from sandfort.drivers.errors import DriverConflict, DriverError, DriverNotFound

logger = logging.getLogger(__name__)

RECV_BYTES = 65536
POLL_INTERVAL_S = 0.25
RESIZE_ATTEMPTS = 20
RESIZE_RETRY_S = 0.05
DEFAULT_TERM = "xterm-256color"
PID_FILE_TEMPLATE = "/tmp/.sf-pty-{run_id}.pid"
# $1 = pid file. The wrapper ends in ``exec`` and cannot trap, so a session that ended on its own
# leaves its pid file behind; the host removes it when the session closes.
_REMOVE_PID_FILE_SCRIPT = 'rm -f -- "$1"'


class DockerPty:
    """One live tty exec: the hijacked socket plus the ids needed to resize and kill it."""

    def __init__(self, client: Any, ref: str, exec_id: str, sock: Any, pid_file: str) -> None:
        self._client = client
        self._ref = ref
        self._exec_id = exec_id
        self._pid_file = pid_file
        self._sock = sock
        self._raw: Any = getattr(sock, "_sock", sock)
        self._lock = threading.Lock()  # serialises a polling read against socket close
        self._closed = False

    def read_some(self, wait_s: float) -> bytes | None:
        """Next output bytes; ``None`` if nothing arrived in ``wait_s``; ``b""`` at EOF/close."""
        with self._lock:
            if self._closed:
                return b""
            try:
                readable, _, _ = select.select([self._raw], [], [], wait_s)
                if not readable:
                    return None
                return bytes(self._raw.recv(RECV_BYTES))
            except (OSError, ValueError):
                return b""

    def write_all(self, data: bytes) -> None:
        if self._closed:
            raise DriverConflict("pty is closed", ref=self._ref)
        try:
            self._raw.sendall(data)
        except (OSError, ValueError) as exc:
            raise DriverConflict("pty is closed", ref=self._ref) from exc

    def resize(self, rows: int, cols: int) -> None:
        if self._closed:
            raise DriverConflict("pty is closed", ref=self._ref)
        with translate_errors(self._ref, "pty.resize"):
            self._client.api.exec_resize(self._exec_id, height=rows, width=cols)

    def initial_resize(self, rows: int, cols: int) -> None:
        """Apply the requested size; the exec may need a moment to reach ``running``."""
        for attempt in range(RESIZE_ATTEMPTS):
            try:
                self.resize(rows, cols)
                return
            except DriverError:
                if attempt == RESIZE_ATTEMPTS - 1:
                    logger.warning("could not set the initial pty size in %s", self._ref)
                    return
                time.sleep(RESIZE_RETRY_S)

    def close(self) -> None:
        """Kill the process tree if it is still running, then drop the socket (idempotent)."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        if self._running():
            # the kill exec removes the pid file itself, so no second exec on this path
            docker_exec._kill_blocking(self._client, self._ref, None, self._pid_file)
        else:
            _remove_pid_file_blocking(self._client, self._ref, self._pid_file)
        with contextlib.suppress(OSError):
            self._sock.close()
        if self._raw is not self._sock:
            with contextlib.suppress(OSError):
                self._raw.close()

    def exit_code(self) -> int | None:
        """The exec's ``ExitCode``; ``None`` while it runs, is not recorded yet or on error."""
        try:
            state = self._client.api.exec_inspect(self._exec_id)
            code = state.get("ExitCode")
        except Exception:
            logger.debug("could not read the exit code of a pty in %s", self._ref, exc_info=True)
            return None
        if state.get("Running") or not isinstance(code, int) or isinstance(code, bool):
            return None
        return code

    def _running(self) -> bool:
        try:
            with translate_errors(self._ref, "pty.inspect"):
                return bool(self._client.api.exec_inspect(self._exec_id).get("Running"))
        except DriverError:
            return True  # unknown: kill to be safe


def _remove_pid_file_blocking(client: Any, ref: str, pid_file: str) -> None:
    """Best effort: delete the pid file of a session whose process already ended (detached)."""
    try:
        with translate_errors(ref, "pty.cleanup"):
            cleanup_id = client.api.exec_create(
                ref, cmd=["sh", "-c", _REMOVE_PID_FILE_SCRIPT, "sh", pid_file]
            )["Id"]
            client.api.exec_start(cleanup_id, detach=True)
    except (DriverNotFound, DriverConflict):
        # the container was removed or stopped meanwhile: its pid files went with it
        logger.debug(
            "pty pid file not removed in %s: container gone or stopped", ref, exc_info=True
        )
    except Exception:
        logger.warning("could not remove the pid file of a pty in %s", ref, exc_info=True)


class DockerPtyRegistry:
    """Live terminals of one driver keyed by opaque handle id (event-loop access only)."""

    def __init__(self) -> None:
        self._ptys: dict[str, DockerPty] = {}

    def add(self, pty: DockerPty) -> PtySessionHandle:
        handle = PtySessionHandle(handle_id=f"dockerpty-{uuid.uuid4().hex}")
        self._ptys[handle.handle_id] = pty
        return handle

    def get(self, handle: PtySessionHandle) -> DockerPty:
        handle_id = handle.handle_id
        try:
            return self._ptys[handle_id]
        except KeyError:
            raise DriverNotFound(f"no such pty: {handle_id}", ref=handle_id) from None

    def pop(self, handle: PtySessionHandle) -> DockerPty | None:
        return self._ptys.pop(handle.handle_id, None)

    def drain(self) -> list[DockerPty]:
        """Hand over every live terminal and forget them; their handles stop resolving."""
        live = list(self._ptys.values())
        self._ptys.clear()
        return live


def _start_blocking(
    client: Any, ref: str, argv: Sequence[str], env: Mapping[str, str], pid_file: str
) -> tuple[str, Any]:
    with translate_errors(ref, "pty.start"):
        created = client.api.exec_create(
            ref,
            cmd=["sh", "-c", docker_exec._WRAPPER, pid_file, *argv],
            stdin=True,
            stdout=True,
            stderr=True,
            tty=True,
            environment={"TERM": DEFAULT_TERM, **env},
        )
        exec_id = str(created["Id"])
        return exec_id, client.api.exec_start(exec_id, tty=True, socket=True)


async def create_pty(
    client: Any,
    registry: DockerPtyRegistry,
    ref: str,
    argv: Sequence[str],
    env: Mapping[str, str],
    rows: int,
    cols: int,
) -> PtySessionHandle:
    if not argv:
        raise DriverError("pty argv must not be empty", ref=ref)
    pid_file = PID_FILE_TEMPLATE.format(run_id=uuid.uuid4().hex)
    exec_id, sock = await run_blocking(_start_blocking, client, ref, list(argv), env, pid_file)
    pty = DockerPty(client, ref, exec_id, sock, pid_file)
    try:
        await run_blocking(pty.initial_resize, rows, cols)
    except BaseException:
        with anyio.CancelScope(shield=True):
            await run_blocking(pty.close)
        raise
    return registry.add(pty)


async def resize_pty(
    registry: DockerPtyRegistry, handle: PtySessionHandle, rows: int, cols: int
) -> None:
    await run_blocking(registry.get(handle).resize, rows, cols)


async def write_pty(registry: DockerPtyRegistry, handle: PtySessionHandle, data: bytes) -> None:
    await run_bulk(registry.get(handle).write_all, data)


async def read_pty(registry: DockerPtyRegistry, handle: PtySessionHandle) -> bytes:
    """Next output chunk as it arrives; ``b""`` once the process exits or the pty is closed."""
    pty = registry.get(handle)
    while True:
        data = await run_bulk(pty.read_some, POLL_INTERVAL_S)
        if data is not None:
            return data


async def pty_exit_code(registry: DockerPtyRegistry, handle: PtySessionHandle) -> int | None:
    """Exit code of the terminal's process; ``None`` while running, unknown or on any error."""
    try:
        pty = registry.get(handle)
    except DriverNotFound:
        return None
    return await run_blocking(pty.exit_code)


async def close_pty(registry: DockerPtyRegistry, handle: PtySessionHandle) -> None:
    """Kill and detach; closing an unknown or already closed handle is a no-op."""
    pty = registry.pop(handle)
    if pty is None:
        return
    with anyio.CancelScope(shield=True):
        await run_blocking(pty.close)


async def close_all(registry: DockerPtyRegistry) -> None:
    """Kill every live terminal (driver shutdown); one failure never spares the others."""
    live = registry.drain()
    if not live:
        return
    with anyio.CancelScope(shield=True):
        results = await asyncio.gather(
            *(run_blocking(pty.close) for pty in live), return_exceptions=True
        )
    for result in results:
        if isinstance(result, BaseException):
            logger.warning("failed to close a pty while closing the driver", exc_info=result)
