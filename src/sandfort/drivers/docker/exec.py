"""Docker exec: create/start, demuxed streaming, wall-clock timeout, kill and output caps.

The command runs behind a tiny ``sh`` wrapper that records its pid in a file, runs the real
argv in the foreground, then removes the file and exits with the command's status. On
timeout, cap overrun or consumer abort a second exec reads that pid file and SIGKILLs the
process tree rooted at the wrapper inside the container (and removes the file). Blocking
docker-py / socket calls go through ``run_blocking`` (control lane), except the output poll
``_Pump.read``, which depends on the process and goes through ``run_bulk`` (bulk lane). The
kill exec is started detached (fire-and-forget), so no client-side read depends on the kill
exec's stream.

When a gVisor sandbox dies under memory or pid pressure, runsc's RPC error is replaced by a
clean stderr message and exit code 137 (``rewrite_sandbox_death``). A dead Kata guest is
reported the same way: the shim's ttrpc error and backtrace in the output are dropped, and an
exec the daemon no longer knows ("No such exec instance") ends as a stopped sandbox.
"""

import contextlib
import logging
import select
import socket
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

import anyio

from sandfort.drivers.base import ExecEvent, ExecRequest, ExecResult, ExitEvent, OutputChunk
from sandfort.drivers.docker.client import run_blocking, translate_errors
from sandfort.drivers.docker.demux import STDERR, STDOUT, FrameDemuxer, OutputCaps
from sandfort.drivers.docker.exec_liveness import ContainerLiveness
from sandfort.drivers.docker.hardening import GVISOR_RUNTIME
from sandfort.drivers.docker.lanes import run_bulk
from sandfort.drivers.docker.oom import OomCounter
from sandfort.drivers.errors import DriverError, DriverNotFound

logger = logging.getLogger(__name__)

RECV_BYTES = 65536
SEND_BYTES = 65536
POLL_INTERVAL_S = 0.25
EXIT_POLL_S = 0.05
EXIT_WAIT_S = 5.0
TIMED_OUT_EXIT_CODE = 124
KILLED_EXIT_CODE = 137  # 128 + SIGKILL: what a process killed by the OOM killer exits with
UNKNOWN_EXIT_CODE = -1
PID_FILE_TEMPLATE = "/tmp/.sf-exec-{run_id}.pid"

# gVisor stops the whole sandbox when it exhausts its memory or pid limit; the exec then
# ends (exit 128) with a runsc RPC error naming the sandbox id. Callers get this instead.
SANDBOX_DIED_MARKER = b'urpc method "containerManager.WaitPID" failed'
SANDBOX_DIED_PID_PART = b"waiting on PID"
SANDBOX_DIED_SANDBOX_PART = b"in sandbox"
SANDBOX_DIED_MESSAGE = (
    b"the sandbox stopped while running this command "
    b"(a resource limit was hit or its main process ended); start it again"
)
SANDBOX_DIED_EXIT_CODE = 137
# The driver only sees the container die. When the row says the caller or auto-stop stopped the
# sandbox, the process routes put this line in place of SANDBOX_DIED_MESSAGE (no limit was hit).
SANDBOX_STOPPED_MESSAGE = b"the sandbox was stopped while the command was running; start it again"

# Kata Containers: when the guest dies the shim's ttrpc error and a Rust backtrace arrive as the
# command's output (exit 128), and an exec still running is gone from the daemon afterwards.
KATA_DIED_MARKER = b"failed to handle message handler TaskRequest"
KATA_DIED_TTRPC_PART = b"ttrpc"
KATA_DIED_EOF_PART = b"early eof"
EXEC_GONE_MARKER = "No such exec instance"

# A guest that dies mid-exec can leave any of these exit codes with no recognizable text (a fork
# bomb gave 255 with empty output). For runtimes with their own kernel the container state decides.
KATA_RUNTIME_PREFIX = "kata"
SUSPECT_DEATH_EXIT_CODES = frozenset({128, 137, 255})
# The VM can still report Running=True for a moment after it died, so a suspect exec on such a
# runtime polls the container state for up to this long (a timed-out exec is a suspect too).
DEATH_POLL_INTERVAL_S = 0.25
DEATH_POLL_WINDOW_S = 3.0
_poll_sleep = time.sleep

# A command stopped at the output cap exits 137 with empty stderr, which reads like an OOM kill.
OUTPUT_CAP_MESSAGE_TEMPLATE = (
    "the command was stopped because its output exceeded the limit of {limit} bytes"
)
# A timed-out command exits 124 with otherwise empty stderr; this line says why and that more time
# can be allowed. It names no parameter, as clients spell the setting differently. 3600 is the
# API's MAX_TIMEOUT_S, repeated because drivers must not import the API.
TIMEOUT_MESSAGE_TEMPLATE = (
    "the command was stopped after {timeout_s:g} s (timeout); allow more time, up to 3600 s"
)

# $0 = pid file, remaining args = user argv. Still used by the PTY path (pty.py).
_WRAPPER = 'echo $$ > "$0" 2>/dev/null; exec "$@"'

# $0 is a neutral word so shell errors never expose the pid file path.
WRAPPER_ARG0 = "sandfort"
COMMAND_NOT_FOUND_MESSAGE = "command not found: "
MISSING_CWD_MESSAGE = "working directory does not exist: "
MISSING_COMMAND_EXIT_CODE = 127

# POSIX sh. Positional args: $1 = pid file, $2 = cwd ("" = container default), rest = argv.
# The pid is written first so the kill path works even when the checks below fail. An EXIT trap
# removes the file on every way the wrapper itself ends (cwd missing, command not found, normal
# exit); a SIGKILLed wrapper (timeout, output cap, disconnect) is cleaned by the kill exec. The
# command runs in the foreground (stdin is inherited) so the wrapper can exit with the command's
# status; the wrapper's pid is the root of the killed tree.
EXEC_WRAPPER = (
    'f=$1; { echo $$ > "$f"; } 2>/dev/null; trap \'rm -f "$f"\' EXIT; d=$2; shift 2; '
    'if [ -n "$d" ] && ! cd -- "$d" 2>/dev/null; then '
    f"printf '%s%s\\n' '{MISSING_CWD_MESSAGE}' \"$d\" >&2; "
    f"exit {MISSING_COMMAND_EXIT_CODE}; fi; "
    'if ! command -v "$1" >/dev/null 2>&1; then '
    f"printf '%s%s\\n' '{COMMAND_NOT_FOUND_MESSAGE}' \"$1\" >&2; "
    f"exit {MISSING_COMMAND_EXIT_CODE}; fi; "
    '"$@"; rc=$?; rm -f "$f"; exit "$rc"'
)

# $1 = pid file. Waits briefly for the file, then stops, walks and kills the tree.
_KILL_SCRIPT = """
f="$1"; i=0
while [ ! -s "$f" ] && [ "$i" -lt 20 ]; do i=$((i+1)); sleep 0.1; done
p=$(cat "$f" 2>/dev/null) || { rm -f "$f"; exit 0; }
rm -f "$f"
k() {
  kill -STOP "$1" 2>/dev/null
  for c in $(cat "/proc/$1/task/$1/children" 2>/dev/null); do k "$c"; done
  kill -KILL "$1" 2>/dev/null
}
k "$p"
"""


class _Pump:
    """Blocking duplex socket access: reads output and feeds stdin without extra threads."""

    def __init__(self, sock: Any, stdin: bytes | None) -> None:
        self._sock = sock
        self._raw: Any = getattr(sock, "_sock", sock)
        self._stdin = memoryview(stdin) if stdin is not None else None
        self._offset = 0

    def read(self, wait_s: float) -> bytes | None:
        """Next output bytes; ``None`` if nothing arrived in ``wait_s``; ``b""`` on EOF."""
        writing = [self._raw] if self._stdin is not None else []
        try:
            readable, writable, _ = select.select([self._raw], writing, [], wait_s)
            if writable:
                self._send_more()
            if readable:
                return bytes(self._raw.recv(RECV_BYTES))
        except (OSError, ValueError):
            # A closed descriptor raises ValueError from select (the generator's finally can
            # close the pump while a cancelled poll is still running); treat it as EOF.
            return b""
        return None

    def _send_more(self) -> None:
        assert self._stdin is not None
        try:
            chunk = self._stdin[self._offset : self._offset + SEND_BYTES]
            self._offset += self._raw.send(chunk) if len(chunk) else 0
            if self._offset < len(self._stdin):
                return
            self._raw.shutdown(socket.SHUT_WR)
        except OSError:
            pass  # process closed stdin early; output side still drains normally
        self._stdin = None

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self._sock.close()
        if self._raw is not self._sock:
            with contextlib.suppress(OSError):
                self._raw.close()


def _create_exec(client: Any, ref: str, request: ExecRequest, pid_file: str) -> str:
    kwargs: dict[str, Any] = {
        "cmd": [
            "sh",
            "-c",
            EXEC_WRAPPER,
            WRAPPER_ARG0,
            pid_file,
            request.cwd or "",
            *request.argv,
        ],
        "stdout": True,
        "stderr": True,
        "stdin": request.stdin is not None,
        "tty": False,
    }
    if request.env:
        kwargs["environment"] = dict(request.env)
    if request.user:
        kwargs["user"] = request.user
    with translate_errors(ref, "exec.create"):
        return str(client.api.exec_create(ref, **kwargs)["Id"])


def _open_pump(client: Any, ref: str, exec_id: str, stdin: bytes | None) -> _Pump:
    with translate_errors(ref, "exec.start"):
        return _Pump(client.api.exec_start(exec_id, socket=True), stdin)


def _kill_blocking(client: Any, ref: str, user: str | None, pid_file: str) -> None:
    kwargs: dict[str, Any] = {"cmd": ["sh", "-c", _KILL_SCRIPT, "sh", pid_file]}
    if user:
        kwargs["user"] = user  # same uid as the target; the sandbox drops CAP_KILL
    try:
        with translate_errors(ref, "exec.kill"):
            kill_id = client.api.exec_create(ref, **kwargs)["Id"]
            client.api.exec_start(kill_id, detach=True)
    except DriverError:
        logger.warning("failed to kill exec process in %s", ref, exc_info=True)


def _wait_exit_blocking(client: Any, ref: str, exec_id: str) -> int:
    deadline = time.monotonic() + EXIT_WAIT_S
    while True:
        with translate_errors(ref, "exec.inspect"):
            state = client.api.exec_inspect(exec_id)
        if not state.get("Running"):
            code = state.get("ExitCode")
            return UNKNOWN_EXIT_CODE if code is None else int(code)
        if time.monotonic() >= deadline:
            return UNKNOWN_EXIT_CODE
        time.sleep(EXIT_POLL_S)


async def _wait_exit(client: Any, ref: str, exec_id: str) -> tuple[int, bool]:
    """The exec's exit code, and whether the exec vanished because the Kata guest died."""
    try:
        return await run_blocking(_wait_exit_blocking, client, ref, exec_id), False
    except DriverNotFound as exc:
        if EXEC_GONE_MARKER not in exc.classification_text:
            raise
        return UNKNOWN_EXIT_CODE, True


def has_own_network_stack(runtime: str) -> bool:
    """True for runtimes with their own kernel and network stack: runsc and kata*."""
    return runtime == GVISOR_RUNTIME or runtime.startswith(KATA_RUNTIME_PREFIX)


def _container_stopped_blocking(
    client: Any, ref: str, window_s: float = DEATH_POLL_WINDOW_S
) -> bool:
    """True when ``ref`` runs on runsc/kata and docker reports it as not running.

    A dying Kata guest still reports ``Running=True`` for a moment, so while docker says
    running the state is polled every ``DEATH_POLL_INTERVAL_S`` for up to ``window_s``
    (0 means a single inspection). The runtime is decided from the first inspect: other
    runtimes (runc) are never polled. Any inspection problem (including an unexpected
    payload) answers False.
    """
    try:
        attrs = client.api.inspect_container(ref)
        runtime = (attrs.get("HostConfig") or {}).get("Runtime") or ""
        if not has_own_network_stack(str(runtime)):
            return False
        running = (attrs.get("State") or {}).get("Running")
        waited = 0.0
        while running is True and waited < window_s:
            _poll_sleep(DEATH_POLL_INTERVAL_S)
            waited += DEATH_POLL_INTERVAL_S
            running = (client.api.inspect_container(ref).get("State") or {}).get("Running")
        return running is False
    except Exception:
        logger.debug("could not inspect %s after an exec ended", ref, exc_info=True)
        return False


async def _sandbox_died_silently(client: Any, ref: str, exit_code: int, timed_out: bool) -> bool:
    """Whether an exec that timed out or ended with a suspect exit code took its sandbox down."""
    if not (timed_out or exit_code in SUSPECT_DEATH_EXIT_CODES):
        return False
    # A plain timeout is not death evidence: one inspection, no polling window. Deaths at the
    # deadline are covered by the liveness checker and the runtime's death text.
    window_s = 0.0 if timed_out else DEATH_POLL_WINDOW_S
    try:
        return await run_blocking(_container_stopped_blocking, client, ref, window_s)
    except Exception:
        return False


def kata_death_offset(data: bytes) -> int:
    """Where the Kata shim's guest-death report starts in ``data``; -1 when it is absent."""
    at = data.find(KATA_DIED_MARKER)
    if at >= 0:
        return at
    ttrpc = data.find(KATA_DIED_TTRPC_PART)
    eof = data.find(KATA_DIED_EOF_PART)
    return min(ttrpc, eof) if ttrpc >= 0 and eof >= 0 else -1


def _sandbox_death_offset(data: bytes) -> int:
    """Where gVisor's or Kata's sandbox-death report starts in ``data``; -1 when absent."""
    at = kata_death_offset(data)
    if at >= 0:
        return at
    at = data.find(SANDBOX_DIED_MARKER)
    if at >= 0:
        return at
    at = data.find(SANDBOX_DIED_PID_PART)
    if at < 0:
        return -1
    line_end = data.find(b"\n", at)
    line = data[at:] if line_end < 0 else data[at:line_end]
    return at if SANDBOX_DIED_SANDBOX_PART in line else -1


def rewrite_sandbox_death(
    stream: str, data: bytes, reported: bool
) -> tuple[list[OutputChunk], bool]:
    """Chunks to yield for one admitted payload, and whether the sandbox died so far.

    gVisor's report, from the start of its line, becomes one clean stderr message; earlier
    lines of the payload pass through and a repeated report is dropped. Any other payload
    passes through unchanged.
    """
    at = _sandbox_death_offset(data)
    if at < 0:
        return ([OutputChunk(stream, data)] if data else []), reported
    kept = data[: data.rfind(b"\n", 0, at) + 1]
    chunks = [OutputChunk(stream, kept)] if kept else []
    if not reported:
        chunks.append(OutputChunk(STDERR, SANDBOX_DIED_MESSAGE))
    return chunks, True


def output_cap_message(limit: int) -> bytes:
    """The stderr text for a command stopped because its output reached ``limit`` bytes."""
    return OUTPUT_CAP_MESSAGE_TEMPLATE.format(limit=limit).encode()


def timeout_message(timeout_s: float) -> bytes:
    """The stderr line for a command stopped at its ``timeout_s`` wall-clock deadline."""
    return TIMEOUT_MESSAGE_TEMPLATE.format(timeout_s=timeout_s).encode()


def timeout_note(stderr_tail: bytes, timeout_s: float) -> bytes:
    """The timeout note to append after output ending in ``stderr_tail``.

    It starts on its own line: a newline comes first when the captured stderr is non-empty and
    does not end with one.
    """
    note = timeout_message(timeout_s)
    return b"\n" + note if stderr_tail and not stderr_tail.endswith(b"\n") else note


def with_timeout_note(stderr: bytes, timeout_s: float) -> bytes:
    """``stderr`` followed by the timeout note on its own line; unchanged when already noted."""
    note = timeout_message(timeout_s)
    if stderr.endswith(note):
        return stderr
    return stderr + timeout_note(stderr, timeout_s)


async def exec_stream(client: Any, ref: str, request: ExecRequest) -> AsyncIterator[ExecEvent]:
    """Yield demuxed output chunks, then exactly one ``ExitEvent``.

    A cap overrun or the timeout kills the process; the consumer abandoning the
    iterator kills it too.
    """
    if not request.argv:
        raise DriverError("exec argv must not be empty", ref=ref)
    deadline = time.monotonic() + request.timeout_s
    oom_counter = OomCounter(client, ref)
    await oom_counter.start()
    pid_file = PID_FILE_TEMPLATE.format(run_id=uuid.uuid4().hex)
    exec_id = await run_blocking(_create_exec, client, ref, request, pid_file)
    pump = await run_blocking(_open_pump, client, ref, exec_id, request.stdin)
    demuxer = FrameDemuxer()
    caps = OutputCaps(request.max_output_bytes)
    timed_out = False
    sandbox_died = False
    shim_died = False
    exec_gone = False
    vm_died = False
    finished = False
    exit_code = UNKNOWN_EXIT_CODE
    liveness = ContainerLiveness(client, ref, has_own_network_stack)
    stderr_tail = b""  # the last bytes of stderr delivered, to start the timeout note on a line
    try:
        while not caps.truncated:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            data = await run_bulk(pump.read, min(remaining, POLL_INTERVAL_S))
            if data is None:
                vm_died = not await liveness.is_running()
                if vm_died:
                    break
                continue
            if not data:
                break
            for stream, payload in demuxer.feed(data):
                if shim_died:
                    continue  # the rest of the Kata shim report (its backtrace) is dropped
                allowed = caps.admit(stream, payload)
                shim_died = kata_death_offset(allowed) >= 0
                chunks, sandbox_died = rewrite_sandbox_death(stream, allowed, sandbox_died)
                for chunk in chunks:
                    if chunk.stream == STDERR and chunk.data:
                        stderr_tail = chunk.data[-1:]
                    yield chunk
        if timed_out or caps.truncated or vm_died:
            await run_blocking(pump.close)  # release the stalled stream before the kill exec
        if vm_died:
            exec_gone = True  # a kill exec or an exit wait would hang or fail on a dead container
        else:
            if timed_out or caps.truncated:
                await run_blocking(_kill_blocking, client, ref, request.user, pid_file)
            exit_code, exec_gone = await _wait_exit(client, ref, exec_id)
        finished = True
    finally:
        with anyio.CancelScope(shield=True):
            if not finished:
                await run_blocking(_kill_blocking, client, ref, request.user, pid_file)
            await run_blocking(pump.close)
    if not (sandbox_died or exec_gone or caps.truncated):
        exec_gone = await _sandbox_died_silently(client, ref, exit_code, timed_out)
        timed_out = timed_out and not exec_gone  # a confirmed death is reported as one
    if exec_gone and not sandbox_died:
        yield OutputChunk(STDERR, SANDBOX_DIED_MESSAGE)
        sandbox_died = True
    if sandbox_died:
        timed_out = False  # a sandbox death report wins over the deadline
    if timed_out:
        exit_code = TIMED_OUT_EXIT_CODE
    elif sandbox_died:
        exit_code = SANDBOX_DIED_EXIT_CODE
    oom_killed = False
    if exit_code == KILLED_EXIT_CODE and not (timed_out or caps.truncated or sandbox_died):
        oom_killed = await oom_counter.rose()
    if caps.truncated:
        yield OutputChunk(STDERR, output_cap_message(request.max_output_bytes))
    if timed_out:
        yield OutputChunk(STDERR, timeout_note(stderr_tail, request.timeout_s))
    yield ExitEvent(
        exit_code,
        timed_out=timed_out,
        truncated=caps.truncated,
        sandbox_stopped=sandbox_died and not timed_out,
        oom_killed=oom_killed,
    )


async def exec_run(client: Any, ref: str, request: ExecRequest) -> ExecResult:
    started = time.monotonic()
    stdout = bytearray()
    stderr = bytearray()
    exit_event: ExitEvent | None = None
    async for event in exec_stream(client, ref, request):
        if isinstance(event, OutputChunk):
            (stdout if event.stream == STDOUT else stderr).extend(event.data)
        else:
            exit_event = event
    if exit_event is None:
        raise DriverError("exec stream ended without an exit event", ref=ref)
    return ExecResult(
        exit_code=exit_event.exit_code,
        stdout=bytes(stdout),
        stderr=bytes(stderr),
        timed_out=exit_event.timed_out,
        truncated=exit_event.truncated,
        duration_ms=int((time.monotonic() - started) * 1000),
        sandbox_stopped=exit_event.sandbox_stopped,
        oom_killed=exit_event.oom_killed,
    )
