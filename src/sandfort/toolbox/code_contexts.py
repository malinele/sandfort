"""Persistent Python code contexts: variables survive between runs, like a notebook kernel.

A context is a small Python kernel started detached inside the sandbox (``setsid`` through
``sh -c``, output to a log file). The kernel and its client are two stdlib-only files (sources
in ``code_context_kernel``) uploaded with ``put_archive`` into a private
``/tmp/.sandfort-ctx-<id>`` directory (mode 0700) next to a unix socket, a pid file and a log.
A run uploads the cell as a file and execs ``python3 client.py`` against the socket; the client
streams the kernel's stdout and stderr and exits 0, 1 when the cell raised, or 124 when the
kernel timed it out. Its last stdout line is an outcome trailer (trailing-expression repr, cell
error, kernel lost; text cut to 4096 characters), keyed by a per-run token and removed before
the result is returned (``ContextRun``); the exec's stdout cap leaves room for it.

The kernel runs every cell in one persistent module named ``__main__`` (installed in
``sys.modules``, so ``pickle`` and ``multiprocessing`` find functions the cells define) with
its own filename ``<cell-N>``, prints the repr of a trailing expression like a notebook, and
enforces the timeout with ``signal.alarm``: a cell running Python code raises ``TimeoutError``,
the state stays, and the result reports ``timed_out``.

A running cell can be interrupted: SIGINT makes the kernel raise ``KeyboardInterrupt`` in the
cell (an ordinary cell error, the state stays); between cells it does nothing. Each run has a
cell number (``new_cell_number``, kept in ``kernel.busy`` while it runs). The interrupts the
platform sends for a run (cancel, disconnect, output limit, exec timeout) name it, so they never
stop another cell, and a cell not yet begun is refused; the REST route stops whichever cell
runs. SIGINT stays blocked from the end of a cell's code until its reply is sent. A pid file is
trusted only when ``/proc/<pid>/cmdline`` names ``<dir>/kernel.py`` (``/tmp`` outlives the
processes of a stopped sandbox). State lives in the kernel process (lost on stop, reset, delete
or ``os._exit``); Python only. A context may have a name (``kernel.name`` in its directory, read
back with ``get_archive``); ``find_context`` looks a live one up by it.

Kernel limit: ``multiprocessing`` needs the ``fork`` start method (``spawn`` and ``forkserver``
children cannot find functions defined in cells): ``multiprocessing.get_context("fork").Pool()``.
A cell timed out or interrupted while such children live gets a hint line in its error message.
"""

import asyncio
import io
import json
import logging
import re
import tarfile
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass, replace
from typing import Literal

from sandfort.domain.sandbox import Sandbox, visible_stop_cause
from sandfort.drivers.base import ExecRequest, ExecResult, SandboxDriver
from sandfort.drivers.docker.exec import (
    EXEC_GONE_MARKER,
    SANDBOX_DIED_EXIT_CODE,
    SANDBOX_DIED_MESSAGE,
    output_cap_message,
    timeout_message,
)
from sandfort.drivers.errors import DriverError, DriverNotFound
from sandfort.errors import OPERATION_FAILED, Conflict, NotFound, no_container_conflict
from sandfort.toolbox.code_context_kernel import (
    _DELETE_SCRIPT,
    _IDLE_SCRIPT,
    _INTERRUPT_SCRIPT,
    _KILL_SCRIPT,
    _LIST_SCRIPT,
    _NOT_FOUND_EXIT_CODE,
    _PROBE_SCRIPT,
    _READY_SCRIPT,
    _START_SCRIPT,
    CLIENT_SOURCE,
    KERNEL_SOURCE,
    TRAILER_RESERVE_BYTES,
    _tar,
)
from sandfort.toolbox.code_run import _single_chunk
from sandfort.toolbox.process import MAX_OUTPUT_BYTES, MAX_TIMEOUT_S, execute

UPLOAD_DIR = "/tmp"  # a path inside the sandbox, not on the host
DIR_PREFIX = ".sandfort-ctx-"
KERNEL_FILE = "kernel.py"
CLIENT_FILE = "client.py"
SOCKET_FILE = "kernel.sock"
NAME_FILE = "kernel.name"  # the context's name, written only for a named context
NAME_ARCHIVE_MAX_BYTES = 16 * 1024  # a name's tar is a few blocks; a larger one is not read
TIMED_OUT_EXIT_CODE = 124  # the client's exit code for a cell the kernel timed out
EXEC_MARGIN_S = 5.0  # the exec timeout is the cell timeout plus this
READY_TIMEOUT_S = 10.0
READY_POLL_S = 0.1
SHORT_TIMEOUT_S = 10.0
INTERRUPT_WAIT_S = 2.0  # how long an interrupted cell gets to finish
INTERRUPT_POLL_S = 0.05
STOPPED_MESSAGE = "the context was stopped because the cell did not return; create a new context\n"
INTERRUPTED_MESSAGE = "the cell did not return in time and was interrupted; the context was kept\n"
UNCONFIRMED_MESSAGE = (
    "the cell exceeded its time limit; the kernel state could not be confirmed, "
    "so the context was kept\n"
)
# Replaces the driver's deadline line, which names the exec timeout (the limit plus the margin).
HARD_KILL_TEMPLATE = (
    "the cell exceeded its {limit_s:g} s limit and the kernel did not stop when interrupted; "
    "its state is lost"
)
# The run ended because the sandbox stopped under the cell (a stop, a death) or its container
# vanished, not because a limit of the cell was hit. All answer stop_reason "sandbox_stopped".
STOP_REASON_SANDBOX_STOPPED = "sandbox_stopped"
# The sentence for a stop by the caller or by auto-stop. Only the route may use it for a run
# (it reads the row, see ``_explain_gone`` in ``api.routes.toolbox.process``): this module cannot
# tell such a stop from a death by a resource limit, so a run keeps the driver's death line.
STOPPED_WHILE_RUNNING_MESSAGE = (
    "the sandbox was stopped while the cell was running; the context is gone, "
    "create or ensure a new one"
)
CONTAINER_GONE_MESSAGE = (
    "the sandbox container is gone; the context is gone, create or ensure a new one"
)
# The driver's sandbox-death line (it names a resource limit), for modules kept off the driver.
DRIVER_DEATH_LINE = SANDBOX_DIED_MESSAGE
NOT_RUNNING_PHRASE = "is not running"  # the driver conflict for an exec on a stopped container
NO_SUCH_CONTAINER_PHRASE = "No such container"
LOG_TAIL_BYTES = 2000
CLIENT_OUTPUT_LIMIT = MAX_OUTPUT_BYTES - TRAILER_RESERVE_BYTES  # leaves the trailer its room
_CONTEXT_ID = re.compile(r"ctx_[0-9a-f]{16}")
CONTEXT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}")  # the rule of sandbox names
OUTCOME_MARK = b"\x1esandfort-outcome "  # starts the client's stdout trailer; token, space follow
type RunExec = Callable[[ExecRequest, str], Awaitable[ExecResult]]  # (client exec, trailer token)
type GoneCause = Literal["stopped", "gone"]  # the sandbox was stopped / its container is gone
type KernelState = Literal["alive", "dead", "unknown", "stopped", "gone"]  # the probe's verdict
NO_LIVE_KERNEL_EXIT_CODE = 1  # the interrupt script's "no live kernel" (0 signalled, 44 no dir)
NOT_RUNNING_CELL_EXIT_CODE = 2  # its "no cell is running" (only when asked to skip an idle kernel)
ONLY_RUNNING_FLAG = "1"  # its third argument: signal the kernel only while a cell runs
logger = logging.getLogger(__name__)


def new_cell_number() -> int:
    """A cell number for one run: the clock in ns, so a later run gets a larger number."""
    return time.time_ns()


@dataclass(frozen=True, slots=True)
class CellError:
    """An exception a cell raised: its class name and ``str()``."""

    type: str
    message: str


@dataclass(frozen=True, slots=True)
class ClientOutcome:
    """The client's trailer: reply status, trailing-expression repr, cell error, ``lost``."""

    status: int
    result: str | None
    error: CellError | None
    lost: bool


def _cell_error(raw: object) -> CellError | None:
    if not isinstance(raw, dict):
        return None
    kind, message = raw.get("type"), raw.get("message")
    if isinstance(kind, str) and isinstance(message, str):
        return CellError(type=kind, message=message)
    return None


def _parse_outcome(body: bytes) -> ClientOutcome | None:
    """The trailer's JSON object, ``None`` when it is not of the expected shape."""
    try:
        raw = json.loads(body.decode("utf-8"))
    except ValueError:  # includes UnicodeDecodeError and json.JSONDecodeError
        return None
    if not isinstance(raw, dict):
        return None
    status, result, error, lost = raw.get("x"), raw.get("r"), raw.get("err"), raw.get("lost")
    if type(status) is not int or not isinstance(lost, bool) or not isinstance(result, str | None):
        return None
    cell_error = _cell_error(error)
    if error is not None and cell_error is None:
        return None
    return ClientOutcome(status=status, result=result, error=cell_error, lost=lost)


def split_outcome(stdout: bytes, token: str) -> tuple[bytes, ClientOutcome | None]:
    """``stdout`` without the client's trailer for ``token``, and the parsed trailer.

    Only the last marker counts. A trailer cut short (the client was killed mid-line: no final
    newline, or only the start of the marker) is removed too, with no outcome. Without a marker
    or with a complete but malformed trailer, ``stdout`` is returned unchanged, outcome ``None``.
    """
    marker = OUTCOME_MARK + token.encode() + b" "
    at = stdout.rfind(marker)
    if at < 0:  # no marker, or only its start at the very end (the client was killed there)
        for length in range(min(len(marker) - 1, len(stdout)), 0, -1):
            if stdout.endswith(marker[:length]):
                return stdout[:-length], None
        return stdout, None
    body = stdout[at + len(marker) :]
    if not body.endswith(b"\n"):
        return stdout[:at], None
    outcome = _parse_outcome(body)
    if outcome is None:
        return stdout, None
    return stdout[:at], outcome


@dataclass(frozen=True, slots=True)
class ContextInfo:
    id: str
    cwd: str
    name: str | None = None


@dataclass(frozen=True, slots=True)
class ContextRun:
    """A finished run: the exec result (stdout as the cell wrote it) plus the cell's outcome.

    ``result``: repr of the trailing expression (``None`` when none or ``None``); ``error``: the
    exception the cell raised; ``context_lost``: the kernel was unreachable or closed the
    connection first, or was stopped and removed after the exec deadline (state gone). Empty
    without an outcome (output limit, or an exec timeout that the kernel survived).
    """

    exec_result: ExecResult
    result: str | None = None
    error: CellError | None = None
    context_lost: bool = False


def context_dir(context_id: str) -> str:
    return f"{UPLOAD_DIR}/{DIR_PREFIX}{context_id}"


def _checked_dir(context_id: str) -> str:
    """The context directory; an id of any other shape cannot name a context (404)."""
    if not _CONTEXT_ID.fullmatch(context_id):
        raise NotFound(f"code context {context_id} not found")
    return context_dir(context_id)


def _ref(sandbox: Sandbox) -> str:
    if sandbox.driver_ref is None:
        raise no_container_conflict(sandbox.state.value, visible_stop_cause(sandbox))
    return sandbox.driver_ref


async def _sh(
    driver: SandboxDriver, ref: str, script: str, *args: str, cwd: str | None = None
) -> ExecResult:
    argv = ["sh", "-c", script, "sh", *args]
    request = ExecRequest(argv=argv, cwd=cwd, timeout_s=SHORT_TIMEOUT_S)
    return await driver.exec(ref, request)


async def _remove(driver: SandboxDriver, ref: str, path: str) -> None:
    with suppress(DriverError):  # best-effort cleanup; the caller's own outcome matters
        await driver.exec(ref, ExecRequest(argv=["rm", "-rf", path], timeout_s=SHORT_TIMEOUT_S))


async def _discard(driver: SandboxDriver, ref: str, directory: str) -> None:
    """Kill the context's kernel (when the pid is really it), then remove the directory."""
    with suppress(DriverError):  # best-effort, like the removal below
        await _sh(driver, ref, _KILL_SCRIPT, directory)
    await _remove(driver, ref, directory)


async def _wait_ready(driver: SandboxDriver, ref: str, directory: str) -> str | None:
    """The kernel's working directory once its socket exists, ``None`` after the deadline."""
    deadline = time.monotonic() + READY_TIMEOUT_S
    while True:
        result = await _sh(driver, ref, _READY_SCRIPT, directory)
        if result.exit_code == 0:
            return result.stdout.decode(errors="replace").strip()
        if time.monotonic() >= deadline:
            return None
        await asyncio.sleep(READY_POLL_S)


def _cell_args(
    directory: str, cell: int | None, *, only_running: bool = False
) -> tuple[str, ...]:
    """The scripts' arguments: the directory, then the cell number when one is targeted.

    ``only_running`` (the interrupt script only) adds the flag that makes it signal a kernel
    only while a cell runs; the cell argument is then empty (no cell is targeted).
    """
    if only_running:
        return (directory, "" if cell is None else str(cell), ONLY_RUNNING_FLAG)
    return (directory,) if cell is None else (directory, str(cell))


async def _signal_kernel(
    driver: SandboxDriver, ref: str, directory: str, cell: int | None, only_running: bool = False
) -> int:
    """Run the interrupt script: 0 signalled, 1 no live kernel, 2 no cell running (only when
    ``only_running``), 44 no such directory."""
    args = _cell_args(directory, cell, only_running=only_running)
    return (await _sh(driver, ref, _INTERRUPT_SCRIPT, *args)).exit_code


async def _wait_idle(
    driver: SandboxDriver, ref: str, directory: str, wait_s: float, cell: int | None = None
) -> bool:
    """``True`` once the kernel runs no (such) cell, ``False`` when ``wait_s`` passed first."""
    deadline = time.monotonic() + wait_s
    while True:
        if (await _sh(driver, ref, _IDLE_SCRIPT, *_cell_args(directory, cell))).exit_code == 0:
            return True
        if time.monotonic() >= deadline:
            return False
        await asyncio.sleep(INTERRUPT_POLL_S)


async def create_context(
    driver: SandboxDriver, sandbox: Sandbox, *, cwd: str | None = None, name: str | None = None
) -> ContextInfo:
    """Start a kernel in the sandbox; ``cwd`` (default: the sandbox working directory) is its.

    ``name`` is stored with the context, unchecked for uniqueness (the route serializes that
    per API process only).
    """
    ref = _ref(sandbox)
    if (await _sh(driver, ref, "command -v python3 >/dev/null 2>&1")).exit_code != 0:
        raise Conflict(
            "python3 is not available in this sandbox image; code contexts need it",
            reason=OPERATION_FAILED,
        )
    context_id = f"ctx_{uuid.uuid4().hex[:16]}"
    base = f"{DIR_PREFIX}{context_id}"
    directory = f"{UPLOAD_DIR}/{base}"
    files = {KERNEL_FILE: KERNEL_SOURCE.encode(), CLIENT_FILE: CLIENT_SOURCE.encode()}
    if name is not None:
        files[NAME_FILE] = name.encode()
    try:
        await driver.put_archive(ref, UPLOAD_DIR, _single_chunk(_tar(files, directory=base)))
        await _sh(driver, ref, _START_SCRIPT, directory, cwd=cwd)
        resolved = await _wait_ready(driver, ref, directory)
        if resolved is None:
            log = await _sh(driver, ref, f'tail -c {LOG_TAIL_BYTES} "$1/kernel.log"', directory)
            tail = log.stdout.decode(errors="replace").strip()
            message = f"the context kernel did not start within {READY_TIMEOUT_S:g} s"
            raise Conflict(f"{message}: {tail}" if tail else message, reason=OPERATION_FAILED)
    except BaseException:
        await _discard(driver, ref, directory)
        raise
    return ContextInfo(id=context_id, cwd=resolved, name=name)


async def _capped(stream: AsyncIterator[bytes]) -> bytes | None:
    """The stream's bytes; ``None`` (and the stream closed) once they pass the name cap."""
    payload = b""
    async for chunk in stream:
        payload += chunk
        if len(payload) > NAME_ARCHIVE_MAX_BYTES:
            aclose = getattr(stream, "aclose", None)
            if aclose is not None:
                await aclose()
            return None
    return payload


async def _read_name(driver: SandboxDriver, ref: str, context_id: str) -> str | None:
    """The context's name; ``None`` without a name file or with one that is not a valid name.

    Only the driver's not-found error means "no name file". Any other ``DriverError`` (timeout,
    daemon outage) propagates, so a lookup never reads a live named context as unnamed.
    """
    try:
        payload = await _capped(driver.get_archive(ref, f"{context_dir(context_id)}/{NAME_FILE}"))
    except DriverNotFound:  # no such file: an unnamed context
        return None
    if payload is None:
        return None
    try:
        with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
            member = next((m for m in archive.getmembers() if m.isfile()), None)
            handle = None if member is None else archive.extractfile(member)
            raw = b"" if handle is None else handle.read()
    except tarfile.TarError:
        return None
    name = raw.decode(errors="replace")
    return name if CONTEXT_NAME.fullmatch(name) else None


async def list_contexts(
    driver: SandboxDriver, sandbox: Sandbox, *, name: str | None = None
) -> list[ContextInfo]:
    """The contexts whose kernel is alive (socket present and pid running), in no set order.

    Each carries its name; with ``name`` only the contexts of that name are returned.
    """
    ref = _ref(sandbox)
    result = await _sh(driver, ref, _LIST_SCRIPT)
    rows = (line.partition("\t") for line in result.stdout.decode(errors="replace").splitlines())
    live = [(i, cwd) for i, _, cwd in rows if _CONTEXT_ID.fullmatch(i)]
    names = await asyncio.gather(*(_read_name(driver, ref, i) for i, _ in live))
    found = [ContextInfo(id=i, cwd=cwd, name=n) for (i, cwd), n in zip(live, names, strict=True)]
    return [info for info in found if name is None or info.name == name]


async def find_context(driver: SandboxDriver, sandbox: Sandbox, name: str) -> ContextInfo | None:
    """The live context named ``name`` (the first one listed), ``None`` when there is none."""
    return next(iter(await list_contexts(driver, sandbox, name=name)), None)


async def delete_context(driver: SandboxDriver, sandbox: Sandbox, context_id: str) -> None:
    """Kill the kernel by its pid file and remove the directory; 404 for an unknown id."""
    directory = _checked_dir(context_id)
    result = await _sh(driver, _ref(sandbox), _DELETE_SCRIPT, directory)
    if result.exit_code == _NOT_FOUND_EXIT_CODE:
        raise NotFound(f"code context {context_id} not found")


async def interrupt_context(
    driver: SandboxDriver,
    sandbox: Sandbox,
    context_id: str,
    *,
    cell: int | None = None,
    only_running: bool = False,
) -> bool:
    """Send SIGINT to the context's kernel; ``True`` when a kernel was signalled.

    With ``only_running`` (the REST route) an idle kernel, one with no cell running, is not
    signalled and the answer is ``False``.

    With ``cell`` (the number a run was given) only that cell is stopped, and a cell that has
    not begun is refused; without it, whichever cell is running (the REST route). The pid is
    trusted only when ``/proc/<pid>/cmdline`` has the kernel script. A missing directory is a
    404; one without a live kernel answers ``False``.
    """
    directory = _checked_dir(context_id)
    code = await _signal_kernel(driver, _ref(sandbox), directory, cell, only_running)
    if code == _NOT_FOUND_EXIT_CODE:
        raise NotFound(f"code context {context_id} not found")
    return code == 0


async def wait_until_idle(
    driver: SandboxDriver,
    sandbox: Sandbox,
    context_id: str,
    *,
    wait_s: float | None = None,
    cell: int | None = None,
) -> bool:
    """Wait up to ``wait_s`` (default ``INTERRUPT_WAIT_S``) until the kernel runs no cell (or,
    with ``cell``, not that one), so the next run does not queue behind it."""
    limit = INTERRUPT_WAIT_S if wait_s is None else wait_s
    return await _wait_idle(driver, _ref(sandbox), _checked_dir(context_id), limit, cell)


def _add_line(stderr: bytes, line: bytes) -> bytes:
    """``stderr`` with ``line`` appended, starting a line of its own."""
    return stderr + (b"\n" if stderr and not stderr.endswith(b"\n") else b"") + line


def _hard_kill_line(stderr: bytes, exec_timeout_s: float, limit_s: float) -> bytes:
    """``stderr`` with the driver's deadline line (it names the exec timeout, the cell's limit
    plus ``EXEC_MARGIN_S``) replaced by one naming the cell's own limit; else unchanged."""
    deadline = timeout_message(exec_timeout_s)
    at = stderr.rfind(deadline)
    if at < 0:
        return stderr
    line = HARD_KILL_TEMPLATE.format(limit_s=limit_s).encode()
    return stderr[:at] + line + stderr[at + len(deadline) :]


def stop_cause(exc: DriverError) -> GoneCause | None:
    """Why a driver failure means the sandbox is no longer running, ``None`` if it does not.

    Read from ``classification_text``: "is not running" is a stopped container, a missing
    container or exec (``DriverNotFound``) one that is gone.
    """
    text = exc.classification_text
    if NOT_RUNNING_PHRASE in text:
        return "stopped"
    if isinstance(exc, DriverNotFound) and (
        NO_SUCH_CONTAINER_PHRASE in text or EXEC_GONE_MARKER in text
    ):
        return "gone"
    return None


def _gone_run(result: ExecResult, cause: GoneCause, exec_timeout_s: float) -> ContextRun:
    """The run of a cell whose sandbox is no longer running: not a timeout, a sandbox stop.

    The deadline line and the driver's death line are removed and one line for the cause is
    appended: a vanished container is named as such; a container that is not running keeps the
    driver's death line (a resource limit was hit or its main process ended). This module does
    not read the sandbox row, so it cannot tell a stop by the caller or auto-stop from a death:
    the route does, and it rewords that line to ``STOPPED_WHILE_RUNNING_MESSAGE`` only for a stop
    (``_explain_gone``). The result is exit 137, ``sandbox_stopped``, not ``timed_out``.
    """
    stderr = result.stderr
    for driver_line in (timeout_message(exec_timeout_s), SANDBOX_DIED_MESSAGE):
        stderr = stderr.replace(driver_line, b"")
    line = SANDBOX_DIED_MESSAGE if cause == "stopped" else CONTAINER_GONE_MESSAGE.encode()
    stopped = replace(
        result,
        exit_code=SANDBOX_DIED_EXIT_CODE,
        timed_out=False,
        sandbox_stopped=True,
        stderr=_add_line(stderr, line + b"\n"),
    )
    return ContextRun(stopped, context_lost=True)  # the kernel died with the sandbox


async def _stopped_cause(driver: SandboxDriver, ref: str, directory: str) -> GoneCause | None:
    """``stopped`` / ``gone`` when a probe of the context says the sandbox is not running."""
    try:
        await _sh(driver, ref, _PROBE_SCRIPT, directory)
    except DriverError as exc:
        return stop_cause(exc)
    return None


def _notice_on_its_own_line(result: ExecResult) -> bytes:
    """The run's stderr; the driver's output-limit notice at its end starts on its own line."""
    notice = output_cap_message(CLIENT_OUTPUT_LIMIT)
    if not (result.truncated and result.stderr.endswith(notice)):
        return result.stderr
    return _add_line(result.stderr[: -len(notice)], notice)


async def _settle_stuck_cell(
    driver: SandboxDriver, ref: str, directory: str, cell: int
) -> KernelState:
    """Interrupt the cell the exec timeout gave up on and say what became of the kernel.

    ``dead`` only when the probe ran to completion and answered "no live kernel", or the
    interrupted kernel never reported its cell done; a probe that timed out, any other exit code
    or a ``DriverError`` is ``unknown``, which the caller treats like ``alive``.
    """
    try:
        probe = await _sh(driver, ref, _INTERRUPT_SCRIPT, *_cell_args(directory, cell))
        if probe.timed_out or probe.exit_code not in (0, NO_LIVE_KERNEL_EXIT_CODE):
            return "unknown"
        if probe.exit_code == NO_LIVE_KERNEL_EXIT_CODE:
            return "dead"
        idle = await _wait_idle(driver, ref, directory, INTERRUPT_WAIT_S, cell)
    except DriverError as exc:
        if (cause := stop_cause(exc)) is not None:  # not a kernel verdict: the sandbox is down
            return cause
        logger.warning("probing the code context kernel failed; keeping the context", exc_info=True)
        return "unknown"
    return "alive" if idle else "dead"


async def _discard_checked(driver: SandboxDriver, ref: str, directory: str) -> bool:
    """Kill the kernel and remove the directory; ``False`` (logged) when the driver failed."""
    try:
        await _sh(driver, ref, _KILL_SCRIPT, directory)
        remove = ExecRequest(argv=["rm", "-rf", directory], timeout_s=SHORT_TIMEOUT_S)
        await driver.exec(ref, remove)
    except DriverError:
        logger.warning("discarding the code context failed; keeping the context", exc_info=True)
        return False
    return True


async def run_in_context(
    driver: SandboxDriver,
    sandbox: Sandbox,
    context_id: str,
    code: str,
    *,
    timeout_s: float,
    cell: int | None = None,
    runner: RunExec | None = None,
) -> ContextRun:
    """Run ``code`` in the context; the result's ``timed_out`` is also set for a kernel timeout.

    A cell that raised answers exit code 1, its traceback on stderr (``<cell-N>`` frames only)
    and ``error``; one the kernel timed out answers 124, ``timed_out`` and a ``TimeoutError``.
    The state stays. A kernel that died or closed the connection mid-run answers 1 and
    ``context_lost``. The outcome trailer is removed from stdout; an output-limit notice starts
    its own stderr line. ``cell`` is the run's cell number (default: ``new_cell_number``).

    The alarm is clamped so that alarm plus ``EXEC_MARGIN_S`` fits ``MAX_TIMEOUT_S``. When the
    exec timeout still ends the run (a cell stuck in native code), the kernel is interrupted and
    given ``INTERRUPT_WAIT_S``: if it answers the context is kept; if the probe says no live
    kernel, or the kernel stays silent, it is killed and removed (a later run is a 404). A probe
    that timed out or failed, or a removal that failed, keeps the context. The result is
    ``timed_out`` with a stderr line saying which; ``context_lost`` is set only when the context
    was actually removed; then the driver's deadline line names the cell's limit, not the exec
    timeout. ``runner`` replaces the plain exec of the client (it gets the request and the
    trailer token and must return the same ``ExecResult``); the streaming run uses it to
    forward output while the cell writes it.
    """
    number = new_cell_number() if cell is None else cell
    directory = _checked_dir(context_id)
    ref = _ref(sandbox)
    if (await _sh(driver, ref, _PROBE_SCRIPT, directory)).exit_code != 0:
        raise NotFound(f"code context {context_id} not found")
    cell_timeout_s = min(timeout_s, MAX_TIMEOUT_S - EXEC_MARGIN_S)  # the margin must fit too
    cell_file = f"cell-{uuid.uuid4().hex}.py"
    token = uuid.uuid4().hex  # keys the client's outcome trailer to this run
    await driver.put_archive(ref, directory, _single_chunk(_tar({cell_file: code.encode()})))
    try:
        paths = [f"{directory}/{name}" for name in (CLIENT_FILE, SOCKET_FILE, cell_file)]
        argv = ["python3", *paths, str(cell_timeout_s), token, str(number)]
        timeout = cell_timeout_s + EXEC_MARGIN_S
        request = ExecRequest(argv=argv, timeout_s=timeout, max_output_bytes=CLIENT_OUTPUT_LIMIT)
        result = await (
            execute(driver, sandbox, request) if runner is None else runner(request, token)
        )
    finally:
        await _remove(driver, ref, f"{directory}/{cell_file}")
    stdout, outcome = split_outcome(result.stdout, token)
    result = replace(result, stdout=stdout, stderr=_notice_on_its_own_line(result))
    if result.timed_out:  # the exec timeout fired: the kernel did not answer
        state = await _settle_stuck_cell(driver, ref, directory, number)
        if state in ("stopped", "gone"):  # no limit was hit: the sandbox itself went away
            return _gone_run(result, state, timeout)
        removed = state == "dead" and await _discard_checked(driver, ref, directory)
        if removed:
            message = STOPPED_MESSAGE
        elif state == "unknown":  # the probe was inconclusive: an interrupt is not confirmed
            message = UNCONFIRMED_MESSAGE
        else:
            message = INTERRUPTED_MESSAGE
        stderr = result.stderr
        if removed:
            stderr = _hard_kill_line(stderr, timeout, cell_timeout_s)
        stuck = replace(result, stderr=_add_line(stderr, message.encode()))
        return ContextRun(stuck, context_lost=removed)  # removed: its state is gone
    if result.sandbox_stopped and (cause := await _stopped_cause(driver, ref, directory)):
        return _gone_run(result, cause, timeout)
    if result.exit_code == TIMED_OUT_EXIT_CODE:
        result = replace(result, timed_out=True)
    if outcome is None:
        return ContextRun(result)
    return ContextRun(result, result=outcome.result, error=outcome.error, context_lost=outcome.lost)
