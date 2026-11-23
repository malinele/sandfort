"""``/code-contexts``: persistent Python contexts, like a notebook kernel.

``POST`` creates a context (a Python kernel started inside the sandbox), ``GET`` lists the live
ones, ``DELETE /{context_id}`` kills one, and ``POST /{context_id}/run`` runs a cell in it:
variables, imports and open data survive from one run to the next. The run answers with the
execute response of ``/process/code-run`` (``stop_reason`` included) plus ``result`` (the
repr of the cell's trailing expression) and ``error`` (``{"type", "message"}`` of the
exception the cell raised); stdout is unchanged. A kernel that died or closed the connection
mid-run (or a context deleted mid-run) answers ``context_lost``.

A cell that does not finish ends in one of three ways, in this order:

1. The cell's own ``timeout_s`` fires inside the kernel when control is back in Python and ends
   the cell with ``TimeoutError`` (``timed_out``). The state stays and the context is kept.
   Only a run has a ``timeout_s``.
2. An interrupt request does the same at once when it can: ``POST /{context_id}/interrupt``
   sends SIGINT, a running cell raises ``KeyboardInterrupt`` (a cell error, the state stays),
   between cells nothing is signalled and it answers ``interrupted: false``. Native code that
   never returns to Python (a long C call, a ctypes sleep) does not stop. Later runs on the
   context then queue behind that cell, each for up to its own ``queue_timeout``, until the
   cell ends at 1 or 3. The interrupt route never removes the context.
3. Only when the run's exec deadline (``timeout_s`` plus a 5 s margin) passes with the cell
   still not answering is the kernel sent an interrupt and given 2 s. A kernel that answers
   keeps its context and the run is ``timed_out`` with ``stop_reason`` ``timeout``. One that
   does not is stopped and the context removed only after that 2 s grace, and later runs on
   it answer 404; that run answers ``stop_reason`` ``context_lost`` (``exit_code`` 124 and
   ``timed_out`` stay, and stderr says the context was stopped). Only the run route reaches
   this step; ``DELETE`` removes the context at once, without a grace.

The interrupt route names no cell, so it interrupts whichever cell is running at that
moment. A run whose client
went away, and a run that hit the output limit, interrupt their own cell before the next run
can start: each run has a cell number that the kernel checks, so such an interrupt never stops
the next run's cell, and one that arrives before the kernel began the cell makes it skip the
cell (the run ends as an interrupted cell). A run's stdout is limited to 1 MiB minus 64 KiB,
which keeps room for `result` and `error` (their text is cut to 4096 characters).

The kernel runs one cell at a time, so runs on one context queue on a per-context lock held in
this process. A run that waits longer than its own ``timeout_s`` answers ``queue_timeout`` with
exit code 124, ``timed_out`` and a stderr line saying another run was still executing; the
context is kept.

A context may have a ``name``: a create with the name of a live context returns that context
(200, its own cwd; the request's cwd is ignored), so a client can re-create its context after a
stop with the same call (the state is gone). Uniqueness is per API process only: named creates of
one sandbox and name are serialized on a lock in this process, so two creates racing across
processes may both succeed. ``GET ?name=`` looks one up.

Only ``python`` is supported. The state lives in the kernel process, so it is lost when the
sandbox is stopped, reset or deleted. Scope, label scope, audit rows and error mapping are
those of ``/process/code-run``; the work lives in ``toolbox.code_contexts``.
"""

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Awaitable
from dataclasses import dataclass, field, replace
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from sandfort.api.deps import get_audit_recorder, get_driver, get_uow
from sandfort.api.envelope import Envelope, ok
from sandfort.api.query_guard import KnownQuery, single_valued
from sandfort.api.routes.toolbox.process import (
    OOM_KILLED_MESSAGE,
    _gone_reason,
    _run_until_disconnect,
    _started_sandbox,
)
from sandfort.api.routes.toolbox.scope_guard import require_visible_sandbox
from sandfort.api.schemas.common import NoBool, RequestModel
from sandfort.api.schemas.sandboxes import MAX_NAME_LENGTH, NAME_PATTERN
from sandfort.api.schemas.toolbox_process import (
    CONTEXT_NAME_DESCRIPTION,
    CONTEXT_STOP_REASON_CONTEXT_LOST,
    CONTEXT_STOP_REASON_QUEUE_TIMEOUT,
    MAX_TIMEOUT_S,
    STOP_REASON_OOM_KILLED,
    STOP_REASON_SANDBOX_DELETED,
    STOP_REASON_SANDBOX_RESET,
    STOP_REASON_SANDBOX_STOPPED,
    CellErrorResponse,
    CodeContextCreateRequest,
    CodeContextResponse,
    ContextRunResponse,
    context_run_response,
)
from sandfort.api.sse import DEFAULT_KEEPALIVE_INTERVAL_S, format_event, with_keepalive
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import require_scopes
from sandfort.clock import SystemClock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.org import Scope
from sandfort.domain.sandbox import Sandbox
from sandfort.drivers.base import ExecResult, SandboxDriver
from sandfort.errors import IN_PROGRESS, Conflict
from sandfort.services.audit import AuditRecorder
from sandfort.toolbox import code_context_stream, code_contexts, stop_wording
from sandfort.toolbox.guards import load_started_sandbox

router = APIRouter(
    prefix="/v1/sandboxes/{sandbox_id}/toolbox/code-contexts",
    tags=["toolbox"],
    dependencies=[Depends(require_visible_sandbox)],
)

logger = logging.getLogger(__name__)
_CLOCK = SystemClock()
BUSY_EXIT_CODE = 124  # the answer of a run that waited for its context longer than its timeout
BUSY_MESSAGE = b"another run on this context was still executing; this run timed out waiting\n"
NAME_LOCK_PREFIX = "name:"  # a named create's lock key; context ids start with ``ctx_``
NAME_WAIT_S = 30.0  # how long a named create waits for another create of the same name
# The lines for a run that ended with its sandbox gone, in the shape of a command's lines but
# naming the cell. The route picks the line from the row: a delete or a reset gets its line, a
# stop by the caller or auto-stop (no error_code) the stop sentence, every other death keeps the
# driver's limit/died line.
CELL_GONE_MESSAGES = {
    STOP_REASON_SANDBOX_DELETED: b"the sandbox was deleted while the cell was running",
    STOP_REASON_SANDBOX_RESET: (
        b"the sandbox was reset while the cell was running; the context is gone, "
        b"create or ensure a new one"
    ),
    STOP_REASON_SANDBOX_STOPPED: code_contexts.STOPPED_WHILE_RUNNING_MESSAGE.encode(),
}
# A vanished container is already named by the run itself; no reason line is added after it.
CELL_EXPLAINED = (code_contexts.CONTAINER_GONE_MESSAGE.encode(),)


_CREATE_DESCRIPTION = (
    "Start a persistent Python kernel inside the started sandbox, like a notebook kernel. "
    "Variables, imports and loaded data survive from one run to the next. `cwd` sets the "
    "kernel's working directory and defaults to the sandbox's working directory; the response "
    "returns the resolved `cwd`. Only `python` is supported, and the sandbox image must have "
    "`python3`, otherwise the create is refused with 409. The context lives in the kernel "
    "process, so it is lost when the sandbox is reset, stopped (auto-stop included) or "
    "deleted; files written to disk are not affected. Needs the `toolbox:use` scope.\n\n"
    "`name` is optional. Uniqueness among the live contexts of the sandbox is enforced per API "
    "process: two creates of one name that race across processes may both succeed. A create "
    "with the name of a live context returns that context with 200 instead of starting a new "
    "one (201); its `cwd` is kept and the `cwd` of the request is ignored, so the reply carries "
    "the existing context's `cwd`. A name no live context has starts a new one. If the live "
    "contexts cannot be read (a driver failure), the create fails instead of starting a "
    "context. After a stop and start the same call brings a context of that name back, with "
    "empty state."
)
_LIST_DESCRIPTION = (
    "List the code contexts of a started sandbox whose kernel is alive, in no set order. "
    "Each entry has the context `id`, its working directory `cwd` and, for a named context, "
    "its `name`; `?name=` lists only the context of that name (an empty list when none). "
    "Contexts lost to a reset, stop or auto-stop are not listed. Reads are not audited."
)
_DELETE_DESCRIPTION = (
    "Kill the kernel of the context and remove its directory at once, without the 2 s grace "
    "a run gives a stuck cell; its state is gone. Answers 404 for an unknown id. A cell that "
    "is running on the context when it is deleted ends with `stop_reason` `context_lost`. "
    "Besides this call, a context is removed only by a run whose exec deadline passed with the "
    "cell still not answering after the 2 s grace (see the run operation); the timeout of a "
    "cell and an interrupt request keep it."
)
_INTERRUPT_DESCRIPTION = (
    "Send an interrupt (SIGINT) to the kernel of the context. A running cell raises "
    "`KeyboardInterrupt` in Python code, which is a cell error, and the state stays; between "
    "cells there is nothing to interrupt and the answer is `interrupted: false`. The route names "
    "no cell, so it interrupts whichever cell is running at that moment.\n\n"
    "This is the same sequence the run operation describes. A cell's own `timeout_s` ends it "
    "with `TimeoutError` once control is back in Python, and this call does the same at once "
    "when it can. It cannot stop a cell stuck in native code (a long C call or a ctypes sleep "
    "that never returns to Python): that cell goes on, and later runs on the context queue "
    "behind it, each for up to its own `queue_timeout`, until the cell ends at its `timeout_s` "
    "or the run's exec deadline passes. This call never stops the kernel or removes the "
    "context; that happens only to a run whose exec deadline passed with the cell still not "
    "answering, and the kernel is stopped and the context removed only after that 2 s grace; "
    "later runs then answer 404. "
    "`interrupted` is `true` when a cell was running and the kernel was sent the interrupt, and "
    "`false` when no cell is running or the context has no live kernel. Each call is audited as "
    "`toolbox.code_contexts.interrupt`."
)
_RUN_DESCRIPTION = (
    "Run a cell of Python code in the context; state from earlier cells is still there. The "
    "response has every field of `/process/code-run` (`stdout`, `stderr`, `exit_code`, "
    "`timed_out`, `stop_reason`) plus `result`, the `repr` of the cell's trailing expression "
    "(`null` when there is none or the cell raised), and `error`, `{type, message}` of the "
    "exception the cell raised (`null` otherwise). `result` and the error text are cut to "
    "4096 characters. A cell that raises exits 1.\n\n"
    "Cells of one context are serialized: runs on one context queue and run in order. A run "
    "that waits longer than its own `timeout_s` answers exit code 124, `timed_out` and "
    "`stop_reason` `queue_timeout`; it never started and the context is kept, so send the "
    "cell again.\n\n"
    "How a cell that does not finish ends, in order:\n\n"
    "1. `timeout_s` limits one cell. It fires inside the kernel when control is back in "
    "Python and ends the cell with `TimeoutError`; the result reports `timed_out` and the "
    "state stays.\n"
    "2. `POST .../interrupt` does the same at once when it can. A cell stuck in native code "
    "(a long C call or a ctypes sleep that never returns to Python) does not stop, and later "
    "runs on the context queue behind it, each for up to its own `queue_timeout`, until the "
    "cell ends at 1 or 3. Interrupt requests never remove the context.\n"
    "3. Only when this run's exec deadline (`timeout_s` plus a 5 s margin) passes with the "
    "cell still not answering is the kernel sent an interrupt and given 2 s. A kernel that "
    "answers keeps its context, and the run ends with `stop_reason` `timeout`. One that does "
    "not is stopped and the context removed only after that 2 s grace, so later runs on it "
    "answer 404; that run ends with `stop_reason` `context_lost`, `exit_code` 124 and "
    "`timed_out` true, and its stderr says the context was stopped. A cell that ends at 1 "
    "(the kernel answered, state kept) is a plain `timeout`.\n\n"
    "A run can end at 1 or 3 and can queue as in 2; an interrupt request can only cause 2; "
    "`DELETE` removes the context at once.\n\n"
    "`stdout` is capped at 1 MiB minus 64 KiB, which leaves room for `result` and `error`. A "
    "run that hits the cap ends with `stop_reason` `output_limit`; its cell is interrupted "
    "and the context and its state are kept. When the client of a run disconnects or the run "
    "is cancelled, the run's own cell is interrupted (never a later run's cell) before the "
    "next run can start.\n\n"
    "Other stop reasons: `context_lost` when the kernel died or closed the connection during "
    "the run, the context was deleted mid-run, or the kernel was stopped and the context "
    "removed after the exec deadline and the 2 s grace (see 3). The contexts are lost when "
    "the sandbox is reset, stopped (auto-stop included) or deleted. Scope, label scope, audit "
    "rows and error mapping are those of `/process/code-run`."
)
_RUN_STREAM_DESCRIPTION = (
    "Run a cell of Python code in the context and receive its output as server-sent events "
    "while it runs. The request body is that of the run operation, and so are the rules: runs "
    "on one context are serialized and wait up to `timeout_s` (`queue_timeout`), `timeout_s` "
    "and the exec deadline end a cell as described there, `stdout` is capped at 1 MiB minus "
    "64 KiB (`output_limit`), and a client that disconnects interrupts its own cell.\n\n"
    'The stream has `stdout` and `stderr` events, `data: {"data": <text>}`, one per chunk '
    "the driver delivers (UTF-8, invalid bytes replaced), then exactly one final `result` "
    "event whose data is the object the run operation answers in `data` (`stdout`, `stderr`, "
    "`exit_code`, `timed_out`, `truncated`, `stop_reason`, `result`, `error`, ...). `stdout` "
    "is forwarded by whole lines: the last line, without its newline yet, is held back until "
    "its newline or the end of the run, and the outcome line the platform's client prints "
    "last is never sent (the `result` event carries it as `result` and `error`). `stderr` is "
    "forwarded as it arrives. The `result` event holds the complete `stdout` and `stderr`, "
    "including lines the platform adds to `stderr` after the exec ended.\n\n"
    "An unknown context, a sandbox that is not started and the scope and label checks answer "
    "as for run, with the error envelope, before the stream starts. A failure after the "
    'stream started sends one `error` event, `data: {"code": <error code>, "message": '
    "<text>}`, instead of `result`, and ends the stream. Scope, label scope and the audit "
    "rows (action `toolbox.code_contexts.run_stream`, the details of run) are those of run."
)


@dataclass(slots=True)
class _RunLock:
    """One context's lock plus the number of runs that hold or wait for it."""

    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    users: int = 0


# (sandbox id, context id) -> lock; an entry lives only while a run holds or waits for it.
_RUN_LOCKS: dict[tuple[str, str], _RunLock] = {}


@contextlib.asynccontextmanager
async def _context_turn(key: tuple[str, str], wait_s: float) -> AsyncIterator[bool]:
    """Yield ``True`` while holding the context's lock, ``False`` after waiting ``wait_s`` for it.

    The kernel runs one cell at a time, so runs on one context queue here instead of waiting
    behind each other inside the exec timeout. The registry entry is dropped with its last user,
    also when a waiter is cancelled (client disconnect).
    """
    entry = _RUN_LOCKS.setdefault(key, _RunLock())
    entry.users += 1
    try:
        acquired = False
        try:
            await asyncio.wait_for(entry.lock.acquire(), wait_s)
            acquired = True
        except TimeoutError:
            pass  # reported to the caller as ``False``
        if not acquired:
            yield False
            return
        try:
            yield True
        finally:
            entry.lock.release()
    finally:
        entry.users -= 1
        if entry.users == 0:
            del _RUN_LOCKS[key]


async def _interrupt_cell(
    driver: SandboxDriver, sandbox: Sandbox, context_id: str, cell: int
) -> None:
    """Interrupt the run's cell (``cell`` is its number) and wait (up to 2 s) for it to end.

    The kernel only stops that cell, so the interrupt cannot hit the next run's cell; a cell
    that has not begun yet is refused by the kernel. Failures are logged, never raised: this
    runs while a run is already ending.
    """
    try:
        if await code_contexts.interrupt_context(driver, sandbox, context_id, cell=cell):
            await code_contexts.wait_until_idle(driver, sandbox, context_id, cell=cell)
    except Exception:
        logger.exception("could not interrupt code context %s of %s", context_id, sandbox.id)


async def _interrupt_shielded(
    driver: SandboxDriver, sandbox: Sandbox, context_id: str, cell: int
) -> None:
    """``_interrupt_cell`` that a cancellation of the caller does not cut short."""
    await asyncio.shield(_interrupt_cell(driver, sandbox, context_id, cell))


@dataclass(frozen=True, slots=True)
class _Turn:
    """A finished run on a context and the stop reason only the context route knows."""

    run: code_contexts.ContextRun
    stop_reason: str | None = None

    @property
    def result(self) -> ExecResult:
        return self.run.exec_result


async def _run_in_turn(
    driver: SandboxDriver,
    sandbox: Sandbox,
    context_id: str,
    code: str,
    timeout_s: float,
    runner: code_contexts.RunExec | None = None,
) -> _Turn:
    """Run the cell once the context is free; ``queue_timeout`` when it stayed busy too long.

    A run that waited ``timeout_s`` for the lock answers 124 and ``queue_timeout``; a run whose
    kernel was lost answers ``context_lost``. Only the run that held the lock and got no answer
    from the kernel discards the context (``run_in_context``); a run that merely waited leaves
    it alone. A run that is cancelled (the client went away) or that hit the output limit
    leaves its cell running in the kernel, so the cell is interrupted before the lock is
    released and the next run does not queue behind it.
    """
    async with _context_turn((sandbox.id, context_id), timeout_s) as acquired:
        if not acquired:
            busy = ExecResult(exit_code=BUSY_EXIT_CODE, stderr=BUSY_MESSAGE, timed_out=True)
            return _Turn(code_contexts.ContextRun(busy), CONTEXT_STOP_REASON_QUEUE_TIMEOUT)
        cell = code_contexts.new_cell_number()  # names this run's cell for its interrupts
        try:
            run = await code_contexts.run_in_context(
                driver, sandbox, context_id, code, timeout_s=timeout_s, cell=cell, runner=runner
            )
        except asyncio.CancelledError:
            await _interrupt_shielded(driver, sandbox, context_id, cell)
            raise
        result = run.exec_result
        if result.truncated and not result.timed_out:  # stop_reason output_limit
            await _interrupt_shielded(driver, sandbox, context_id, cell)
        return _Turn(run, CONTEXT_STOP_REASON_CONTEXT_LOST if run.context_lost else None)


async def _exec_of(turn: Awaitable[_Turn], finished: list[_Turn]) -> ExecResult:
    """Await ``turn`` for ``_run_until_disconnect``: keep the whole turn, hand on its exec."""
    done = await turn
    finished.append(done)
    return done.result


def _end_gone_line(result: ExecResult, stop_reason: str | None) -> ExecResult:
    """``result`` whose stderr ends with a newline when it ends with the cell's gone line.

    A death line the route rewords keeps the newline after it; a line it appends (a bare kill,
    as a reset's exec often ends) has none. Every delete, reset and stop line ends the same way,
    in the result and in the streamed stderr (the stream sends the result's unsent tail).
    """
    line = CELL_GONE_MESSAGES.get(stop_reason) if stop_reason is not None else None
    if line is None or not result.stderr.endswith(line):
        return result
    return replace(result, stderr=result.stderr + b"\n")


def _cell_worded(result: ExecResult, stop_reason: str | None) -> ExecResult:
    """``result`` with the driver's command sentences worded for a cell.

    A cell run says "cell" in the output-limit and sandbox-death sentences, and a sandbox that
    ran out of memory under a cell also says the context and its variables are gone.
    """
    stderr = stop_wording.cell_reword(result.stderr)
    if stop_reason == STOP_REASON_OOM_KILLED and result.sandbox_stopped:
        stderr = stderr.replace(
            OOM_KILLED_MESSAGE, OOM_KILLED_MESSAGE + b"; " + stop_wording.CELL_LOST_HINT.encode()
        )
    return replace(result, stderr=stderr)


def _run_response(
    turn: _Turn | None, result: ExecResult, stop_reason: str | None
) -> ContextRunResponse:
    """The run response; ``stop_reason`` (a sandbox death the route explained) comes first."""
    result = _cell_worded(_end_gone_line(result, stop_reason), stop_reason)
    if turn is None:  # the client went away: nothing is delivered
        return context_run_response(result, stop_reason=stop_reason)
    error = turn.run.error
    cell_error = (
        None if error is None else CellErrorResponse(type=error.type, message=error.message)
    )
    return context_run_response(
        result,
        stop_reason=stop_reason or turn.stop_reason,
        value=turn.run.result,
        error=cell_error,
    )


ToolboxUser = Annotated[Principal, Depends(require_scopes(Scope.TOOLBOX))]
Uow = Annotated[UnitOfWorkPort, Depends(get_uow)]
Driver = Annotated[SandboxDriver, Depends(get_driver)]
Recorder = Annotated[AuditRecorder, Depends(get_audit_recorder)]


class CodeContextDeleteResponse(BaseModel):
    id: str
    deleted: bool = True


class CodeContextInterruptResponse(BaseModel):
    id: str
    interrupted: bool = Field(
        description="`true` when a cell was running and the context's kernel was sent SIGINT "
        "(the cell raises `KeyboardInterrupt`), `false` when no cell is running or the "
        "context has no live kernel."
    )


class CodeContextRunRequest(RequestModel):
    language: Literal["python"] = "python"
    code: str
    timeout_s: NoBool[int] = Field(
        default=60,
        ge=1,
        le=MAX_TIMEOUT_S,
        description=(
            "Per-cell limit enforced inside the kernel. When control is back in Python, a "
            "timed-out cell raises `TimeoutError` there, the context keeps its state and the "
            "result reports `timed_out`. A cell stuck in native code does not stop at this "
            "limit; later runs queue behind it (up to their `queue_timeout`). Only when the "
            "exec deadline (this limit plus a 5 s margin) passes with the cell still not "
            "answering is the kernel sent an interrupt and given 2 s; if it still does not "
            "answer, the context is stopped and removed only after that 2 s grace, the result "
            "reports `timed_out` and a new context must be created. The kernel's limit is at "
            "most 3595 s, so that the exec timeout fits in 3600 s."
        ),
    )


def _response(info: code_contexts.ContextInfo) -> CodeContextResponse:
    return CodeContextResponse(id=info.id, cwd=info.cwd, name=info.name)


async def _live_sandbox(uow: UnitOfWorkPort, principal: Principal, sandbox_id: str) -> Sandbox:
    """The started sandbox of the caller's org (a read: no audit row)."""
    async with uow:
        return await load_started_sandbox(uow, principal.org_id, sandbox_id, _CLOCK)


@router.post(
    "",
    status_code=201,
    summary="Create a code context",
    description=_CREATE_DESCRIPTION,
    responses={
        200: {
            "model": Envelope[CodeContextResponse],
            "description": "A live context already has the requested `name`: that existing "
            "context is returned instead of a new one. Its `cwd` is kept and the `cwd` of "
            "the request is ignored.",
        }
    },
)
async def create_code_context(
    sandbox_id: str,
    body: CodeContextCreateRequest,
    principal: ToolboxUser,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
    response: Response,
) -> Envelope[CodeContextResponse]:
    details: dict[str, Any] = {"language": body.language, "cwd": body.cwd}
    if body.name is not None:
        details["name"] = body.name
    sandbox = await _started_sandbox(
        uow, recorder, principal, sandbox_id, "toolbox.code_contexts.create", details
    )
    if body.name is None:
        return ok(_response(await code_contexts.create_context(driver, sandbox, cwd=body.cwd)))
    info, created = await _ensure_named(driver, sandbox, body.name, body.cwd)
    if not created:
        response.status_code = 200
    return ok(_response(info))


async def _ensure_named(
    driver: SandboxDriver, sandbox: Sandbox, name: str, cwd: str | None
) -> tuple[code_contexts.ContextInfo, bool]:
    """The live context named ``name`` (``False``) or a new one with that name (``True``).

    Named creates of one sandbox and name take turns on the lock registry of the runs, so two
    concurrent calls in this process get the same context.
    """
    async with _context_turn((sandbox.id, NAME_LOCK_PREFIX + name), NAME_WAIT_S) as acquired:
        if not acquired:
            message = f"another create of code context {name!r} is still starting; retry"
            raise Conflict(message, reason=IN_PROGRESS)
        existing = await code_contexts.find_context(driver, sandbox, name)
        if existing is not None:
            return existing, False
        return await code_contexts.create_context(driver, sandbox, cwd=cwd, name=name), True


ContextName = Annotated[
    str | None,
    Query(
        min_length=1,
        max_length=MAX_NAME_LENGTH,
        pattern=NAME_PATTERN,
        description=CONTEXT_NAME_DESCRIPTION + " Lists only the context of this name.",
    ),
]


NameOnce = Annotated[None, Depends(single_valued("name"))]


@router.get(
    "",
    summary="List code contexts",
    description=_LIST_DESCRIPTION,
)
async def list_code_contexts(
    sandbox_id: str,
    principal: ToolboxUser,
    _known: KnownQuery,
    _once: NameOnce,
    uow: Uow,
    driver: Driver,
    name: ContextName = None,
) -> Envelope[list[CodeContextResponse]]:
    sandbox = await _live_sandbox(uow, principal, sandbox_id)
    contexts = await code_contexts.list_contexts(driver, sandbox, name=name)
    return ok([_response(info) for info in contexts])


@router.delete(
    "/{context_id}",
    summary="Delete a code context",
    description=_DELETE_DESCRIPTION,
)
async def delete_code_context(
    sandbox_id: str,
    context_id: str,
    principal: ToolboxUser,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
) -> Envelope[CodeContextDeleteResponse]:
    sandbox = await _started_sandbox(
        uow,
        recorder,
        principal,
        sandbox_id,
        "toolbox.code_contexts.delete",
        {"context_id": context_id},
    )
    await code_contexts.delete_context(driver, sandbox, context_id)
    return ok(CodeContextDeleteResponse(id=context_id))


@router.post(
    "/{context_id}/interrupt",
    summary="Interrupt the running cell of a code context",
    description=_INTERRUPT_DESCRIPTION,
)
async def interrupt_code_context(
    sandbox_id: str,
    context_id: str,
    principal: ToolboxUser,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
) -> Envelope[CodeContextInterruptResponse]:
    sandbox = await _started_sandbox(
        uow,
        recorder,
        principal,
        sandbox_id,
        "toolbox.code_contexts.interrupt",
        {"context_id": context_id},
    )
    interrupted = await code_contexts.interrupt_context(
        driver, sandbox, context_id, only_running=True
    )
    return ok(CodeContextInterruptResponse(id=context_id, interrupted=interrupted))


@router.post(
    "/{context_id}/run",
    summary="Run a cell in a code context",
    description=_RUN_DESCRIPTION,
)
async def run_in_code_context(
    sandbox_id: str,
    context_id: str,
    request: Request,
    body: CodeContextRunRequest,
    principal: ToolboxUser,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
) -> Envelope[ContextRunResponse]:
    details = {
        "context_id": context_id,
        "language": body.language,
        "code": body.code,
        "timeout_s": body.timeout_s,
    }
    sandbox = await _started_sandbox(
        uow, recorder, principal, sandbox_id, "toolbox.code_contexts.run", details
    )
    finished: list[_Turn] = []
    turn = _run_in_turn(driver, sandbox, context_id, body.code, float(body.timeout_s))
    call = _exec_of(turn, finished)
    outcome = await _run_until_disconnect(
        request, driver, sandbox, call, CELL_GONE_MESSAGES, explained=CELL_EXPLAINED
    )
    turn_done = finished[0] if finished else None
    return ok(_run_response(turn_done, outcome.result, outcome.stop_reason))


def _stop_check(request: Request, sandbox: Sandbox) -> code_context_stream.StopCheck:
    """The stop reason the row now gives, read as the non-streamed result path reads it.

    For the error event of a streamed run whose exec found the sandbox not running:
    ``sandbox_deleted``, ``sandbox_reset``, ``sandbox_stopped`` for a stop by the caller or
    auto-stop, or ``None`` (``_gone_reason``). A row that is missing or cannot be read gives
    ``None``, so the driver's line is kept. The stream maps the reason through
    ``CELL_GONE_MESSAGES``.
    """

    async def stop_reason() -> str | None:
        return await _gone_reason(request, sandbox)

    return stop_reason


async def _stream_frames(
    request: Request,
    driver: SandboxDriver,
    sandbox: Sandbox,
    context_id: str,
    body: CodeContextRunRequest,
) -> AsyncIterator[str]:
    """The SSE frames of one run: its output events, then ``result`` (or ``error``)."""

    async def finish(events: code_context_stream.RunEvents) -> dict[str, Any]:
        runner = code_context_stream.streaming_runner(driver, sandbox, events)
        finished: list[_Turn] = []
        turn = _run_in_turn(driver, sandbox, context_id, body.code, float(body.timeout_s), runner)
        call = _exec_of(turn, finished)
        outcome = await _run_until_disconnect(
            request, driver, sandbox, call, CELL_GONE_MESSAGES, explained=CELL_EXPLAINED
        )
        turn_done = finished[0] if finished else None
        return _run_response(turn_done, outcome.result, outcome.stop_reason).model_dump(mode="json")

    stream = code_context_stream.stream_run(
        finish, _stop_check(request, sandbox), CELL_GONE_MESSAGES
    )
    async with contextlib.aclosing(stream) as events:
        async for name, payload in events:
            yield format_event(payload, event=name)


@router.post(
    "/{context_id}/run/stream",
    summary="Run a cell in a code context and stream its output",
    description=_RUN_STREAM_DESCRIPTION,
)
async def stream_code_context_run(
    sandbox_id: str,
    context_id: str,
    request: Request,
    body: CodeContextRunRequest,
    principal: ToolboxUser,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
) -> StreamingResponse:
    details = {
        "context_id": context_id,
        "language": body.language,
        "code": body.code,
        "timeout_s": body.timeout_s,
    }
    sandbox = await _started_sandbox(
        uow, recorder, principal, sandbox_id, "toolbox.code_contexts.run_stream", details
    )
    await code_context_stream.ensure_context(driver, sandbox, context_id)  # 404 before streaming
    frames = with_keepalive(
        _stream_frames(request, driver, sandbox, context_id, body),
        interval_s=DEFAULT_KEEPALIVE_INTERVAL_S,
    )
    return StreamingResponse(
        frames,
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
