"""``/process/execute`` and ``/process/code-run``.

Each call loads the sandbox in a short unit of work (org scoping, started check,
activity touch), writes the audit row in that same unit of work, closes it, and only
then talks to the driver.
"""

import asyncio
import contextlib
import hashlib
import logging
from collections.abc import Awaitable, Callable, Collection, Mapping
from dataclasses import dataclass, replace
from datetime import timedelta
from typing import Annotated, Any

import anyio
from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel

from sandfort.api.dead_sandbox import settle_dead_sandbox
from sandfort.api.death_probe import schedule_death_probe
from sandfort.api.deps import get_audit_recorder, get_driver, get_uow
from sandfort.api.envelope import Envelope, ok
from sandfort.api.routes.toolbox.scope_guard import require_visible_sandbox
from sandfort.api.safe_json import SafeJSONResponse
from sandfort.api.schemas.toolbox_process import (
    KILLED_EXIT_CODE,
    STOP_REASON_OOM_KILLED,
    STOP_REASON_SANDBOX_DELETED,
    STOP_REASON_SANDBOX_RESET,
    STOP_REASON_SANDBOX_STOPPED,
    CodeRunRequest,
    ExecuteRequest,
    ExecuteResponse,
    execute_response,
)
from sandfort.api.wiring import (
    IDEMPOTENCY_HEADER,
    RECONCILER_ATTR,
    IdempotencyGuard,
    get_idempotency_service,
    single_idempotency_key,
)
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import require_scopes
from sandfort.clock import SystemClock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.events import ActorType, AuditOutcome
from sandfort.domain.org import Scope
from sandfort.domain.reset_events import replaced
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.drivers.base import ExecRequest, ExecResult, OomObservableDriver, SandboxDriver
from sandfort.drivers.docker.exec import SANDBOX_DIED_MESSAGE, SANDBOX_STOPPED_MESSAGE
from sandfort.drivers.errors import DriverConflict
from sandfort.errors import RESULT_UNAVAILABLE, Conflict
from sandfort.logging import current_request_id
from sandfort.services.audit import AuditRecorder
from sandfort.services.idempotency import MAX_KEY_LENGTH, StoredResponse
from sandfort.toolbox import code_run, process
from sandfort.toolbox.guards import load_started_sandbox
from sandfort.workers.reconciler import (
    RESET_EVENTS_READ,
    RESET_SETTLE_S,
    SANDBOX_RESET_ACTION,
    Reconciler,
)

NOT_RUNNING_PHRASE = "is not running"  # the driver conflict for an exec on a dead container
RECHECK_KICK_FIRST_DELAY_S = 1.5  # delayed reconciler kicks after a dead-sandbox signal
RECHECK_KICK_SECOND_DELAY_S = 5.0
DISCONNECT_POLL_INTERVAL_S = 0.5  # how often a running exec checks that its client is still there
CLIENT_GONE_EXIT_CODE = 137  # placeholder result for a cancelled exec; nobody receives it
DELETED_STATES = frozenset({SandboxState.DESTROYING, SandboxState.DESTROYED})
# The stderr line that replaces the driver's death line (an OOM hint) when the row explains it.
# 'sandbox_stopped' here is a stop by the caller or by auto-stop, not a death under a limit.
GONE_MESSAGES = {
    STOP_REASON_SANDBOX_DELETED: b"the sandbox was deleted while running this command",
    STOP_REASON_SANDBOX_RESET: b"the sandbox was reset while running this command",
    STOP_REASON_SANDBOX_STOPPED: SANDBOX_STOPPED_MESSAGE,
}
# The stderr line added to an exec the driver reports as out-of-memory killed. Not in
# ``GONE_MESSAGES``: an OOM answer is kept for replay like any other death under a limit.
OOM_KILLED_MESSAGE = b"the process was killed because the sandbox ran out of memory"
# Keyed exec (Idempotency-Key): the outcome reasons for which the key is released. They are the
# reasons the service reports from the row (``ExecOutcome.stop_reason``): an explicit stop, reset
# or delete. A ``sandbox_stopped`` the driver derives from a death under a limit, while the row
# still reads started, carries no outcome reason: that answer is stored and the key stays pinned.
GONE_STOP_REASONS = frozenset(GONE_MESSAGES)
EXEC_KEY_PREFIX = "exec:"
REPLAY_ACTION = "sandbox.exec.replay"
MAX_KEPT_OUTPUT_BYTES = 256 * 1024  # stdout plus stderr of an answer kept for replay
STORED_ANSWER = "answer"
STORED_REQUEST_ID = "request_id"
STORED_UNAVAILABLE = "result_unavailable"
RESULT_UNAVAILABLE_MESSAGE = (
    "this command already ran; its output was too large to keep for replay"
    "; use a new Idempotency-Key to run it again"
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ExecOutcome:
    """A finished exec and, when the row explains a sandbox death, the stop reason to report.

    ``client_gone`` marks the placeholder of an exec cancelled because its client disconnected.
    """

    result: ExecResult
    stop_reason: str | None = None
    client_gone: bool = False


router = APIRouter(
    prefix="/v1/sandboxes/{sandbox_id}/toolbox/process",
    tags=["toolbox"],
    dependencies=[Depends(require_visible_sandbox)],
)

_CLOCK = SystemClock()

ToolboxUser = Annotated[Principal, Depends(require_scopes(Scope.TOOLBOX))]
Uow = Annotated[UnitOfWorkPort, Depends(get_uow)]
Driver = Annotated[SandboxDriver, Depends(get_driver)]
Recorder = Annotated[AuditRecorder, Depends(get_audit_recorder)]
OK_STATUS = 200


def sandbox_scoped_key(sandbox_id: str, generation: str, key: str) -> str:
    """The key the guard sees: ``exec:``, the sandbox id, and a sha256 of generation and key.

    ``generation`` names the sandbox's current run (``_generation``), which a reset or a new
    start replaces: an answer stored before it is never found again, so the command runs. The
    ``exec:`` prefix keeps the slot apart from create keys; two sandboxes never share one. The
    hash keeps the result inside the service's length limit for any key it accepts; a key the
    service rejects (empty, too long) is passed on unchanged so the guard refuses it.
    """
    if not 0 < len(key) <= MAX_KEY_LENGTH:
        return key
    digest = hashlib.sha256(f"{generation}\n{key}".encode()).hexdigest()
    return f"{EXEC_KEY_PREFIX}{sandbox_id}:{digest}"


def _generation(sandbox: Sandbox, last_reset_id: str) -> str:
    """The sandbox's current run: ``driver_ref``, ``started_at`` and the last reset's audit id.

    A reset replaces the container (a new ``driver_ref`` on the docker driver) and, for a
    started sandbox, sets ``started_at``; every start sets ``started_at`` too. Neither is enough
    alone: a driver may reuse its ref, and two resets inside one clock tick share a time. The row
    has no reset counter (``version`` moves on every activity touch, so it cannot name a run),
    so the id of the newest ``sandbox.reset`` audit event stands in: the reset writes it with its
    intent, ids only grow, and every reset adds one, whatever the clock says.
    """
    started = "" if sandbox.started_at is None else sandbox.started_at.isoformat()
    return f"{sandbox.driver_ref or ''}@{started}#{last_reset_id}"


def _key_header(operation: str, what: str) -> Any:
    return Header(
        alias=IDEMPOTENCY_HEADER,
        min_length=1,
        max_length=MAX_KEY_LENGTH,
        description=f"Makes the {operation} safe to retry: the same key and body replays the "
        f"first response without {what} again; the same key with another body answers 422. "
        "1 to 255 characters; an empty or longer key answers 422 VALIDATION_ERROR.",
    )


def exec_idempotency_key(
    request: Request,
    idempotency_key: Annotated[str | None, _key_header("exec", "running the command")] = None,
) -> str | None:
    """The caller's ``Idempotency-Key``; ``None`` without the header (nothing else changes).

    The header given twice with different values is a 422.
    """
    return single_idempotency_key(request, idempotency_key)


def code_run_idempotency_key(
    request: Request,
    idempotency_key: Annotated[str | None, _key_header("code run", "running the code")] = None,
) -> str | None:
    """The caller's ``Idempotency-Key`` for a code run (same rules as ``exec``)."""
    return single_idempotency_key(request, idempotency_key)


ExecIdempotencyKey = Annotated[str | None, Depends(exec_idempotency_key)]
CodeRunIdempotencyKey = Annotated[str | None, Depends(code_run_idempotency_key)]


class IdempotencyResultUnavailable(Conflict):
    """The keyed command already ran, but its answer was not kept for replay."""

    code = "IDEMPOTENCY_RESULT_UNAVAILABLE"

    def __init__(self, message: str) -> None:
        super().__init__(message, reason=RESULT_UNAVAILABLE)


class UnkeptAnswer(Exception):
    """Raised inside the guard so the key is released: the answer must not be replayed.

    The client left while the exec ran, or the row says the sandbox went away under it (stopped
    by a caller or auto-stop, deleted, reset): a retry must run the command again. A death the
    driver reports while the row still reads started is not this: that answer is stored.
    """

    def __init__(self, envelope: Envelope[ExecuteResponse]) -> None:
        super().__init__("answer not kept")
        self.envelope = envelope


def _kept_answer(status: int, body: dict[str, Any]) -> StoredResponse:
    """What is stored for an exec answer: the answer, or a marker when the output is large.

    The answer is kept only when it is not truncated and stdout plus stderr (UTF-8 of the
    response text) are at most ``MAX_KEPT_OUTPUT_BYTES``; otherwise only a marker is kept, so
    the key stays pinned (the command does not run twice) but no output outlives the request.
    The id of the request that ran the command is stored with either.
    """
    data = body.get("data")
    output = data if isinstance(data, dict) else {}
    size = sum(len(str(output.get(name) or "").encode()) for name in ("stdout", "stderr"))
    kept: dict[str, Any] = {STORED_REQUEST_ID: current_request_id()}
    if output.get("truncated") or size > MAX_KEPT_OUTPUT_BYTES:
        return StoredResponse(status, {**kept, STORED_UNAVAILABLE: True})
    return StoredResponse(status, {**kept, STORED_ANSWER: body})


async def _replay_answer(
    request: Request,
    recorder: AuditRecorder,
    principal: Principal,
    sandbox_id: str,
    stored: StoredResponse,
) -> StoredResponse:
    """Audit the replay (``sandbox.exec.replay``), then the stored answer or the marker's 409.

    A replay of the marker got no output: it is audited ``denied`` with ``reason``
    ``result_unavailable``; a replayed answer is ``success``.
    """
    answer = stored.body.get(STORED_ANSWER)
    unavailable = not isinstance(answer, dict)
    details: dict[str, Any] = {"original_request_id": stored.body.get(STORED_REQUEST_ID)}
    if unavailable:
        details["reason"] = RESULT_UNAVAILABLE
    async with get_uow(request) as uow:
        await recorder.record(
            uow,
            org_id=principal.org_id,
            actor_type=ActorType.API_KEY,
            actor_id=principal.key_id,
            action=REPLAY_ACTION,
            target_type="sandbox",
            target_id=sandbox_id,
            outcome=AuditOutcome.DENIED if unavailable else AuditOutcome.SUCCESS,
            details=details,
        )
        await uow.commit()
    if not isinstance(answer, dict):
        raise IdempotencyResultUnavailable(RESULT_UNAVAILABLE_MESSAGE)
    return StoredResponse(stored.status, answer)


async def _exec_guard(
    sandbox_id: str,
    request: Request,
    principal: Principal,
    recorder: AuditRecorder,
    idempotency_key: str,
) -> IdempotencyGuard:
    """The guard for a keyed exec, built only for a sandbox that exists and is started.

    A missing, deleted or stopped sandbox answers its normal error before any key is looked
    up, so nothing is replayed for it and no key is claimed. The slot carries the sandbox's
    generation (see ``sandbox_scoped_key``), so a reset sandbox runs the command again.

    The generation is read here, before the command runs. A reset that lands between this read
    and the execution leaves the slot under the old generation, so the answer is stored there:
    the command ran in the new container, but a retry reads the new generation, misses the slot
    and runs again. That is a rerun, never a leak: an answer is never replayed into a
    generation it did not come from.
    """
    async with get_uow(request) as uow:
        sandbox = await load_started_sandbox(uow, principal.org_id, sandbox_id, _CLOCK)
        resets = await uow.audit.list(
            principal.org_id,
            action=SANDBOX_RESET_ACTION,
            target_id=sandbox_id,
            limit=1,
            order="desc",
        )
    last_reset_id = resets[0].id if resets else ""
    key = sandbox_scoped_key(sandbox_id, _generation(sandbox, last_reset_id), idempotency_key)

    async def replay(stored: StoredResponse) -> StoredResponse:
        return await _replay_answer(request, recorder, principal, sandbox_id, stored)

    service = get_idempotency_service(request)
    return IdempotencyGuard(service, key, request, keep=_kept_answer, replay=replay)


async def _started_sandbox(
    uow: UnitOfWorkPort,
    recorder: AuditRecorder,
    principal: Principal,
    sandbox_id: str,
    action: str,
    details: dict[str, Any],
) -> Sandbox:
    """Guard the sandbox, then audit the call (redacted) before the driver is touched."""
    async with uow:
        sandbox = await load_started_sandbox(uow, principal.org_id, sandbox_id, _CLOCK)
        await recorder.record(
            uow,
            org_id=principal.org_id,
            actor_type=ActorType.API_KEY,
            actor_id=principal.key_id,
            action=action,
            target_type="sandbox",
            target_id=sandbox_id,
            details=details,
        )
        await uow.commit()
        return sandbox


def _kick_reconciler(request: Request) -> None:
    """Ask the reconciler for an immediate pass, then re-kick it after short delays.

    The runtime often still reports the container as running at the instant the exec saw it
    die, so the immediate pass can find no drift. The delayed kicks are scheduled on the
    running event loop (the request never waits for them). Nothing happens when no reconciler
    is wired.
    """
    reconciler = getattr(request.app.state, RECONCILER_ATTR, None)
    if not isinstance(reconciler, Reconciler):
        return
    reconciler.kick()
    loop = asyncio.get_running_loop()
    for delay_s in (RECHECK_KICK_FIRST_DELAY_S, RECHECK_KICK_SECOND_DELAY_S):
        loop.call_later(delay_s, reconciler.kick)


async def _on_death(request: Request, driver: SandboxDriver, sandbox: Sandbox) -> None:
    if not await settle_dead_sandbox(request, driver, sandbox):
        _kick_reconciler(request)


def _stopped_on_purpose(row: Sandbox) -> bool:
    """``True`` when the caller or auto-stop stopped the sandbox (not the reconciler's settle).

    Both move the row to ``stopping`` first; a stop that already finished is ``stopped`` with no
    ``error_code``, while a death the reconciler settled is ``stopped`` with one.
    """
    if row.state is SandboxState.STOPPING:
        return True
    return row.state is SandboxState.STOPPED and row.error_code is None


async def _gone_reason(request: Request, sandbox: Sandbox) -> str | None:
    """Why the row says the exec's sandbox went away; ``None`` when it does not say.

    ``sandbox_deleted``, ``sandbox_reset``, or ``sandbox_stopped`` for a stop by the caller or by
    auto-stop (``_stopped_on_purpose``). A row that is destroying or destroyed was deleted; a row
    whose ``driver_ref`` differs from the one the exec ran against had its container replaced by
    a reset. A reset updates the row only after it created the new container, so an exec it cut
    short usually ends while the row still has the old ``driver_ref``: then a ``sandbox.reset``
    audit event from the last ``RESET_SETTLE_S`` seconds whose ``previous_driver_ref`` is the
    ref the exec ran against also means ``sandbox_reset``. A stop is checked last, so a delete
    or a reset wins. Any failure to read the row or the events returns ``None``, so the caller
    keeps reporting a plain ``sandbox_stopped`` with the driver's limit wording.
    """
    try:
        async with get_uow(request) as uow:
            current = await uow.sandboxes.get(sandbox.org_id, sandbox.id)
            if current is None:
                return None
            if current.state in DELETED_STATES:
                return STOP_REASON_SANDBOX_DELETED
            if current.driver_ref != sandbox.driver_ref:
                return STOP_REASON_SANDBOX_RESET
            events = await uow.audit.list(
                sandbox.org_id,
                action=SANDBOX_RESET_ACTION,
                target_id=sandbox.id,
                since=_CLOCK.now() - timedelta(seconds=RESET_SETTLE_S),
                limit=RESET_EVENTS_READ,
            )
    except Exception:
        logger.exception("could not re-read sandbox %s after its exec died", sandbox.id)
        return None
    if replaced([event.details for event in events], sandbox.driver_ref):
        return STOP_REASON_SANDBOX_RESET
    if _stopped_on_purpose(current):
        return STOP_REASON_SANDBOX_STOPPED
    return None


def _explain_gone(
    result: ExecResult,
    reason: str,
    messages: Mapping[str, bytes] = GONE_MESSAGES,
    *,
    explained: Collection[bytes] = (),
) -> ExecResult:
    """``result`` with the driver's death line (an OOM hint) replaced by the line for ``reason``.

    ``messages`` maps a reason to its line (``GONE_MESSAGES``; a cell run passes its own).

    Exit code and ``sandbox_stopped`` are kept, so existing clients see the same flags. When the
    driver wrote no death line, the new line is appended on a line of its own; for a stop, only
    when the result is a bare kill: a ``sandbox_stopped`` result without the driver's line was
    already reworded (a vanished container, named by a code-context run). ``explained`` lists
    such rewordings: a ``sandbox_stopped`` result whose stderr has one gets no line for any
    reason, so the line is not said twice.
    """
    line = messages[reason]
    if SANDBOX_DIED_MESSAGE in result.stderr:
        return replace(result, stderr=result.stderr.replace(SANDBOX_DIED_MESSAGE, line))
    if result.sandbox_stopped and (
        reason == STOP_REASON_SANDBOX_STOPPED or any(done in result.stderr for done in explained)
    ):
        return result
    separator = b"\n" if result.stderr and not result.stderr.endswith(b"\n") else b""
    return replace(result, stderr=result.stderr + separator + line)


def _is_bare_kill(result: ExecResult) -> bool:
    """``True`` for a plain SIGKILL exit: no timeout, no output limit, no death flag."""
    return (
        result.exit_code == KILLED_EXIT_CODE
        and not result.timed_out
        and not result.truncated
        and not result.sandbox_stopped
    )


async def _container_oom_killed(driver: SandboxDriver, sandbox: Sandbox) -> bool:
    """``True`` when the driver can see that the sandbox's dead container was OOM-killed.

    ``False`` for a driver or tier that cannot tell, a running container, or any failure.
    """
    if not isinstance(driver, OomObservableDriver) or not sandbox.driver_ref:
        return False
    try:
        return await driver.container_oom_killed(sandbox.driver_ref)
    except Exception:
        logger.exception("could not read the OOM verdict of sandbox %s", sandbox.id)
        return False


def _with_oom_line(result: ExecResult) -> ExecResult:
    """``result`` with the driver's death line replaced by (or the result given) the OOM line."""
    if SANDBOX_DIED_MESSAGE in result.stderr:
        return replace(
            result, stderr=result.stderr.replace(SANDBOX_DIED_MESSAGE, OOM_KILLED_MESSAGE)
        )
    separator = b"\n" if result.stderr and not result.stderr.endswith(b"\n") else b""
    return replace(result, stderr=result.stderr + separator + OOM_KILLED_MESSAGE)


async def _oom_outcome(
    request: Request, driver: SandboxDriver, sandbox: Sandbox, result: ExecResult
) -> ExecOutcome | None:
    """The ``oom_killed`` outcome when the driver saw an out-of-memory kill; else ``None``.

    A container that died of it is settled like any other dead sandbox (the reconciler reads
    the same verdict and stores ``stop_cause`` ``oom_killed``) and the result is marked
    ``sandbox_stopped``. A process the kernel killed (``result.oom_killed``) leaves the
    sandbox running, so nothing is settled.
    """
    if await _container_oom_killed(driver, sandbox):
        await _on_death(request, driver, sandbox)
        worded = _with_oom_line(result)
        return ExecOutcome(replace(worded, sandbox_stopped=True), STOP_REASON_OOM_KILLED)
    if result.oom_killed:
        return ExecOutcome(_with_oom_line(result), STOP_REASON_OOM_KILLED)
    return None


async def _run_watching_death(
    request: Request,
    driver: SandboxDriver,
    sandbox: Sandbox,
    call: Awaitable[ExecResult],
    messages: Mapping[str, bytes] = GONE_MESSAGES,
    *,
    explained: Collection[bytes] = (),
) -> ExecOutcome:
    """Await ``call``; a dead sandbox (result flag or not-running conflict) is settled first.

    A ``sandbox_stopped`` result, and a bare kill (exit 137 that is not a timeout, not
    truncated and not ``sandbox_stopped``; the driver sometimes cannot tell a cut-short exec
    from a plain SIGKILL), is first checked against the row: a sandbox deleted or reset
    meanwhile did not die unexpectedly, so it is neither settled nor reconciled and the outcome
    names the reason; the same holds for one the caller or auto-stop stopped (stderr says so,
    the reason stays ``sandbox_stopped``). For a bare kill the result is also marked
    ``sandbox_stopped`` (the sandbox did die; the response only keeps a deleted/reset reason on
    a stopped result). When the row
    names no reason, a bare kill is returned unchanged with no settle and no kick, and a
    ``sandbox_stopped`` result has the row marked stopped before returning when the runtime
    agrees, or the reconciler kicked, and is returned unchanged. An error is raised unchanged.
    ``messages`` gives the line for each reason, ``explained`` the lines that already explain
    a result (see ``_explain_gone``). When no such reason applies and the driver saw an
    out-of-memory kill (the container died of it, or the kernel killed the process), the
    outcome names ``oom_killed`` (see ``_oom_outcome``).
    """
    try:
        result = await call
    except DriverConflict as exc:
        if NOT_RUNNING_PHRASE in exc.classification_text:
            await _on_death(request, driver, sandbox)
        raise
    if not (result.sandbox_stopped or _is_bare_kill(result)):
        schedule_death_probe(request, driver, sandbox)  # a death after a normal answer
        return ExecOutcome(result)
    reason = await _gone_reason(request, sandbox)
    if reason is not None:
        logger.info("sandbox %s: exec ended because of %s", sandbox.id, reason)
        worded = _explain_gone(result, reason, messages, explained=explained)
        return ExecOutcome(replace(worded, sandbox_stopped=True), reason)
    if (oom := await _oom_outcome(request, driver, sandbox, result)) is not None:
        return oom
    if result.sandbox_stopped:
        await _on_death(request, driver, sandbox)
    else:
        schedule_death_probe(request, driver, sandbox)
    return ExecOutcome(result)


async def _watch_disconnect(request: Request) -> None:
    """Return once the client has gone away (polled; Starlette does not cancel the handler)."""
    while not await request.is_disconnected():
        await asyncio.sleep(DISCONNECT_POLL_INTERVAL_S)


async def _run_until_disconnect(
    request: Request,
    driver: SandboxDriver,
    sandbox: Sandbox,
    call: Awaitable[ExecResult],
    messages: Mapping[str, bytes] = GONE_MESSAGES,
    *,
    explained: Collection[bytes] = (),
) -> ExecOutcome:
    """Run ``call`` under the death watch; cancel it when the client disconnects first.

    Cancelling the exec makes the driver's exec stream kill the process tree. A connected
    client gets the result or the error exactly as ``_run_watching_death`` produces them. When
    the client is gone the response is never delivered, so a placeholder result is returned.
    When this helper is itself cancelled, the exec is cancelled and awaited (shielded) before
    the cancellation goes on, so its cleanup (a cell interrupt, a lock release) is finished by
    the time the helper returns.
    """
    watched = _run_watching_death(request, driver, sandbox, call, messages, explained=explained)
    exec_task = asyncio.create_task(watched)
    watcher = asyncio.create_task(_watch_disconnect(request))
    try:
        await asyncio.wait({exec_task, watcher}, return_when=asyncio.FIRST_COMPLETED)
        if exec_task.done():
            return exec_task.result()
        exec_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await exec_task
        logger.info("client disconnected; exec cancelled (sandbox %s)", sandbox.id)
        return ExecOutcome(ExecResult(exit_code=CLIENT_GONE_EXIT_CODE), client_gone=True)
    finally:
        watcher.cancel()  # no-op for a finished task; stops the loser
        if not exec_task.done():  # an abandoned exec: this helper itself was cancelled
            exec_task.cancel()
            with anyio.CancelScope(shield=True), contextlib.suppress(asyncio.CancelledError):
                await exec_task


@router.post("/execute", response_model=Envelope[ExecuteResponse])
async def execute_command(
    sandbox_id: str,
    request: Request,
    body: ExecuteRequest,
    principal: ToolboxUser,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
    idempotency_key: ExecIdempotencyKey,
) -> Envelope[ExecuteResponse] | SafeJSONResponse:
    """Run a command in the sandbox and wait for its result.

    With an `Idempotency-Key` header the same key and body replays the first response and the
    command does not run again; the key is kept for one day (24 hours) after the response is
    stored. The same key with another body answers 422; a body is compared as the API reads it,
    so spelling a default out (`timeout_s` 60 or 60.0, `"env": {}`, `"stdin": null`) is the same
    body. The key belongs to the API key and the sandbox, and a failed attempt does not keep it.
    Replays carry `Idempotent-Replayed: true` and are audited as `sandbox.exec.replay`.

    A replay needs the sandbox started, as a first run does; after a reset of the sandbox, or a
    stop and a new start, the command runs again. A result cut short by a stop, delete or reset
    of the sandbox (`stop_reason` `sandbox_stopped`, `sandbox_deleted` or `sandbox_reset`, as
    the service reads it from the sandbox) is not kept, so a retry runs the command. A
    `sandbox_stopped` that only reports a death under a limit, while the sandbox still reads
    started, is kept like any other answer. When stdout plus stderr exceed
    256 KiB or the output was truncated, the output is not kept: a retry answers 409
    `IDEMPOTENCY_RESULT_UNAVAILABLE` and the command does not run again; that replay is audited
    `denied` with reason `result_unavailable`.

    The command runs at most once per server process while it runs; after a crash between the
    command finishing and the answer being stored, a retry may run it again.
    """

    async def outcome() -> ExecOutcome:
        return await _execute(sandbox_id, request, body, principal, uow, driver, recorder)

    return await _answer(sandbox_id, request, body, principal, recorder, idempotency_key, outcome)


async def _answer(
    sandbox_id: str,
    request: Request,
    body: BaseModel,
    principal: Principal,
    recorder: AuditRecorder,
    idempotency_key: str | None,
    run_command: Callable[[], Awaitable[ExecOutcome]],
) -> Envelope[ExecuteResponse] | SafeJSONResponse:
    """Run a command (exec or code run), once per ``Idempotency-Key`` when one is given."""
    keyed = idempotency_key is not None
    produced: list[Envelope[ExecuteResponse]] = []

    async def run() -> Envelope[ExecuteResponse]:
        outcome = await run_command()
        response = execute_response(outcome.result, stop_reason=outcome.stop_reason)
        envelope = ok(response)
        if keyed and (outcome.client_gone or outcome.stop_reason in GONE_STOP_REASONS):
            raise UnkeptAnswer(envelope)  # the guard releases the key and stores nothing
        produced.append(envelope)
        return envelope

    if idempotency_key is None:
        return await run()
    guard = await _exec_guard(sandbox_id, request, principal, recorder, idempotency_key)
    try:
        return await guard.run(principal.org_id, OK_STATUS, run, request_model=body)
    except UnkeptAnswer as unkept:
        return unkept.envelope  # the command was cut short, so a retry may run it
    except Exception:
        if not produced:
            raise
        # The command ran; only keeping its answer failed. Answer it: failing the request would
        # make the client retry a command that already ran. The key is not pinned then.
        logger.exception("command ran but its answer could not be stored (sandbox %s)", sandbox_id)
        return produced[0]


async def _execute(
    sandbox_id: str,
    request: Request,
    body: ExecuteRequest,
    principal: Principal,
    uow: UnitOfWorkPort,
    driver: SandboxDriver,
    recorder: AuditRecorder,
) -> ExecOutcome:
    details = {
        "command": body.command,
        "args": body.argv,
        "cwd": body.cwd,
        "env": body.env,
        "stdin": body.stdin,
        "timeout_s": body.timeout_s,
    }
    sandbox = await _started_sandbox(
        uow, recorder, principal, sandbox_id, "toolbox.process.execute", details
    )
    argv = body.argv if body.argv is not None else ["sh", "-c", body.command or ""]
    exec_request = ExecRequest(
        argv=argv,
        cwd=body.cwd,
        env=body.env,
        stdin=None if body.stdin is None else body.stdin.encode(),
        timeout_s=float(body.timeout_s),
    )
    return await _run_until_disconnect(
        request, driver, sandbox, process.execute(driver, sandbox, exec_request)
    )


@router.post("/code-run", response_model=Envelope[ExecuteResponse])
async def run_code(
    sandbox_id: str,
    request: Request,
    body: CodeRunRequest,
    principal: ToolboxUser,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
    idempotency_key: CodeRunIdempotencyKey,
) -> Envelope[ExecuteResponse] | SafeJSONResponse:
    """Run a snippet of code in the sandbox and wait for its result.

    `Idempotency-Key` works as on `/process/execute`: the same key and body replays the first
    response without running the code again, another body answers 422, the key belongs to the
    API key and the sandbox, and replays carry `Idempotent-Replayed: true`.
    """

    async def outcome() -> ExecOutcome:
        return await _run_code(sandbox_id, request, body, principal, uow, driver, recorder)

    return await _answer(sandbox_id, request, body, principal, recorder, idempotency_key, outcome)


async def _run_code(
    sandbox_id: str,
    request: Request,
    body: CodeRunRequest,
    principal: Principal,
    uow: UnitOfWorkPort,
    driver: SandboxDriver,
    recorder: AuditRecorder,
) -> ExecOutcome:
    details = {
        "language": body.language,
        "code": body.code,
        "args": body.argv,
        "cwd": body.cwd,
        "env": body.env,
        "timeout_s": body.timeout_s,
    }
    sandbox = await _started_sandbox(
        uow, recorder, principal, sandbox_id, "toolbox.process.code_run", details
    )
    return await _run_until_disconnect(
        request,
        driver,
        sandbox,
        code_run.run_code(
            driver,
            sandbox,
            body.language,
            body.code,
            argv=body.argv,
            env=body.env,
            timeout_s=float(body.timeout_s),
            cwd=body.cwd,
        ),
    )
