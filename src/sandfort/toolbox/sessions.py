"""Exec sessions: a persisted working directory and environment around single shell commands.

Every command runs as ``[sh, -c, script]``. The script removes the session's private cwd file,
changes into the stored cwd, exports the stored env, installs an ``EXIT`` trap that writes
``pwd`` into that file (stdout and stderr of the command are untouched) and ``eval``s the user
command. After the command the service ``cat``s the file and stores the directory as the
session's new cwd. A command that fails to ``cd`` leaves no file, so the stored cwd is kept.

Like the process toolbox, each call guards the sandbox and writes its audit row in one short
unit of work, closes it, and only then talks to the driver. Asynchronous commands persist a
``running`` row first; a background task pumps driver output into the in-process log store and
records the exit. Kill cancels that task (the driver kills the process tree when its output
stream is abandoned) and marks the row ``killed``. Concurrent commands in one session race on
the cwd file and the last one to finish wins. An org runs at most ``max_running_per_org`` async
commands per process: the slot is held before any row is written and freed when the pump ends.

A command whose sandbox was stopped on purpose while it ran (the driver reports the sandbox
gone and the row is ``stopping``, or ``stopped`` without an error code) is recorded ``killed``
with no exit code, like a kill, and reads ``stop_cause`` ``sandbox_stopped``. The cause is
remembered in memory only (the row has no column for it): after a server restart such a command
still reads ``killed`` with no exit code, but ``stop_cause`` is null. The memory is per process,
so it is not shared between workers either. The cause is kept only when the finish step itself
recorded the stop; a user kill that wins the finish leaves ``killed`` with a null cause.
"""

import asyncio
import logging
import shlex
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace

from sandfort.auth.principal import Principal
from sandfort.clock import Clock
from sandfort.db.models.exec import ExecCommandState, ExecSessionState
from sandfort.db.repositories.ports import ExecCommandRecord, ExecSessionRecord, UnitOfWorkPort
from sandfort.domain.events import ActorType
from sandfort.domain.sandbox import Sandbox, SandboxState, visible_stop_cause
from sandfort.drivers.base import ExecRequest, ExecResult, OutputChunk, SandboxDriver
from sandfort.drivers.docker.exec import SANDBOX_DIED_MESSAGE
from sandfort.errors import CLOSED, Conflict, NotFound, Unprocessable, no_container_conflict
from sandfort.ids import JOB, new_id
from sandfort.toolbox import command_logs, process, stop_wording
from sandfort.toolbox.command_logs import STDERR, STDOUT, CommandLog, CommandLogStore
from sandfort.toolbox.guards import load_started_sandbox
from sandfort.toolbox.pty import AuditSink, OrgSlots

logger = logging.getLogger(__name__)

SHELL = "sh"
SESSION_PREFIX = "ses"
COMMAND_PREFIX = "cmd"
CWD_FILE_TEMPLATE = "/tmp/.sf-session-{session_id}.cwd"
CWD_READ_TIMEOUT_S = 10.0
MAX_CWD_BYTES = 4096
FAILED_EXIT_CODE = -1
STOP_CAUSE_SANDBOX_STOPPED = "sandbox_stopped"
MAX_REMEMBERED_STOPS = 10_000

type UowFactory = Callable[[], UnitOfWorkPort]


def new_session_id() -> str:
    return _prefixed_id(SESSION_PREFIX)


def new_command_id() -> str:
    return _prefixed_id(COMMAND_PREFIX)


def _prefixed_id(prefix: str) -> str:
    """Time-sortable id with a session/command prefix (the shared id module has no such prefix)."""
    return f"{prefix}_{new_id(JOB).partition('_')[2]}"


def compose_script(command: str, cwd: str | None, env: Mapping[str, str], cwd_file: str) -> str:
    """The ``sh -c`` script that wraps ``command`` with the session's cwd and env."""
    trap_body = f"__sf_rc=$?; pwd > {shlex.quote(cwd_file)} 2>/dev/null; exit $__sf_rc"
    lines = [f"rm -f -- {shlex.quote(cwd_file)}"]
    if cwd:
        lines.append(f"cd -- {shlex.quote(cwd)} || exit 1")
    lines.extend(f"export {name}={shlex.quote(value)}" for name, value in env.items())
    lines.append(f"trap {shlex.quote(trap_body)} EXIT")
    lines.append(f"eval {shlex.quote(command)}")
    return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class SessionExecOutcome:
    """A finished synchronous ``result`` or the freshly started asynchronous ``command``."""

    cwd: str | None
    result: ExecResult | None = None
    command: ExecCommandRecord | None = None


class SessionRuntime:
    """Process-wide state shared by all requests: command logs, pump tasks and org slots."""

    def __init__(self, max_running_per_org: int = 0) -> None:
        self.logs = CommandLogStore()
        self.tasks: dict[str, asyncio.Task[None]] = {}
        self.slots = OrgSlots(max_running_per_org, "running async commands")
        self._stopped: dict[str, None] = {}  # command ids a sandbox stop ended, oldest first

    def log_for(self, command: ExecCommandRecord) -> CommandLog:
        """The live log, or an empty finished one when the output is no longer in memory."""
        return self.logs.get(command.id) or CommandLog.closed(command.state, command.exit_code)

    def mark_stopped(self, command_id: str) -> None:
        """Remember that a sandbox stop ended this command (bounded: the oldest are dropped)."""
        self._stopped[command_id] = None
        while len(self._stopped) > MAX_REMEMBERED_STOPS:
            del self._stopped[next(iter(self._stopped))]

    def unmark_stopped(self, command_id: str) -> None:
        """Withdraw a stop mark whose finish did not record the stop (a kill won)."""
        self._stopped.pop(command_id, None)

    def stop_cause_of(self, command_id: str, state: str | None) -> str | None:
        """``sandbox_stopped`` for a killed command a sandbox stop ended; ``None`` otherwise."""
        if state == ExecCommandState.KILLED.value and command_id in self._stopped:
            return STOP_CAUSE_SANDBOX_STOPPED
        return None

    def discard(self, command_id: str) -> None:
        """Drop the command's log and its stop mark (its session was deleted)."""
        self.logs.discard(command_id)
        self._stopped.pop(command_id, None)

    def forget(self, command_id: str) -> None:
        """The command's pump ended (or never started): drop its task and free its slot."""
        self.tasks.pop(command_id, None)
        self.slots.release(command_id)


class SessionService:
    def __init__(
        self,
        uow_factory: UowFactory,
        driver: SandboxDriver,
        recorder: AuditSink,
        clock: Clock,
        runtime: SessionRuntime,
    ) -> None:
        self._uow_factory = uow_factory
        self._driver = driver
        self._recorder = recorder
        self._clock = clock
        self._runtime = runtime

    # -- sessions ---------------------------------------------------------------------

    async def create_session(
        self, principal: Principal, sandbox_id: str, cwd: str | None, env: Mapping[str, str]
    ) -> ExecSessionRecord:
        process.validate_env(env)
        if cwd is not None and not cwd.startswith("/"):
            raise Unprocessable("session cwd must be an absolute path")
        session_id = new_session_id()
        async with self._uow_factory() as uow:
            await load_started_sandbox(uow, principal.org_id, sandbox_id, self._clock)
            await self._audit(
                uow,
                principal,
                sandbox_id,
                "toolbox.session.create",
                {"session_id": session_id, "cwd": cwd, "env": dict(env)},
            )
            now = self._clock.now()
            record = ExecSessionRecord(
                id=session_id,
                org_id=principal.org_id,
                sandbox_id=sandbox_id,
                cwd=cwd,
                env=dict(env),
                state=ExecSessionState.ACTIVE.value,
                created_at=now,
                updated_at=now,
            )
            await uow.exec_sessions.add(record)
            await uow.commit()
        return record

    async def list_sessions(self, org_id: str, sandbox_id: str) -> list[ExecSessionRecord]:
        async with self._uow_factory() as uow:
            if await uow.sandboxes.get(org_id, sandbox_id) is None:
                raise NotFound(f"sandbox {sandbox_id} not found")
            return list(await uow.exec_sessions.list_for_sandbox(org_id, sandbox_id))

    async def get_session(self, org_id: str, sandbox_id: str, session_id: str) -> ExecSessionRecord:
        async with self._uow_factory() as uow:
            return await self._session_in(uow, org_id, sandbox_id, session_id)

    async def delete_session(
        self, principal: Principal, sandbox_id: str, session_id: str
    ) -> ExecSessionRecord:
        """Close the session, kill its running commands and remove it with its command rows.

        Works on a stopped sandbox too (only the sandbox must exist). The session is closed
        first, so no new command starts in it while the running ones are killed. A second
        delete finds no session and answers not found.
        """
        async with self._uow_factory() as uow:
            if await uow.sandboxes.get(principal.org_id, sandbox_id) is None:
                raise NotFound(f"sandbox {sandbox_id} not found")
            session = await self._session_in(uow, principal.org_id, sandbox_id, session_id)
            closed = await uow.exec_sessions.set_state(
                principal.org_id, session_id, ExecSessionState.CLOSED.value, self._clock.now()
            )
            commands = await uow.exec_commands.list_for_session(principal.org_id, session_id)
            running = [c.id for c in commands if c.state == ExecCommandState.RUNNING.value]
            await self._audit(
                uow,
                principal,
                sandbox_id,
                "toolbox.session.delete",
                {"session_id": session_id, "killed_commands": running},
            )
            await uow.commit()
        await self._stop_pumps(running)
        async with self._uow_factory() as uow:
            commands = await uow.exec_commands.list_for_session(principal.org_id, session_id)
            await uow.exec_commands.delete_for_session(principal.org_id, session_id)
            await uow.exec_sessions.delete(principal.org_id, session_id)
            await uow.commit()
        for command in commands:
            self._runtime.discard(command.id)
        await self._remove_cwd_file(sandbox_id, principal.org_id, session_id)
        return closed or session

    # -- commands ---------------------------------------------------------------------

    async def execute(
        self,
        principal: Principal,
        sandbox_id: str,
        session_id: str,
        command: str,
        *,
        run_async: bool,
        timeout_s: int,
    ) -> SessionExecOutcome:
        command_id = new_command_id()
        details = {
            "session_id": session_id,
            "command_id": command_id,
            "command": command,
            "mode": "async" if run_async else "sync",
            "timeout_s": timeout_s,
        }
        if run_async:  # an org at its cap is refused before any row or audit is written
            self._runtime.slots.hold(principal.org_id, command_id)
        try:
            async with self._uow_factory() as uow:
                sandbox = await load_started_sandbox(uow, principal.org_id, sandbox_id, self._clock)
                session = await self._session_in(uow, principal.org_id, sandbox_id, session_id)
                if session.state != ExecSessionState.ACTIVE.value:
                    raise Conflict(
                        f"session is {session.state}",
                        reason=CLOSED,
                        details={"state": session.state},
                    )
                await self._audit(uow, principal, sandbox_id, "toolbox.session.exec", details)
                record = ExecCommandRecord(
                    id=command_id,
                    org_id=principal.org_id,
                    sandbox_id=sandbox_id,
                    session_id=session_id,
                    argv=[SHELL, "-c", command],
                    state=ExecCommandState.RUNNING.value,
                    exit_code=None,
                    stdout_bytes=0,
                    stderr_bytes=0,
                    created_at=self._clock.now(),
                    finished_at=None,
                )
                if run_async:
                    await uow.exec_commands.add(record)
                await uow.commit()
            ref = sandbox.driver_ref
            if ref is None:
                raise no_container_conflict(sandbox.state.value, visible_stop_cause(sandbox))
        except BaseException:
            self._runtime.forget(command_id)  # nothing will run: give the slot back
            raise
        script = compose_script(
            command, session.cwd, session.env, CWD_FILE_TEMPLATE.format(session_id=session_id)
        )
        request = ExecRequest(argv=[SHELL, "-c", script], timeout_s=float(timeout_s))
        if run_async:
            self._start_pump(principal.org_id, sandbox_id, ref, session_id, command_id, request)
            return SessionExecOutcome(cwd=session.cwd, command=record)
        result = await process.execute(self._driver, sandbox, request)
        if result.sandbox_stopped and SANDBOX_DIED_MESSAGE in result.stderr:
            current = await self._read_sandbox(principal.org_id, sandbox_id)
            result = replace(result, stderr=stop_wording.reword(result.stderr, current))
        cwd = await self._store_cwd(principal.org_id, ref, session_id)
        return SessionExecOutcome(cwd=cwd or session.cwd, result=result)

    async def get_command(
        self, org_id: str, sandbox_id: str, session_id: str, command_id: str
    ) -> ExecCommandRecord:
        async with self._uow_factory() as uow:
            await self._session_in(uow, org_id, sandbox_id, session_id)
            return await self._command_in(uow, org_id, session_id, command_id)

    def log_for(self, command: ExecCommandRecord) -> CommandLog:
        return self._runtime.log_for(command)

    def stop_cause(self, command_id: str, state: str | None) -> str | None:
        """``sandbox_stopped`` when a sandbox stop (not a kill or the command) ended it.

        The answer is kept in this process's memory only: it is lost on a restart (the command
        then reads ``killed`` with a null cause) and is not shared between workers, so another
        worker answers null for a command this one marked.
        """
        return self._runtime.stop_cause_of(command_id, state)

    async def kill(
        self, principal: Principal, sandbox_id: str, session_id: str, command_id: str
    ) -> ExecCommandRecord:
        async with self._uow_factory() as uow:
            await load_started_sandbox(uow, principal.org_id, sandbox_id, self._clock)
            await self._session_in(uow, principal.org_id, sandbox_id, session_id)
            record = await self._command_in(uow, principal.org_id, session_id, command_id)
            details = {"session_id": session_id, "command_id": command_id}
            await self._audit(uow, principal, sandbox_id, "toolbox.session.kill", details)
            await uow.commit()
        if record.state != ExecCommandState.RUNNING.value:
            return record
        task = self._runtime.tasks.get(command_id)
        if task is not None:
            task.cancel()
            await asyncio.wait({task})
        killed = await self._finish(
            principal.org_id, command_id, ExecCommandState.KILLED, None, self.log_for(record)
        )
        return killed or record

    # -- internals --------------------------------------------------------------------

    async def _stop_pumps(self, command_ids: list[str]) -> None:
        """Cancel the running pumps of these commands and wait until they have ended."""
        tasks = [t for t in (self._runtime.tasks.get(c) for c in command_ids) if t is not None]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.wait(tasks)

    async def _remove_cwd_file(self, sandbox_id: str, org_id: str, session_id: str) -> None:
        """Best effort: delete the session's cwd file when the sandbox has a container."""
        sandbox = await self._read_sandbox(org_id, sandbox_id)
        if (
            sandbox is None
            or sandbox.driver_ref is None
            or sandbox.state is not SandboxState.STARTED
        ):
            return
        cwd_file = CWD_FILE_TEMPLATE.format(session_id=session_id)
        try:
            await self._driver.exec(
                sandbox.driver_ref,
                ExecRequest(argv=["rm", "-f", "--", cwd_file], timeout_s=CWD_READ_TIMEOUT_S),
            )
        except Exception:
            logger.warning("could not remove the cwd file of session %s", session_id, exc_info=True)

    async def _read_sandbox(self, org_id: str, sandbox_id: str) -> Sandbox | None:
        """The sandbox row, or ``None`` when it is missing or cannot be read."""
        try:
            async with self._uow_factory() as uow:
                return await uow.sandboxes.get(org_id, sandbox_id)
        except Exception:
            logger.warning("could not read sandbox %s", sandbox_id)
            return None

    async def _audit(
        self,
        uow: UnitOfWorkPort,
        principal: Principal,
        sandbox_id: str,
        action: str,
        details: Mapping[str, object],
    ) -> None:
        await self._recorder.record(
            uow,
            org_id=principal.org_id,
            actor_type=ActorType.API_KEY,
            actor_id=principal.key_id,
            action=action,
            target_type="sandbox",
            target_id=sandbox_id,
            details=details,
        )

    @staticmethod
    async def _session_in(
        uow: UnitOfWorkPort, org_id: str, sandbox_id: str, session_id: str
    ) -> ExecSessionRecord:
        session = await uow.exec_sessions.get(org_id, session_id)
        if session is None or session.sandbox_id != sandbox_id:
            raise NotFound(f"session {session_id} not found")
        return session

    @staticmethod
    async def _command_in(
        uow: UnitOfWorkPort, org_id: str, session_id: str, command_id: str
    ) -> ExecCommandRecord:
        command = await uow.exec_commands.get(org_id, command_id)
        if command is None or command.session_id != session_id:
            raise NotFound(f"command {command_id} not found")
        return command

    def _start_pump(
        self,
        org_id: str,
        sandbox_id: str,
        ref: str,
        session_id: str,
        command_id: str,
        request: ExecRequest,
    ) -> None:
        bounded = ExecRequest(
            argv=request.argv,
            timeout_s=min(request.timeout_s, process.MAX_TIMEOUT_S),
            max_output_bytes=command_logs.MAX_LOG_BYTES,
        )
        log = self._runtime.logs.create(command_id, org_id)
        task = asyncio.create_task(
            self._pump(org_id, sandbox_id, ref, session_id, command_id, bounded, log),
            name=f"session-command-{command_id}",
        )
        self._runtime.tasks[command_id] = task
        task.add_done_callback(lambda _done: self._runtime.forget(command_id))

    async def _pump(
        self,
        org_id: str,
        sandbox_id: str,
        ref: str,
        session_id: str,
        command_id: str,
        request: ExecRequest,
        log: CommandLog,
    ) -> None:
        exit_code = FAILED_EXIT_CODE
        sandbox_gone = False  # the driver says (or the stream failed as if) the sandbox is gone
        held: list[tuple[str, bytes]] = []  # output from the driver's death line on
        try:
            async for event in self._driver.exec_stream(ref, request):
                if isinstance(event, OutputChunk):
                    self._append_or_hold(log, held, event)
                else:
                    exit_code = event.exit_code
                    sandbox_gone = event.sandbox_stopped
                    if event.truncated:
                        log.mark_truncated()
            await self._store_cwd(org_id, ref, session_id)
        except asyncio.CancelledError:
            # Kill or shutdown: close the log now so followers never hang; kill records the row.
            for stream, data in held:
                log.append(stream, data)
            log.finish(ExecCommandState.KILLED.value, None)
            raise
        except Exception:
            logger.exception("session command %s failed", command_id)
            exit_code = FAILED_EXIT_CODE
            # On purpose: a pump error (e.g. the exec stream breaking) is treated as "the
            # sandbox is gone". It only counts as a stop if _stopped_on_purpose then finds the
            # sandbox stopping or stopped without an error; otherwise the command reads exited.
            sandbox_gone = True
        sandbox = await self._read_sandbox(org_id, sandbox_id) if sandbox_gone or held else None
        for stream, data in held:
            log.append(stream, stop_wording.reword(data, sandbox))
        if sandbox_gone and sandbox is not None and self._stopped_on_purpose(sandbox):
            await self._finish_as_stopped(org_id, command_id, log)
            return
        await self._finish(org_id, command_id, ExecCommandState.EXITED, exit_code, log)

    @staticmethod
    def _append_or_hold(log: CommandLog, held: list[tuple[str, bytes]], chunk: OutputChunk) -> None:
        """Log the chunk, except the driver's death line and what follows it.

        That line guesses at a resource limit; once the run has ended the sandbox row can say
        why it really stopped, so the line is held back and reworded before it is logged.
        """
        head, found, tail = chunk.data.partition(SANDBOX_DIED_MESSAGE)
        if held or found:
            if head:
                if held:
                    held.append((chunk.stream, head))
                else:
                    log.append(chunk.stream, head)
            if found:
                held.append((chunk.stream, found + tail))
            return
        log.append(chunk.stream, chunk.data)

    async def _finish_as_stopped(self, org_id: str, command_id: str, log: CommandLog) -> None:
        """Record ``killed`` and remember the stop, but only if this finish recorded it.

        The id is marked before the row commits, so a read right after the commit already sees
        the cause. The mark is withdrawn when the finish did not record the outcome: a user
        kill cancelled the pump mid-finish (the kill then writes ``killed`` without a cause),
        or the write failed. A kill only writes after the pump has ended, so a ``killed`` row
        returned here is this finish's own.
        """
        self._runtime.mark_stopped(command_id)
        recorded = False
        try:
            record = await self._finish(org_id, command_id, ExecCommandState.KILLED, None, log)
            recorded = record is not None and record.state == ExecCommandState.KILLED.value
        finally:
            if not recorded:
                self._runtime.unmark_stopped(command_id)

    @staticmethod
    def _stopped_on_purpose(sandbox: Sandbox) -> bool:
        """``True`` when a caller or auto-stop is stopping, or has stopped, the sandbox.

        Both move the row to ``stopping`` first; a stop that finished is ``stopped`` with no
        ``error_code``, while a death the reconciler settled has one. A row that could not be
        read never gets here, so the command keeps today's ``exited`` answer.

        Known imprecision: the row is read after the command ended. A container OOM kill
        followed by a user stop before this read is labelled as the stop.
        """
        if sandbox.state is SandboxState.STOPPING:
            return True
        return sandbox.state is SandboxState.STOPPED and sandbox.error_code is None

    async def _finish(
        self,
        org_id: str,
        command_id: str,
        state: ExecCommandState,
        exit_code: int | None,
        log: CommandLog,
    ) -> ExecCommandRecord | None:
        """Persist the outcome (first one wins) and close the log with what was stored."""
        record: ExecCommandRecord | None = None
        try:
            async with self._uow_factory() as uow:
                record = await uow.exec_commands.finish(
                    org_id,
                    command_id,
                    state=state.value,
                    exit_code=exit_code,
                    stdout_bytes=log.stream_bytes(STDOUT),
                    stderr_bytes=log.stream_bytes(STDERR),
                    at=self._clock.now(),
                )
                await uow.commit()
        except Exception:
            logger.exception("could not record the outcome of command %s", command_id)
        finally:
            if record is not None:
                log.finish(record.state, record.exit_code)
            else:
                log.finish(state.value, exit_code)
        return record

    async def _store_cwd(self, org_id: str, ref: str, session_id: str) -> str | None:
        """Read the cwd file the command left behind and persist it; best effort."""
        try:
            result = await self._driver.exec(
                ref,
                ExecRequest(
                    argv=["cat", CWD_FILE_TEMPLATE.format(session_id=session_id)],
                    timeout_s=CWD_READ_TIMEOUT_S,
                    max_output_bytes=MAX_CWD_BYTES,
                ),
            )
            cwd = result.stdout.decode("utf-8", errors="replace").removesuffix("\n")
            if result.exit_code != 0 or not cwd.startswith("/") or "\n" in cwd:
                return None
            async with self._uow_factory() as uow:
                await uow.exec_sessions.set_cwd(org_id, session_id, cwd, self._clock.now())
                await uow.commit()
        except Exception:
            logger.warning("could not update the cwd of session %s", session_id, exc_info=True)
            return None
        return cwd
