"""Idle scanner: stops sandboxes idle past their auto stop minutes, deletes stop-then-delete ones.

Each pass lists the non-destroyed sandboxes, then handles every started one whose idle time
(from the injected clock and the in-process activity tracker) exceeds its ``auto_stop_minutes``
and every stopped one whose ``auto_delete_minutes`` is 0 or has elapsed since ``stopped_at``.
State moves go through the
shared ``Lifecycle`` core (intent commit, driver call with no transaction open, outcome commit),
so the audit rows and the terminal teardown hook match a manual stop or delete. One sandbox
failing never stops the pass or the loop. Sleeping between passes uses real time.
"""

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta

from sandfort.clock import Clock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.sandbox import STOP_CAUSE_AUTO_STOP, Sandbox, SandboxState
from sandfort.drivers.base import SandboxDriver
from sandfort.egress.env import EgressReminting
from sandfort.services.activity import ActivityTracker
from sandfort.services.sandbox_jobs import AuditNote, Lifecycle
from sandfort.workers.reconciler import list_node_sandboxes

logger = logging.getLogger(__name__)

AUTO_STOPPED = "sandbox.auto_stopped"
AUTO_DELETED = "sandbox.auto_deleted"

_S = SandboxState


class AutoStopScanner:
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWorkPort],
        driver: SandboxDriver,
        clock: Clock,
        tracker: ActivityTracker,
        *,
        interval_s: float,
        on_stopped: Callable[[str, str], Awaitable[None]] | None = None,  # (org_id, sandbox_id)
        node_id: str | None = None,
        read_uow_factory: Callable[[], UnitOfWorkPort] | None = None,
        egress: EgressReminting | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._read_uow_factory = read_uow_factory or uow_factory  # undecorated, for the listing
        self._node_id = node_id  # only this node's sandboxes are scanned; None means all
        self._clock = clock
        self._tracker = tracker
        self._interval_s = interval_s
        self._core = Lifecycle(uow_factory, driver, clock, on_stopped=on_stopped, egress=egress)
        self._task: asyncio.Task[None] | None = None

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self) -> None:
        if not self.running:
            self._task = asyncio.get_running_loop().create_task(self._loop())

    async def stop(self) -> None:
        task, self._task = self._task, None
        if task is None:
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def scan_once(self) -> None:
        """One pass over every sandbox; a failure on one is logged and the rest still run."""
        async with self._read_uow_factory() as uow:
            sandboxes = await list_node_sandboxes(uow, self._node_id)
        for sandbox in sandboxes:
            try:
                await self._process(sandbox)
            except Exception:  # one bad sandbox must not starve the others
                logger.exception("auto-stop pass failed for sandbox %s", sandbox.id)

    async def _loop(self) -> None:
        while True:
            try:
                await self.scan_once()
            except Exception:
                logger.exception("auto-stop scan failed")
            await asyncio.sleep(self._interval_s)

    async def _process(self, sandbox: Sandbox) -> None:
        state = sandbox.state
        if state is _S.STARTED and self._is_idle(sandbox):
            state = await self._auto_stop(sandbox)
        if state is _S.STOPPED and self._is_due_for_delete(sandbox):
            await self._auto_delete(sandbox)

    def _is_due_for_delete(self, sandbox: Sandbox) -> bool:
        minutes = sandbox.auto_delete_minutes
        if minutes < 0:
            return False  # unset: never
        if minutes == 0:
            return True  # delete as soon as it is stopped
        if sandbox.stopped_at is None:
            return False  # no clock to measure from
        return self._clock.now() - sandbox.stopped_at >= timedelta(minutes=minutes)

    def _is_idle(self, sandbox: Sandbox) -> bool:
        if sandbox.auto_stop_minutes <= 0:
            return False  # unset or disabled
        return self._idle_for(sandbox) > timedelta(minutes=sandbox.auto_stop_minutes)

    def _idle_for(self, sandbox: Sandbox) -> timedelta:
        return self._clock.now() - self._last_activity(sandbox)

    def _last_activity(self, sandbox: Sandbox) -> datetime:
        """Latest of the in-process record and the row's own mark (a restart-safe floor)."""
        recorded = self._tracker.last_activity(sandbox.id)
        stored = sandbox.last_activity_at or sandbox.started_at
        return recorded if stored is None else max(recorded, stored)

    async def _auto_stop(self, sandbox: Sandbox) -> SandboxState:
        details = {
            "auto_stop_minutes": sandbox.auto_stop_minutes,
            "idle_seconds": int(self._idle_for(sandbox).total_seconds()),
            "stop_cause": STOP_CAUSE_AUTO_STOP,
        }
        await self._core.transition(
            sandbox.org_id,
            sandbox.id,
            _S.STOPPING,
            desired_state=_S.STOPPED,
            audit=AuditNote(None, AUTO_STOPPED, details),
            stop_cause=STOP_CAUSE_AUTO_STOP,
        )
        stopped = await self._core.drive_stop(sandbox.org_id, sandbox.id)
        self._tracker.forget(sandbox.id)
        return stopped.state

    async def _auto_delete(self, sandbox: Sandbox) -> None:
        details = {"auto_delete_minutes": sandbox.auto_delete_minutes}
        await self._core.transition(
            sandbox.org_id,
            sandbox.id,
            _S.DESTROYING,
            desired_state=_S.DESTROYED,
            audit=AuditNote(None, AUTO_DELETED, details),
        )
        await self._core.drive_delete(sandbox.org_id, sandbox.id, None)
        self._tracker.forget(sandbox.id)
