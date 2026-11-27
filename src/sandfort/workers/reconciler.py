"""Reconciler: repairs drift between the sandbox rows and the containers the driver reports.

Each pass reads the non-destroyed rows first and the driver inventory second, so a container
created in between can only look extra (the grace period and a fresh row check cover that),
never missing. Two repairs:

* a ``started`` row whose container still exists but has exited (its process tree died, for
  example a gVisor sandbox over its memory or process limit) moves to ``stopped`` with desired
  state ``stopped`` and an ``error_reason`` telling the customer to start it again, so the
  normal start path restarts it with its files intact; a successful start clears the reason.
  The audit event is ``sandbox.drift_detected`` with ``stopped_unexpectedly`` set.
* a ``started`` row whose container is gone, or was created and never started, moves to
  ``error`` with the same audit event. The frozen transition table has no ``started`` to
  ``error`` or ``started`` to ``stopped`` edge for a system observation, so both moves are
  written directly after re-reading the row, guarded by the row version; ``error`` then
  leads to ``destroying`` like every other failed sandbox. A sandbox reset passes through
  both states, and its removal of the old container (which the row still points at) shows as
  an exited one first. Settling the row mid-reset would leave the reset's new container
  behind, so for a missing or exited container the pass skips a row while any
  ``sandbox.reset`` event for it in the org audit log, from the last ``RESET_SETTLE_S``
  seconds, names the container the row still points at: an event's ``previous_driver_ref``
  equals the row's ``driver_ref``, the row's ``driver_ref`` is null, or an event has no
  ``previous_driver_ref`` key (written before the key existed). Every event in the window is
  checked, not just the last, because with several resets in the window the one removing the
  row's container is the newest and an older event names an older container. A row whose
  ``driver_ref`` no event names already points at the reset's new container, so a death on it
  (a fork-bombed fresh sandbox) is settled at once, not after the window. A container that
  was created and never started (``Drift.never_started``) is different: the reset saves the
  new container's ref on the row before it starts it, so in that window the row points at
  the new container and the container is CREATED. It is skipped while ANY ``sandbox.reset``
  event for the row is in the window, whatever the row's ``driver_ref``; a crash between the
  saved ref and the start is settled by the first pass after ``RESET_SETTLE_S``. Only a
  row that already shows drift pays for that query; a row with no recent reset event is settled at
  once, however recently it was written. ``mark_stopped_unexpectedly`` returns ``False``
  without writing when the row's ``driver_ref`` changed since the caller read it or when the
  same recent-reset check is true.
* a platform-labelled container with no live row is an orphan. Its first sighting is kept in
  process memory (no table; a restart restarts the grace) and it is removed only once it has
  been seen for the grace period, with the audit event ``sandbox.orphan_removed``.

A pass is idempotent (a repaired row is no longer ``started``, a removed orphan is no longer
listed) and an error on one item is logged and never ends the pass. A driver without the
inventory protocol, or an inventory that cannot be read, skips the pass: an unreadable
inventory must never be mistaken for "no containers exist". Sleeping uses real time.

``kick()`` asks the running loop for an immediate extra pass (the API calls it when an exec
shows the container is dead); without a running loop it does nothing, and kicks made before
that pass runs collapse into one.
"""

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any

from sandfort.clock import Clock
from sandfort.db.repositories.ports import StandbyRepository, UnitOfWorkPort
from sandfort.domain.events import ActorType, AuditOutcome
from sandfort.domain.reset_events import has_reset_in_window, may_point_at_replaced
from sandfort.domain.sandbox import (
    ERROR_CONTAINER_EXITED,
    ERROR_CONTAINER_MISSING,
    STOP_CAUSE_CONTAINER_EXITED,
    STOP_CAUSE_OOM_KILLED,
    Sandbox,
    SandboxState,
)
from sandfort.drivers.base import (
    InstanceState,
    InventoryDriver,
    InventoryInstance,
    SandboxDriver,
)
from sandfort.drivers.docker.labels import LABEL_ORG_ID, LABEL_SANDBOX_ID
from sandfort.drivers.errors import DriverNotFound
from sandfort.errors import Conflict, InternalError
from sandfort.services.audit import AuditRecorder
from sandfort.workers.stop_facts import StopFacts, gather_stop_facts

logger = logging.getLogger(__name__)

DRIFT_DETECTED = "sandbox.drift_detected"
ORPHAN_REMOVED = "sandbox.orphan_removed"
MIN_SLEEP_S = 1.0
RECHECK_KICK_DELAYS_S = (1.5, 5.0)  # follow-up kicks after a container-exit signal
MAX_REASON_CHARS = 500
# A sandbox reset audits ``sandbox.reset`` in its intent and then removes, creates and starts the
# container. A started row whose container is missing, only created or exited, and that has such
# an audit event from less than this long ago, may be mid-reset: the pass leaves it for the next.
RESET_SETTLE_S = 60
# Page of ``sandbox.reset`` events (oldest first) read per check; every one of them is checked.
# A grader resets between submissions, so many resets can fall inside ``RESET_SETTLE_S``; the
# page must cover them all, because the reset removing the container the row still points at
# is the newest one, and an older event's ``previous_driver_ref`` names an older container.
RESET_EVENTS_READ = 50
# Same string as ``sandfort.services.sandbox_reset.SANDBOX_RESET``; defined here because importing
# that module would be a cycle (sandbox_reset -> sandbox_jobs -> node_registry -> reconciler).
# A test pins the two together.
SANDBOX_RESET_ACTION = "sandbox.reset"

# Only a settled running row can be checked against the provider: every in-flight state has a
# job that is still creating, stopping or destroying the container.
CHECKED_STATES = frozenset({SandboxState.STARTED})
STOPPED_UNEXPECTEDLY_REASON = (
    "the sandbox stopped unexpectedly (its process tree exited, for example after exceeding "
    "its memory or process limit); start it again"
)
OOM_KILLED_REASON = (
    "the sandbox was killed for exceeding its memory limit; start it again, or resize it to "
    "more memory first"
)


@dataclass(frozen=True, slots=True)
class ReconcileReport:
    drifted: tuple[str, ...] = ()  # sandbox ids moved to error (or stopped, when it only exited)
    orphans_removed: tuple[str, ...] = ()  # provider ids
    errors: int = 0


@dataclass(frozen=True, slots=True)
class Drift:
    reason: str
    code: str  # the row's error_code, one of the domain ERROR_CODES (from the drift kind)
    stopped: bool = False  # the container exited: the row becomes restartable, not an error
    never_started: bool = False  # the container exists in the CREATED state, never started
    oom_killed: bool = False  # set when settling: the runtime says the container was OOM-killed


class GraceTracker:
    """First-seen instants kept in memory; a key is due once seen for the whole grace."""

    def __init__(self, clock: Clock, grace_s: float) -> None:
        self._clock = clock
        self._grace = timedelta(seconds=grace_s)
        self._first_seen: dict[str, datetime] = {}

    def expired(self, key: str) -> bool:
        now = self._clock.now()
        first = self._first_seen.setdefault(key, now)
        return now - first >= self._grace

    def forget(self, key: str) -> None:
        self._first_seen.pop(key, None)

    def retain(self, keys: Collection[str]) -> None:
        """Drop every key not in ``keys``: whatever stopped being a candidate starts over."""
        keep = set(keys)
        for key in [known for known in self._first_seen if known not in keep]:
            del self._first_seen[key]


class PassLoop:
    """Runs ``one_pass`` now and then every ``interval_s``; a failing pass never ends the loop."""

    def __init__(
        self, name: str, one_pass: Callable[[], Awaitable[object]], interval_s: float
    ) -> None:
        self._name = name
        self._one_pass = one_pass
        self._interval_s = max(interval_s, MIN_SLEEP_S)
        self._task: asyncio.Task[None] | None = None
        self._wake: asyncio.Event | None = None  # made per start, so it binds to that loop

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def kick(self) -> None:
        """Wake the running loop for an extra pass; no-op without one. Kicks coalesce."""
        if self.running and self._wake is not None:
            self._wake.set()

    def start(self) -> None:
        if not self.running:
            self._wake = asyncio.Event()
            self._task = asyncio.get_running_loop().create_task(self._run(self._wake))

    async def stop(self) -> None:
        task, self._task = self._task, None
        if task is None:
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def _run(self, wake: asyncio.Event) -> None:
        while True:
            try:
                await self._one_pass()
            except Exception:
                logger.exception("%s pass failed", self._name)
            await self._sleep(wake)

    async def _sleep(self, wake: asyncio.Event) -> None:
        """Wait out the interval, or less when kicked.

        The flag is cleared right before the next pass, so kicks made earlier collapse into
        it and a kick made during a pass still earns another one.
        """
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(wake.wait(), timeout=self._interval_s)
        wake.clear()


async def record_system_audit(
    uow_factory: Callable[[], UnitOfWorkPort],
    audit: AuditRecorder,
    *,
    org_id: str,
    action: str,
    target_type: str,
    target_id: str,
    details: Mapping[str, Any],
) -> None:
    """Write one system-actor audit row in its own unit of work."""
    async with uow_factory() as uow:
        await audit.record(
            uow,
            org_id=org_id,
            actor_type=ActorType.SYSTEM,
            actor_id=None,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=details,
        )
        await uow.commit()


async def list_node_sandboxes(uow: UnitOfWorkPort, node_id: str | None) -> Sequence[Sandbox]:
    """Non-destroyed sandboxes owned by ``node_id`` (every node's when ``None``).

    The node filter lives in the SQL repository, so ``uow`` must not wrap ``sandboxes``.
    """
    if node_id is None:
        return await uow.sandboxes.list_for_reconciler()
    repository = uow.sandboxes
    if not isinstance(repository, StandbyRepository):
        raise InternalError("node scoped listing needs the undecorated sandbox repository")
    return await repository.list_for_node(node_id)


class Reconciler:
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWorkPort],
        driver: SandboxDriver,
        clock: Clock,
        *,
        interval_s: float,
        grace_s: float,
        on_stopped: Callable[[str, str], Awaitable[None]] | None = None,  # (org_id, sandbox_id)
        node_id: str | None = None,
        read_uow_factory: Callable[[], UnitOfWorkPort] | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._read_uow_factory = read_uow_factory or uow_factory  # undecorated, for the listing
        self._node_id = node_id  # only this node's rows are reconciled; None means every row
        self._driver = driver
        self._clock = clock
        self._audit = AuditRecorder(clock)
        self._on_stopped = on_stopped
        self._grace = GraceTracker(clock, grace_s)
        self._loop = PassLoop("reconciler", self.reconcile_once, interval_s)

    @property
    def running(self) -> bool:
        return self._loop.running

    def start(self) -> None:
        self._loop.start()

    async def stop(self) -> None:
        await self._loop.stop()

    def kick(self) -> None:
        """Request an immediate extra pass; does nothing when the loop is not running."""
        self._loop.kick()

    def kick_with_rechecks(self) -> None:
        """Kick now and again after ``RECHECK_KICK_DELAYS_S``; call from the running loop.

        The runtime can still report a container as running for about a second after it died,
        so the immediate pass may find no drift; the delayed kicks catch it. A kick that lands
        after ``stop()`` does nothing.
        """
        self.kick()
        loop = asyncio.get_running_loop()
        for delay_s in RECHECK_KICK_DELAYS_S:
            loop.call_later(delay_s, self.kick)

    async def reconcile_once(self) -> ReconcileReport:
        inventory = self._driver
        if not isinstance(inventory, InventoryDriver):
            logger.info("driver %s has no inventory; reconcile pass skipped", self._driver.name)
            return ReconcileReport()
        async with self._read_uow_factory() as uow:
            rows = await list_node_sandboxes(uow, self._node_id)
        try:
            instances = await inventory.list_instances()
        except Exception:  # an unreadable inventory is not an empty one
            logger.exception("reconcile pass skipped: cannot read the driver inventory")
            return ReconcileReport(errors=1)
        drifted, drift_errors = await self._repair_drift(rows, instances)
        removed, orphan_errors = await self._remove_orphans(rows, instances)
        return ReconcileReport(tuple(drifted), tuple(removed), drift_errors + orphan_errors)

    # -- drift ---------------------------------------------------------------------------

    async def _repair_drift(
        self, rows: Collection[Sandbox], instances: Collection[InventoryInstance]
    ) -> tuple[list[str], int]:
        by_ref = {item.provider_id: item for item in instances}
        by_sandbox = {item.labels.get(LABEL_SANDBOX_ID, ""): item for item in instances}
        drifted: list[str] = []
        errors = 0
        for row in rows:
            if row.state not in CHECKED_STATES:
                continue
            found = by_ref.get(row.driver_ref or "") or by_sandbox.get(row.id)
            drift = _classify_drift(found)
            if drift is None:
                continue
            try:
                if await self._may_be_mid_reset(row, drift):
                    logger.info(
                        "sandbox %s: %s, but it was reset less than %ss ago; "
                        "it may be mid-reset, left for a later pass",
                        row.id,
                        drift.reason,
                        RESET_SETTLE_S,
                    )
                    continue
                if await self._mark_drift(row, drift):
                    drifted.append(row.id)
            except Conflict:
                logger.info("sandbox %s changed mid-pass; retried next pass", row.id)
            except Exception:
                logger.exception("could not record drift for sandbox %s", row.id)
                errors += 1
        return drifted, errors

    async def _may_be_mid_reset(self, row: Sandbox, drift: Drift) -> bool:
        """Whether a drift on ``row`` may be a reset in progress, so the pass leaves it.

        A reset audits ``sandbox.reset`` (with ``previous_driver_ref``), removes the old
        container while the row still points at it, then saves the new container's ref on the
        row and only afterwards starts that container.

        * Missing and exited (the exit signal of the destroyed container triggers a pass): the
          pass waits while the row's ``driver_ref`` is still ``previous_driver_ref`` (or null,
          or the event predates that key). Once the row points at the new container, its
          death is settled at once.
        * Never started (``Drift.never_started``, the CREATED state): between the saved ref and
          the start, the row already points at the new container, so any ``sandbox.reset``
          event for the row within the window defers it, whatever the row's ``driver_ref``.

        A crash between saving the ref and the start is settled by the first pass after
        ``RESET_SETTLE_S``. A row without a ``sandbox.reset`` event for it in the org audit log
        within the window is settled at once, however recently it was written.
        """
        details = await self._recent_reset_details(row)
        if drift.never_started and has_reset_in_window(details):
            return True
        return may_point_at_replaced(details, row.driver_ref)

    async def _reset_is_recent(self, row: Sandbox) -> bool:
        """Whether ``row`` may still point at the container a recent reset is replacing.

        Checks every ``sandbox.reset`` event of ``row`` within ``RESET_SETTLE_S`` (see
        ``may_point_at_replaced``): with several resets in the window, the one removing the
        container the row still points at is not necessarily the last event read. ``True``
        (defer) when the row's ``driver_ref`` is null, when any event has no
        ``previous_driver_ref`` key (written before the key existed), or when any event's
        ``previous_driver_ref`` equals the row's ``driver_ref``: the row still points at a
        container a reset is removing. ``False`` when there is no such event, or no event names
        the row's ``driver_ref``: the row already points at the new container, so a death on
        it is settled at once.
        """
        return may_point_at_replaced(await self._recent_reset_details(row), row.driver_ref)

    async def _recent_reset_details(self, row: Sandbox) -> list[Mapping[str, Any]]:
        """Details of up to ``RESET_EVENTS_READ`` ``sandbox.reset`` events within the window."""
        since = self._clock.now() - timedelta(seconds=RESET_SETTLE_S)
        async with self._read_uow_factory() as uow:
            recent = await uow.audit.list(
                row.org_id,
                action=SANDBOX_RESET_ACTION,
                target_id=row.id,
                since=since,
                limit=RESET_EVENTS_READ,
            )
        return [event.details for event in recent]

    async def _mark_drift(
        self, row: Sandbox, drift: Drift, *, require_same_ref: bool = False
    ) -> bool:
        """Move the freshly re-read row to error (or stopped when its container merely exited).

        ``False`` when the row is no longer started, or, with ``require_same_ref``, when its
        ``driver_ref`` is no longer the one of ``row`` (the container was replaced meanwhile).
        A container that exited is settled with ``stop_cause`` ``oom_killed`` when the driver
        can see that the runtime killed it for its memory, else with ``container_exited``. Its
        audit row also carries ``oom_killed`` and ``exit_code`` (``None`` when unknown, see
        ``stop_facts``), read from the driver before the transaction opens.
        """
        facts: StopFacts | None = None
        if drift.stopped:
            facts = await gather_stop_facts(self._driver, row.driver_ref, row.id)
            if facts.oom_killed:
                drift = replace(drift, reason=OOM_KILLED_REASON, oom_killed=True)
        async with self._uow_factory() as uow:
            current = await uow.sandboxes.get(row.org_id, row.id)
            if current is None or current.state not in CHECKED_STATES:
                return False
            if require_same_ref and current.driver_ref != row.driver_ref:
                return False
            now = self._clock.now()
            changes: dict[str, Any] = {
                "state": SandboxState.ERROR,
                "error_reason": drift.reason[:MAX_REASON_CHARS],
                "error_code": drift.code,
                "updated_at": now,
            }
            details: dict[str, Any] = {"reason": drift.reason, "driver_ref": current.driver_ref}
            if drift.stopped:
                cause = STOP_CAUSE_OOM_KILLED if drift.oom_killed else STOP_CAUSE_CONTAINER_EXITED
                changes.update(
                    state=SandboxState.STOPPED,
                    desired_state=SandboxState.STOPPED,
                    stopped_at=now,
                    stop_cause=cause,
                )
                details["stopped_unexpectedly"] = True
                details["stop_cause"] = cause
                if facts is not None:
                    details.update(facts.as_details())
            await uow.sandboxes.update(
                row.org_id, current.model_copy(update=changes), expected_version=current.version
            )
            await self._audit.record(
                uow,
                org_id=row.org_id,
                actor_type=ActorType.SYSTEM,
                actor_id=None,
                action=DRIFT_DETECTED,
                target_type="sandbox",
                target_id=row.id,
                outcome=AuditOutcome.ERROR,
                details=details,
            )
            await uow.commit()
        await self._notify_stopped(row)
        return True

    async def mark_stopped_unexpectedly(self, row: Sandbox) -> bool:
        """Settle a started row whose container is known to be dead, as a reconcile pass would.

        ``False`` when the row is no longer started or its ``driver_ref`` differs from ``row``'s
        (a reset replaced the container the caller saw die), or when the sandbox has a
        ``sandbox.reset`` audit event from the last ``RESET_SETTLE_S`` seconds and ``row`` still
        points at the container that event replaces (``previous_driver_ref``; the dead container
        may be the one the reset destroyed); nothing is written then. A row that already points
        at the reset's new container is settled at once and ``True`` is returned.
        """
        if await self._reset_is_recent(row):
            logger.info(
                "sandbox %s: container is dead, but it was reset less than %ss ago; "
                "not settling it, a later pass will",
                row.id,
                RESET_SETTLE_S,
            )
            return False
        drift = Drift(STOPPED_UNEXPECTEDLY_REASON, ERROR_CONTAINER_EXITED, stopped=True)
        return await self._mark_drift(row, drift, require_same_ref=True)

    async def _notify_stopped(self, row: Sandbox) -> None:
        if self._on_stopped is None:
            return
        try:
            await self._on_stopped(row.org_id, row.id)  # tear down terminals of the dead sandbox
        except Exception:
            logger.exception("stop hook failed for drifted sandbox %s", row.id)

    # -- orphans -------------------------------------------------------------------------

    async def _remove_orphans(
        self, rows: Collection[Sandbox], instances: Collection[InventoryInstance]
    ) -> tuple[list[str], int]:
        live_ids = {row.id for row in rows}
        live_refs = {row.driver_ref for row in rows if row.driver_ref is not None}
        orphans = [
            item
            for item in instances
            if item.labels.get(LABEL_SANDBOX_ID, "") not in live_ids
            and item.provider_id not in live_refs
        ]
        self._grace.retain([item.provider_id for item in orphans])
        removed: list[str] = []
        errors = 0
        for orphan in orphans:
            try:
                if self._grace.expired(orphan.provider_id) and await self._remove(orphan):
                    removed.append(orphan.provider_id)
            except Exception:
                logger.exception("could not remove orphan container %s", orphan.provider_id)
                errors += 1
        return removed, errors

    async def _remove(self, orphan: InventoryInstance) -> bool:
        """Remove an expired orphan unless a row claimed it meanwhile; ``True`` when removed."""
        sandbox_id = orphan.labels.get(LABEL_SANDBOX_ID, "")
        org_id = orphan.labels.get(LABEL_ORG_ID, "")
        if sandbox_id and org_id and await self._has_live_row(org_id, sandbox_id):
            self._grace.forget(orphan.provider_id)
            return False
        with contextlib.suppress(DriverNotFound):  # already gone is the outcome we want
            await self._driver.destroy(orphan.provider_id)
        self._grace.forget(orphan.provider_id)
        await self._audit_orphan(orphan, org_id, sandbox_id)
        return True

    async def _has_live_row(self, org_id: str, sandbox_id: str) -> bool:
        async with self._uow_factory() as uow:
            row = await uow.sandboxes.get(org_id, sandbox_id)
        return row is not None and row.state is not SandboxState.DESTROYED

    async def _org_exists(self, org_id: str) -> bool:
        async with self._uow_factory() as uow:
            return await uow.orgs.get(org_id) is not None

    async def _audit_orphan(self, orphan: InventoryInstance, org_id: str, sandbox_id: str) -> None:
        if not org_id:
            logger.warning("orphan %s removed; no org label, nothing to audit", orphan.provider_id)
            return
        try:
            if not await self._org_exists(org_id):  # labels may outlive this database
                logger.debug(
                    "orphan %s removed; org %s unknown here, audit skipped",
                    orphan.provider_id,
                    org_id,
                )
                return
            await record_system_audit(
                self._uow_factory,
                self._audit,
                org_id=org_id,
                action=ORPHAN_REMOVED,
                target_type="sandbox",
                target_id=sandbox_id or orphan.provider_id,
                details={"provider_id": orphan.provider_id, "state": orphan.state.value},
            )
        except Exception:  # the container is already gone; do not fail the pass over its record
            logger.exception("could not audit removal of orphan %s", orphan.provider_id)


def _classify_drift(found: InventoryInstance | None) -> Drift | None:
    if found is None:
        return Drift("container missing from the provider", ERROR_CONTAINER_MISSING)
    if found.state is InstanceState.EXITED:
        return Drift(STOPPED_UNEXPECTEDLY_REASON, ERROR_CONTAINER_EXITED, stopped=True)
    if found.state is InstanceState.CREATED:  # never started: nothing to resume
        reason = f"container is {found.state.value}"
        return Drift(reason, ERROR_CONTAINER_MISSING, never_started=True)
    return None
