"""Lifecycle orchestration. Transitions go through ``domain.lifecycle``; the driver is
never called inside an open transaction (intent first, then act, architecture D4).

Every lifecycle operation follows the same three steps: commit the intent state in
its own unit of work, call the driver with no transaction open, then commit the
outcome in a fresh unit of work. The drive-and-transition core lives in
``sandbox_jobs.Lifecycle`` and is shared with the job handlers. By default the driver call
runs inline after the intent commit (the job-less sync path); with ``use_jobs`` the intent
commit also enqueues the lifecycle job and the runner finishes it. Each command writes one
audit row in the unit of work of its intent (delete: its final state, so a retry audits once).

Volume mounts are resolved in the create intent (another org's or a missing volume is not
found) and recorded on the row's reserved mounts label (``services.volumes``); the inline
create drives the container with them as named volume binds. The job runner's create path
builds its own plain ``Lifecycle`` that knows nothing of mounts, so with ``use_jobs`` a create
that asks for mounts is refused rather than silently started without its volumes.

The class is assembled from mixins on ``sandbox_service_base``: ``sandbox_queries`` (get,
list), ``sandbox_resize`` (the resize recreate), ``sandbox_create_rules`` (create checks and
the new row), ``sandbox_snapshot_resolution`` (snapshot id, tier, resources and image),
``sandbox_create_intent`` (the create intent, quota, key cap and placement) and
``sandbox_update`` (update). The create command, the protocols and ``MountingLifecycle``
live in ``sandbox_commands`` and ``sandbox_mounting``.
"""

import dataclasses
import logging
from collections.abc import Awaitable, Callable
from typing import cast

from sandfort.auth.label_scope import current_key_sandbox_cap, current_label_scope
from sandfort.clock import Clock
from sandfort.config import Settings
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.sandbox import STOP_CAUSE_REQUESTED, Sandbox, SandboxState
from sandfort.drivers.base import SandboxDriver
from sandfort.errors import IN_PROGRESS, CapacityExceeded, Conflict, QuotaExceeded
from sandfort.services.admission import (
    SANDBOX_CREATE_REFUSED,
    SANDBOX_START_REFUSED,
    RefusalCoalescer,
    audit_capacity_refusal,
    audit_key_cap_refusal,
)
from sandfort.services.audit import AuditRecorder
from sandfort.services.events import EventPublisher, OutboxEventPublisher, with_sandbox_events
from sandfort.services.label_scope import merge_scope
from sandfort.services.quota import QuotaService
from sandfort.services.sandbox_commands import (
    DEFAULT_IMAGE,
    SNAPSHOT_ID_PREFIX,
    CreateSandboxCommand,
    PendingSnapshotReader,
    StandbyClaimer,
)
from sandfort.services.sandbox_create_intent import SandboxCreateIntentMixin
from sandfort.services.sandbox_create_rules import MIN_AUTO_MINUTES
from sandfort.services.sandbox_jobs import AuditNote
from sandfort.services.sandbox_mounting import MountingLifecycle, with_image_mounts_label
from sandfort.services.sandbox_queries import (
    LIVE_SCAN_PAGE,
    MAX_WAIT_S,
    POLL_INTERVAL_S,
    SandboxQueriesMixin,
)
from sandfort.services.sandbox_reset import SandboxReset
from sandfort.services.sandbox_resize import RESIZE_FAILED_MESSAGE, SandboxResizeMixin
from sandfort.services.sandbox_update import SandboxUpdateMixin
from sandfort.services.usage import with_usage_metering
from sandfort.services.volume_limit import MountGuard
from sandfort.wiring import egress_reminting
from sandfort.workers.jobs import (
    DEFAULT_WAKEUP,
    SandboxDeleteJob,
    SandboxStartJob,
    SandboxStopJob,
)

__all__ = [
    "CreateSandboxCommand",
    "DEFAULT_IMAGE",
    "DELETE_MAX_ATTEMPTS",
    "LIVE_SCAN_PAGE",
    "MAX_WAIT_S",
    "MIN_AUTO_MINUTES",
    "MountingLifecycle",
    "PendingSnapshotReader",
    "POLL_INTERVAL_S",
    "RESIZE_FAILED_MESSAGE",
    "SNAPSHOT_ID_PREFIX",
    "SandboxService",
    "StandbyClaimer",
    "audit_capacity_refusal",
    "audit_key_cap_refusal",
    "with_image_mounts_label",
]

logger = logging.getLogger(__name__)

DELETE_MAX_ATTEMPTS = 3  # total tries of a delete whose versioned transition raced a writer

_S = SandboxState


def _is_version_conflict(exc: Conflict) -> bool:
    """True for the repository's stale-version refusal (``details['expected_version']``)."""
    return "expected_version" in exc.details


class SandboxService(
    SandboxCreateIntentMixin, SandboxUpdateMixin, SandboxResizeMixin, SandboxQueriesMixin
):
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWorkPort],
        driver: SandboxDriver,
        settings: Settings,
        clock: Clock,
        audit: AuditRecorder | None = None,
        on_stopped: Callable[[str, str], Awaitable[None]] | None = None,  # (org_id, sandbox_id)
        use_jobs: bool = False,
        quota: QuotaService | None = None,
        events: EventPublisher | None = None,
        warm_pool: StandbyClaimer | None = None,
        volume_guard: MountGuard | None = None,
        on_refusal_coalesced: Callable[[], None] | None = None,
    ) -> None:
        self._refusals = RefusalCoalescer(clock)
        self._on_refusal_coalesced = on_refusal_coalesced
        self._warm_pool = warm_pool
        self._volume_guard = volume_guard  # samples volume sizes before the create transaction
        # Lifecycle events are appended in the unit of work of the transition itself.
        uow_factory = with_sandbox_events(uow_factory, events or OutboxEventPublisher(clock))
        # usage intervals ride the same unit; the driver gives stop and delete a final disk look
        uow_factory = with_usage_metering(
            uow_factory, clock, driver, tail_s=settings.metering_sample_interval_s
        )
        self._audit = audit or AuditRecorder(clock)
        self._use_jobs = use_jobs
        self._quota = quota
        self._core = MountingLifecycle(
            uow_factory,
            driver,
            clock,
            self._audit,
            self._releasing(on_stopped),
            node_id=settings.node_id,
        )
        self._uow_factory = uow_factory
        self._driver = driver
        self._settings = settings
        self._clock = clock
        # A reset recreates the container, so its core re-mints the egress token into the new
        # env. ``self._core`` has no reminting: a start reuses the container and its old env.
        reset_core = MountingLifecycle(
            uow_factory,
            driver,
            clock,
            self._audit,
            self._releasing(on_stopped),
            node_id=settings.node_id,
            egress=egress_reminting(settings),
        )
        self._reset = SandboxReset(
            reset_core,
            uow_factory,
            driver,
            clock,
            use_jobs=use_jobs,
            refuse_if_busy=self._refuse_while_snapshotting,
            on_replaced=on_stopped,  # the raw hook: closes PTYs, no quota release
        )

    # -- commands --------------------------------------------------------------

    async def create(self, org_id: str, actor_id: str, command: CreateSandboxCommand) -> Sandbox:
        command = self._with_carried_mounts(command)
        command = self._with_default_network(command)
        command = await self._with_snapshot_id(org_id, command)  # a name becomes its id first
        self._validate_create(command)
        scope = current_label_scope()
        if scope is not None and not command.standby:  # a scoped key creates inside its scope
            command = dataclasses.replace(command, labels=merge_scope(command.labels, scope))
        await self._require_visible_snapshot(org_id, command.snapshot)  # before any pool claim
        command = await self._inherit_snapshot_tier(org_id, command)
        command = await self._inherit_snapshot_resources(org_id, command)  # before the pool claim
        # Standbys run the default tier, so only a create on that tier may claim one.
        default_tier = command.isolation in (None, self._settings.default_isolation)
        cap = None if command.standby else current_key_sandbox_cap()
        capped = scope is not None and cap is not None
        # A capped key never claims a standby: the claim commits in the pool's own transaction,
        # before the cap could be counted under the org lock, so it builds through the checked
        # insert below instead.
        if self._warm_pool is not None and default_tier and not capped:  # a standby is claimed
            claimed = await self._warm_pool.try_claim(org_id, actor_id, command)
            if claimed is not None:
                return claimed
        # Driver calls never run inside an open transaction: sample the volumes first.
        try:
            volume_limit = await self._sample_volumes(org_id, command, scope, cap)
            sandbox = await self._commit_create_intent(
                org_id, actor_id, command, volume_limit, scope, cap
            )
        except QuotaExceeded as exc:  # the key cap: a refused create, not a generic denial
            await audit_key_cap_refusal(
                self._uow_factory,
                self._audit,
                exc,
                org_id=org_id,
                actor_id=actor_id,
                coalescer=self._refusals,
                on_coalesced=self._on_refusal_coalesced,
            )
            raise
        except CapacityExceeded as exc:  # the intent rolled back: audit the refusal, same 503
            await audit_capacity_refusal(
                self._uow_factory,
                self._audit,
                exc,
                org_id=org_id,
                actor_id=actor_id,
                action=SANDBOX_CREATE_REFUSED,
                target_type="org",
                target_id=org_id,
                coalescer=self._refusals,
                on_coalesced=self._on_refusal_coalesced,
            )
            raise
        if self._use_jobs:
            DEFAULT_WAKEUP.notify()
            return sandbox
        created = await self._core.drive_create(org_id, sandbox.id)
        if created.state is _S.ERROR:  # the driver failed: the capacity is free again
            await self._release(org_id, created.id)
        return created

    async def start(self, org_id: str, actor_id: str, sandbox_id: str) -> Sandbox:
        current = await self._load(org_id, sandbox_id)
        if current.state is _S.STARTED:  # target already reached: a retry is a no-op
            return current
        await self._refuse_over_limit_mounts(org_id, current)  # before any container is replaced
        await self._recreate_if_resized(org_id, sandbox_id)
        job = SandboxStartJob(org_id, sandbox_id, actor_id)
        try:
            sandbox = await self._core.transition(
                org_id,
                sandbox_id,
                _S.STARTING,
                desired_state=_S.STARTED,
                audit=AuditNote(actor_id, "sandbox.start"),
                job=job if self._use_jobs else None,
                before_commit=self._reserve_on_start if self._quota is not None else None,
            )
        except CapacityExceeded as exc:  # the move rolled back: audit the refusal, same 503
            await audit_capacity_refusal(
                self._uow_factory,
                self._audit,
                exc,
                org_id=org_id,
                actor_id=actor_id,
                action=SANDBOX_START_REFUSED,
                target_type="sandbox",
                target_id=sandbox_id,
                coalescer=self._refusals,
                on_coalesced=self._on_refusal_coalesced,
            )
            raise
        return sandbox if self._use_jobs else await self._core.drive_start(org_id, sandbox_id)

    async def _reserve_on_start(self, uow: UnitOfWorkPort, sandbox: Sandbox) -> None:
        """A running sandbox always holds a reservation: re-reserve with the start intent."""
        if self._quota is not None:
            await self._quota.reserve(uow, sandbox.org_id, sandbox.id, sandbox.resources)

    async def stop(self, org_id: str, actor_id: str, sandbox_id: str) -> Sandbox:
        current = await self._load(org_id, sandbox_id)
        if current.state is _S.STOPPED:  # target already reached: a retry is a no-op
            return current
        job = SandboxStopJob(org_id, sandbox_id, actor_id)
        sandbox = await self._core.transition(
            org_id,
            sandbox_id,
            _S.STOPPING,
            desired_state=_S.STOPPED,
            audit=AuditNote(actor_id, "sandbox.stop", {"stop_cause": STOP_CAUSE_REQUESTED}),
            job=job if self._use_jobs else None,
            stop_cause=STOP_CAUSE_REQUESTED,
        )
        return sandbox if self._use_jobs else await self._core.drive_stop(org_id, sandbox_id)

    async def reset(self, org_id: str, actor_id: str, sandbox_id: str) -> Sandbox:
        """Replace the container with a fresh one; see ``services.sandbox_reset``."""
        return await self._reset.reset(org_id, actor_id, sandbox_id)

    async def delete(self, org_id: str, actor_id: str, sandbox_id: str) -> Sandbox:
        job = SandboxDeleteJob(org_id, sandbox_id, actor_id)
        for attempt in range(1, DELETE_MAX_ATTEMPTS + 1):
            current = await self._load(org_id, sandbox_id)
            if current.state is _S.DESTROYED:  # target already reached: a retry is a no-op
                return current
            if current.state is _S.DESTROYING:  # retry of a delete whose driver call failed
                if self._use_jobs:
                    await self._core.enqueue(job)
                    return current
                break
            await self._refuse_while_snapshotting(org_id, sandbox_id)
            try:
                current = await self._core.transition(
                    org_id,
                    sandbox_id,
                    _S.DESTROYING,
                    desired_state=_S.DESTROYED,
                    job=job if self._use_jobs else None,
                )
            except Conflict as exc:
                # The row moved (reconciler, exec route) between the read and the versioned
                # write: decide again from the fresh row. Other conflicts propagate.
                if attempt == DELETE_MAX_ATTEMPTS or not _is_version_conflict(exc):
                    raise
                continue
            if self._use_jobs:
                return current
            break
        return await self._core.drive_delete(org_id, sandbox_id, actor_id)

    # -- helpers ---------------------------------------------------------------

    async def _refuse_while_snapshotting(self, org_id: str, sandbox_id: str) -> None:
        """A pending snapshot's commit needs its source; deleting it now would fail the job."""
        async with self._uow_factory() as uow:
            reader = cast(PendingSnapshotReader, uow.snapshots)
            pending = await reader.has_pending_from_source(org_id, sandbox_id)
        if pending:
            raise Conflict(
                f"sandbox {sandbox_id} has a snapshot in progress; wait for the snapshot "
                "to finish or delete it, then retry",
                reason=IN_PROGRESS,
            )

    async def _release(self, org_id: str, sandbox_id: str) -> None:
        if self._quota is not None:
            await self._quota.release(org_id, sandbox_id)  # idempotent

    def _releasing(
        self, on_stopped: Callable[[str, str], Awaitable[None]] | None
    ) -> Callable[[str, str], Awaitable[None]] | None:
        """Wrap ``on_stopped`` so a stopped or destroyed sandbox releases its reservation."""
        if self._quota is None:
            return on_stopped

        async def stopped(org_id: str, sandbox_id: str) -> None:
            await self._release(org_id, sandbox_id)
            if on_stopped is not None:
                await on_stopped(org_id, sandbox_id)

        return stopped
