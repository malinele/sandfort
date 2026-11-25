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
"""

import asyncio
import dataclasses
import json
import logging
import re
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, cast

from sandfort.auth.label_scope import current_key_sandbox_cap, current_label_scope
from sandfort.clock import Clock
from sandfort.config import (
    ENV_PREFIX,
    FAULT_RESIZE_COMMIT_FAIL,
    FAULT_RESIZE_CREATE_FAIL,
    Settings,
    is_reserved_env_name,
)
from sandfort.db.locking import lock_quota
from sandfort.db.repositories.ports import (
    LiveSandboxListing,
    SandboxRepository,
    ScopedSandboxCounting,
    SortOrder,
    UnitOfWorkPort,
)
from sandfort.domain.isolation import isolation_labels
from sandfort.domain.resources import ResourceSpec
from sandfort.domain.sandbox import (
    STOP_CAUSE_REQUESTED,
    NetworkPolicy,
    Sandbox,
    SandboxState,
    check_egress_allowlist,
    take_egress_allowlist,
)
from sandfort.domain.snapshot import SnapshotState
from sandfort.drivers.base import (
    IMAGE_MOUNTS_LABEL,
    RESIZE_IMAGE_LABEL,
    ImageRegistryDriver,
    InstanceInfo,
    SandboxDriver,
    SandboxSpec,
    VolumeBind,
    resize_image_reference,
)
from sandfort.drivers.errors import DriverError, DriverNotFound, DriverUnsupported
from sandfort.egress.env import compose_proxy_env
from sandfort.errors import (
    IN_PROGRESS,
    CapacityExceeded,
    Conflict,
    Forbidden,
    InternalError,
    InvalidState,
    NotFound,
    QuotaExceeded,
    Unprocessable,
)
from sandfort.ids import SNAPSHOT, new_sandbox_id
from sandfort.services.admission import (
    SANDBOX_CREATE_REFUSED,
    SANDBOX_START_REFUSED,
    RefusalCoalescer,
    audit_capacity_refusal,
    audit_key_cap_refusal,
)
from sandfort.services.audit import AuditRecorder
from sandfort.services.egress_provision import needs_egress_stack, without_proxy_variables
from sandfort.services.egress_update import (
    NETWORK_POLICY_MESSAGE,
    EgressUpdate,
    plan_egress_update,
)
from sandfort.services.events import EventPublisher, OutboxEventPublisher, with_sandbox_events
from sandfort.services.image_policy import check_user_image_reference
from sandfort.services.label_scope import (
    SCAN_PAGE,
    count_by_scanning,
    list_in_order,
    merge_scope,
)
from sandfort.services.node_registry import pick_node, stamp_job, stamp_sandbox
from sandfort.services.quota import QuotaService, reservation_for
from sandfort.services.sandbox_jobs import AuditNote, Lifecycle
from sandfort.services.sandbox_listing import list_by_stop_cause
from sandfort.services.sandbox_reset import SandboxReset
from sandfort.services.snapshot_resources import merge_recorded
from sandfort.services.snapshots import snapshot_in_label_scope
from sandfort.services.usage import with_usage_metering
from sandfort.services.volume_limit import MountGuard, MountLimit
from sandfort.services.volumes import (
    MOUNT_REQUESTS_LABEL,
    RESERVED_LABEL_PREFIX,
    MountRequest,
    VolumeMount,
    decode_mounts,
    encode_mounts,
    is_reserved_label,
    resolve_mounts,
    take_mount_requests,
    validate_mount_requests,
)
from sandfort.wiring import egress_reminting
from sandfort.workers.jobs import (
    DEFAULT_WAKEUP,
    SandboxCreateJob,
    SandboxDeleteJob,
    SandboxJob,
    SandboxStartJob,
    SandboxStopJob,
    enqueue_job,
)

logger = logging.getLogger(__name__)

DEFAULT_IMAGE = "python:3.12-slim"
MAX_WAIT_S = 60.0
POLL_INTERVAL_S = 0.1
MIN_AUTO_MINUTES = -1  # -1 disables the timer
LIVE_SCAN_PAGE = SCAN_PAGE  # rows per read while skipping tombstones (the repository's page cap)
SNAPSHOT_ID_PREFIX = f"{SNAPSHOT}_"  # ``snapshot`` values with it are ids, not image refs

RESIZE_FAILED_MESSAGE = (
    "resize could not prepare the sandbox's container; try again or contact the operator"
)
DELETE_MAX_ATTEMPTS = 3  # total tries of a delete whose versioned transition raced a writer

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_S = SandboxState


def _is_version_conflict(exc: Conflict) -> bool:
    """True for the repository's stale-version refusal (``details['expected_version']``)."""
    return "expected_version" in exc.details


async def _live_by_scanning(
    repo: SandboxRepository,
    org_id: str,
    labels: Mapping[str, str] | None,
    cursor: str | None,
    limit: int,
    order: SortOrder = "asc",
) -> list[Sandbox]:
    """Up to ``limit`` non-destroyed sandboxes after ``cursor``, read through ``repo.list``.

    The fallback for a repository without ``list_live`` (or one behind a decorator): scan the
    id-ordered pages (in ``order``) and skip tombstones, so a run of destroyed rows never fills
    the page.
    """
    live: list[Sandbox] = []
    while len(live) < limit:
        page = await list_in_order(
            repo, org_id, labels=labels, cursor=cursor, limit=LIVE_SCAN_PAGE, order=order
        )
        live.extend(item for item in page if item.state is not _S.DESTROYED)
        if len(page) < LIVE_SCAN_PAGE:
            break
        cursor = page[-1].id
    return live[:limit]


async def _live_in_scope(
    repo: SandboxRepository, org_id: str, scope: Mapping[str, str], stop_at: int
) -> int:
    """Non-destroyed, non-standby sandboxes carrying every ``scope`` pair.

    A repository with ``count_in_scope`` answers in SQL; the label-scope, event and metering
    decorators each forward it explicitly. Any other repository has its id-ordered ``list``
    pages scanned instead, stopping once ``stop_at`` is reached (the caller only needs to know
    whether the cap is hit).
    """
    if isinstance(repo, ScopedSandboxCounting):
        return await repo.count_in_scope(org_id, scope)
    return await count_by_scanning(repo, org_id, scope, stop_at)


def _key_cap_error(cap: int, current: int) -> QuotaExceeded:
    """The refusal for a key already holding ``current`` of its ``cap`` sandboxes."""
    return QuotaExceeded(
        f"this API key is capped at {cap} sandboxes (key max_sandboxes) and holds "
        f"{current}; delete a sandbox before creating another",
        details={"limit": "key_max_sandboxes", "max": cap, "current": current},
    )


@dataclass(frozen=True, slots=True)
class CreateSandboxCommand:
    name: str | None = None
    snapshot: str | None = None
    resources: ResourceSpec = field(default_factory=ResourceSpec)
    inherit_resources: bool = False  # adopt the resources recorded on ``snapshot``, if any
    env: Mapping[str, str] = field(default_factory=dict)
    labels: Mapping[str, str] = field(default_factory=dict)
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    auto_stop_minutes: int = 15
    auto_delete_minutes: int = -1
    public: bool = False
    volumes: Sequence[MountRequest] = ()
    standby: bool = False  # set only by the warm pool's refill: build a standby, not a sandbox
    spec_hash: str | None = None  # the pool key a standby is built for
    egress_allowlist: tuple[str, ...] | None = None  # None keeps today's egress (domain rules)
    isolation: str | None = None  # isolation tier (``domain.isolation``); None = the default


class StandbyClaimer(Protocol):
    """The warm pool as ``create`` sees it (implemented in ``services.warm_pool``)."""

    async def try_claim(
        self, org_id: str, actor_id: str, command: CreateSandboxCommand
    ) -> Sandbox | None: ...


class PendingSnapshotReader(Protocol):
    """What the SQL snapshot repository adds to the frozen port for sandbox delete."""

    async def has_pending_from_source(self, org_id: str, sandbox_id: str) -> bool: ...


def with_image_mounts_label(labels: Mapping[str, str], paths: Sequence[str]) -> dict[str, str]:
    """``labels`` with the reserved image-mounts record set to ``paths`` (dropped when empty)."""
    rest = {name: value for name, value in labels.items() if name != IMAGE_MOUNTS_LABEL}
    if not paths:
        return rest
    return {**rest, IMAGE_MOUNTS_LABEL: json.dumps(sorted(paths))}


class MountingLifecycle(Lifecycle):
    """``Lifecycle`` whose driver spec carries the volume mounts recorded on the row.

    After a create it also records the image-declared volume paths the driver backed with
    scratch volumes (``InstanceInfo.image_mounts``) on the row, for the sandbox view.
    """

    async def drive_create(
        self, org_id: str, sandbox_id: str, actor_id: str | None = None
    ) -> Sandbox:
        sandbox = await super().drive_create(org_id, sandbox_id, actor_id)
        if sandbox.state is not SandboxState.STARTED or sandbox.driver_ref is None:
            return sandbox
        return await self._record_image_mounts(org_id, sandbox)

    async def _record_image_mounts(self, org_id: str, sandbox: Sandbox) -> Sandbox:
        """Best effort: the container is already running, so a failure here only logs."""
        assert sandbox.driver_ref is not None
        try:
            info = await self._driver.inspect(sandbox.driver_ref)
            labels = with_image_mounts_label(sandbox.labels, info.image_mounts)
            if labels == sandbox.labels:
                return sandbox
            async with self._uow_factory() as uow:
                current = await self.require(uow, org_id, sandbox.id)
                changes = {"labels": labels, "updated_at": self._clock.now()}
                saved = await uow.sandboxes.update(
                    org_id, current.model_copy(update=changes), expected_version=current.version
                )
                await uow.commit()
        except Exception:
            logger.warning("could not record image mounts of %s", sandbox.id, exc_info=True)
            return sandbox
        return saved

    @staticmethod
    def spec(sandbox: Sandbox) -> SandboxSpec:
        base = Lifecycle.spec(sandbox)
        mounts = decode_mounts(sandbox.labels)
        if not mounts:
            return base
        binds = tuple(
            VolumeBind(mount.provider_volume_name, mount.mount_path, read_only=mount.read_only)
            for mount in mounts
        )
        return dataclasses.replace(base, volumes=binds)


class SandboxService:
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

    # -- queries ---------------------------------------------------------------

    async def get(
        self,
        org_id: str,
        sandbox_id: str,
        *,
        wait_for: SandboxState | None = None,
        timeout_s: float = 0.0,
    ) -> Sandbox:
        deadline = time.monotonic() + min(max(timeout_s, 0.0), MAX_WAIT_S)
        while True:
            sandbox = await self._load(org_id, sandbox_id)
            settled = sandbox.state in (wait_for, _S.ERROR, _S.DESTROYED)
            remaining = deadline - time.monotonic()
            if wait_for is None or settled or remaining <= 0:
                return sandbox
            await asyncio.sleep(min(POLL_INTERVAL_S, remaining))

    async def list(
        self,
        org_id: str,
        *,
        state: SandboxState | None = None,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 50,
        include_destroyed: bool = True,
        order: SortOrder = "asc",
        stop_cause: str | None = None,
    ) -> Sequence[Sandbox]:
        """One page by id (``order="desc"``: newest first; the cursor continues in that order).

        Without ``state``, ``include_destroyed=False`` hides tombstones. ``stop_cause`` keeps
        the sandboxes that show that cause (a destroyed row shows none, so no tombstone matches).
        """
        async with self._uow_factory() as uow:
            repo = uow.sandboxes
            if stop_cause is not None:
                return await list_by_stop_cause(
                    repo,
                    org_id,
                    stop_cause,
                    state=state,
                    labels=labels,
                    cursor=cursor,
                    limit=limit,
                    order=order,
                )
            if include_destroyed or state is not None:
                return await list_in_order(
                    repo,
                    org_id,
                    state=state,
                    labels=labels,
                    cursor=cursor,
                    limit=limit,
                    order=order,
                )
            # ``list_live`` is not scope-aware and the event/metering decorators do not forward
            # it, so it is used only on a bare repository with no label scope active.
            if current_label_scope() is None and isinstance(repo, LiveSandboxListing):
                return await repo.list_live(
                    org_id, labels=labels, cursor=cursor, limit=limit, order=order
                )
            return await _live_by_scanning(repo, org_id, labels, cursor, limit, order)

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

    async def _commit_create_intent(
        self,
        org_id: str,
        actor_id: str,
        command: CreateSandboxCommand,
        volume_limit: MountLimit | None,
        scope: Mapping[str, str] | None,
        cap: int | None,
    ) -> Sandbox:
        """Commit the create intent: the row, its reservation, the audit row and the job."""
        async with self._uow_factory() as uow:  # intent: the row exists before any container
            image_ref = await self._resolve_image(uow, org_id, command.snapshot)
            mounts = await resolve_mounts(uow, org_id, command.volumes, limit=volume_limit)
            sandbox = self._new_sandbox(org_id, command, image_ref, mounts)
            if scope is not None and cap is not None:
                await self._require_under_key_cap(uow, org_id, scope, cap)
            await uow.sandboxes.add(sandbox)
            node_id = await self._place(uow, command)
            await stamp_sandbox(uow, sandbox.id, node_id)
            if self._quota is not None:  # checked and recorded with the intent, before any driver
                await self._quota.reserve(uow, org_id, sandbox.id, command.resources)
            await self._core.record(uow, org_id, sandbox.id, self._create_note(actor_id, command))
            if self._use_jobs:
                await self._enqueue(uow, SandboxCreateJob(org_id, sandbox.id, actor_id), node_id)
            await uow.commit()
        return sandbox

    async def _sample_volumes(
        self,
        org_id: str,
        command: CreateSandboxCommand,
        scope: Mapping[str, str] | None,
        cap: int | None,
    ) -> MountLimit | None:
        """The pre-step of the soft volume size limit; no unit of work is open while it runs.

        The request is validated by now. Quota and key cap are read once without the org lock
        so a create they would refuse pays for no inspect (the checks in the create transaction
        stay authoritative); only the read-write volumes the key's ``scope`` allows are sampled.
        ``None`` when there is no guard, no limit or no read-write mount.
        """
        guard = self._volume_guard
        if guard is None or not guard.wants_sampling(command.volumes):
            return None
        await self._refuse_over_quota(org_id, command.resources)
        if scope is not None and cap is not None:
            async with self._uow_factory() as uow:
                current = await _live_in_scope(uow.sandboxes, org_id, scope, cap)
            if current >= cap:
                raise _key_cap_error(cap, current)
        return await guard.prepare(self._uow_factory, org_id, command.volumes, scope=scope)

    async def _refuse_over_quota(self, org_id: str, resources: ResourceSpec) -> None:
        """Raise ``QuotaExceeded`` when the org's reservation plus this one cannot fit."""
        if self._quota is None:
            return
        usage = await self._quota.get(org_id)
        requested = reservation_for(resources)
        if not usage.reserved.add(requested).fits_within(usage.limits):
            raise QuotaExceeded(
                "organization quota exceeded",
                details={
                    "limits": usage.limits.model_dump(mode="json"),
                    "reserved": usage.reserved.model_dump(mode="json"),
                    "requested": requested.model_dump(mode="json"),
                },
            )

    async def _refuse_over_limit_mounts(self, org_id: str, sandbox: Sandbox) -> None:
        """Start and the resize recreate: refuse a read-write mount of an over-limit volume.

        Same pre-step and refusal as on create, for the mounts recorded on the sandbox; it runs
        before any container is destroyed or recreated, with no unit of work open.
        """
        guard = self._volume_guard
        requests = [
            MountRequest(mount.volume_id, mount.mount_path, mount.read_only)
            for mount in decode_mounts(sandbox.labels)
        ]
        if guard is None or not guard.wants_sampling(requests):
            return
        limit = await guard.prepare(
            self._uow_factory, org_id, requests, scope=current_label_scope()
        )
        if limit is None:
            return
        async with self._uow_factory() as uow:
            await limit.check_requests(uow, org_id, requests)

    @staticmethod
    async def _require_under_key_cap(
        uow: UnitOfWorkPort, org_id: str, scope: Mapping[str, str], cap: int
    ) -> None:
        """Refuse a create when the key already holds ``cap`` sandboxes inside its scope.

        Runs in the transaction that inserts the row, after the org locks are taken (Postgres
        ``FOR UPDATE``; SQLite's ``BEGIN IMMEDIATE`` already serialises), so two creates at
        ``cap - 1`` cannot both count ``cap - 1``.
        """
        await lock_quota(uow, org_id)
        current = await _live_in_scope(uow.sandboxes, org_id, scope, cap)
        if current >= cap:
            raise _key_cap_error(cap, current)

    async def update(
        self,
        org_id: str,
        actor_id: str,
        sandbox_id: str,
        *,
        labels: Mapping[str, str] | None = None,
        auto_stop_minutes: int | None = None,
        auto_delete_minutes: int | None = None,
        public: bool | None = None,
        egress_allowlist: tuple[str, ...] | None = None,
    ) -> Sandbox:
        self._validate_minutes(auto_stop_minutes, auto_delete_minutes)
        self._validate_labels(labels)
        requested: dict[str, Any] = {
            "labels": None if labels is None else dict(labels),
            "auto_stop_minutes": auto_stop_minutes,
            "auto_delete_minutes": auto_delete_minutes,
            "public": public,
        }
        changes = {key: value for key, value in requested.items() if value is not None}

        async with self._uow_factory() as uow:
            current = await self._core.require(uow, org_id, sandbox_id)
            if current.state in (_S.DESTROYING, _S.DESTROYED):
                raise InvalidState(
                    f"sandbox is {current.state.value}", details={"state": current.state.value}
                )
            note = AuditNote(actor_id, "sandbox.update", dict(changes))
            # the egress change, when the request carries an effective one
            plan: EgressUpdate | None = None
            if egress_allowlist is not None:  # None: the field was absent
                plan = plan_egress_update(current, egress_allowlist, actor_id, self._settings)
            if plan is not None:
                changes["egress_allowlist"] = plan.allowlist
                changes["egress_policy_generation"] = plan.generation
            if labels is not None:  # replacing user labels keeps the platform's reserved ones
                reserved = {k: v for k, v in current.labels.items() if is_reserved_label(k)}
                changes["labels"] = {**changes["labels"], **reserved}
            changes["updated_at"] = self._clock.now()
            saved = await uow.sandboxes.update(
                org_id, current.model_copy(update=changes), expected_version=current.version
            )
            if plan is None or note.details:  # an egress-only change has no update row
                await self._core.record(uow, org_id, sandbox_id, note)
            if plan is not None:
                await self._core.record(uow, org_id, sandbox_id, plan.note)
            await uow.commit()
        return saved

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

    async def _recreate_if_resized(self, org_id: str, sandbox_id: str) -> None:
        """Replace a stopped sandbox's container when its resources no longer match the row.

        A resize only changes the row; the container (adopted by its deterministic name
        otherwise) is replaced here, before the start intent. The root filesystem is kept: the
        stopped container is committed to the local image ``sf-resize-<id>`` and the new
        container is created from it. The tag stays while the sandbox lives (the new container is
        based on it, and on classic overlay2 removing it would delete the image under that
        container); the next resize commits to the same tag and the driver removes the tag with
        the sandbox. No transaction is open during the driver calls. A failing commit or create
        is an internal error, never a 404 for a sandbox that exists; the row stays as it was.
        A create that fails after the destroy keeps the image (the only copy of the files); a
        later start finds no container but the image, and creates the container from it.
        """
        sandbox = await self._load(org_id, sandbox_id)
        if sandbox.state is not _S.STOPPED or sandbox.driver_ref is None:
            return
        try:
            existing = await self._driver.inspect(sandbox.driver_ref)
        except DriverNotFound:
            # No container. With the sandbox's resize image the replace died between its destroy
            # and its create, and the data lives in that image: create from it. Without one a
            # vanished container is reported by the start itself.
            if not await self._resize_image_exists(sandbox.id):
                return
            created = await self._guarded(sandbox_id, self._create_from_resize_image, sandbox)
        else:
            if existing.resources == sandbox.resources:
                return
            created = await self._guarded(
                sandbox_id, self._replace_container, sandbox, sandbox.driver_ref
            )
        if created.ref == sandbox.driver_ref:
            return
        async with self._uow_factory() as uow:
            current = await self._core.require(uow, org_id, sandbox_id)
            changes = {"driver_ref": created.ref, "updated_at": self._clock.now()}
            await uow.sandboxes.update(
                org_id, current.model_copy(update=changes), expected_version=current.version
            )
            await uow.commit()

    @staticmethod
    async def _guarded(
        sandbox_id: str, step: Callable[..., Awaitable[InstanceInfo]], *args: Any
    ) -> InstanceInfo:
        """Run a replace step; a driver failure is an internal error, never a 404 or a leak."""
        try:
            return await step(*args)
        except DriverUnsupported:
            raise
        except DriverError as exc:
            logger.exception("resize of %s could not replace its container", sandbox_id)
            raise InternalError(RESIZE_FAILED_MESSAGE) from exc

    async def _replace_container(self, sandbox: Sandbox, old_ref: str) -> InstanceInfo:
        """Commit ``old_ref``, destroy it and create the new container from the committed image."""
        images = self._driver
        if not isinstance(images, ImageRegistryDriver):
            raise DriverUnsupported(
                f"driver {self._driver.name} cannot commit a container, so a resize "
                "could not keep its files"
            )
        faults = self._settings.fault_injection
        if FAULT_RESIZE_COMMIT_FAIL in faults:  # instead of the commit: nothing is touched
            raise DriverError(f"injected fault: {FAULT_RESIZE_COMMIT_FAIL}", ref=old_ref)
        image = resize_image_reference(sandbox.id)
        previous = await self._resize_image_id(image)
        committed = await images.commit_container(old_ref, image, labels={RESIZE_IMAGE_LABEL: "1"})
        try:
            # Scratch volumes belong to the sandbox id, not to this container: keep them, so the
            # new container mounts the same ones (image-declared data survives the resize).
            await self._driver.destroy(old_ref, remove_volumes=False)
        except Exception:
            await self._discard_resize_image(images, image)  # the old container lives on
            raise
        try:
            created = await self._create_from_resize_image(sandbox)
        except Exception:
            # The old container is gone: the committed image is now the only copy of the
            # sandbox's files. Keep it; the next start creates the container from it.
            logger.warning(
                "resize of %s lost its container: the sandbox's data lives in the image %s "
                "until the next successful start",
                sandbox.id,
                image,
            )
            raise
        if previous is not None and previous != committed.digest:
            await self._discard_resize_image(images, previous)  # the image the tag moved off
        return created

    async def _create_from_resize_image(self, sandbox: Sandbox) -> InstanceInfo:
        """Create the sandbox's container from its resize image with the row's resources."""
        if FAULT_RESIZE_CREATE_FAIL in self._settings.fault_injection:  # instead of the create
            raise DriverError(f"injected fault: {FAULT_RESIZE_CREATE_FAIL}", ref=sandbox.id)
        image = resize_image_reference(sandbox.id)
        spec = dataclasses.replace(MountingLifecycle.spec(sandbox), image=image)
        return await self._driver.create(spec)

    async def _resize_image_exists(self, sandbox_id: str) -> bool:
        """True when the sandbox's resize image is present; a driver that cannot say, or fails."""
        images = self._driver
        if not isinstance(images, ImageRegistryDriver):
            return False
        try:
            return await images.image_exists(resize_image_reference(sandbox_id))
        except Exception:
            logger.warning("could not look for the resize image of %s", sandbox_id, exc_info=True)
            return False

    async def _resize_image_id(self, image: str) -> str | None:
        """The id the resize tag points at now (a resize before this one), else ``None``."""
        try:
            return (await self._driver.inspect_image(image)).digest
        except DriverNotFound:
            return None
        except Exception:
            logger.debug("could not inspect the resize image %s", image, exc_info=True)
            return None

    @staticmethod
    async def _discard_resize_image(images: ImageRegistryDriver, image: str) -> None:
        """Best effort: remove a resize image by tag or id (forced; failure only logs)."""
        try:
            await images.remove_image(image, force=True)
        except Exception:
            logger.debug("could not remove the resize image %s", image, exc_info=True)

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

    @staticmethod
    def _with_carried_mounts(command: CreateSandboxCommand) -> CreateSandboxCommand:
        """Move what the create schema carried in ``labels`` to ``volumes`` and the allowlist."""
        labels, allowlist = take_egress_allowlist(command.labels)
        if allowlist is not None:
            command = dataclasses.replace(command, labels=labels, egress_allowlist=allowlist)
        if MOUNT_REQUESTS_LABEL not in command.labels:
            return command
        labels, carried = take_mount_requests(command.labels)
        return dataclasses.replace(command, labels=labels, volumes=(*command.volumes, *carried))

    def _with_default_network(self, command: CreateSandboxCommand) -> CreateSandboxCommand:
        """Block the network of a create that names no policy, when the deployment says so.

        Only an unset ``network.block_all`` takes the default: an explicit ``false`` keeps the
        network open, and a create with a non-empty egress allowlist keeps its own rules. An
        empty allowlist reaches nothing, so it always blocks the network (fail closed), whatever
        the default or an explicit ``false``. Runs after ``_with_carried_mounts`` so the
        allowlist is already a command field.

        With ``enforce_block_network`` the default is no longer one a tenant overrides: an
        explicit ``block_all: false`` or a non-empty allowlist is refused with 403, and every
        accepted create is stored with ``block_all`` true.
        """
        if self._settings.enforce_block_network:
            return self._enforced_network(command)
        if command.egress_allowlist is not None and not command.egress_allowlist:
            return dataclasses.replace(command, network=NetworkPolicy(block_all=True))
        if not self._settings.default_block_network:
            return command
        if command.egress_allowlist is not None:
            return command
        if "block_all" in command.network.model_fields_set:
            return command
        return dataclasses.replace(command, network=NetworkPolicy(block_all=True))

    @staticmethod
    def _enforced_network(command: CreateSandboxCommand) -> CreateSandboxCommand:
        opens_network = (
            "block_all" in command.network.model_fields_set and not command.network.block_all
        )
        if opens_network or command.egress_allowlist:
            raise Forbidden(NETWORK_POLICY_MESSAGE)
        return dataclasses.replace(command, network=NetworkPolicy(block_all=True))

    @staticmethod
    def _create_note(actor_id: str, command: CreateSandboxCommand) -> AuditNote:
        details = {
            "name": command.name,
            "snapshot": command.snapshot,
            "resources": command.resources.model_dump(mode="json"),
            "env": dict(command.env),
            "labels": dict(command.labels),
            "network": command.network.model_dump(mode="json"),
            "auto_stop_minutes": command.auto_stop_minutes,
            "auto_delete_minutes": command.auto_delete_minutes,
            "public": command.public,
            "egress_allowlist": command.egress_allowlist,  # hostnames, not secrets
            "isolation": command.isolation,  # None: the deployment default
            "volumes": [
                {
                    "volume_id": mount.volume_id,
                    "mount_path": mount.mount_path,
                    "read_only": mount.read_only,
                }
                for mount in command.volumes
            ],
        }
        return AuditNote(actor_id, "sandbox.create", details)

    async def _load(self, org_id: str, sandbox_id: str) -> Sandbox:
        return await self._core.load(org_id, sandbox_id)

    async def _place(self, uow: UnitOfWorkPort, command: CreateSandboxCommand) -> str:
        """Jobs run on any node; an inline create drives this process's own daemon.

        An allowlisted create in jobs mode only lands on a node that reported ``egress_ready``
        (409 when none did); the node that runs the job mints the token (design 7.2, 7.3). An
        empty allowlist forces ``block_all`` before placement and needs no egress node.
        """
        local = self._settings.node_id
        if not self._use_jobs:
            return local
        needs_egress = needs_egress_stack(command.egress_allowlist, command.network.block_all)
        return await pick_node(uow, self._clock, local, require_egress=needs_egress)

    async def _enqueue(self, uow: UnitOfWorkPort, job: SandboxJob, node_id: str) -> None:
        queued = await enqueue_job(uow, self._clock, job.org_id, job.kind, job.payload())
        await stamp_job(uow, queued.id, node_id)

    async def _with_snapshot_id(
        self, org_id: str, command: CreateSandboxCommand
    ) -> CreateSandboxCommand:
        """Replace a snapshot name of this org with the snapshot's id.

        A value that starts with the id prefix is already an id. A name that matches no snapshot,
        or whose snapshot is outside the caller's label scope, stays as it is and takes the
        image-reference path, so a scoped key cannot tell the two apart or learn the id. The
        state check is left to the id steps that follow, so the outcome equals a create by id.
        """
        name = command.snapshot
        if name is None or name.startswith(SNAPSHOT_ID_PREFIX):
            return command
        async with self._uow_factory() as uow:
            found = await uow.snapshots.get_by_name(org_id, name)
            if found is None or not await snapshot_in_label_scope(uow, found):
                return command
        return dataclasses.replace(command, snapshot=found.id)

    async def _inherit_snapshot_tier(
        self, org_id: str, command: CreateSandboxCommand
    ) -> CreateSandboxCommand:
        """Give a create that names no tier the tier recorded on its snapshot, if any.

        An explicit tier wins. A recorded tier this deployment does not offer is refused
        with the unavailable-tier 422 rather than replaced by the default.
        """
        snapshot_id = command.snapshot
        if command.isolation is not None or snapshot_id is None:
            return command
        if not snapshot_id.startswith(SNAPSHOT_ID_PREFIX):
            return command
        async with self._uow_factory() as uow:
            found = await uow.snapshots.get(org_id, snapshot_id)
        if found is None or found.isolation is None:  # a missing snapshot is reported later
            return command
        self._validate_isolation(found.isolation, f" (recorded on snapshot {snapshot_id})")
        return dataclasses.replace(command, isolation=found.isolation)

    async def _inherit_snapshot_resources(
        self, org_id: str, command: CreateSandboxCommand
    ) -> CreateSandboxCommand:
        """Opt-in: fill the resource fields the request left unset from the snapshot's record.

        Only a snapshot id (names are resolved to ids before this) whose row recorded resources
        changes anything; an explicit field wins. The merged values face the per-sandbox
        maximum again, so an oversized record is a 422, never clamped.
        """
        snapshot_id = command.snapshot
        if not command.inherit_resources or snapshot_id is None:
            return command
        if not snapshot_id.startswith(SNAPSHOT_ID_PREFIX):
            return command
        async with self._uow_factory() as uow:
            found = await uow.snapshots.get(org_id, snapshot_id)
        if found is None or found.resources is None:  # a missing snapshot is reported later
            return command
        merged = merge_recorded(command.resources, found.resources)
        self._check_resource_maximum(merged)
        return dataclasses.replace(command, resources=merged)

    async def _require_visible_snapshot(self, org_id: str, snapshot: str | None) -> None:
        """A label-scoped create from a snapshot id needs its source sandbox in scope (else 404).

        Runs before the warm pool is asked, since a standby built from such a snapshot would
        otherwise be claimed without ever resolving the snapshot. A missing snapshot is reported
        by ``_resolve_image``.
        """
        if current_label_scope() is None or snapshot is None:
            return
        if not snapshot.startswith(SNAPSHOT_ID_PREFIX):
            return
        async with self._uow_factory() as uow:
            found = await uow.snapshots.get(org_id, snapshot)
            if found is not None and not await snapshot_in_label_scope(uow, found):
                raise NotFound(f"snapshot {snapshot} not found")

    async def _resolve_image(self, uow: UnitOfWorkPort, org_id: str, snapshot: str | None) -> str:
        """A snapshot id resolves to its pinned image; anything else is an image reference."""
        if snapshot is None:
            return DEFAULT_IMAGE
        if not snapshot.startswith(SNAPSHOT_ID_PREFIX):
            check_user_image_reference(snapshot, self._settings.allowed_registries)
            return snapshot
        found = await uow.snapshots.get(org_id, snapshot)
        if found is None or not await snapshot_in_label_scope(uow, found):
            raise NotFound(f"snapshot {snapshot} not found")
        if found.state is not SnapshotState.READY:
            raise InvalidState(
                f"snapshot {snapshot} is {found.state.value}",
                details={"state": found.state.value},
            )
        return found.image_ref

    def _new_sandbox(
        self,
        org_id: str,
        command: CreateSandboxCommand,
        image_ref: str,
        mounts: Sequence[VolumeMount] = (),
    ) -> Sandbox:
        sandbox_id = new_sandbox_id()
        now = self._clock.now()
        tier = command.isolation or self._settings.default_isolation
        return Sandbox(
            id=sandbox_id,
            org_id=org_id,
            name=command.name or sandbox_id,
            state=_S.PENDING,
            desired_state=_S.STARTED,
            image_ref=image_ref,
            driver=self._driver.name,
            resources=command.resources,
            env=self._sandbox_env(sandbox_id, command, now),
            labels={**command.labels, **encode_mounts(mounts), **isolation_labels(tier)},
            network=command.network,
            public=command.public,
            auto_stop_minutes=command.auto_stop_minutes,
            auto_delete_minutes=command.auto_delete_minutes,
            created_at=now,
            updated_at=now,
            standby=command.standby,
            spec_hash=command.spec_hash,
            egress_allowlist=command.egress_allowlist,
            egress_policy_generation=0 if command.egress_allowlist is None else 1,
            snapshot=command.snapshot,
        )

    def _check_resource_maximum(self, resources: ResourceSpec) -> None:
        """422 when ``resources`` exceed the deployment's per-sandbox maximum."""
        maximum = ResourceSpec(
            cpu_millicores=self._settings.max_sandbox_cpu_millicores,
            memory_mib=self._settings.max_sandbox_memory_mib,
            disk_gib=self._settings.max_sandbox_disk_gib,
        )
        if not resources.fits_within(maximum):
            raise Unprocessable(
                "requested resources exceed the per-sandbox maximum",
                details={
                    "requested": resources.model_dump(),
                    "maximum": maximum.model_dump(),
                },
            )

    def _validate_create(self, command: CreateSandboxCommand) -> None:
        image = command.snapshot
        if image is not None and not image.startswith(SNAPSHOT_ID_PREFIX):
            check_user_image_reference(image, self._settings.allowed_registries)
        reserved = sorted(name for name in command.env if is_reserved_env_name(name))
        if reserved:
            raise Unprocessable(
                f"environment variable names starting with {ENV_PREFIX} are reserved",
                details={"names": reserved},
            )
        malformed = sorted(name for name in command.env if not _ENV_NAME.fullmatch(name))
        if malformed:
            raise Unprocessable("invalid environment variable names", details={"names": malformed})
        self._check_resource_maximum(command.resources)
        self._validate_minutes(command.auto_stop_minutes, command.auto_delete_minutes)
        self._validate_labels(command.labels)
        self._validate_isolation(command.isolation)
        validate_mount_requests(command.volumes)
        if command.volumes and self._use_jobs:
            raise Unprocessable(
                "volume mounts are not supported when sandboxes are created by jobs"
            )
        limit = self._settings.egress_allowlist_max_entries
        check_egress_allowlist(
            command.egress_allowlist,
            command.network,
            limit,
            Unprocessable,
            denied=self._settings.egress_denied_cidrs,
        )
        configured = self._settings.egress_proxy_address and self._settings.egress_secret
        if command.egress_allowlist and not configured:
            raise InvalidState("egress proxy address and secret are not configured")

    def _sandbox_env(
        self, sandbox_id: str, command: CreateSandboxCommand, now: datetime
    ) -> dict[str, str]:
        env = dict(command.env)
        if command.egress_allowlist and self._use_jobs:
            # The node that runs the create job mints (``egress_provision``); a user variable
            # must not pass for a minted one there.
            return without_proxy_variables(env)
        if command.egress_allowlist:
            address, secret = self._settings.egress_proxy_address, self._settings.egress_secret
            proxy_env = compose_proxy_env(
                address,
                secret,
                sandbox_id,
                now,
                ttl_s=self._settings.egress_token_ttl_s,
                auto_delete_minutes=command.auto_delete_minutes,
                epoch=0,
            )
            env.update(proxy_env)
        return env

    @staticmethod
    def _validate_labels(labels: Mapping[str, str] | None) -> None:
        reserved = sorted(name for name in labels or {} if is_reserved_label(name))
        if reserved:
            raise Unprocessable(
                f"label names starting with {RESERVED_LABEL_PREFIX} are reserved",
                details={"names": reserved},
            )

    def _validate_isolation(self, tier: str | None, origin: str = "") -> None:
        available = list(self._settings.isolation_tiers())
        if tier is not None and tier not in available:
            raise Unprocessable(
                f"isolation '{tier}'{origin} is not available here; "
                f"available: {', '.join(available)}",
                details={"requested": tier, "available": available},
            )

    @staticmethod
    def _validate_minutes(*values: int | None) -> None:
        if any(value is not None and value < MIN_AUTO_MINUTES for value in values):
            raise Unprocessable(f"auto stop/delete minutes must be >= {MIN_AUTO_MINUTES}")
