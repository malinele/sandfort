"""Snapshot orchestration: register a registry image, commit a sandbox, get/list, delete.

Driver calls never run inside an open transaction (intent first, then act, architecture D4).
Registering pulls first, then persists a ``ready`` row pinned to the repo digest. Creating
from a sandbox commits a ``pending`` row together with a ``snapshot.create`` job; the job runs
``complete_create``: commit the container (paused) and, when the commit stacks more than
``MAX_LAYER_COUNT`` layers, flatten it to a single layer instead, then mark the row ready. A
failure marks the row ``error``; the reason lands in the audit trail (the table has no reason
column). Deleting refuses while a non-deleted sandbox in the org runs from the snapshot's
image, otherwise marks the row ``deleting``, removes the image best-effort and deletes the row.
"""

import logging
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, cast, runtime_checkable

from sandfort.auth.label_scope import current_label_scope, matches
from sandfort.clock import Clock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.events import ActorType, AuditOutcome
from sandfort.domain.isolation import recorded_tier
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.domain.snapshot import Snapshot, SnapshotState
from sandfort.drivers.base import CommitResult, ImageRegistryDriver, SandboxDriver
from sandfort.drivers.errors import DriverError, DriverUnsupported
from sandfort.errors import IN_USE, Conflict, Forbidden, InvalidState, NotFound
from sandfort.ids import new_snapshot_id
from sandfort.services.audit import AuditRecorder
from sandfort.services.image_policy import (
    SNAPSHOT_REPOSITORY,
    check_user_image_reference,
    is_reserved_image_reference,
)
from sandfort.services.label_scope import contradicts, merge_scope, unscoped
from sandfort.workers.jobs import DEFAULT_WAKEUP, JobWakeup, enqueue_job

__all__ = ["SNAPSHOT_REPOSITORY", "is_reserved_image_reference"]  # one implementation: image_policy

logger = logging.getLogger(__name__)

SNAPSHOT_CREATE = "snapshot.create"
MAX_LAYER_COUNT = 20
MAX_ERROR_REASON_CHARS = 500
REFERENCE_SCAN_PAGE = 200
TARGET_TYPE = "snapshot"
SNAPSHOTTABLE_STATES = frozenset({SandboxState.STARTED, SandboxState.STOPPED, SandboxState.ERROR})


@runtime_checkable
class SnapshotImageDriver(ImageRegistryDriver, Protocol):
    """The registry protocol plus the export/import flatten both shipped drivers provide."""

    async def flatten_container(self, provider_id: str, image_reference: str) -> CommitResult:
        """Export the instance filesystem and import it as a single-layer image."""
        ...


class SnapshotReadyWriter(Protocol):
    """What the SQL snapshot repository adds to the frozen port."""

    async def mark_ready(
        self, org_id: str, snapshot_id: str, *, digest: str, layer_count: int
    ) -> Snapshot | None: ...


@dataclass(frozen=True, slots=True)
class SnapshotCreateJob:
    org_id: str
    snapshot_id: str
    actor_id: str | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "org_id": self.org_id,
            "snapshot_id": self.snapshot_id,
            "actor_id": self.actor_id,
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "SnapshotCreateJob":
        actor = payload.get("actor_id")
        return cls(
            org_id=str(payload["org_id"]),
            snapshot_id=str(payload["snapshot_id"]),
            actor_id=None if actor is None else str(actor),
        )


def pin_reference(reference: str, digest: str) -> str:
    """``repository@digest`` for ``reference``; any tag or earlier digest is replaced."""
    name = reference.split("@", 1)[0]
    slash, colon = name.rfind("/"), name.rfind(":")
    if colon > slash:
        name = name[:colon]
    return f"{name}@{digest}"


def snapshot_image_reference(snapshot_id: str) -> str:
    """The local tag a committed snapshot is written to; unique per snapshot, never reused."""
    return f"{SNAPSHOT_REPOSITORY}:{snapshot_id.lower()}"


class ScopeReach(Enum):
    """How the request's label scope reaches a snapshot."""

    NONE = "none"  # not visible: 404
    OWNED = "owned"  # unscoped request, scope labels on the snapshot, or a visible source sandbox
    SHARED = "shared"  # unlabelled and sourceless (registered by an org-wide key, or built)


async def snapshot_scope_reach(uow: UnitOfWorkPort, snapshot: Snapshot) -> ScopeReach:
    """How the request's label scope reaches ``snapshot``.

    Unscoped requests own every snapshot. A snapshot is owned when its labels contain the scope
    or when the sandbox it was committed from is visible to the scope, so a labelled snapshot
    does not vanish for a key that sees its source (an ``env=prod`` snapshot of a ``team=red``
    sandbox stays visible to the ``team=red`` key). A snapshot with no labels and no source
    sandbox (registered by an org-wide key, or built) is shared by every scope: visible, but not
    deletable by a scoped key. A destroyed source keeps its labels, so it still decides; a source
    row that is gone entirely does not match.
    """
    scope = current_label_scope()
    if scope is None or matches(snapshot.labels, scope):
        return ScopeReach.OWNED
    source_id = snapshot.source_sandbox_id
    if source_id is None:
        return ScopeReach.NONE if snapshot.labels else ScopeReach.SHARED
    source = await uow.sandboxes.get(snapshot.org_id, source_id)
    if source is not None and matches(source.labels, scope):
        return ScopeReach.OWNED
    return ScopeReach.NONE


async def snapshot_in_label_scope(uow: UnitOfWorkPort, snapshot: Snapshot) -> bool:
    """Whether the request's label scope can see ``snapshot`` (see ``snapshot_scope_reach``)."""
    return await snapshot_scope_reach(uow, snapshot) is not ScopeReach.NONE


def shared_snapshot_refusal(snapshot_id: str) -> Forbidden:
    """The 403 for a scoped key deleting a snapshot that no scope owns."""
    return Forbidden(
        f"snapshot {snapshot_id} is shared across the org; "
        "only a key without sandbox_labels can delete it"
    )


def require_source(sandbox: Sandbox | None) -> str:
    """The container ref of a sandbox that can be snapshotted; ``InvalidState`` otherwise.

    A sandbox in ``error`` is allowed while its row still has a ``driver_ref``: that is data
    recovery. A sandbox whose code filled the disk can no longer start, but the commit works on a
    container that is not running, so snapshot it and create a new sandbox from the snapshot with
    a larger ``disk_gib``. If the container is already gone the commit fails and the usual
    snapshot failure path (row ``error``, reason in the audit trail) applies.
    """
    if sandbox is None:
        raise InvalidState("the source sandbox no longer exists")
    if sandbox.state not in SNAPSHOTTABLE_STATES or sandbox.driver_ref is None:
        raise InvalidState(
            f"sandbox {sandbox.id} is {sandbox.state.value}, not started, stopped or error",
            details={"state": sandbox.state.value},
        )
    return sandbox.driver_ref


class SnapshotService:
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWorkPort],
        driver: SandboxDriver,
        clock: Clock,
        audit: AuditRecorder | None = None,
        wakeup: JobWakeup = DEFAULT_WAKEUP,
        default_tier: str | None = None,
        allowed_registries: Iterable[str] | None = None,
    ) -> None:
        # None: the policy default (SANDFORT_ALLOWED_REGISTRIES); () accepts any registry.
        self._allowed_registries = None if allowed_registries is None else tuple(allowed_registries)
        self._default_tier = default_tier  # recorded for a source sandbox without a tier label
        self._uow_factory = uow_factory
        self._driver = driver
        self._clock = clock
        self._audit = audit or AuditRecorder(clock)
        self._wakeup = wakeup

    # -- queries ---------------------------------------------------------------

    async def get(self, org_id: str, snapshot_id: str) -> Snapshot:
        async with self._uow_factory() as uow:
            return await self._require(uow, org_id, snapshot_id)

    async def list(
        self,
        org_id: str,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> Sequence[Snapshot]:
        """Snapshots carrying every requested label that the key's label scope can see."""
        wanted = dict(labels or {})
        scope = current_label_scope()
        if scope is not None and contradicts(wanted, scope):
            return []
        async with self._uow_factory() as uow:
            if scope is None:
                return await uow.snapshots.list(org_id, labels=wanted, cursor=cursor, limit=limit)
            return await self._list_in_scope(uow, org_id, wanted, cursor, limit)

    # -- commands --------------------------------------------------------------

    async def register(
        self,
        org_id: str,
        actor_id: str | None,
        image: str,
        name: str | None = None,
        labels: Mapping[str, str] | None = None,
    ) -> Snapshot:
        """Pull ``image`` and persist a ready snapshot pinned to its repo digest.

        A label-scoped key's scope labels are merged into ``labels``.

        The reference is policy-checked first: an image ID or a reserved repository would
        otherwise resolve against the local store before anything is pulled.
        """
        stored = merge_scope(labels or {}, current_label_scope())
        check_user_image_reference(image, self._allowed_registries)
        digest = await self._images().pull_image_digest(image)
        info = await self._driver.inspect_image(image)
        snapshot = Snapshot(
            id=new_snapshot_id(),
            org_id=org_id,
            name=name or image,
            image_ref=pin_reference(image, digest),
            digest=digest,
            layer_count=info.layer_count,
            state=SnapshotState.READY,
            labels=stored,
            created_at=self._clock.now(),
        )
        async with self._uow_factory() as uow:
            await uow.snapshots.add(snapshot)
            details = {
                "name": snapshot.name,
                "image": image,
                "digest": digest,
                "labels": dict(snapshot.labels),
            }
            await self._record(uow, snapshot, actor_id, "snapshot.register", details)
            await uow.commit()
        return snapshot

    async def create_from_sandbox(
        self,
        org_id: str,
        actor_id: str | None,
        sandbox_id: str,
        name: str,
        labels: Mapping[str, str] | None = None,
    ) -> Snapshot:
        """Commit the pending row and its ``snapshot.create`` job; the runner finishes it.

        A label-scoped key's scope labels are merged into ``labels``.
        """
        stored = merge_scope(labels or {}, current_label_scope())
        snapshot_id = new_snapshot_id()
        async with self._uow_factory() as uow:
            sandbox = await uow.sandboxes.get(org_id, sandbox_id)
            if sandbox is None:
                raise NotFound(f"sandbox {sandbox_id} not found")
            require_source(sandbox)
            snapshot = Snapshot(
                id=snapshot_id,
                org_id=org_id,
                name=name,
                image_ref=snapshot_image_reference(snapshot_id),
                digest="",
                layer_count=0,
                state=SnapshotState.PENDING,
                source_sandbox_id=sandbox_id,
                isolation=recorded_tier(sandbox.labels) or self._default_tier,
                labels=stored,
                created_at=self._clock.now(),
            )
            await uow.snapshots.add(snapshot)
            details = {"name": name, "sandbox_id": sandbox_id, "labels": dict(snapshot.labels)}
            await self._record(uow, snapshot, actor_id, "snapshot.create", details)
            job = SnapshotCreateJob(org_id, snapshot_id, actor_id)
            await enqueue_job(uow, self._clock, org_id, SNAPSHOT_CREATE, job.payload())
            await uow.commit()
        self._wakeup.notify()
        return snapshot

    async def complete_create(self, org_id: str, snapshot_id: str) -> Snapshot | None:
        """The job body. Idempotent: only a pending row is committed; otherwise it is returned."""
        async with self._uow_factory() as uow:
            snapshot = await uow.snapshots.get(org_id, snapshot_id)
            if snapshot is None or snapshot.state is not SnapshotState.PENDING:
                return snapshot
            source_id = snapshot.source_sandbox_id
            sandbox = None if source_id is None else await uow.sandboxes.get(org_id, source_id)
        try:
            result = await self._commit(require_source(sandbox), snapshot.image_ref)
        except (InvalidState, DriverError) as exc:
            return await self._fail(snapshot, exc.message)
        return await self._finish(snapshot, result)

    async def delete(self, org_id: str, actor_id: str | None, snapshot_id: str) -> Snapshot:
        async with self._uow_factory() as uow:
            snapshot = await self._require(uow, org_id, snapshot_id)
            if await snapshot_scope_reach(uow, snapshot) is ScopeReach.SHARED:
                raise shared_snapshot_refusal(snapshot_id)
            user = await self._referencing_sandbox(uow, org_id, snapshot.image_ref)
            if user is not None:
                raise self._in_use(snapshot_id, user)
            deleting = await uow.snapshots.set_state(org_id, snapshot_id, SnapshotState.DELETING)
            if deleting is None:
                raise NotFound(f"snapshot {snapshot_id} not found")
            details = {"name": snapshot.name}
            await self._record(uow, snapshot, actor_id, "snapshot.delete", details)
            await uow.commit()
        await self._discard(snapshot.image_ref)
        async with self._uow_factory() as uow:
            await uow.snapshots.delete(org_id, snapshot_id)
            await uow.commit()
        return deleting

    # -- helpers ---------------------------------------------------------------

    def _images(self) -> SnapshotImageDriver:
        driver = self._driver
        if not isinstance(driver, SnapshotImageDriver):
            raise DriverUnsupported(f"driver {driver.name} cannot pin, commit or flatten images")
        return driver

    async def _commit(self, ref: str, image_ref: str) -> CommitResult:
        images = self._images()
        committed = await images.commit_container(ref, image_ref)
        if committed.layer_count <= MAX_LAYER_COUNT:
            return committed
        flat = await images.flatten_container(ref, image_ref)
        if flat.digest != committed.digest:
            await self._discard(committed.digest)  # the deep commit lost its tag to the flat one
        return flat

    async def _finish(self, snapshot: Snapshot, result: CommitResult) -> Snapshot | None:
        async with self._uow_factory() as uow:
            writer = cast(SnapshotReadyWriter, uow.snapshots)
            ready = await writer.mark_ready(
                snapshot.org_id,
                snapshot.id,
                digest=result.digest,
                layer_count=result.layer_count,
            )
            await uow.commit()
        if ready is None:  # deleted while committing: do not leave the image behind
            await self._discard(snapshot.image_ref)
        return ready

    async def _fail(self, snapshot: Snapshot, reason: str) -> Snapshot | None:
        reason = reason[:MAX_ERROR_REASON_CHARS]
        logger.warning("snapshot %s failed: %s", snapshot.id, reason)
        async with self._uow_factory() as uow:
            current = await uow.snapshots.get(snapshot.org_id, snapshot.id)
            if current is None or current.state is not SnapshotState.PENDING:
                return current
            failed = await uow.snapshots.set_state(
                snapshot.org_id, snapshot.id, SnapshotState.ERROR
            )
            await self._record(
                uow,
                snapshot,
                None,
                "snapshot.create",
                {"name": snapshot.name, "reason": reason},
                outcome=AuditOutcome.ERROR,
                actor_type=ActorType.SYSTEM,
            )
            await uow.commit()
        return failed

    async def _discard(self, ref: str) -> None:
        """Remove an image best-effort: a failure is logged, never raised."""
        try:
            await self._images().remove_image(ref)
        except DriverError as exc:
            logger.warning("could not remove image %s: %s", ref, exc.message)

    @staticmethod
    async def _referencing_sandbox(
        uow: UnitOfWorkPort, org_id: str, image_ref: str
    ) -> Sandbox | None:
        """A non-deleted sandbox in ``org_id`` running from ``image_ref``, if any.

        The scan is a system check: it runs on the unscoped repository so a label-scoped key
        cannot delete an image from under another team's sandbox.
        """
        sandboxes = unscoped(uow.sandboxes)
        cursor: str | None = None
        while True:
            page = await sandboxes.list(org_id, cursor=cursor, limit=REFERENCE_SCAN_PAGE)
            for sandbox in page:
                live = sandbox.state is not SandboxState.DESTROYED and sandbox.deleted_at is None
                if live and sandbox.image_ref == image_ref:
                    return sandbox
            if len(page) < REFERENCE_SCAN_PAGE:
                return None
            cursor = page[-1].id

    @staticmethod
    def _in_use(snapshot_id: str, sandbox: Sandbox) -> Conflict:
        """The 409 for a snapshot a sandbox still runs from.

        The sandbox id is only named when the request's label scope can see that sandbox.
        """
        if not matches(sandbox.labels, current_label_scope()):
            return Conflict(f"snapshot {snapshot_id} is in use by a sandbox", reason=IN_USE)
        return Conflict(
            f"snapshot {snapshot_id} is used by sandbox {sandbox.id}",
            reason=IN_USE,
            details={"sandbox_id": sandbox.id},
        )

    @staticmethod
    async def _list_in_scope(
        uow: UnitOfWorkPort,
        org_id: str,
        labels: Mapping[str, str],
        cursor: str | None,
        limit: int,
    ) -> Sequence[Snapshot]:
        """Up to ``limit`` snapshots after ``cursor`` that carry ``labels`` and the key can see."""
        visible: list[Snapshot] = []
        while len(visible) < limit:
            page = await uow.snapshots.list(
                org_id, labels=labels, cursor=cursor, limit=REFERENCE_SCAN_PAGE
            )
            for snapshot in page:
                if await snapshot_in_label_scope(uow, snapshot):
                    visible.append(snapshot)
                    if len(visible) == limit:
                        return visible
            if len(page) < REFERENCE_SCAN_PAGE:
                break
            cursor = page[-1].id
        return visible

    @staticmethod
    async def _require(uow: UnitOfWorkPort, org_id: str, snapshot_id: str) -> Snapshot:
        snapshot = await uow.snapshots.get(org_id, snapshot_id)
        if snapshot is None or not await snapshot_in_label_scope(uow, snapshot):
            raise NotFound(f"snapshot {snapshot_id} not found")
        return snapshot

    async def _record(
        self,
        uow: UnitOfWorkPort,
        snapshot: Snapshot,
        actor_id: str | None,
        action: str,
        details: Mapping[str, Any],
        *,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        actor_type: ActorType = ActorType.API_KEY,
    ) -> None:
        await self._audit.record(
            uow,
            org_id=snapshot.org_id,
            actor_type=actor_type,
            actor_id=actor_id,
            action=action,
            target_type=TARGET_TYPE,
            target_id=snapshot.id,
            outcome=outcome,
            details=details,
        )
