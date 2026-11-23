"""Declarative image builds: validate, compile, cache by spec hash, build as a job.

``build`` validates the wire payload against the schema, compiles it (any unsafe value is a 422)
and hashes the spec. A ready snapshot with that hash in the org is returned untouched; otherwise
a ``pending`` snapshot row carrying the hash is committed together with an ``image.build`` job.
The job handler runs the driver build under fixed cpu, memory and wall-clock limits, mirrors the
build log into an in-process ``LiveBuild`` and marks the row ``ready`` (digest, layer count) or
``error``; the reason lands in the audit trail (the table has no reason column) and on the
live build. Driver calls never run inside an open transaction.

A build creates an unlabelled snapshot with no source sandbox. By design it is shared by every
label scope: any key in the org sees and uses it, and a cache hit returns another scope's build.
A label-scoped key cannot delete such a snapshot (``snapshot_scope_reach``).

``follow_build_logs`` replays a build's log from its first line for any subscriber, then follows
it until the build finishes. Live builds are in-process only and bounded: each keeps at most
``MAX_LIVE_LINES`` lines and the registry retains at most ``MAX_RETAINED_BUILDS`` finished ones.
The build itself runs as a shielded task, so the runner's per-job timeout cannot kill a long
build; the retried job attaches to the same task instead of starting a second build.
"""

import asyncio
import logging
from collections import OrderedDict
from collections.abc import AsyncIterator, Callable, Iterable, Mapping
from dataclasses import dataclass
from functools import partial
from typing import Any, cast

from sandfort.clock import Clock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.events import ActorType, AuditOutcome
from sandfort.domain.image_spec import ImageSpec
from sandfort.domain.snapshot import Snapshot, SnapshotState
from sandfort.drivers.base import ImageBuildDriver, SandboxDriver
from sandfort.drivers.errors import DriverError, DriverUnsupported
from sandfort.errors import NotFound, Unprocessable
from sandfort.ids import new_snapshot_id
from sandfort.images.dockerfile import build_context
from sandfort.images.sdk_dsl_schema import validate_image_spec_payload
from sandfort.services.audit import AuditRecorder
from sandfort.services.image_policy import check_user_image_reference
from sandfort.services.snapshots import (
    MAX_ERROR_REASON_CHARS,
    SnapshotReadyWriter,
    snapshot_image_reference,
    snapshot_in_label_scope,
)
from sandfort.workers.handlers import JobContext, register
from sandfort.workers.jobs import DEFAULT_WAKEUP, JobWakeup, enqueue_job

logger = logging.getLogger(__name__)

IMAGE_BUILD = "image.build"
AUDIT_REQUEST = "image.build.request"
AUDIT_COMPLETE = "image.build.complete"
TARGET_TYPE = "snapshot"
BUILD_CPU_MILLICORES = 2000
BUILD_MEMORY_MIB = 2048
BUILD_TIMEOUT_S = 600.0
MAX_LIVE_LINES = 5000
MAX_RETAINED_BUILDS = 64
SCAN_PAGE = 200
TRUNCATION_NOTICE = "[build log truncated]"


class LiveBuild:
    """The log and outcome of one build; replayable from the first line, bounded in size."""

    def __init__(self) -> None:
        self._lines: list[str] = []
        self._changed = asyncio.Condition()
        self.state: SnapshotState | None = None
        self.reason: str | None = None
        self.task: asyncio.Task[Snapshot | None] | None = None

    @property
    def finished(self) -> bool:
        return self.state is not None

    async def add(self, line: str) -> None:
        async with self._changed:
            if len(self._lines) < MAX_LIVE_LINES:
                self._lines.append(line)
            elif len(self._lines) == MAX_LIVE_LINES:
                self._lines.append(TRUNCATION_NOTICE)
            self._changed.notify_all()

    async def finish(self, state: SnapshotState, reason: str | None = None) -> None:
        async with self._changed:
            self.state, self.reason = state, reason
            self._changed.notify_all()

    def _has_more(self, index: int) -> bool:
        return index < len(self._lines) or self.finished

    async def follow(self) -> AsyncIterator[str]:
        index = 0
        while True:
            async with self._changed:
                await self._changed.wait_for(partial(self._has_more, index))
                batch = self._lines[index:]
                done = self.finished
            for line in batch:
                yield line
            index += len(batch)
            if done and not batch:
                return


class LiveBuilds:
    """Process-wide live builds by snapshot id; finished ones are evicted oldest-first."""

    def __init__(self, max_retained: int = MAX_RETAINED_BUILDS) -> None:
        self._max_retained = max_retained
        self._builds: OrderedDict[str, LiveBuild] = OrderedDict()

    def open(self, snapshot_id: str) -> LiveBuild:
        build = self._builds.get(snapshot_id)
        if build is None:
            build = self._builds[snapshot_id] = LiveBuild()
            self._evict()
        return build

    def get(self, snapshot_id: str) -> LiveBuild | None:
        return self._builds.get(snapshot_id)

    def _evict(self) -> None:
        finished = [key for key, build in self._builds.items() if build.finished]
        for key in finished[: max(len(finished) - self._max_retained, 0)]:
            del self._builds[key]


LIVE_BUILDS = LiveBuilds()


@dataclass(frozen=True, slots=True)
class ImageBuildJob:
    org_id: str
    snapshot_id: str
    spec: Mapping[str, Any]
    actor_id: str | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "org_id": self.org_id,
            "snapshot_id": self.snapshot_id,
            "spec": dict(self.spec),
            "actor_id": self.actor_id,
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ImageBuildJob":
        actor = payload.get("actor_id")
        return cls(
            org_id=str(payload["org_id"]),
            snapshot_id=str(payload["snapshot_id"]),
            spec=dict(payload["spec"]),
            actor_id=None if actor is None else str(actor),
        )


class ImageBuildService:
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWorkPort],
        driver: SandboxDriver,
        clock: Clock,
        audit: AuditRecorder | None = None,
        wakeup: JobWakeup = DEFAULT_WAKEUP,
        live: LiveBuilds = LIVE_BUILDS,
        allowed_registries: Iterable[str] | None = None,
    ) -> None:
        # None = the policy default (the validated SANDFORT_ALLOWED_REGISTRIES); [] = any registry.
        self._allowed_registries = None if allowed_registries is None else tuple(allowed_registries)
        self._uow_factory = uow_factory
        self._driver = driver
        self._clock = clock
        self._audit = audit or AuditRecorder(clock)
        self._wakeup = wakeup
        self._live = live

    # -- queries ---------------------------------------------------------------

    async def get(self, org_id: str, snapshot_id: str) -> Snapshot:
        async with self._uow_factory() as uow:
            snapshot = await uow.snapshots.get(org_id, snapshot_id)
            visible = snapshot is not None and await snapshot_in_label_scope(uow, snapshot)
        if snapshot is None or not visible:
            raise NotFound(f"snapshot {snapshot_id} not found")
        return snapshot

    def failure_reason(self, snapshot_id: str) -> str | None:
        live = self._live.get(snapshot_id)
        return None if live is None else live.reason

    async def follow_build_logs(self, org_id: str, snapshot_id: str) -> AsyncIterator[str]:
        """Log lines of the build behind ``snapshot_id`` (404 for a foreign or missing one)."""
        await self.get(org_id, snapshot_id)
        live = self._live.get(snapshot_id)
        return live.follow() if live is not None else _no_lines()

    # -- commands --------------------------------------------------------------

    async def build(
        self,
        org_id: str,
        actor_id: str | None,
        payload: Mapping[str, Any],
        name: str | None = None,
    ) -> Snapshot:
        """Return the ready snapshot for this spec, or commit a pending one with its job."""
        spec = validate_image_spec_payload(payload)
        self._check_base_registry(spec)  # a foreign registry is a 422 like on the create path
        build_context(spec)  # compile now: an unsafe value is a 422 before anything is stored
        spec_hash = spec.spec_hash
        snapshot_id = new_snapshot_id()
        async with self._uow_factory() as uow:
            cached = await self._find_ready(uow, org_id, spec_hash)
            if cached is not None:
                details = {"spec_hash": spec_hash, "reused": True}
                await self._record(uow, cached, actor_id, AUDIT_REQUEST, details)
                await uow.commit()
                return cached
            snapshot = Snapshot(
                id=snapshot_id,
                org_id=org_id,
                name=name or f"build-{snapshot_id.lower()}",
                image_ref=snapshot_image_reference(snapshot_id),
                digest="",
                layer_count=0,
                state=SnapshotState.PENDING,
                spec_hash=spec_hash,
                created_at=self._clock.now(),
            )
            await uow.snapshots.add(snapshot)
            details = {"spec_hash": spec_hash, "reused": False, "name": snapshot.name}
            await self._record(uow, snapshot, actor_id, AUDIT_REQUEST, details)
            job = ImageBuildJob(org_id, snapshot_id, spec.model_dump(mode="json"), actor_id)
            await enqueue_job(uow, self._clock, org_id, IMAGE_BUILD, job.payload())
            await uow.commit()
        self._live.open(snapshot_id)
        self._wakeup.notify()
        return snapshot

    async def complete_build(self, job: ImageBuildJob) -> Snapshot | None:
        """The job body. Idempotent: only a pending row is built; a retry joins a running build."""
        async with self._uow_factory() as uow:
            snapshot = await uow.snapshots.get(job.org_id, job.snapshot_id)
        if snapshot is None or snapshot.state is not SnapshotState.PENDING:
            return snapshot
        live = self._live.open(job.snapshot_id)
        if live.task is None or live.task.done():
            live.task = asyncio.get_running_loop().create_task(self._execute(snapshot, job, live))
        return await asyncio.shield(live.task)

    # -- helpers ---------------------------------------------------------------

    def _check_base_registry(self, spec: ImageSpec) -> None:
        check_user_image_reference(spec.base_image, self._allowed_registries)

    def _builder(self) -> ImageBuildDriver:
        driver = self._driver
        if not isinstance(driver, ImageBuildDriver):
            raise DriverUnsupported(f"driver {driver.name} cannot build images")
        return driver

    async def _execute(
        self, snapshot: Snapshot, job: ImageBuildJob, live: LiveBuild
    ) -> Snapshot | None:
        try:
            spec = ImageSpec.model_validate(job.spec)
            self._check_base_registry(spec)  # the policy may have tightened since the request
            context = build_context(spec)
            handle = await self._builder().start_build(
                context,
                snapshot.image_ref,
                cpu_millicores=BUILD_CPU_MILLICORES,
                memory_mib=BUILD_MEMORY_MIB,
                timeout_s=BUILD_TIMEOUT_S,
            )
            pump = asyncio.get_running_loop().create_task(_mirror_logs(handle.logs(), live))
            try:
                digest = await handle.result()
            finally:
                await pump
            layer_count = (await self._driver.inspect_image(snapshot.image_ref)).layer_count
        except (Unprocessable, DriverError) as exc:
            return await self._fail(snapshot, exc.message, live)
        return await self._finish(snapshot, job.actor_id, digest, layer_count, live)

    async def _finish(
        self, snapshot: Snapshot, actor_id: str | None, digest: str, layers: int, live: LiveBuild
    ) -> Snapshot | None:
        async with self._uow_factory() as uow:
            writer = cast(SnapshotReadyWriter, uow.snapshots)
            ready = await writer.mark_ready(
                snapshot.org_id, snapshot.id, digest=digest, layer_count=layers
            )
            if ready is not None:
                details = {"digest": digest, "layer_count": layers, "spec_hash": snapshot.spec_hash}
                await self._record(uow, snapshot, actor_id, AUDIT_COMPLETE, details)
            await uow.commit()
        await live.finish(SnapshotState.READY if ready is not None else SnapshotState.DELETING)
        return ready

    async def _fail(self, snapshot: Snapshot, reason: str, live: LiveBuild) -> Snapshot | None:
        reason = reason[:MAX_ERROR_REASON_CHARS]
        logger.warning("image build %s failed: %s", snapshot.id, reason)
        async with self._uow_factory() as uow:
            failed = await uow.snapshots.get(snapshot.org_id, snapshot.id)
            if failed is not None and failed.state is SnapshotState.PENDING:
                failed = await uow.snapshots.set_state(
                    snapshot.org_id, snapshot.id, SnapshotState.ERROR
                )
                details = {"reason": reason, "spec_hash": snapshot.spec_hash}
                await self._record(
                    uow,
                    snapshot,
                    None,
                    AUDIT_COMPLETE,
                    details,
                    outcome=AuditOutcome.ERROR,
                    actor_type=ActorType.SYSTEM,
                )
            await uow.commit()
        await live.finish(SnapshotState.ERROR, reason)
        return failed

    @staticmethod
    async def _find_ready(uow: UnitOfWorkPort, org_id: str, spec_hash: str) -> Snapshot | None:
        cursor: str | None = None
        while True:
            page = await uow.snapshots.list(org_id, cursor=cursor, limit=SCAN_PAGE)
            for item in page:
                if item.spec_hash == spec_hash and item.state is SnapshotState.READY:
                    return item
            if len(page) < SCAN_PAGE:
                return None
            cursor = page[-1].id

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


async def _no_lines() -> AsyncIterator[str]:
    return
    yield


async def _mirror_logs(lines: AsyncIterator[str], live: LiveBuild) -> None:
    async for line in lines:
        await live.add(line)


@register(IMAGE_BUILD)
async def handle_image_build(payload: Mapping[str, Any], context: JobContext) -> None:
    service = ImageBuildService(context.uow_factory, context.driver, context.clock)
    await service.complete_build(ImageBuildJob.from_payload(payload))
