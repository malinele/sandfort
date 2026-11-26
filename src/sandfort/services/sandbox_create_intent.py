"""The create intent of ``SandboxService``: quota, key cap, volumes, placement, a mixin."""

from collections.abc import Mapping

from sandfort.auth.label_scope import current_label_scope
from sandfort.db.locking import lock_quota
from sandfort.db.repositories.ports import (
    SandboxRepository,
    ScopedSandboxCounting,
    UnitOfWorkPort,
)
from sandfort.domain.resources import ResourceSpec
from sandfort.domain.sandbox import Sandbox
from sandfort.errors import QuotaExceeded
from sandfort.services.egress_provision import needs_egress_stack
from sandfort.services.label_scope import count_by_scanning
from sandfort.services.node_registry import pick_node, stamp_job, stamp_sandbox
from sandfort.services.quota import reservation_for
from sandfort.services.sandbox_commands import CreateSandboxCommand
from sandfort.services.sandbox_snapshot_resolution import SnapshotResolutionMixin
from sandfort.services.volume_limit import MountLimit
from sandfort.services.volumes import MountRequest, decode_mounts, resolve_mounts
from sandfort.workers.jobs import SandboxCreateJob, SandboxJob, enqueue_job


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


class SandboxCreateIntentMixin(SnapshotResolutionMixin):
    """Commit a create intent: refusals before it, the row, reservation, audit and job."""

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
