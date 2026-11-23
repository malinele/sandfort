"""Resize of a stopped sandbox (WP 5.7).

Only a ``stopped`` sandbox can be resized; any other state is an ``InvalidState`` conflict.
The new spec is the row's resources with the requested fields replaced. Releasing the old
ledger reservation, reserving the new one (the same org quota and host admission checks as
create) and persisting the new resources on the row happen in one unit of work, so a refused
resize (``QuotaExceeded`` 429, ``CapacityExceeded`` 503) rolls back and leaves the old
reservation and the old row untouched. No driver call is made here: the row now differs from
the stopped container, and the next start (``SandboxService.start``) recreates the container.
"""

from collections.abc import Callable
from dataclasses import dataclass

from sandfort.clock import Clock
from sandfort.config import Settings
from sandfort.db.locking import lock_quota
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.events import ActorType
from sandfort.domain.resources import ResourceSpec
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.errors import InvalidState, NotFound, Unprocessable
from sandfort.services.audit import AuditRecorder
from sandfort.services.quota import QuotaService

SANDBOX_RESIZED = "sandbox.resized"


@dataclass(frozen=True, slots=True)
class ResizeCommand:
    """The resource fields to change; ``None`` keeps the sandbox's current value."""

    cpu_millicores: int | None = None
    memory_mib: int | None = None
    disk_gib: int | None = None


class ResizeService:
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWorkPort],
        quota: QuotaService,
        settings: Settings,
        clock: Clock,
        audit: AuditRecorder | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._quota = quota
        self._settings = settings
        self._clock = clock
        self._audit = audit or AuditRecorder(clock)

    async def resize(
        self, org_id: str, actor_id: str | None, sandbox_id: str, command: ResizeCommand
    ) -> Sandbox:
        async with self._uow_factory() as uow:
            current = await uow.sandboxes.get(org_id, sandbox_id)
            if current is None:
                raise NotFound(f"sandbox {sandbox_id} not found")
            if current.state is not SandboxState.STOPPED:
                raise InvalidState(
                    f"sandbox is {current.state.value}; only a stopped sandbox can be resized",
                    details={"state": current.state.value},
                )
            resources = self._resolve(current.resources, command)
            now = self._clock.now()
            await lock_quota(uow, org_id)  # queue behind other reserves before the ledger moves
            await uow.quotas.ledger_release_by_sandbox(org_id, sandbox_id, now)
            await self._quota.reserve(uow, org_id, sandbox_id, resources)
            saved = await uow.sandboxes.update(
                org_id,
                current.model_copy(update={"resources": resources, "updated_at": now}),
                expected_version=current.version,
            )
            await self._audit.record(
                uow,
                org_id=org_id,
                actor_type=ActorType.API_KEY,
                actor_id=actor_id,
                action=SANDBOX_RESIZED,
                target_type="sandbox",
                target_id=sandbox_id,
                details={
                    "old_resources": current.resources.model_dump(mode="json"),
                    "new_resources": resources.model_dump(mode="json"),
                },
            )
            await uow.commit()
        return saved

    def _resolve(self, current: ResourceSpec, command: ResizeCommand) -> ResourceSpec:
        """The new spec; it must stay within the per-sandbox maximum, as on create."""
        requested = {
            "cpu_millicores": command.cpu_millicores,
            "memory_mib": command.memory_mib,
            "disk_gib": command.disk_gib,
        }
        changes = {name: value for name, value in requested.items() if value is not None}
        resources = ResourceSpec.model_validate({**current.model_dump(), **changes})
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
        return resources
