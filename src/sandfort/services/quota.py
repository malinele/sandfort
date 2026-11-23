"""Quota service (WP 4.1): effective limits, ledger-backed reservation, release and recount.

``reserve`` runs inside the caller's unit of work, the same one that inserts the sandbox row,
so the check (limits, reserved totals, host totals) and the ledger insert commit atomically
and the unit of work's lock (``BEGIN IMMEDIATE`` on SQLite, ``FOR UPDATE`` row locks from
``sandfort.db.locking`` on Postgres) makes two overlapping reserves queue rather than both pass.
A violated org limit raises ``QuotaExceeded`` (429); a violated host capacity (checked by
``services.admission``, with its overcommit factor) raises ``CapacityExceeded`` (503).
``release`` is idempotent and runs in its own unit of work.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from sandfort.clock import Clock
from sandfort.config import Settings
from sandfort.db.locking import lock_quota
from sandfort.db.repositories.ports import ScopedSandboxCounting, UnitOfWorkPort
from sandfort.db.repositories.quotas import ScopedLedger
from sandfort.domain.events import ActorType
from sandfort.domain.quota import VCPU_DECIMALS, OrgQuota, Reservation
from sandfort.domain.resources import ResourceSpec
from sandfort.errors import InternalError, QuotaExceeded
from sandfort.services.admission import MILLICORES_PER_VCPU, AdmissionService, ledger_inspection
from sandfort.services.audit import AuditRecorder

QUOTA_UPDATED = "quota.updated"


@dataclass(frozen=True, slots=True)
class QuotaUsage:
    """Effective limits plus what is currently reserved against them."""

    limits: OrgQuota
    reserved: Reservation


@dataclass(frozen=True, slots=True)
class ScopedQuotaUsage:
    """What a label-scoped key may see: the org's limits, its own cap, count and reservation.

    ``reserved`` and ``sandboxes`` cover only the sandboxes inside the key's label scope, so
    no other team's usage is in it.
    """

    limits: OrgQuota
    reserved: Reservation
    labels: Mapping[str, str]
    max_sandboxes: int | None
    sandboxes: int


@dataclass(frozen=True, slots=True)
class RecountResult:
    """Ledger totals (summed in SQL) next to the totals recomputed from scratch."""

    ledger: Reservation
    recomputed: Reservation

    @property
    def consistent(self) -> bool:
        return self.ledger == self.recomputed


def reservation_for(resources: ResourceSpec) -> Reservation:
    """The ledger entry one sandbox with ``resources`` holds."""
    return Reservation(
        vcpus=round(resources.cpu_millicores / MILLICORES_PER_VCPU, VCPU_DECIMALS),
        memory_mib=resources.memory_mib,
        disk_gib=resources.disk_gib,
        sandboxes=1,
    )


class QuotaService:
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWorkPort],
        settings: Settings,
        clock: Clock,
        audit: AuditRecorder | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._settings = settings
        self._clock = clock
        self._audit = audit or AuditRecorder(clock)
        self._admission = AdmissionService(settings)

    async def get(self, org_id: str) -> QuotaUsage:
        async with self._uow_factory() as uow:
            return QuotaUsage(
                limits=await uow.quotas.get_or_default(org_id),
                reserved=await uow.quotas.ledger_totals(org_id),
            )

    async def get_scoped(
        self, org_id: str, labels: Mapping[str, str], max_sandboxes: int | None
    ) -> ScopedQuotaUsage:
        """The view of a key limited to ``labels`` (its cap ``max_sandboxes`` may be ``None``)."""
        async with self._uow_factory() as uow:
            counting, ledger = uow.sandboxes, uow.quotas
            if not isinstance(counting, ScopedSandboxCounting) or not isinstance(
                ledger, ScopedLedger
            ):
                raise InternalError("repositories cannot report a label scope's usage")
            return ScopedQuotaUsage(
                limits=await uow.quotas.get_or_default(org_id),
                reserved=await ledger.ledger_totals_in_scope(org_id, labels),
                labels=dict(labels),
                max_sandboxes=max_sandboxes,
                sandboxes=await counting.count_in_scope(org_id, labels),
            )

    async def set_limits(self, org_id: str, actor_id: str | None, quota: OrgQuota) -> QuotaUsage:
        async with self._uow_factory() as uow:
            saved = await uow.quotas.upsert_limits(org_id, quota, self._clock.now())
            await self._audit.record(
                uow,
                org_id=org_id,
                actor_type=ActorType.API_KEY,
                actor_id=actor_id,
                action=QUOTA_UPDATED,
                target_type="org",
                target_id=org_id,
                details={"limits": saved.model_dump(mode="json")},
            )
            reserved = await uow.quotas.ledger_totals(org_id)
            await uow.commit()
        return QuotaUsage(limits=saved, reserved=reserved)

    async def reserve(
        self, uow: UnitOfWorkPort, org_id: str, sandbox_id: str, resources: ResourceSpec
    ) -> Reservation:
        """Check and record a reservation in ``uow``; the caller commits it with its intent."""
        await lock_quota(uow, org_id)  # dialect strategy: no-op on SQLite, FOR UPDATE on PG
        requested = reservation_for(resources)
        limits = await uow.quotas.get_or_default(org_id)  # also takes the org lock
        held = await uow.quotas.ledger_totals(org_id)
        if not held.add(requested).fits_within(limits):
            raise QuotaExceeded(
                "organization quota exceeded",
                details={
                    "limits": limits.model_dump(mode="json"),
                    "reserved": held.model_dump(mode="json"),
                    "requested": requested.model_dump(mode="json"),
                },
            )
        await self._admission.admit(uow, requested)
        await uow.quotas.ledger_reserve(org_id, sandbox_id, requested, self._clock.now())
        return requested

    async def release(self, org_id: str, sandbox_id: str) -> bool:
        """Release the sandbox's reservation; False when it was already released."""
        async with self._uow_factory() as uow:
            changed = await uow.quotas.ledger_release_by_sandbox(
                org_id, sandbox_id, self._clock.now()
            )
            await uow.commit()
        return changed > 0

    async def recount(self, org_id: str) -> RecountResult:
        async with self._uow_factory() as uow:
            return RecountResult(
                ledger=await uow.quotas.ledger_totals(org_id),
                recomputed=await ledger_inspection(uow).ledger_recount(org_id),
            )
