"""SQLAlchemy ``QuotaRepository`` (WP 4.1).

* ``get_or_default`` returns the stored limits, or an all-unlimited ``OrgQuota``. It also
  takes a row lock on the org (``FOR UPDATE``; SQLite ignores it because every SQLite
  transaction already begins ``BEGIN IMMEDIATE``), so the check-then-reserve sequence a
  service runs inside one unit of work is serialised per org.
* ``upsert_limits`` inserts or replaces the org's limits and returns them.
* ``ledger_reserve`` inserts one ``reserved`` row; the caller checked the quota first,
  in the same unit of work.
* ``ledger_release_by_sandbox`` marks the sandbox's ``reserved`` rows ``released`` and
  yields how many changed (zero when already released, so release is idempotent).
* ``ledger_totals`` sums ``reserved`` rows in SQL; ``ledger_recount`` recomputes the same
  totals from scratch by folding the rows; ``host_totals`` sums across every org.
"""

from collections.abc import Mapping
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sandfort.db.models.orgs import OrgRow
from sandfort.db.models.quotas import QuotaLedgerRow, QuotaRow
from sandfort.db.models.sandboxes import SandboxRow
from sandfort.db.repositories.sandboxes import label_match
from sandfort.db.support import flush_or_conflict, rowcount
from sandfort.domain.quota import VCPU_DECIMALS, LedgerEntryState, OrgQuota, Reservation

_RESERVED = LedgerEntryState.RESERVED.value


@runtime_checkable
class LedgerInspection(Protocol):
    """Reads beyond the frozen port: the from-scratch recount and the host-wide totals."""

    async def ledger_recount(self, org_id: str) -> Reservation: ...
    async def host_totals(self) -> Reservation: ...


@runtime_checkable
class ScopedLedger(Protocol):
    """Reserved totals of the sandboxes inside a label scope (a scoped key's own share)."""

    async def ledger_totals_in_scope(
        self, org_id: str, labels: Mapping[str, str]
    ) -> Reservation: ...


def _quota(row: QuotaRow) -> OrgQuota:
    return OrgQuota(
        max_vcpus=row.max_vcpus,
        max_memory_mib=row.max_memory_mib,
        max_disk_gib=row.max_disk_gib,
        max_sandboxes=row.max_sandboxes,
    )


def _totals(vcpus: float | None, memory: int | None, disk: int | None, count: int) -> Reservation:
    return Reservation(
        vcpus=round(vcpus or 0.0, VCPU_DECIMALS),
        memory_mib=int(memory or 0),
        disk_gib=int(disk or 0),
        sandboxes=count,
    )


class SqlQuotaRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_or_default(self, org_id: str) -> OrgQuota:
        await self._session.execute(select(OrgRow.id).where(OrgRow.id == org_id).with_for_update())
        row = await self._get_row(org_id)
        return OrgQuota() if row is None else _quota(row)

    async def upsert_limits(self, org_id: str, quota: OrgQuota, at: datetime) -> OrgQuota:
        row = await self._get_row(org_id)
        if row is None:
            row = QuotaRow(org_id=org_id)
            self._session.add(row)
        row.max_vcpus = quota.max_vcpus
        row.max_memory_mib = quota.max_memory_mib
        row.max_disk_gib = quota.max_disk_gib
        row.max_sandboxes = quota.max_sandboxes
        row.updated_at = at
        await flush_or_conflict(self._session, "quota org does not exist")
        return quota

    async def ledger_reserve(
        self, org_id: str, sandbox_id: str, reservation: Reservation, at: datetime
    ) -> None:
        self._session.add(
            QuotaLedgerRow(
                org_id=org_id,
                sandbox_id=sandbox_id,
                vcpus=reservation.vcpus,
                memory_mib=reservation.memory_mib,
                disk_gib=reservation.disk_gib,
                state=_RESERVED,
                created_at=at,
                updated_at=at,
            )
        )
        await flush_or_conflict(self._session, "ledger org does not exist")

    async def ledger_release_by_sandbox(self, org_id: str, sandbox_id: str, at: datetime) -> int:
        result = await self._session.execute(
            update(QuotaLedgerRow)
            .where(
                QuotaLedgerRow.org_id == org_id,
                QuotaLedgerRow.sandbox_id == sandbox_id,
                QuotaLedgerRow.state == _RESERVED,
            )
            .values(state=LedgerEntryState.RELEASED.value, updated_at=at)
        )
        return rowcount(result)

    async def ledger_totals(self, org_id: str) -> Reservation:
        return await self._sum(QuotaLedgerRow.org_id == org_id)

    async def host_totals(self) -> Reservation:
        return await self._sum()

    async def ledger_totals_in_scope(self, org_id: str, labels: Mapping[str, str]) -> Reservation:
        """Reserved totals of the org's non-standby sandboxes carrying every pair of ``labels``."""
        stmt = (
            select(
                func.sum(QuotaLedgerRow.vcpus),
                func.sum(QuotaLedgerRow.memory_mib),
                func.sum(QuotaLedgerRow.disk_gib),
                func.count(QuotaLedgerRow.id),
            )
            .join(SandboxRow, SandboxRow.id == QuotaLedgerRow.sandbox_id)
            .where(
                QuotaLedgerRow.org_id == org_id,
                QuotaLedgerRow.state == _RESERVED,
                SandboxRow.org_id == org_id,
                SandboxRow.standby.is_(False),
                label_match(labels),
            )
        )
        vcpus, memory, disk, count = (await self._session.execute(stmt)).one()
        return _totals(vcpus, memory, disk, count)

    async def ledger_recount(self, org_id: str) -> Reservation:
        stmt = (
            select(QuotaLedgerRow)
            .where(QuotaLedgerRow.org_id == org_id, QuotaLedgerRow.state == _RESERVED)
            .execution_options(populate_existing=True)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        total = Reservation()
        for row in rows:
            held = Reservation(
                vcpus=row.vcpus, memory_mib=row.memory_mib, disk_gib=row.disk_gib, sandboxes=1
            )
            total = total.add(held)
        return total

    async def _get_row(self, org_id: str) -> QuotaRow | None:
        stmt = (
            select(QuotaRow)
            .where(QuotaRow.org_id == org_id)
            .execution_options(populate_existing=True)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def _sum(self, *conditions: Any) -> Reservation:
        stmt = select(
            func.sum(QuotaLedgerRow.vcpus),
            func.sum(QuotaLedgerRow.memory_mib),
            func.sum(QuotaLedgerRow.disk_gib),
            func.count(QuotaLedgerRow.id),
        ).where(QuotaLedgerRow.state == _RESERVED, *conditions)
        vcpus, memory, disk, count = (await self._session.execute(stmt)).one()
        return _totals(vcpus, memory, disk, count)
