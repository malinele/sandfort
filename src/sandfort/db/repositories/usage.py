"""SQLAlchemy ``UsageRepository`` (WP 4.3).

* ``open_interval`` inserts an interval as given (normally with ``ended_at=None``).
* ``close_open_intervals`` sets ``ended_at=at`` on the sandbox's open intervals and
  yields how many it closed (zero when none is open, so closing is idempotent); with a
  ``dimension`` only that dimension's open interval is closed. An
  ``at`` before an interval's start closes it at its start instead (zero length).
* ``list_intervals`` returns intervals overlapping ``[start, end)`` (open intervals
  included) in insertion order; ``org_id=None`` is the system path across all orgs and
  ``sandbox_id`` narrows it to one sandbox.
* ``upsert_rollup`` inserts or replaces the total for (org, period_start, dimension),
  so rerunning a rollup never double counts.
* ``get_rollups`` returns the org's rollups with ``start <= period_start < end``.
"""

from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import case, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sandfort.db.models.usage import UsageIntervalRow, UsageRollupRow
from sandfort.db.support import as_utc, flush_or_conflict, opt_utc, rowcount
from sandfort.domain.usage import UsageDimension, UsageInterval, UsageRollup


def _interval(row: UsageIntervalRow) -> UsageInterval:
    return UsageInterval(
        org_id=row.org_id,
        sandbox_id=row.sandbox_id,
        dimension=UsageDimension(row.dimension),
        amount=row.amount,
        started_at=as_utc(row.started_at),
        ended_at=opt_utc(row.ended_at),
    )


def _rollup(row: UsageRollupRow) -> UsageRollup:
    return UsageRollup(
        org_id=row.org_id,
        period_start=as_utc(row.period_start),
        dimension=UsageDimension(row.dimension),
        total=row.total,
    )


class SqlUsageRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def open_interval(self, interval: UsageInterval) -> None:
        self._session.add(
            UsageIntervalRow(
                org_id=interval.org_id,
                sandbox_id=interval.sandbox_id,
                dimension=interval.dimension.value,
                amount=interval.amount,
                started_at=as_utc(interval.started_at),
                ended_at=opt_utc(interval.ended_at),
            )
        )
        await flush_or_conflict(self._session, "usage interval org does not exist")

    async def close_open_intervals(
        self,
        org_id: str,
        sandbox_id: str,
        at: datetime,
        *,
        dimension: UsageDimension | None = None,
    ) -> int:
        closed_at = as_utc(at)
        stmt = update(UsageIntervalRow).where(
            UsageIntervalRow.org_id == org_id,
            UsageIntervalRow.sandbox_id == sandbox_id,
            UsageIntervalRow.ended_at.is_(None),
        )
        if dimension is not None:
            stmt = stmt.where(UsageIntervalRow.dimension == dimension.value)
        result = await self._session.execute(
            stmt.values(
                ended_at=case(
                    (UsageIntervalRow.started_at > closed_at, UsageIntervalRow.started_at),
                    else_=closed_at,
                )
            )
        )
        return rowcount(result)

    async def list_intervals(
        self,
        start: datetime,
        end: datetime,
        *,
        org_id: str | None = None,
        sandbox_id: str | None = None,
    ) -> Sequence[UsageInterval]:
        stmt = select(UsageIntervalRow).where(
            UsageIntervalRow.started_at < as_utc(end),
            (UsageIntervalRow.ended_at.is_(None)) | (UsageIntervalRow.ended_at > as_utc(start)),
        )
        if org_id is not None:
            stmt = stmt.where(UsageIntervalRow.org_id == org_id)
        if sandbox_id is not None:
            stmt = stmt.where(UsageIntervalRow.sandbox_id == sandbox_id)
        stmt = stmt.order_by(UsageIntervalRow.id).execution_options(populate_existing=True)
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_interval(row) for row in rows]

    async def upsert_rollup(self, rollup: UsageRollup) -> None:
        period_start = as_utc(rollup.period_start)
        stmt = (
            select(UsageRollupRow)
            .where(
                UsageRollupRow.org_id == rollup.org_id,
                UsageRollupRow.period_start == period_start,
                UsageRollupRow.dimension == rollup.dimension.value,
            )
            .execution_options(populate_existing=True)
        )
        row = (await self._session.execute(stmt)).scalar_one_or_none()
        if row is None:
            self._session.add(
                UsageRollupRow(
                    org_id=rollup.org_id,
                    period_start=period_start,
                    dimension=rollup.dimension.value,
                    total=rollup.total,
                )
            )
        else:
            row.total = rollup.total
        await flush_or_conflict(self._session, "usage rollup org does not exist")

    async def get_rollups(
        self, org_id: str, start: datetime, end: datetime
    ) -> Sequence[UsageRollup]:
        stmt = (
            select(UsageRollupRow)
            .where(
                UsageRollupRow.org_id == org_id,
                UsageRollupRow.period_start >= as_utc(start),
                UsageRollupRow.period_start < as_utc(end),
            )
            .order_by(UsageRollupRow.period_start, UsageRollupRow.dimension)
            .execution_options(populate_existing=True)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_rollup(row) for row in rows]
