"""SQLAlchemy ``JobRepository``: a durable leased queue.

State changes are single guarded UPDATE statements (the same optimistic idea as the
sandboxes repository's version check), so two runners can never lease or finish the
same row twice. ``list_for_org`` and ``get_for_org`` are tenant-facing reads used by the
jobs api; every other method is a system path and is not org scoped.
"""

from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sandfort.db.models.jobs import JobRow, JobState
from sandfort.db.repositories.ports import JobRecord
from sandfort.db.support import as_utc, flush_or_conflict, opt_utc, rowcount

MAX_PAGE_SIZE = 200
MAX_ERROR_CHARS = 2000


def _to_record(row: JobRow) -> JobRecord:
    return JobRecord(
        id=row.id,
        org_id=row.org_id,
        kind=row.kind,
        payload=dict(row.payload),
        state=row.state,
        attempts=row.attempts,
        run_after=as_utc(row.run_after),
        lease_expires_at=opt_utc(row.lease_expires_at),
        last_error=row.last_error,
        created_at=as_utc(row.created_at),
        updated_at=as_utc(row.updated_at),
    )


class SqlJobRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def enqueue(self, job: JobRecord) -> None:
        self._session.add(
            JobRow(
                id=job.id,
                org_id=job.org_id,
                kind=job.kind,
                payload=dict(job.payload),
                state=job.state,
                attempts=job.attempts,
                run_after=as_utc(job.run_after),
                lease_expires_at=opt_utc(job.lease_expires_at),
                last_error=job.last_error,
                created_at=as_utc(job.created_at),
                updated_at=as_utc(job.updated_at),
            )
        )
        await flush_or_conflict(self._session, "job id already exists, or its org does not exist")

    async def lease_next(
        self,
        kinds: Sequence[str],
        *,
        now: datetime,
        lease_expires_at: datetime,
        node_id: str | None = None,
    ) -> JobRecord | None:
        if not kinds:
            return None
        candidates = select(JobRow.id).where(
            JobRow.state == JobState.QUEUED.value,
            JobRow.kind.in_(list(kinds)),
            JobRow.run_after <= as_utc(now),
        )
        if node_id is not None:  # node affinity: a runner leases only its own node's jobs
            candidates = candidates.where(JobRow.node_id == node_id)
        due = candidates.order_by(JobRow.run_after, JobRow.id).limit(1).scalar_subquery()
        # One statement picks and claims the row; the state guard makes a lost race a no-op.
        stmt = (
            update(JobRow)
            .where(JobRow.id == due, JobRow.state == JobState.QUEUED.value)
            .values(
                state=JobState.LEASED.value,
                attempts=JobRow.attempts + 1,
                lease_expires_at=as_utc(lease_expires_at),
                updated_at=as_utc(now),
            )
            .returning(JobRow.id)
            .execution_options(synchronize_session=False)
        )
        leased_id = (await self._session.execute(stmt)).scalar_one_or_none()
        return None if leased_id is None else await self._get(JobRow.id == leased_id)

    async def complete(self, job_id: str, at: datetime) -> JobRecord | None:
        await self._guarded_update(
            job_id,
            state=JobState.DONE.value,
            lease_expires_at=None,
            last_error=None,
            updated_at=as_utc(at),
        )
        return await self._get(JobRow.id == job_id)

    async def fail(
        self,
        job_id: str,
        *,
        error: str,
        now: datetime,
        backoff_s: float,
        max_attempts: int,
    ) -> JobRecord | None:
        current = await self._get(JobRow.id == job_id)
        if current is None or current.state != JobState.LEASED.value:
            return current
        exhausted = current.attempts >= max_attempts
        values: dict[str, Any] = {
            "state": JobState.DEAD.value if exhausted else JobState.QUEUED.value,
            "lease_expires_at": None,
            "last_error": error[:MAX_ERROR_CHARS],
            "updated_at": as_utc(now),
        }
        if not exhausted:
            values["run_after"] = as_utc(now) + timedelta(seconds=backoff_s)
        await self._guarded_update(job_id, **values)
        return await self._get(JobRow.id == job_id)

    async def reap_expired(self, now: datetime) -> int:
        stmt = (
            update(JobRow)
            .where(
                JobRow.state == JobState.LEASED.value,
                JobRow.lease_expires_at.is_not(None),
                JobRow.lease_expires_at < as_utc(now),
            )
            .values(state=JobState.QUEUED.value, lease_expires_at=None, updated_at=as_utc(now))
            .execution_options(synchronize_session=False)
        )
        return rowcount(await self._session.execute(stmt))

    # -- tenant-facing reads -----------------------------------------------------

    async def get_for_org(self, org_id: str, job_id: str) -> JobRecord | None:
        return await self._get(JobRow.org_id == org_id, JobRow.id == job_id)

    async def list_for_org(
        self,
        org_id: str,
        *,
        state: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> Sequence[JobRecord]:
        stmt = select(JobRow).where(JobRow.org_id == org_id)
        if state is not None:
            stmt = stmt.where(JobRow.state == state)
        if cursor is not None:
            stmt = stmt.where(JobRow.id > cursor)
        stmt = (
            stmt.order_by(JobRow.id)
            .limit(max(1, min(limit, MAX_PAGE_SIZE + 1)))
            .execution_options(populate_existing=True)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_to_record(row) for row in rows]

    # -- helpers -----------------------------------------------------------------

    async def _guarded_update(self, job_id: str, **values: Any) -> int:
        """Apply ``values`` only while the job is still leased (a reaped job is left alone)."""
        stmt = (
            update(JobRow)
            .where(JobRow.id == job_id, JobRow.state == JobState.LEASED.value)
            .values(**values)
            .execution_options(synchronize_session=False)
        )
        return rowcount(await self._session.execute(stmt))

    async def _get(self, *criteria: Any) -> JobRecord | None:
        stmt = select(JobRow).where(*criteria).execution_options(populate_existing=True)
        row = (await self._session.execute(stmt)).scalar_one_or_none()
        return None if row is None else _to_record(row)
