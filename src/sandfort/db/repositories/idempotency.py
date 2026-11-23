"""SQLAlchemy implementation of ``IdempotencyRepository``."""

from datetime import datetime

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from sandfort.db.models.idempotency import IdempotencyRow
from sandfort.db.repositories.ports import IdempotencyRecord
from sandfort.db.support import as_utc, flush_or_conflict, rowcount


class SqlIdempotencyRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, org_id: str, key: str) -> IdempotencyRecord | None:
        """Return the stored record; callers compare ``expires_at`` themselves."""
        stmt = (
            select(IdempotencyRow)
            .where(IdempotencyRow.org_id == org_id, IdempotencyRow.key == key)
            .execution_options(populate_existing=True)
        )
        row = (await self._session.execute(stmt)).scalar_one_or_none()
        if row is None:
            return None
        return IdempotencyRecord(
            org_id=row.org_id,
            key=row.key,
            request_hash=row.request_hash,
            response_status=row.response_status,
            response_body=dict(row.response_body),
            expires_at=as_utc(row.expires_at),
        )

    async def put(self, record: IdempotencyRecord) -> None:
        """First writer wins; a second ``put`` for the same key raises ``Conflict``."""
        self._session.add(
            IdempotencyRow(
                org_id=record.org_id,
                key=record.key,
                request_hash=record.request_hash,
                response_status=record.response_status,
                response_body=dict(record.response_body),
                expires_at=as_utc(record.expires_at),
            )
        )
        await flush_or_conflict(self._session, "idempotency key already recorded")

    async def purge_expired(self, now: datetime) -> int:
        stmt = (
            delete(IdempotencyRow)
            .where(IdempotencyRow.expires_at < as_utc(now))
            .execution_options(synchronize_session=False)
        )
        return rowcount(await self._session.execute(stmt))
