"""SQLAlchemy implementation of ``PtySessionRepository``.

Every method filters on ``org_id`` in SQL, so another org's row is indistinguishable from a
missing one. ``resize`` only touches an open session; ``close`` only moves a session out of
``open``: the first close wins and later calls return the stored record unchanged.
"""

from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sandfort.db.models.pty import PtySessionRow, PtySessionState
from sandfort.db.repositories.ports import PtySessionRecord
from sandfort.db.support import as_utc, flush_or_conflict, opt_utc


def _record(row: PtySessionRow) -> PtySessionRecord:
    return PtySessionRecord(
        id=row.id,
        org_id=row.org_id,
        sandbox_id=row.sandbox_id,
        state=row.state,
        rows=row.rows,
        cols=row.cols,
        created_at=as_utc(row.created_at),
        closed_at=opt_utc(row.closed_at),
    )


class SqlPtySessionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, pty: PtySessionRecord) -> None:
        self._session.add(
            PtySessionRow(
                id=pty.id,
                org_id=pty.org_id,
                sandbox_id=pty.sandbox_id,
                state=pty.state,
                rows=pty.rows,
                cols=pty.cols,
                created_at=as_utc(pty.created_at),
                closed_at=opt_utc(pty.closed_at),
            )
        )
        await flush_or_conflict(self._session, "pty session id already exists")

    async def get(self, org_id: str, pty_id: str) -> PtySessionRecord | None:
        stmt = (
            select(PtySessionRow)
            .where(PtySessionRow.org_id == org_id, PtySessionRow.id == pty_id)
            .execution_options(populate_existing=True)
        )
        row = (await self._session.execute(stmt)).scalar_one_or_none()
        return None if row is None else _record(row)

    async def list_for_sandbox(self, org_id: str, sandbox_id: str) -> Sequence[PtySessionRecord]:
        stmt = (
            select(PtySessionRow)
            .where(PtySessionRow.org_id == org_id, PtySessionRow.sandbox_id == sandbox_id)
            .order_by(PtySessionRow.id)
            .execution_options(populate_existing=True)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_record(row) for row in rows]

    async def resize(
        self, org_id: str, pty_id: str, rows: int, cols: int
    ) -> PtySessionRecord | None:
        stmt = (
            update(PtySessionRow)
            .where(
                PtySessionRow.org_id == org_id,
                PtySessionRow.id == pty_id,
                PtySessionRow.state == PtySessionState.OPEN.value,
            )
            .values(rows=rows, cols=cols)
            .execution_options(synchronize_session=False)
        )
        await self._session.execute(stmt)
        return await self.get(org_id, pty_id)

    async def close(self, org_id: str, pty_id: str, at: datetime) -> PtySessionRecord | None:
        stmt = (
            update(PtySessionRow)
            .where(
                PtySessionRow.org_id == org_id,
                PtySessionRow.id == pty_id,
                PtySessionRow.state == PtySessionState.OPEN.value,
            )
            .values(state=PtySessionState.CLOSED.value, closed_at=as_utc(at))
            .execution_options(synchronize_session=False)
        )
        await self._session.execute(stmt)
        return await self.get(org_id, pty_id)
