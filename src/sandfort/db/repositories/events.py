"""SQLAlchemy ``EventRepository``: the transactional outbox (D5).

``list_undispatched`` is a system path (not org scoped) returning the oldest undispatched
events first. ``mark_dispatched`` is a compare-and-set on ``dispatched_at IS NULL`` that also
counts the attempt, so two dispatchers fanning out the same event cannot both win.
``get`` is a system lookup used by the dispatcher to load the payload of a delivery; it is
reached through ``event_lookup`` because the frozen port does not carry it.
"""

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sandfort.db.models.events import OutboxEventRow
from sandfort.db.repositories.ports import OutboxEventRecord, UnitOfWorkPort
from sandfort.db.support import as_utc, flush_or_conflict, opt_utc, rowcount
from sandfort.errors import InternalError

MAX_BATCH_SIZE = 500


def _to_record(row: OutboxEventRow) -> OutboxEventRecord:
    return OutboxEventRecord(
        id=row.id,
        org_id=row.org_id,
        event_type=row.event_type,
        payload=dict(row.payload),
        created_at=as_utc(row.created_at),
        dispatched_at=opt_utc(row.dispatched_at),
        attempts=row.attempts,
    )


class SqlEventRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def append(self, event: OutboxEventRecord) -> None:
        self._session.add(
            OutboxEventRow(
                id=event.id,
                org_id=event.org_id,
                event_type=event.event_type,
                payload=dict(event.payload),
                created_at=as_utc(event.created_at),
                dispatched_at=opt_utc(event.dispatched_at),
                attempts=event.attempts,
            )
        )
        await flush_or_conflict(
            self._session, "event id already exists, or its org does not exist"
        )

    async def list_undispatched(self, *, limit: int = 100) -> Sequence[OutboxEventRecord]:
        stmt = (
            select(OutboxEventRow)
            .where(OutboxEventRow.dispatched_at.is_(None))
            .order_by(OutboxEventRow.created_at, OutboxEventRow.id)
            .limit(max(1, min(limit, MAX_BATCH_SIZE)))
            .execution_options(populate_existing=True)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_to_record(row) for row in rows]

    async def mark_dispatched(self, event_id: str, at: datetime) -> bool:
        stmt = (
            update(OutboxEventRow)
            .where(OutboxEventRow.id == event_id, OutboxEventRow.dispatched_at.is_(None))
            .values(dispatched_at=as_utc(at), attempts=OutboxEventRow.attempts + 1)
            .execution_options(synchronize_session=False)
        )
        return rowcount(await self._session.execute(stmt)) > 0

    async def get(self, event_id: str) -> OutboxEventRecord | None:
        stmt = (
            select(OutboxEventRow)
            .where(OutboxEventRow.id == event_id)
            .execution_options(populate_existing=True)
        )
        row = (await self._session.execute(stmt)).scalar_one_or_none()
        return None if row is None else _to_record(row)


class EventLookup(Protocol):
    async def get(self, event_id: str) -> OutboxEventRecord | None: ...


_MAX_WRAPPER_DEPTH = 8


def _unwrapped(repository: object) -> object:
    """Follow the public ``wrapped`` attribute of decorators down to the repository they wrap."""
    for _ in range(_MAX_WRAPPER_DEPTH):
        if isinstance(repository, SqlEventRepository):
            break
        inner = getattr(repository, "wrapped", None)
        if inner is None:
            break
        repository = inner
    return repository


def event_lookup(uow: UnitOfWorkPort) -> EventLookup:
    """The by-id event read of the SQL repository (the frozen port only lists and marks).

    A decorator around the repository is looked through.
    """
    repository = _unwrapped(uow.events)
    if not isinstance(repository, SqlEventRepository):
        raise InternalError("event repository does not support lookups")
    return repository
