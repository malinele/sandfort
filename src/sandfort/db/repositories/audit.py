"""SQLAlchemy implementation of ``AuditRepository``.

Append-only apart from ``prune_before``, the retention path: it deletes only a prefix of an
org's rows (in id order), so the remaining chain stays verifiable from its new first row.

Chain lock. Each new row links to the org's newest row (``latest_link``), so two writers that
read the same head would both link to it and fork the chain. SQLite is safe: every transaction
begins ``BEGIN IMMEDIATE`` and holds the single writer lock. On Postgres ``latest_link`` first
takes ``FOR NO KEY UPDATE`` on the org row (``lock_org_for_audit`` in
``sandfort.db.locking``). A second writer for the same org waits until the first transaction
commits or rolls back, then reads the new head (READ COMMITTED: the head query is a new
statement after the lock). Other orgs are unaffected.

Lock mode. It is ``FOR NO KEY UPDATE``, not ``FOR UPDATE``, and only the org row: any earlier
INSERT in the same transaction of a row with a foreign key to the org (an exec command row)
holds ``FOR KEY SHARE`` on it, which ``FOR UPDATE`` conflicts with. Two such transactions of
one org would each wait for the other's ``FOR UPDATE`` (deadlock). ``FOR NO KEY UPDATE``
conflicts with itself, so appends of one org stay serialised, but not with ``FOR KEY SHARE``,
so foreign-key inserts never block it. A quota transaction holding the org row ``FOR UPDATE``
takes it compatibly in its own transaction; one that comes second waits. There is no advisory
lock and no quota-row lock. The lock is released when the transaction ends.
"""

from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import Select, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sandfort.db.locking import POSTGRESQL, lock_org_for_audit
from sandfort.db.models.audit import AuditRow
from sandfort.db.repositories.ports import AuditLink, ChainedAuditEvent, SortOrder
from sandfort.db.support import as_utc, flush_or_conflict, rowcount
from sandfort.domain.events import ActorType, AuditEvent, AuditOutcome

MAX_PAGE_SIZE = 200
MAX_CHAIN_PAGE_SIZE = 1000


def _to_entity(row: AuditRow) -> AuditEvent:
    return AuditEvent(
        id=row.id,
        org_id=row.org_id,
        actor_type=ActorType(row.actor_type),
        actor_id=row.actor_id,
        action=row.action,
        target_type=row.target_type,
        target_id=row.target_id,
        outcome=AuditOutcome(row.outcome),
        request_id=row.request_id,
        ip=row.ip,
        user_agent=row.user_agent,
        details=dict(row.details),
        occurred_at=as_utc(row.occurred_at),
    )


def _match_request(
    stmt: Select[AuditRow], request_id: str | None, outcome: AuditOutcome | None
) -> Select[AuditRow]:
    """``stmt`` narrowed to rows with exactly this request id and/or outcome (when given)."""
    if request_id is not None:
        stmt = stmt.where(AuditRow.request_id == request_id)
    if outcome is not None:
        stmt = stmt.where(AuditRow.outcome == outcome.value)
    return stmt


class SqlAuditRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(
        self, event: AuditEvent, *, prev_hash: str | None = None, entry_hash: str | None = None
    ) -> None:
        self._session.add(
            AuditRow(
                id=event.id,
                org_id=event.org_id,
                actor_type=event.actor_type.value,
                actor_id=event.actor_id,
                action=event.action,
                target_type=event.target_type,
                target_id=event.target_id,
                outcome=event.outcome.value,
                request_id=event.request_id,
                ip=event.ip,
                user_agent=event.user_agent,
                details=dict(event.details),
                occurred_at=as_utc(event.occurred_at),
                prev_hash=prev_hash,
                hash=entry_hash,
            )
        )
        await flush_or_conflict(self._session, "audit event id already exists")

    async def list(
        self,
        org_id: str,
        *,
        actor_id: str | None = None,
        action: str | None = None,
        target_id: str | None = None,
        request_id: str | None = None,
        outcome: AuditOutcome | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        cursor: str | None = None,
        limit: int = 50,
        order: SortOrder = "asc",
    ) -> Sequence[AuditEvent]:
        """One page by id (``order="desc"``: newest first; the cursor continues in that order).

        The cursor is the last id of the previous page: ``desc`` continues with smaller ids.
        """
        stmt = select(AuditRow).where(AuditRow.org_id == org_id)
        if actor_id is not None:
            stmt = stmt.where(AuditRow.actor_id == actor_id)
        if action is not None:
            stmt = stmt.where(AuditRow.action == action)
        if target_id is not None:
            stmt = stmt.where(AuditRow.target_id == target_id)
        stmt = _match_request(stmt, request_id, outcome)
        if since is not None:
            stmt = stmt.where(AuditRow.occurred_at >= as_utc(since))
        if until is not None:
            stmt = stmt.where(AuditRow.occurred_at < as_utc(until))
        newest_first = order == "desc"
        if cursor is not None:
            stmt = stmt.where(AuditRow.id < cursor if newest_first else AuditRow.id > cursor)
        stmt = (
            stmt.order_by(AuditRow.id.desc() if newest_first else AuditRow.id)
            .limit(max(1, min(limit, MAX_PAGE_SIZE)))
            .execution_options(populate_existing=True)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_to_entity(row) for row in rows]

    async def latest_link(self, org_id: str) -> AuditLink | None:
        """Newest ``(id, hash)`` of the org's chain; on Postgres, after locking the org row."""
        if self._session.get_bind().dialect.name == POSTGRESQL:
            await lock_org_for_audit(self._session, org_id)
        stmt = (
            select(AuditRow.id, AuditRow.hash)
            .where(AuditRow.org_id == org_id)
            .order_by(AuditRow.id.desc())
            .limit(1)
        )
        row = (await self._session.execute(stmt)).first()
        return None if row is None else AuditLink(id=row[0], entry_hash=row[1])

    async def list_chained(
        self,
        org_id: str,
        *,
        cursor: str | None = None,
        limit: int = 500,
        request_id: str | None = None,
        outcome: AuditOutcome | None = None,
    ) -> Sequence[ChainedAuditEvent]:
        """Chained rows in id order; ``request_id`` and ``outcome`` are exact-match filters."""
        base = select(AuditRow).where(AuditRow.org_id == org_id)
        stmt = _match_request(base, request_id, outcome)
        if cursor is not None:
            stmt = stmt.where(AuditRow.id > cursor)
        stmt = (
            stmt.order_by(AuditRow.id)
            .limit(max(1, min(limit, MAX_CHAIN_PAGE_SIZE)))
            .execution_options(populate_existing=True)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [ChainedAuditEvent(_to_entity(r), r.prev_hash, r.hash) for r in rows]

    async def get_chained(self, org_id: str, event_id: str) -> ChainedAuditEvent | None:
        """One row of the org's chain by id; ``None`` when absent or another org's."""
        stmt = (
            select(AuditRow)
            .where(AuditRow.org_id == org_id, AuditRow.id == event_id)
            .execution_options(populate_existing=True)
        )
        row = (await self._session.execute(stmt)).scalars().first()
        if row is None:
            return None
        return ChainedAuditEvent(_to_entity(row), row.prev_hash, row.hash)

    async def org_ids(self) -> Sequence[str]:
        stmt = select(AuditRow.org_id).distinct().order_by(AuditRow.org_id)
        return list((await self._session.execute(stmt)).scalars())

    async def prune_before(self, org_id: str, cutoff: datetime) -> int:
        """Delete the org's leading rows older than ``cutoff``; always keep the newest row.

        The boundary is the first row (id order) at or after the cutoff, so a row with a
        skewed timestamp can never cause a gap: everything from the boundary on is kept.
        """
        first_kept = (
            select(func.min(AuditRow.id))
            .where(AuditRow.org_id == org_id, AuditRow.occurred_at >= as_utc(cutoff))
            .scalar_subquery()
        )
        newest = select(func.max(AuditRow.id)).where(AuditRow.org_id == org_id).scalar_subquery()
        boundary = func.coalesce(first_kept, newest)
        stmt = (
            delete(AuditRow)
            .where(AuditRow.org_id == org_id, AuditRow.id < boundary)
            .execution_options(synchronize_session=False)
        )
        return rowcount(await self._session.execute(stmt))
