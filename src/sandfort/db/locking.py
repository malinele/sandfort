"""Quota locking strategies (WP 5.3), chosen from the engine dialect by the unit of work.

``lock_quota`` serialises check-then-reserve per org inside the reserving transaction.

* SQLite: ``NoopQuotaLock``. Every transaction already begins ``BEGIN IMMEDIATE`` and holds
  the single writer lock, so there is nothing to add.
* Postgres: ``RowQuotaLock`` takes ``SELECT ... FOR UPDATE`` on the org row (which exists even
  when the org has no quota row), then on the org's quota row. It also takes both before
  a new sandbox row is flushed: that insert's foreign key holds ``FOR KEY SHARE`` on the org
  row, and two creates holding it while both wait for ``FOR UPDATE`` would deadlock. Locking
  first makes a concurrent create queue before it holds any lock on the org.

Lock order (Postgres). Every transaction locks the org row before the quota row. A quota
transaction takes the org row, then the quota row, both ``FOR UPDATE`` (``lock_org_rows``).
An audit writer takes only the org row, so one that reserves quota later cannot form a cycle
with a quota transaction: both queue on the org row first.

The audit chain takes a weaker lock on the org row only, ``lock_org_for_audit``:
``FOR NO KEY UPDATE``. It must not be ``FOR UPDATE``: every INSERT of a row with a foreign
key to the org (an exec command row, a sandbox row) holds ``FOR KEY SHARE`` on the org row
until the transaction ends, and ``FOR UPDATE`` conflicts with ``FOR KEY SHARE``. Two
same-org requests that each inserted such a row and then recorded their audit row would each
hold KEY SHARE while waiting for the other's ``FOR UPDATE``: a deadlock. ``FOR NO KEY UPDATE``
conflicts with itself (audit appends of one org are serialised) and with ``FOR UPDATE`` and
``FOR SHARE``, but not with ``FOR KEY SHARE``, so foreign-key inserts never block it.

A quota transaction that already holds the org row ``FOR UPDATE`` takes the audit lock
compatibly within its own transaction; one that comes second simply waits. The audit lock
never touches the quota row, and there is no advisory lock.
"""

from typing import Protocol, runtime_checkable

from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from sandfort.db.models.orgs import OrgRow
from sandfort.db.models.quotas import QuotaRow
from sandfort.db.models.sandboxes import SandboxRow

POSTGRESQL = "postgresql"


@runtime_checkable
class QuotaLock(Protocol):
    async def lock_quota(self, org_id: str) -> None: ...


class NoopQuotaLock:
    """SQLite: the transaction's ``BEGIN IMMEDIATE`` write lock already serialises reserves."""

    async def lock_quota(self, org_id: str) -> None:
        return None


class RowQuotaLock:
    """Postgres: row locks on the org's quota and org rows, held until the transaction ends."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        event.listen(session.sync_session, "before_flush", _lock_before_sandbox_insert)

    async def lock_quota(self, org_id: str) -> None:
        await lock_org_rows(self._session, org_id)


def quota_lock_for(session: AsyncSession) -> QuotaLock:
    if session.get_bind().dialect.name == POSTGRESQL:
        return RowQuotaLock(session)
    return NoopQuotaLock()


async def lock_quota(uow: object, org_id: str) -> None:
    """Take ``uow``'s quota lock; units of work without a strategy (test fakes) skip it."""
    strategy = getattr(uow, "quota_lock", None)
    if isinstance(strategy, QuotaLock):
        await strategy.lock_quota(org_id)


async def lock_org_rows(session: AsyncSession, org_id: str) -> None:
    """Take ``FOR UPDATE`` on the org row, then its quota row (Postgres callers only)."""
    await session.run_sync(_lock_rows, org_id)


async def lock_org_for_audit(session: AsyncSession, org_id: str) -> None:
    """Take ``FOR NO KEY UPDATE`` on the org row only (Postgres callers only).

    Serialises audit appends per org without conflicting with ``FOR KEY SHARE``, which every
    insert of a row with a foreign key to the org holds (see the module docstring).
    """
    await session.run_sync(_lock_org_no_key, org_id)


def _lock_org_no_key(session: Session, org_id: str) -> None:
    org = select(OrgRow.id).where(OrgRow.id == org_id)
    session.connection().execute(org.with_for_update(key_share=True))


def _lock_rows(session: Session, org_id: str) -> None:
    """Org row first, then quota row: the org row is where the audit lock queues too."""
    org = select(OrgRow.id).where(OrgRow.id == org_id)
    quota = select(QuotaRow.org_id).where(QuotaRow.org_id == org_id)
    connection = session.connection()
    connection.execute(org.with_for_update())
    connection.execute(quota.with_for_update())


def _lock_before_sandbox_insert(session: Session, _context: object, _instances: object) -> None:
    for org_id in sorted({row.org_id for row in session.new if isinstance(row, SandboxRow)}):
        _lock_rows(session, org_id)
