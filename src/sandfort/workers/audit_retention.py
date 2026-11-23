"""Audit retention (WP 5.5): prunes each org's audit rows older than the retention window.

Each pass computes ``cutoff = now - retention_days`` and, per org, deletes only a PREFIX of
the trail (never a row newer than a kept row, and never the newest row), so the remaining
hash chain verifies from its new first row. ``retention_days <= 0`` disables the worker.
One org failing is logged and never ends the pass. Sleeping uses real time.
"""

import logging
from collections.abc import Callable
from datetime import datetime, timedelta

from sandfort.clock import Clock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.workers.reconciler import PassLoop

logger = logging.getLogger(__name__)


class AuditRetention:
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWorkPort],
        clock: Clock,
        *,
        retention_days: int,
        interval_s: float,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._retention_days = retention_days
        self._loop = PassLoop("audit-retention", self.prune_once, interval_s)

    @property
    def running(self) -> bool:
        return self._loop.running

    def start(self) -> None:
        if self._retention_days > 0:
            self._loop.start()

    async def stop(self) -> None:
        await self._loop.stop()

    async def prune_once(self) -> dict[str, int]:
        """Prune every org once; return the number of rows deleted per org (non-zero only)."""
        if self._retention_days <= 0:
            return {}
        cutoff = self._clock.now() - timedelta(days=self._retention_days)
        async with self._uow_factory() as uow:
            org_ids = list(await uow.audit.org_ids())
        pruned: dict[str, int] = {}
        for org_id in org_ids:
            try:
                count = await self._prune_org(org_id, cutoff)
            except Exception:
                logger.exception("audit retention failed for org %s", org_id)
                continue
            if count:
                pruned[org_id] = count
        return pruned

    async def _prune_org(self, org_id: str, cutoff: datetime) -> int:
        async with self._uow_factory() as uow:
            count = await uow.audit.prune_before(org_id, cutoff)
            await uow.commit()
        return count
