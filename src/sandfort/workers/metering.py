"""Metering worker: hourly rollups and the storage sampler (WP 4.3).

Three passes, each on its own ``PassLoop``:

* *Rollup*: recomputes the totals of the last few completed hours (``lookback_hours``, newest
  last) and upserts one row per (org, hour, dimension). The rows are keyed, so a rerun for the
  same hour replaces them with identical values; the lookback is what makes a missed pass (a
  restart, an outage) heal itself. An hour that has not finished is never rolled up.
* *Sampler* (the metering tick, ``sample_interval_s``): for each ``started`` sandbox whose
  container the driver inventory lists, asks the driver for a cheap size and credits it to the
  disk intervals of its runs (``UsageService.credit_disk``): the open interval continues when the
  size is unchanged and is split at the tick when it changed. Runs that already ended without a
  disk interval (a stop before any sample) are credited too, while their container still exists.
* *First look* (``FIRST_LOOK_INTERVAL_S``): the same, restricted to runs with no disk interval
  yet, so a new start is sized within seconds instead of at the next tick.

Stop and delete take one more look first (``FinalDiskSampler``, before the driver stops or
removes the container and with no transaction open); error closes the disk interval with the
other dimensions at the last sampled size. A driver without the inventory or the size
capability, or a size that is not cheaply available, is skipped for that pass: an unreadable
inventory is never read as "nothing is running".

One failing hour or sandbox is logged and never ends the pass. Sleeping uses real time.
"""

import logging
from collections import defaultdict
from collections.abc import Callable

from sandfort.clock import Clock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.domain.usage import UsageInterval
from sandfort.drivers.base import InstanceSizeDriver, InventoryDriver, SandboxDriver
from sandfort.services.usage import HOUR, UsageService, floor_hour
from sandfort.services.usage_disk import DISK_LOOKBACK, EDGE, disk_gaps
from sandfort.workers.reconciler import PassLoop

logger = logging.getLogger(__name__)

FIRST_LOOK_INTERVAL_S = 15.0  # how soon a new run gets its first disk size


class MeteringWorker:
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWorkPort],
        driver: SandboxDriver,
        clock: Clock,
        *,
        rollup_interval_s: float,
        sample_interval_s: float,
        lookback_hours: int,
    ) -> None:
        self._uow_factory = uow_factory
        self._driver = driver
        self._clock = clock
        self._usage = UsageService(uow_factory, clock)
        self._lookback_hours = max(lookback_hours, 1)
        self._rollups = PassLoop("usage rollup", self.rollup_once, rollup_interval_s)
        self._sampler = PassLoop("usage sampler", self.sample_once, sample_interval_s)
        self._first_look = PassLoop(
            "usage first look", self.first_look_once, min(sample_interval_s, FIRST_LOOK_INTERVAL_S)
        )

    @property
    def running(self) -> bool:
        return self._rollups.running and self._sampler.running and self._first_look.running

    def start(self) -> None:
        self._rollups.start()
        self._sampler.start()
        self._first_look.start()

    async def stop(self) -> None:
        await self._first_look.stop()
        await self._sampler.stop()
        await self._rollups.stop()

    # -- rollup ------------------------------------------------------------------------

    async def rollup_once(self) -> int:
        """One pass over the recent completed hours; yields the rollup rows written."""
        newest = floor_hour(self._clock.now()) - HOUR
        written = 0
        for back in reversed(range(self._lookback_hours)):
            hour = newest - back * HOUR
            try:
                written += await self._usage.rollup_hour(hour)
            except Exception:  # one bad hour must not starve the others
                logger.exception("usage rollup failed for hour %s", hour.isoformat())
        return written

    # -- storage sampler ---------------------------------------------------------------

    async def sample_once(self) -> int:
        """One tick over every run that needs a disk look; yields the sandboxes credited."""
        return await self._sample_pass(first_look_only=False)

    async def first_look_once(self) -> int:
        """Size only runs that have no disk interval yet (a new start, a stop before a tick)."""
        return await self._sample_pass(first_look_only=True)

    async def _sample_pass(self, *, first_look_only: bool) -> int:
        driver = self._driver
        if not isinstance(driver, InventoryDriver) or not isinstance(driver, InstanceSizeDriver):
            logger.info("driver %s cannot report sizes; sampler pass skipped", driver.name)
            return 0
        targets = await self._targets(first_look_only)
        if not targets:
            return 0
        try:
            instances = await driver.list_instances()
        except Exception:  # an unreadable inventory is not an empty one
            logger.exception("sampler pass skipped: cannot read the driver inventory")
            return 0
        by_ref = {item.provider_id for item in instances}
        recorded = 0
        for row in targets:
            if row.driver_ref not in by_ref:
                continue
            try:
                recorded += int(await self._sample(driver, row))
            except Exception:  # one bad sandbox must not starve the others
                logger.exception("usage sample failed for sandbox %s", row.id)
        return recorded

    async def _targets(self, first_look_only: bool) -> list[Sandbox]:
        """Sandboxes to size: running ones (every tick) and any run with unpaid disk time.

        Read first, driver afterwards: no driver call runs inside this unit of work.
        """
        now = self._clock.now()
        async with self._uow_factory() as uow:
            rows = await uow.sandboxes.list_for_reconciler()
            stored = await uow.usage.list_intervals(now - DISK_LOOKBACK, now + EDGE)
        by_sandbox: dict[str, list[UsageInterval]] = defaultdict(list)
        for interval in stored:
            by_sandbox[interval.sandbox_id].append(interval)
        targets: list[Sandbox] = []
        for row in rows:
            if row.driver_ref is None:
                continue
            gaps = disk_gaps(by_sandbox.get(row.id, []), now)
            if gaps or (row.state is SandboxState.STARTED and not first_look_only):
                targets.append(row)
        return targets

    async def _sample(self, driver: InstanceSizeDriver, row: Sandbox) -> bool:
        size = await driver.instance_size_bytes(row.driver_ref or "")
        if size is None:
            return False
        return await self._usage.credit_disk(row.org_id, row.id, size)
