"""Allocation metering over the injected clock (WP 4.3, D9).

A sandbox entering ``started`` opens one interval per allocated dimension (``vcpu`` with the
vcpu count as the rate basis, ``memory_mib`` likewise); entering ``stopped``, ``destroyed`` or
``error`` closes whatever is open, so a stop then start yields two disjoint intervals. The
usage of a period is, per dimension, the sum of interval overlap seconds times the rate: two
vcpus running one hour are exactly 7200 vcpu seconds. Disk is measured, not allocated, but
it is credited for the full started time like the other dimensions: the sampler (one look per
tick, plus a quick first look at a new run) keeps one disk interval open per run whose rate is
the last sampled size in GiB. A run is credited from its start, so the first sample covers the
time before it; a size change at a tick closes the interval and opens the next at the new size;
error closes it with the other dimensions at the last known size. Stop and delete first take a
final sample (``FinalDiskSampler``): the driver is asked for the size before it stops or removes
the container, with no transaction open, and the size is credited in its own short unit of work,
so a sandbox deleted before its first tick is credited over its whole run, and a size change
since the last tick is credited over the tail the sampler missed (at most one sample interval).
If the driver cannot answer (container gone, no size capability, an error) the last known size
stands. A run seen only after it ended (a stop before any sample) is credited as a closed
interval over the run while its container still exists.

``MeteringSandboxRepository`` decorates the sandbox repository (like the event publisher
does) so the open and close calls ride the same unit of work as the state change itself and
land or vanish with it. Hourly rollups upsert per-org, per-dimension totals for a completed
hour; ``report`` prefers a stored rollup for a whole completed hour and falls back to the
intervals for everything else (partial hours, the running hour, hours not yet rolled up).
``report_grouped`` splits the same totals per sandbox or per label value for chargeback; the
rollups are per org and cannot be split, so it reads the intervals only.

Both take the key's label ``scope`` (``None`` = org-wide): only intervals of sandboxes carrying
every scope label count, destroyed ones included. Volumes are not a usage dimension.
"""

import logging
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from sandfort.clock import Clock
from sandfort.db.repositories.ports import SandboxRepository, UnitOfWorkPort
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.domain.usage import UsageDimension, UsageInterval, UsageRollup
from sandfort.drivers.base import InstanceSizeDriver, SandboxDriver
from sandfort.services.label_scope import count_through
from sandfort.services.usage_disk import DISK_LOOKBACK, EDGE, plan_disk_credit
from sandfort.services.volumes import is_reserved_label

logger = logging.getLogger(__name__)

HOUR = timedelta(hours=1)
MILLICORES_PER_VCPU = 1000
BYTES_PER_GIB = 1024**3
SANDBOX_GROUPING = "sandbox"
LABEL_GROUPING_PREFIX = "label:"
GROUP_BY_MESSAGE = "group_by must be 'sandbox' or 'label:<key>'"
SANDBOX_PAGE_SIZE = 200
DEFAULT_FINAL_TAIL_S = 300.0  # the default metering sample interval
LabelScope = Mapping[str, str] | None  # the key's sandbox labels; None = the whole org

_S = SandboxState
_CLOSING_STATES = frozenset({_S.STOPPED, _S.DESTROYED, _S.ERROR})


@dataclass(frozen=True, slots=True)
class DimensionTotal:
    dimension: UsageDimension
    total: float


@dataclass(frozen=True, slots=True)
class GroupTotals:
    """Per-dimension totals of one group: ``key`` is ``sandbox`` or the label key.

    ``value`` is the sandbox id or the label value; ``None`` collects the sandboxes that do
    not carry the label. ``name`` and ``labels`` describe the sandbox as stored at report time
    (per-sandbox grouping only; ``None`` for label groups and for a sandbox no longer stored).
    """

    key: str
    value: str | None
    totals: tuple[DimensionTotal, ...]
    name: str | None = None
    labels: Mapping[str, str] | None = None


@dataclass(frozen=True, slots=True)
class Grouping:
    """A parsed ``group_by``: ``label_key`` is ``None`` when grouping per sandbox."""

    label_key: str | None = None

    @property
    def key(self) -> str:
        return SANDBOX_GROUPING if self.label_key is None else self.label_key


def parse_group_by(value: str) -> Grouping:
    """``sandbox`` or ``label:<key>`` (a non-empty, non-reserved label key); else ``ValueError``."""
    if value == SANDBOX_GROUPING:
        return Grouping()
    if value.startswith(LABEL_GROUPING_PREFIX):
        key = value[len(LABEL_GROUPING_PREFIX) :]
        if key and not is_reserved_label(key):
            return Grouping(label_key=key)
    raise ValueError(GROUP_BY_MESSAGE)


def floor_hour(value: datetime) -> datetime:
    return value.replace(minute=0, second=0, microsecond=0)


def overlap_seconds(
    interval: UsageInterval, start: datetime, end: datetime, now: datetime
) -> float:
    """Seconds of ``interval`` inside ``[start, end)``; an open interval runs until ``now``."""
    stop = now if interval.ended_at is None else interval.ended_at
    lower = max(interval.started_at, start)
    upper = min(stop, end)
    return max((upper - lower).total_seconds(), 0.0)


def _allocations(sandbox: Sandbox) -> Mapping[UsageDimension, float]:
    resources = sandbox.resources
    return {
        UsageDimension.VCPU: resources.cpu_millicores / MILLICORES_PER_VCPU,
        UsageDimension.MEMORY_MIB: float(resources.memory_mib),
    }


class UsageService:
    def __init__(self, uow_factory: Callable[[], UnitOfWorkPort], clock: Clock) -> None:
        self._uow_factory = uow_factory
        self._clock = clock

    # -- lifecycle hooks (run inside the caller's unit of work) ------------------------

    async def open_for(self, uow: UnitOfWorkPort, sandbox: Sandbox) -> None:
        now = self._clock.now()
        for dimension, amount in _allocations(sandbox).items():
            interval = UsageInterval(
                org_id=sandbox.org_id,
                sandbox_id=sandbox.id,
                dimension=dimension,
                amount=amount,
                started_at=now,
            )
            await uow.usage.open_interval(interval)

    async def close_for(self, uow: UnitOfWorkPort, org_id: str, sandbox_id: str) -> int:
        return await uow.usage.close_open_intervals(org_id, sandbox_id, self._clock.now())

    # -- disk credit -------------------------------------------------------------------

    async def credit_disk(
        self,
        org_id: str,
        sandbox_id: str,
        size_bytes: int,
        *,
        tail: timedelta = timedelta(0),
    ) -> bool:
        """Credit the sampled disk size to the sandbox's runs; ``True`` when rows changed.

        With a ``tail`` a changed size is credited from ``now - tail`` instead of from ``now``
        (see ``plan_disk_credit``); the final sample at stop and delete uses it.

        Runs on its own unit of work (the driver call that produced ``size_bytes`` is finished
        by now). The plan is made from the stored intervals at commit time, so a sandbox that
        stopped between the sample and this call is credited as a closed run instead.
        """
        now = self._clock.now()
        async with self._uow_factory() as uow:
            stored = await uow.usage.list_intervals(
                now - DISK_LOOKBACK, now + EDGE, org_id=org_id, sandbox_id=sandbox_id
            )
            plan = plan_disk_credit(stored, size_bytes / BYTES_PER_GIB, now, tail)
            if not plan.new:
                return False
            if plan.close_open:
                await uow.usage.close_open_intervals(
                    org_id, sandbox_id, plan.split_at or now, dimension=UsageDimension.DISK_GIB
                )
            for interval in plan.new:
                await uow.usage.open_interval(interval)
            await uow.commit()
        return True

    # -- rollups -----------------------------------------------------------------------

    async def rollup_hour(self, hour_start: datetime) -> int:
        """Upsert the totals of the completed hour; idempotent. Yields the rows written.

        An hour that has not finished yet is never rolled up (its totals would be stale).
        """
        hour_end = hour_start + HOUR
        now = self._clock.now()
        if hour_end > now:
            return 0
        async with self._uow_factory() as uow:
            intervals = await uow.usage.list_intervals(hour_start, hour_end)
            totals: dict[tuple[str, UsageDimension], float] = defaultdict(float)
            for interval in intervals:
                seconds = overlap_seconds(interval, hour_start, hour_end, now)
                totals[(interval.org_id, interval.dimension)] += seconds * interval.amount
            for (org_id, dimension), total in sorted(totals.items()):
                await uow.usage.upsert_rollup(
                    UsageRollup(
                        org_id=org_id, period_start=hour_start, dimension=dimension, total=total
                    )
                )
            await uow.commit()
        return len(totals)

    # -- report ------------------------------------------------------------------------

    async def report(
        self, org_id: str, start: datetime, end: datetime, *, scope: LabelScope = None
    ) -> Sequence[DimensionTotal]:
        """Per-dimension totals for ``[start, end)``; a ``scope`` skips the per-org rollups."""
        now = self._clock.now()
        async with self._uow_factory() as uow:
            rollups = [] if scope else await uow.usage.get_rollups(org_id, start, end)
            intervals = await _intervals(uow, org_id, start, end, scope)
        totals = {dimension: 0.0 for dimension in UsageDimension}
        covered: set[tuple[datetime, UsageDimension]] = set()
        for rollup in rollups:
            hour_end = rollup.period_start + HOUR
            if rollup.period_start >= start and hour_end <= end and hour_end <= now:
                totals[rollup.dimension] += rollup.total
                covered.add((rollup.period_start, rollup.dimension))
        for interval in intervals:
            totals[interval.dimension] += _uncovered(interval, start, end, now, covered)
        return [DimensionTotal(dimension, totals[dimension]) for dimension in UsageDimension]

    async def report_grouped(
        self, org_id: str, start: datetime, end: datetime, group_by: str,
        *, scope: LabelScope = None,
    ) -> Sequence[GroupTotals]:
        """Per-group, per-dimension totals for ``[start, end)``; see ``parse_group_by``.

        Grouped totals come from the raw usage intervals (overlap seconds times the rate),
        never from the hourly rollups, which are per org and cannot be split. They therefore
        cover the retained interval history only: a period whose intervals were pruned reports
        less here than ``report`` does from its rollups. Label grouping reads each sandbox's
        labels as stored now (destroyed sandboxes included); a sandbox without the label, or
        one that cannot be found, lands in the ``None`` group. Groups are ordered by value with
        the ``None`` group last. A label ``scope`` limits the intervals as in ``report``.
        """
        grouping = parse_group_by(group_by)
        now = self._clock.now()
        async with self._uow_factory() as uow:
            intervals = await _intervals(uow, org_id, start, end, scope)
            wanted = {interval.sandbox_id for interval in intervals}
            found = await _sandboxes_by_id(uow, org_id, wanted)
        sums: dict[str | None, dict[UsageDimension, float]] = {}
        for interval in intervals:
            value = _group_value(grouping, interval.sandbox_id, found)
            per_dimension = sums.setdefault(value, {dimension: 0.0 for dimension in UsageDimension})
            seconds = overlap_seconds(interval, start, end, now)
            per_dimension[interval.dimension] += seconds * interval.amount
        return [
            _group(grouping, value, sums[value], found)
            for value in sorted(sums, key=lambda item: (item is None, item or ""))
        ]


def _group_value(grouping: Grouping, sandbox_id: str, found: Mapping[str, Sandbox]) -> str | None:
    if grouping.label_key is None:
        return sandbox_id
    sandbox = found.get(sandbox_id)
    return None if sandbox is None else sandbox.labels.get(grouping.label_key)


def _group(
    grouping: Grouping,
    value: str | None,
    sums: Mapping[UsageDimension, float],
    found: Mapping[str, Sandbox],
) -> GroupTotals:
    totals = tuple(DimensionTotal(d, sums[d]) for d in UsageDimension)
    sandbox = found.get(value) if grouping.label_key is None and value is not None else None
    return GroupTotals(
        key=grouping.key,
        value=value,
        totals=totals,
        name=None if sandbox is None else sandbox.name,
        labels=None if sandbox is None else sandbox.labels,
    )


async def _intervals(
    uow: UnitOfWorkPort,
    org_id: str,
    start: datetime,
    end: datetime,
    scope: LabelScope,
) -> Sequence[UsageInterval]:
    """The org's intervals overlapping the window; with a ``scope``, those of its sandboxes."""
    intervals = await uow.usage.list_intervals(start, end, org_id=org_id)
    if not scope:
        return intervals
    allowed = await _scope_ids(uow, org_id, scope)
    return [interval for interval in intervals if interval.sandbox_id in allowed]


async def _scope_ids(uow: UnitOfWorkPort, org_id: str, scope: Mapping[str, str]) -> set[str]:
    """Ids of every sandbox of the org carrying all ``scope`` labels, destroyed ones included."""
    ids: set[str] = set()
    cursor: str | None = None
    while True:
        page = await uow.sandboxes.list(
            org_id, labels=scope, cursor=cursor, limit=SANDBOX_PAGE_SIZE
        )
        ids.update(sandbox.id for sandbox in page)
        if len(page) < SANDBOX_PAGE_SIZE:
            return ids
        cursor = page[-1].id


async def _sandboxes_by_id(
    uow: UnitOfWorkPort, org_id: str, wanted: set[str]
) -> dict[str, Sandbox]:
    """The ``wanted`` sandboxes of ``org_id``, read through the unit of work.

    The org listing covers every state, destroyed included; ids it does not return (a warm
    pool standby is not listed) are looked up one by one.
    """
    found: dict[str, Sandbox] = {}
    cursor: str | None = None
    while len(found) < len(wanted):
        page = await uow.sandboxes.list(org_id, cursor=cursor, limit=SANDBOX_PAGE_SIZE)
        if not page:
            break
        found.update({sandbox.id: sandbox for sandbox in page if sandbox.id in wanted})
        cursor = page[-1].id
    for sandbox_id in sorted(wanted - found.keys()):
        sandbox = await uow.sandboxes.get(org_id, sandbox_id)
        if sandbox is not None:
            found[sandbox_id] = sandbox
    return found


def _uncovered(
    interval: UsageInterval,
    start: datetime,
    end: datetime,
    now: datetime,
    covered: set[tuple[datetime, UsageDimension]],
) -> float:
    """Usage of ``interval`` in ``[start, end)`` outside the hours a rollup already holds."""
    if not covered:
        return overlap_seconds(interval, start, end, now) * interval.amount
    stop = min(end, now if interval.ended_at is None else interval.ended_at)
    total = 0.0
    hour = floor_hour(max(interval.started_at, start))
    while hour < stop:
        if (hour, interval.dimension) not in covered:
            seconds = overlap_seconds(interval, max(hour, start), min(hour + HOUR, end), now)
            total += seconds * interval.amount
        hour += HOUR
    return total


class MeteringSandboxRepository:
    """Decorates a ``SandboxRepository`` so state changes open and close usage intervals.

    ``update`` opens the intervals when a sandbox enters ``started`` and closes them when it
    enters ``stopped``, ``destroyed`` or ``error``, through the caller's unit of work and
    before it commits. A save that does not change the state touches nothing.
    """

    def __init__(
        self, inner: SandboxRepository, uow: UnitOfWorkPort, usage: UsageService
    ) -> None:
        self._inner = inner
        self._uow = uow
        self._usage = usage

    async def add(self, sandbox: Sandbox) -> None:
        await self._inner.add(sandbox)

    async def update(self, org_id: str, sandbox: Sandbox, *, expected_version: int) -> Sandbox:
        previous = await self._inner.get(org_id, sandbox.id)
        saved = await self._inner.update(org_id, sandbox, expected_version=expected_version)
        if previous is None or previous.state is saved.state:
            return saved
        if saved.state is _S.STARTED:
            await self._usage.open_for(self._uow, saved)
        elif saved.state in _CLOSING_STATES:
            await self._usage.close_for(self._uow, saved.org_id, saved.id)
        return saved

    async def get(self, org_id: str, sandbox_id: str) -> Sandbox | None:
        return await self._inner.get(org_id, sandbox_id)

    async def get_by_name(self, org_id: str, name: str) -> Sandbox | None:
        return await self._inner.get_by_name(org_id, name)

    async def list(
        self,
        org_id: str,
        *,
        state: SandboxState | None = None,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> Sequence[Sandbox]:
        return await self._inner.list(
            org_id, state=state, labels=labels, cursor=cursor, limit=limit
        )

    async def list_for_reconciler(self) -> Sequence[Sandbox]:
        return await self._inner.list_for_reconciler()

    async def list_for_egress_policy(self, sandbox_ids: Sequence[str]) -> Sequence[Sandbox]:
        return await self._inner.list_for_egress_policy(sandbox_ids)

    async def count_in_scope(self, org_id: str, labels: Mapping[str, str]) -> int:
        return await count_through(self._inner, org_id, labels)


class FinalDiskSampler:
    """A last disk look at stop and delete, credited in its own short unit of work.

    ``sample`` is called by the lifecycle drive step before the driver stops or removes the
    container: no transaction is open then, and the size can still be read. Best effort: a
    driver without the size capability, a container that is gone, ``None`` or an error leave
    the last known size in place and never fail the stop or delete.
    """

    def __init__(self, usage: UsageService, driver: SandboxDriver, tail: timedelta) -> None:
        self._usage = usage
        self._driver = driver
        self._tail = tail

    async def sample(self, sandbox: Sandbox) -> None:
        driver = self._driver
        ref = sandbox.driver_ref
        if ref is None or not isinstance(driver, InstanceSizeDriver):
            return
        try:
            size = await driver.instance_size_bytes(ref)
            if size is not None:
                await self._usage.credit_disk(sandbox.org_id, sandbox.id, size, tail=self._tail)
        except Exception:  # the stop or delete must go on at the last known size
            logger.warning("final disk sample failed for sandbox %s", sandbox.id, exc_info=True)


class MeteredUnitOfWorkFactory:
    """The factory ``with_usage_metering`` returns: it also carries the final disk sampler."""

    def __init__(
        self,
        inner: Callable[[], UnitOfWorkPort],
        usage: UsageService,
        final_disk: FinalDiskSampler | None,
    ) -> None:
        self._inner = inner
        self._usage = usage
        self.final_disk = final_disk

    def __call__(self) -> UnitOfWorkPort:
        uow = self._inner()
        uow.sandboxes = MeteringSandboxRepository(uow.sandboxes, uow, self._usage)
        return uow


def with_usage_metering(
    uow_factory: Callable[[], UnitOfWorkPort],
    clock: Clock,
    driver: SandboxDriver | None = None,
    *,
    tail_s: float = DEFAULT_FINAL_TAIL_S,
) -> MeteredUnitOfWorkFactory:
    """A unit-of-work factory whose ``sandboxes`` repository meters lifecycle moves.

    With a ``driver`` the lifecycles built on the factory also take a final disk sample at
    stop and delete; ``tail_s`` (the sampler's interval) bounds how far back a changed size
    is credited.
    """
    usage = UsageService(uow_factory, clock)
    final = None if driver is None else FinalDiskSampler(usage, driver, timedelta(seconds=tail_s))
    return MeteredUnitOfWorkFactory(uow_factory, usage, final)
