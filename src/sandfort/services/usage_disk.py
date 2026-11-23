"""Disk credit planning for the usage service (see ``sandfort.services.usage``).

Pure functions over one sandbox's stored intervals: the runs are its vcpu intervals, the time
basis of every allocated dimension, and the plan says which disk rows make each run covered at
the sampled size. No I/O here; the service writes the plan in its own unit of work.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from sandfort.domain.usage import UsageDimension, UsageInterval

DISK_LOOKBACK = timedelta(hours=6)  # runs older than this are no longer backfilled
EDGE = timedelta(microseconds=1)
SIZE_TOLERANCE_GIB = 0.5 / 1024**3  # half a byte: the same size, not a change


@dataclass(frozen=True, slots=True)
class DiskPlan:
    """What to write for the disk of one sandbox: close the open interval, then add ``new``.

    ``split_at`` is the instant the open interval is closed at (and the next one opens at).
    """

    close_open: bool = False
    new: tuple[UsageInterval, ...] = ()
    split_at: datetime | None = None


def _uncovered(
    start: datetime, end: datetime, covered: Sequence[tuple[datetime, datetime]]
) -> list[tuple[datetime, datetime]]:
    """The parts of ``[start, end)`` no ``covered`` span reaches, in order."""
    gaps: list[tuple[datetime, datetime]] = []
    cursor = start
    for low, high in sorted(covered):
        if cursor >= end:
            break
        if high <= cursor:
            continue
        if low > cursor:
            gaps.append((cursor, min(low, end)))
        cursor = max(cursor, high)
    if cursor < end:
        gaps.append((cursor, end))
    return gaps


def _disk_cover(
    intervals: Sequence[UsageInterval], now: datetime
) -> list[tuple[datetime, datetime]]:
    return [
        (item.started_at, now if item.ended_at is None else item.ended_at)
        for item in intervals
        if item.dimension is UsageDimension.DISK_GIB
    ]


def disk_gaps(intervals: Sequence[UsageInterval], now: datetime) -> bool:
    """``True`` when a run in ``intervals`` (one sandbox) has time without a disk interval."""
    covered = _disk_cover(intervals, now)
    floor = now - DISK_LOOKBACK
    for run in intervals:
        if run.dimension is not UsageDimension.VCPU:
            continue
        end = now if run.ended_at is None else run.ended_at
        if _uncovered(max(run.started_at, floor), end, covered):
            return True
    return False


def plan_disk_credit(
    intervals: Sequence[UsageInterval],
    size_gib: float,
    now: datetime,
    tail: timedelta = timedelta(0),
) -> DiskPlan:
    """Disk rows to write so every run in ``intervals`` (one sandbox) is credited ``size_gib``.

    The runs are the sandbox's vcpu intervals, the same time basis as the other dimensions. A
    closed run gets its uncovered parts as closed intervals; an open run with an open disk
    interval of another size is split at ``now``; an open run without one gets an interval
    open from the first uncovered instant (the run start for a first sample).

    ``tail`` backdates the split of a changed size: the new size is credited from ``now - tail``
    (never before the open interval started) instead of from ``now``. A final sample at stop
    or delete passes one sample interval, the longest stretch the sampler could not see.
    """
    disk = [item for item in intervals if item.dimension is UsageDimension.DISK_GIB]
    open_disk = next((item for item in disk if item.ended_at is None), None)
    covered = _disk_cover(intervals, now)
    floor = now - DISK_LOOKBACK
    split_at: datetime | None = None
    new: list[UsageInterval] = []
    for run in sorted(
        (item for item in intervals if item.dimension is UsageDimension.VCPU),
        key=lambda item: item.started_at,
    ):
        if run.ended_at is None and open_disk is not None:
            if abs(open_disk.amount - size_gib) > SIZE_TOLERANCE_GIB:
                split_at = max(open_disk.started_at, now - tail)
                new.append(_disk_interval(run, size_gib, split_at, None))
            continue
        end = now if run.ended_at is None else run.ended_at
        for low, high in _uncovered(max(run.started_at, floor), end, covered):
            still_open = run.ended_at is None and high == end
            new.append(_disk_interval(run, size_gib, low, None if still_open else high))
    return DiskPlan(close_open=split_at is not None, new=tuple(new), split_at=split_at)


def _disk_interval(
    run: UsageInterval, size_gib: float, start: datetime, end: datetime | None
) -> UsageInterval:
    return UsageInterval(
        org_id=run.org_id,
        sandbox_id=run.sandbox_id,
        dimension=UsageDimension.DISK_GIB,
        amount=size_gib,
        started_at=start,
        ended_at=end,
    )
