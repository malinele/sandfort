"""Soft size limit for volumes (``SANDFORT_VOLUME_MAX_BYTES``, round 59).

Docker local volumes cannot be capped by the daemon, so the platform enforces the limit from
the sampled size (``Volume.sampled_size_bytes``). ``0`` means no limit, the default.

The limit is checked when a read-write mount is made: on sandbox create, on start and on the
resize recreate path (which runs inside start). A read-write mount of a volume whose size
exceeds the limit is refused (422 ``VOLUME_OVER_LIMIT``, details ``volume_id``, ``size_bytes``
and ``max_bytes``); a read-only mount is always allowed. Running sandboxes are never stopped
for filling a volume; the next release may add a stop cause for that.

Driver calls never run inside an open transaction, so the check has two steps. The pre-step,
``MountGuard.prepare``, runs before the unit of work opens, and after the request validation,
the label-scope filter and the cheap refusals (quota, key cap): it re-samples each requested
read-write volume the key may mount through the driver when its last sample in this guard is
older than the sampling interval (or there is none), stores a changed size in its own short
transaction and returns a ``MountLimit`` holding the fresh sizes. ``resolve_mounts`` (create)
and ``MountLimit.check_requests`` (start) then decide from that ``MountLimit`` and never touch
the driver. A failed inspect falls back to the stored sample; an inspect that yields no size is
noted like a sample, so it is not repeated within the interval.

A sample is remembered (``note_sample``) only after the transaction that stores it has
committed, and not at all when the volume was deleted meanwhile, so a rolled-back write never
makes a later check trust a size that was not kept. The remembered times are an LRU of fixed
size, and ``forget`` drops a deleted volume.

The limit and the interval are plain constructor arguments of the guard; ``VolumeService``
owns one guard, built from ``Settings`` by ``api.wiring``. The limit a response shows travels
with the volume the service returns (``LimitedVolume``), so it always is the limit of the
service that enforces it; there is no module-global limit.
"""

import logging
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Protocol

from sandfort.auth.label_scope import matches
from sandfort.clock import Clock
from sandfort.config import Settings
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.volume import Volume, VolumeState
from sandfort.drivers.errors import DriverError
from sandfort.errors import Unprocessable

logger = logging.getLogger(__name__)

NO_LIMIT = 0
DEFAULT_SAMPLE_INTERVAL_S = Settings().metering_sample_interval_s
MAX_TRACKED_VOLUMES = 1024  # sample times kept; the least recently sampled volumes go first

Inspect = Callable[[str], Awaitable[Mapping[str, Any]]]
UowFactory = Callable[[], UnitOfWorkPort]


class VolumeOverLimit(Unprocessable):
    """A read-write mount was asked for a volume above the size limit."""

    code = "VOLUME_OVER_LIMIT"


class MountAsk(Protocol):
    """What the guard needs of a mount request."""

    @property
    def volume_id(self) -> str: ...

    @property
    def read_only(self) -> bool: ...


def effective_limit(max_bytes: int) -> int | None:
    """The limit to report and enforce: ``None`` when ``max_bytes`` means no limit."""
    return max_bytes if max_bytes > NO_LIMIT else None


def is_over_limit(size_bytes: int | None, max_bytes: int | None) -> bool:
    """True when a sampled size is known and exceeds an active limit."""
    return max_bytes is not None and size_bytes is not None and size_bytes > max_bytes


class LimitedVolume(Volume):
    """A volume as a limited service returns it: it carries the limit that service enforces."""

    reported_max_bytes: int | None = None


def with_reported_limit(volume: Volume, max_bytes: int | None) -> Volume:
    """``volume`` tagged with ``max_bytes``; the plain volume when there is no limit."""
    if max_bytes is None:
        return volume
    return LimitedVolume.model_validate({**dict(volume), "reported_max_bytes": max_bytes})


def reported_limit(volume: Volume) -> int | None:
    """The limit the service that returned ``volume`` enforces; ``None`` when it has none."""
    return volume.reported_max_bytes if isinstance(volume, LimitedVolume) else None


@dataclass(frozen=True, slots=True)
class MountLimit:
    """An active limit with the sizes the pre-step sampled; decides without the driver."""

    max_bytes: int
    sizes: Mapping[str, int] = field(default_factory=dict)

    async def check_requests(
        self, uow: UnitOfWorkPort, org_id: str, requests: Sequence[MountAsk]
    ) -> None:
        """Raise ``VolumeOverLimit`` for the first read-write request over the limit.

        For mounts already recorded (start): a missing or deleting volume is skipped, as the
        start itself reports it. Reads through ``uow``; never calls the driver.
        """
        for volume_id in dict.fromkeys(ask.volume_id for ask in requests if not ask.read_only):
            volume = await uow.volumes.get(org_id, volume_id)
            if volume is not None and volume.state is VolumeState.READY:
                self.check_read_write(volume)

    def check_read_write(self, volume: Volume) -> None:
        """Raise ``VolumeOverLimit`` when ``volume`` is over the limit.

        The freshly sampled size wins; a volume the pre-step did not sample (its last sample
        was recent, or the inspect failed) is judged by its stored size.
        """
        size = self.sizes.get(volume.id, volume.sampled_size_bytes)
        if size is not None and is_over_limit(size, self.max_bytes):
            raise VolumeOverLimit(
                f"volume {volume.id} is over its size limit ({size} > {self.max_bytes} bytes)",
                details={"volume_id": volume.id, "size_bytes": size, "max_bytes": self.max_bytes},
            )


class MountGuard:
    """Samples requested read-write volumes before the create transaction opens."""

    def __init__(
        self,
        max_bytes: int,
        sample_interval_s: int,
        clock: Clock,
        inspect: Inspect,
        *,
        max_tracked: int = MAX_TRACKED_VOLUMES,
    ) -> None:
        self.max_bytes = effective_limit(max_bytes)
        self.sample_interval_s = sample_interval_s
        self._interval = timedelta(seconds=sample_interval_s)
        self._clock = clock
        self._inspect = inspect
        self._max_tracked = max(1, max_tracked)
        self._sampled_at: OrderedDict[str, datetime] = OrderedDict()  # least recent first

    # -- the remembered sample times -------------------------------------------------

    def note_sample(self, volume_id: str) -> None:
        """Record that ``volume_id`` was sampled and stored just now; evicts the oldest."""
        self._sampled_at[volume_id] = self._clock.now()
        self._sampled_at.move_to_end(volume_id)
        while len(self._sampled_at) > self._max_tracked:
            self._sampled_at.popitem(last=False)

    def forget(self, volume_id: str) -> None:
        """Drop the entry of a volume that no longer exists."""
        self._sampled_at.pop(volume_id, None)

    def is_fresh(self, volume_id: str) -> bool:
        """True when ``volume_id`` was sampled less than one interval ago."""
        last = self._sampled_at.get(volume_id)
        return last is not None and self._clock.now() - last < self._interval

    def tracked_ids(self) -> tuple[str, ...]:
        """The volumes with a remembered sample time, least recently sampled first."""
        return tuple(self._sampled_at)

    # -- the pre-step ----------------------------------------------------------------

    def wants_sampling(self, requests: Sequence[MountAsk]) -> bool:
        """True when a limit is active and ``requests`` hold a read-write mount."""
        return self.max_bytes is not None and any(not ask.read_only for ask in requests)

    async def prepare(
        self,
        uow_factory: UowFactory,
        org_id: str,
        requests: Sequence[MountAsk],
        *,
        scope: Mapping[str, str] | None = None,
    ) -> MountLimit | None:
        """Sample the requested read-write volumes; call it before any unit of work is open.

        ``None`` when there is no limit. Only volumes the key may mount are sampled: with a
        label ``scope`` a volume whose labels do not contain it is left to ``resolve_mounts``
        to refuse, and costs no driver call. Each driver call and each write here runs in its
        own short unit of work (or none), never inside the caller's transaction.
        """
        if self.max_bytes is None:
            return None
        wanted = list(dict.fromkeys(ask.volume_id for ask in requests if not ask.read_only))
        sizes: dict[str, int] = {}
        for volume in await self._load(uow_factory, org_id, wanted, scope):
            size = await self._sample(uow_factory, volume)
            if size is not None:
                sizes[volume.id] = size
        return MountLimit(self.max_bytes, sizes)

    async def store_sample(self, uow_factory: UowFactory, volume: Volume, size: int) -> Volume:
        """Store a sampled ``size`` when it changed, then remember the sample.

        The time is noted only after the commit, so a failed write is never trusted later. A
        volume deleted meanwhile (the setter finds no row) is not noted.
        """
        result = volume
        if size != volume.sampled_size_bytes:
            async with uow_factory() as uow:
                updated = await uow.volumes.set_sampled_size(volume.org_id, volume.id, size)
                await uow.commit()
            if updated is None:
                return volume
            result = updated
        self.note_sample(volume.id)
        return result

    @staticmethod
    async def _load(
        uow_factory: UowFactory,
        org_id: str,
        volume_ids: Sequence[str],
        scope: Mapping[str, str] | None,
    ) -> list[Volume]:
        """The ready volumes among ``volume_ids`` that ``scope`` allows.

        The others are left to ``resolve_mounts``, which refuses or reports them.
        """
        if not volume_ids:
            return []
        async with uow_factory() as uow:
            found = [await uow.volumes.get(org_id, volume_id) for volume_id in volume_ids]
        return [
            item
            for item in found
            if item is not None and item.state is VolumeState.READY and matches(item.labels, scope)
        ]

    async def _sample(self, uow_factory: UowFactory, volume: Volume) -> int | None:
        """A fresh size, or ``None`` when the last sample is recent or no size came back."""
        if self.is_fresh(volume.id):
            return None
        try:
            size = (await self._inspect(volume.provider_volume_name)).get("size_bytes")
        except DriverError as exc:
            logger.warning("could not sample volume %s: %s", volume.id, exc.message)
            return None
        if not isinstance(size, int) or size < 0:
            self.note_sample(volume.id)  # the attempt counts: no re-inspect within the interval
            return None
        await self.store_sample(uow_factory, volume, size)
        return size
