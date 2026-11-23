"""Garbage collector: removes provider images and volumes that no database row accounts for.

* images: only platform-tagged ones (``sandfort-snapshot:<snapshot id>``) that no snapshot row
  and no live sandbox references. A snapshot row in any state, ``deleting`` included, still
  owns its image, so a delete in flight is never raced.
* volumes: only platform-named (``sf-vol-...``) ones whose labels name an org and a volume id
  and whose volume row is gone.
* scratch volumes (``sf-imgvol-...``, managed label plus the image mount path label) whose
  sandbox row is gone or destroyed; audited as ``gc.volume_removed`` on the sandbox.

All wait out the same grace as the reconciler's orphans (first sighting kept in process
memory, no table) and re-check the database right before removing. Removals write the audit
events ``gc.image_removed`` and ``gc.volume_removed``. A snapshot tag carries no org, so the
org of an image removal comes from the audit trail of its snapshot id; an image with no trail
is still removed, just not audited. One item failing never ends the pass.
"""

import contextlib
import logging
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sandfort.clock import Clock
from sandfort.db.models.audit import AuditRow
from sandfort.db.models.snapshots import SnapshotRow
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.sandbox import SandboxState
from sandfort.drivers.base import InventoryDriver, SandboxDriver, VolumeInfo
from sandfort.drivers.docker.capabilities import PLATFORM_IMAGE_PREFIX
from sandfort.drivers.docker.image_volumes import scratch_identity
from sandfort.drivers.errors import DriverConflict, DriverNotFound
from sandfort.services.audit import AuditRecorder
from sandfort.services.volumes import ORG_ID_LABEL, PROVIDER_PREFIX, VOLUME_ID_LABEL
from sandfort.workers.reconciler import (
    GraceTracker,
    PassLoop,
    list_node_sandboxes,
    record_system_audit,
)

logger = logging.getLogger(__name__)

IMAGE_REMOVED = "gc.image_removed"
VOLUME_REMOVED = "gc.volume_removed"


@dataclass(frozen=True, slots=True)
class GcReport:
    images_removed: tuple[str, ...] = ()  # image tags
    volumes_removed: tuple[str, ...] = ()  # provider volume names
    errors: int = 0


class GarbageCollector:
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWorkPort],
        session_factory: async_sessionmaker[AsyncSession],
        driver: SandboxDriver,
        clock: Clock,
        *,
        interval_s: float,
        grace_s: float,
        node_id: str | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._node_id = node_id  # only this node's sandboxes keep an image alive; None means all
        self._session_factory = session_factory
        self._driver = driver
        self._audit = AuditRecorder(clock)
        self._image_grace = GraceTracker(clock, grace_s)
        self._volume_grace = GraceTracker(clock, grace_s)
        self._scratch_grace = GraceTracker(clock, grace_s)
        self._loop = PassLoop("gc", self.collect_once, interval_s)

    @property
    def running(self) -> bool:
        return self._loop.running

    def start(self) -> None:
        self._loop.start()

    async def stop(self) -> None:
        await self._loop.stop()

    async def collect_once(self) -> GcReport:
        inventory = self._driver
        if not isinstance(inventory, InventoryDriver):
            logger.info("driver %s has no inventory; gc pass skipped", self._driver.name)
            return GcReport()
        images, image_errors = await self._collect_images(inventory)
        volumes, volume_errors = await self._collect_volumes(inventory)
        return GcReport(tuple(images), tuple(volumes), image_errors + volume_errors)

    # -- images --------------------------------------------------------------------------

    async def _collect_images(self, inventory: InventoryDriver) -> tuple[list[str], int]:
        try:
            listed = [
                item.ref
                for item in await inventory.list_images()
                if item.ref.startswith(PLATFORM_IMAGE_PREFIX)
            ]
            referenced = await self._referenced_images()
        except Exception:
            logger.exception("gc image pass skipped: cannot read the image state")
            return [], 1
        unreferenced = [ref for ref in listed if ref not in referenced]
        self._image_grace.retain(unreferenced)
        removed: list[str] = []
        errors = 0
        for ref in unreferenced:
            try:
                if self._image_grace.expired(ref) and await self._remove_image(ref):
                    removed.append(ref)
            except Exception:
                logger.exception("could not remove image %s", ref)
                errors += 1
        return removed, errors

    async def _referenced_images(self) -> frozenset[str]:
        """Tags a snapshot row (any state) or a non-destroyed sandbox still points at."""
        async with self._session_factory() as session:
            snapshot_refs = set((await session.execute(select(SnapshotRow.image_ref))).scalars())
        async with self._uow_factory() as uow:
            sandboxes = await list_node_sandboxes(uow, self._node_id)
        return frozenset(snapshot_refs | {sandbox.image_ref for sandbox in sandboxes})

    async def _remove_image(self, ref: str) -> bool:
        if ref in await self._referenced_images():  # a row claimed it since the listing
            self._image_grace.forget(ref)
            return False
        snapshot_id = ref.removeprefix(PLATFORM_IMAGE_PREFIX)
        org_id = await self._snapshot_org(snapshot_id)
        with contextlib.suppress(DriverNotFound):  # already gone is the outcome we want
            await self._driver.remove_image(ref)
        self._image_grace.forget(ref)
        await self._audit_removal(org_id, IMAGE_REMOVED, "snapshot", snapshot_id, {"image": ref})
        return True

    async def _snapshot_org(self, snapshot_id: str) -> str | None:
        """The org that last audited this (lower-cased) snapshot id, if anyone did."""
        stmt = (
            select(AuditRow.org_id).where(func.lower(AuditRow.target_id) == snapshot_id).limit(1)
        )
        async with self._session_factory() as session:
            return (await session.execute(stmt)).scalar_one_or_none()

    # -- volumes -------------------------------------------------------------------------

    async def _collect_volumes(self, inventory: InventoryDriver) -> tuple[list[str], int]:
        try:
            listed = await inventory.list_volumes()
        except Exception:
            logger.exception("gc volume pass skipped: cannot read the driver inventory")
            return [], 1
        user = [
            volume
            for volume in listed
            if volume.name.startswith(PROVIDER_PREFIX) and _identity(volume.labels) is not None
        ]
        scratch = [v for v in listed if scratch_identity(v.name, v.labels) is not None]
        removed, errors = await self._sweep(
            user, self._volume_grace, self._row_is_gone, self._remove_volume
        )
        scratch_removed, scratch_errors = await self._sweep(
            scratch, self._scratch_grace, self._sandbox_is_gone, self._remove_scratch
        )
        return removed + scratch_removed, errors + scratch_errors

    async def _sweep(
        self,
        volumes: Sequence[VolumeInfo],
        grace: GraceTracker,
        is_gone: Callable[[VolumeInfo], Awaitable[bool]],
        remove: Callable[[VolumeInfo], Awaitable[bool]],
    ) -> tuple[list[str], int]:
        """Remove the ``volumes`` whose owner is gone and stayed gone for the whole grace."""
        removed: list[str] = []
        errors = 0
        gone: list[VolumeInfo] = []
        for volume in volumes:
            try:
                if await is_gone(volume):
                    gone.append(volume)
            except Exception:
                logger.exception("could not check the row of volume %s", volume.name)
                errors += 1
        grace.retain([volume.name for volume in gone])
        for volume in gone:
            try:
                if grace.expired(volume.name) and await remove(volume):
                    removed.append(volume.name)
            except Exception:
                logger.exception("could not remove volume %s", volume.name)
                errors += 1
        return removed, errors

    async def _row_is_gone(self, volume: VolumeInfo) -> bool:
        identity = _identity(volume.labels)
        if identity is None:
            return False
        org_id, volume_id = identity
        async with self._uow_factory() as uow:
            return await uow.volumes.get(org_id, volume_id) is None

    async def _remove_volume(self, volume: VolumeInfo) -> bool:
        identity = _identity(volume.labels)
        if identity is None or not await self._row_is_gone(volume):  # claimed since the listing
            self._volume_grace.forget(volume.name)
            return False
        try:
            await self._driver.remove_volume(volume.name)
        except DriverNotFound:
            pass  # already gone is the outcome we want
        except DriverConflict:
            logger.warning("volume %s is still mounted; retried next pass", volume.name)
            return False
        self._volume_grace.forget(volume.name)
        org_id, volume_id = identity
        details = {"volume": volume.name}
        await self._audit_removal(org_id, VOLUME_REMOVED, "volume", volume_id, details)
        return True

    async def _sandbox_is_gone(self, volume: VolumeInfo) -> bool:
        """A scratch volume's sandbox has no row, or a destroyed one."""
        identity = scratch_identity(volume.name, volume.labels)
        if identity is None:
            return False
        org_id, sandbox_id = identity
        async with self._uow_factory() as uow:
            sandbox = await uow.sandboxes.get(org_id, sandbox_id)
        return sandbox is None or sandbox.state is SandboxState.DESTROYED

    async def _remove_scratch(self, volume: VolumeInfo) -> bool:
        identity = scratch_identity(volume.name, volume.labels)
        if identity is None or not await self._sandbox_is_gone(volume):  # claimed meanwhile
            self._scratch_grace.forget(volume.name)
            return False
        try:
            await self._driver.remove_volume(volume.name)
        except DriverNotFound:
            pass  # already gone is the outcome we want
        except DriverConflict:
            logger.warning("scratch volume %s is still mounted; retried next pass", volume.name)
            return False
        self._scratch_grace.forget(volume.name)
        org_id, sandbox_id = identity
        details = {"volume": volume.name, "kind": "scratch"}
        await self._audit_removal(org_id, VOLUME_REMOVED, "sandbox", sandbox_id, details)
        return True

    # -- audit ---------------------------------------------------------------------------

    async def _audit_removal(
        self,
        org_id: str | None,
        action: str,
        target_type: str,
        target_id: str,
        details: Mapping[str, str],
    ) -> None:
        if org_id is None:
            logger.warning("%s of %s has no org to audit under", action, target_id)
            return
        try:
            await record_system_audit(
                self._uow_factory,
                self._audit,
                org_id=org_id,
                action=action,
                target_type=target_type,
                target_id=target_id,
                details=details,
            )
        except Exception:  # the object is already gone; do not fail the pass over its record
            logger.exception("could not audit %s of %s", action, target_id)


def _identity(labels: Mapping[str, str]) -> tuple[str, str] | None:
    """``(org id, volume id)`` from a volume's service labels; ``None`` if either is missing."""
    org_id, volume_id = labels.get(ORG_ID_LABEL), labels.get(VOLUME_ID_LABEL)
    if not org_id or not volume_id:
        return None
    return org_id, volume_id
