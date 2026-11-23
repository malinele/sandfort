"""Start-up recovery of restores that never finished.

A restore sets ``volumes.restoring_since`` after the first decompressed chunk and before the
driver extracts, and clears it when the restore ended with the volume complete or empty. A
SIGKILL runs none of the in-request cleanup, so a marker found at server start is a restore
that died: the daemon had extracted part of the archive and the volume may hold it.

``recover_interrupted_restores`` empties each such volume through the driver, clears the marker
and writes an audit row in one unit of work (``volume.restore``, outcome ``error``, actor
``system``, ``details.reason`` ``recovered_after_crash``, ``details.volume_emptied``). A driver
failure leaves the marker set, so the next start tries again; a provider volume that no longer
exists has nothing to empty and its marker is cleared.

The marker names no process: a server that starts while another process is mid-restore on the
same volume empties that volume under it. Run one API process per volume host.

Driver calls never run inside an open transaction: the scan, the driver call and the final
write are separate units of work.
"""

import logging

import anyio

from sandfort.config import FAULT_VOLUME_RECOVERY_CLEAR_FAIL
from sandfort.domain.volume import Volume
from sandfort.drivers.base import VolumeTransferDriver
from sandfort.drivers.errors import DriverError, DriverNotFound
from sandfort.services.volumes import VolumeService

logger = logging.getLogger(__name__)

RECOVERY_REASON = "recovered_after_crash"


async def recover_interrupted_restores(
    volumes: VolumeService, driver: object, faults: tuple[str, ...] = ()
) -> int:
    """Empty every volume with a dangling restore marker; the number of markers cleared.

    A driver that cannot restore volumes has no markers to recover. With the fault flag
    ``volume_recovery_clear_fail`` in ``faults`` every emptying fails as a ``DriverError``
    without the driver being called: the markers stay and nothing is emptied.
    """
    if not isinstance(driver, VolumeTransferDriver):
        return 0
    transfer = driver
    cleared = 0
    for volume in await volumes.restoring_volumes():
        if await _recover_one(volumes, transfer, volume, faults):
            cleared += 1
    return cleared


async def _recover_one(
    volumes: VolumeService, transfer: VolumeTransferDriver, volume: Volume, faults: tuple[str, ...]
) -> bool:
    emptied = True
    try:
        if FAULT_VOLUME_RECOVERY_CLEAR_FAIL in faults:  # instead of the driver call
            raise DriverError(f"injected fault: {FAULT_VOLUME_RECOVERY_CLEAR_FAIL}")
        await transfer.clear_volume(volume.provider_volume_name)
    except DriverNotFound:
        emptied = False  # the provider volume is gone: nothing can be left in it
        logger.warning("volume %s has a restore marker but no provider volume", volume.id)
    except DriverError as exc:
        logger.error(
            "could not empty volume %s after an interrupted restore, the marker stays: %s",
            volume.id,
            exc,
        )
        return False
    details = {
        "name": volume.name,
        "reason": RECOVERY_REASON,
        "volume_emptied": emptied,
        "restoring_since": None
        if volume.restoring_since is None
        else volume.restoring_since.isoformat(),
    }
    if not await volumes.finish_recovery(volume, details):
        return False  # a newer restore re-marked the volume: its marker stays
    logger.warning(
        "volume %s: a restore that began at %s never finished; the volume was emptied",
        volume.id,
        details["restoring_since"],
    )
    return True


async def mark_restoring(volumes: VolumeService, volume: Volume) -> None:
    """Commit the restore marker on ``volume``; when that fails, no marker is left behind."""
    try:
        await volumes.mark_restoring(volume)
    except BaseException:
        with anyio.CancelScope(shield=True):  # nothing was extracted: leave no marker
            await unmark_restoring(volumes, volume)
        raise


async def unmark_restoring(volumes: VolumeService, volume: Volume) -> None:
    """Clear the restore marker; a failure is logged and leaves it for the next start.

    Accepted trade-off: when the mark commit succeeded but this clear then fails (the failure
    path of ``mark_restoring``), the next start empties a volume that was never touched. That
    is acceptable because the request was about to replace the contents anyway.
    """
    try:
        await volumes.clear_restoring(volume)
    except Exception:  # the marker stays: the next start empties the volume again
        logger.exception("could not clear the restore marker of volume %s", volume.id)


async def abandon_restore(
    volumes: VolumeService, transfer: VolumeTransferDriver, volume: Volume
) -> bool:
    """Empty the volume after a failed restore and clear its marker; whether it was emptied.

    A volume that could not be emptied keeps its marker, so the next start empties it.
    """
    try:
        await transfer.clear_volume(volume.provider_volume_name)
    except DriverError as exc:
        logger.error("could not empty volume %s after a failed restore: %s", volume.id, exc)
        return False
    await unmark_restoring(volumes, volume)
    return True
