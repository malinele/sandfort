"""A small reserve file inside the disk quota, released before every stop.

Docker needs a little free space in a container's quota to mount its layer. A sandbox whose disk
is full then cannot restart (``mkdir .../merged: no space left on device``), nor be snapshotted,
and nothing can be written into a stopped container without that mount. So a running quota
container holds ``RESERVE_FILE_BYTES`` of zeros at ``RESERVE_PATH``; ``release_reserve`` swaps it
for an empty file just before the stop, which frees the blocks for the mount. The quota is
``QUOTA_HEADROOM_BYTES`` above the user's ``disk_gib`` (see ``hardening``), so the reserve never
eats into the disk the user asked for. The file is visible in the sandbox: deleting it only
loses the protection until the next start recreates it.

Both helpers act only on containers whose HostConfig has a ``StorageOpt`` ``size`` and never
raise: a failed put only logs a warning.
"""

import asyncio
import io
import logging
import posixpath
import tarfile
from typing import Any

from sandfort.drivers.docker.client import run_blocking

RESERVE_PATH = "/.sandfort-reserve"
RESERVE_FILE_BYTES = 16 * 1024 * 1024
QUOTA_HEADROOM_BYTES = 32 * 1024 * 1024
RESERVE_FILE_MODE = 0o600
TRUNCATE_USER = "0"
TRUNCATE_ARGV = ("sh", "-c", ": > " + RESERVE_PATH)
TRUNCATE_TIMEOUT_S = 10.0

logger = logging.getLogger(__name__)


def _reserve_archive(size: int) -> bytes:
    """A tar with the reserve file as its only member: ``size`` zero bytes (0 = empty file)."""
    buffer = io.BytesIO()
    member = tarfile.TarInfo(posixpath.basename(RESERVE_PATH))
    member.size = size
    member.mode = RESERVE_FILE_MODE
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        tar.addfile(member, io.BytesIO(bytes(size)))
    return buffer.getvalue()


async def _quota_enforced(client: Any, ref: str) -> bool:
    attrs = await run_blocking(client.api.inspect_container, ref)
    storage_opt = (attrs.get("HostConfig") or {}).get("StorageOpt") or {}
    return bool(storage_opt.get("size"))


async def _put_reserve(client: Any, ref: str, size: int, action: str) -> None:
    try:
        if not await _quota_enforced(client, ref):
            return
        archive = _reserve_archive(size)
        parent = posixpath.dirname(RESERVE_PATH)
        if not await run_blocking(client.api.put_archive, ref, parent, archive):
            logger.warning("docker refused to %s the disk reserve of %s", action, ref)
    except Exception:
        logger.warning("could not %s the disk reserve of %s", action, ref, exc_info=True)


async def fill_reserve(client: Any, ref: str) -> None:
    """Put the zero-filled reserve file into the running container ``ref``; never raises."""
    await _put_reserve(client, ref, RESERVE_FILE_BYTES, "fill")


def _truncate_blocking(client: Any, ref: str) -> bool:
    """Truncate the reserve in place as root; True only when the command exited 0."""
    created = client.api.exec_create(ref, cmd=list(TRUNCATE_ARGV), user=TRUNCATE_USER)
    exec_id = created["Id"]
    client.api.exec_start(exec_id)
    return bool(client.api.exec_inspect(exec_id).get("ExitCode") == 0)


async def _truncate_reserve(client: Any, ref: str) -> bool:
    """Empty the reserve file without needing a free block; False on any failure."""
    try:
        async with asyncio.timeout(TRUNCATE_TIMEOUT_S):
            return await run_blocking(_truncate_blocking, client, ref)
    except Exception:
        logger.debug("in-place truncate of the disk reserve of %s failed", ref, exc_info=True)
        return False


async def release_reserve(client: Any, ref: str) -> None:
    """Empty the reserve so its blocks are free; never raises.

    First truncates the file in place (a full disk has no room to extract an archive), and only
    when that fails falls back to replacing it through the archive API.
    """
    try:
        if not await _quota_enforced(client, ref):
            return
        if await _truncate_reserve(client, ref):
            return
    except Exception:
        logger.warning("could not release the disk reserve of %s", ref, exc_info=True)
        return
    await _put_reserve(client, ref, 0, "release")
