"""Docker ``VolumeTransferDriver``: export, restore and clear of a named volume.

Nothing here reads or writes the volume's files itself. Export and restore use the daemon's own
archive endpoints (``get_archive`` and ``put_archive``, what ``docker cp`` calls) against a
helper container that is created and never started (``volume_helper``), so no process runs next
to the data and the daemon does the extraction and keeps modes, owners and times from the tar.

* Export streams ``get_archive`` of the whole volume through an incremental gzip, one chunk at a
  time (``archive.CHUNK_BYTES``); nothing is held whole. A volume that nothing mounts exports
  like any other; one a sandbox writes to is read live (no point in time snapshot).
* Restore first sweeps the orphan helpers of an interrupted transfer of the volume
  (``volume_helper.remove_orphan_helpers``), empties the volume (``clear_volume``), then streams
  the uploaded tar to ``put_archive`` through the archive policy (``tar_policy.checked_tar``):
  the daemon only ever sees a tar rebuilt from approved members. The policy runs in the worker
  thread that feeds the request body, so a refusal aborts the upload at that member. What the
  daemon had extracted by then stays in the volume until the caller clears it, as the protocol
  says.
* Clear first removes the orphan helpers of an interrupted transfer of the volume (a killed
  restore or export leaves one that makes the daemon refuse the removal), then removes the
  volume and creates it again with the same name, driver, options and labels
  (``volumes.recreate_volume``): the volume is empty by construction and no code runs. It is
  refused with ``DriverConflict`` while a container still references the volume (a live
  transfer of this process included), with nothing changed.
"""

import asyncio
import concurrent.futures
import logging
import threading
import zlib
from collections.abc import AsyncIterator, Iterable, Iterator
from typing import Any

import anyio

from sandfort.drivers.docker import archive, volume_helper, volumes
from sandfort.drivers.docker.client import translate_errors
from sandfort.drivers.docker.lanes import run_bulk
from sandfort.drivers.docker.tar_policy import checked_tar
from sandfort.drivers.errors import DriverError

logger = logging.getLogger(__name__)

GZIP_WBITS = 16 + zlib.MAX_WBITS
UPLOAD_PIECE_BYTES = 256 * 1024  # small tar pieces are joined up to this size before they go out
EXPORT_PATH = f"{volume_helper.HELPER_MOUNT}/."  # the contents, not the mount directory itself


class UploadAborted(DriverError):
    """The restore was cancelled while its upload was waiting for the next piece of the tar."""


class AbortableSource:
    """The restore's async tar source as a blocking iterator for the upload thread, that can be
    aborted from the event loop.

    A cancelled restore must stop the daemon's extraction, or the helper container could not be
    removed until the upload ended. ``abort`` cancels the read the thread is waiting on (and
    every later read), which ends the request body with ``UploadAborted``.
    """

    def __init__(self, data: AsyncIterator[bytes], loop: asyncio.AbstractEventLoop) -> None:
        self._data = data
        self._loop = loop
        self._lock = threading.Lock()
        self._aborted = False
        self._released = threading.Event()  # set by ``abort``; ends a fault-injection hold
        self._pending: concurrent.futures.Future[bytes | None] | None = None

    def __iter__(self) -> Iterator[bytes]:
        return self

    def __next__(self) -> bytes:
        while True:
            chunk = self._read()
            if chunk is None:
                raise StopIteration
            if chunk:  # an empty chunk would end a chunked request body early
                return chunk

    def _read(self) -> bytes | None:
        with self._lock:
            if self._aborted:
                raise UploadAborted("the restore was cancelled")
            self._pending = asyncio.run_coroutine_threadsafe(self._next_chunk(), self._loop)
            pending = self._pending
        try:
            return pending.result()
        except concurrent.futures.CancelledError as exc:
            raise UploadAborted("the restore was cancelled") from exc

    async def _next_chunk(self) -> bytes | None:
        return await anext(self._data, None)

    def abort(self) -> None:
        """Cancel the read in flight and refuse every later one; callable from any thread."""
        with self._lock:
            self._aborted = True
            pending = self._pending
        self._released.set()
        if pending is not None:
            pending.cancel()

    def hold(self, ref: str) -> None:
        """Block the upload thread until ``abort`` (fault injection ``restore_extract_hold``).

        Called after the first piece of the tar went to the daemon, so the daemon has begun
        extracting; the request body is not finished. Raises ``UploadAborted`` once released.
        """
        logger.warning("fault injection: restore of %s held after its first upload piece", ref)
        self._released.wait()
        raise UploadAborted("the restore was cancelled")


def _coalesced(pieces: Iterable[bytes], size: int) -> Iterator[bytes]:
    """``pieces`` joined into chunks of about ``size`` bytes (a header is 512 bytes)."""
    pending: list[bytes] = []
    held = 0
    for piece in pieces:
        pending.append(piece)
        held += len(piece)
        if held >= size:
            yield b"".join(pending)
            pending, held = [], 0
    if pending:
        yield b"".join(pending)


async def export_volume(client: Any, image: str, ref: str) -> AsyncIterator[bytes]:
    """The volume's files as a gzipped tar. A missing volume raises ``DriverNotFound`` before
    the first byte; the helper is removed when the stream ends or is closed."""
    async with volume_helper.helper_container(client, image, ref, writable=False) as container:
        _, chunks = await archive.get_archive_with_stat(client, container, EXPORT_PATH)
        compressor = zlib.compressobj(wbits=GZIP_WBITS)
        try:
            async for chunk in chunks:
                piece = await run_bulk(compressor.compress, chunk)
                if piece:
                    yield piece
            yield await run_bulk(compressor.flush)
        finally:
            with anyio.CancelScope(shield=True):
                close = getattr(chunks, "aclose", None)
                if close is not None:
                    await close()


def _put_checked(
    client: Any, container: str, ref: str, source: AbortableSource, hold: bool = False
) -> None:
    """Blocking: upload the policy-checked tar from ``source`` into the helper's mount.

    The policy runs inside the request body generator. Whatever it raises (or the source did)
    is what the caller gets, not what the HTTP layer made of the aborted request.
    """
    failures: list[Exception] = []

    def body() -> Iterator[bytes]:
        try:
            for index, piece in enumerate(_coalesced(checked_tar(source), UPLOAD_PIECE_BYTES)):
                yield piece
                if hold and index == 0:  # resumed: the first piece was handed to the daemon
                    source.hold(ref)
        except Exception as exc:
            failures.append(exc)
            raise

    try:
        with translate_errors(ref, "volume.restore"):
            accepted = client.api.put_archive(container, volume_helper.HELPER_MOUNT, body())
    except Exception:
        if failures:
            raise failures[0] from None
        raise
    if not accepted:
        raise DriverError("docker refused the archive for the volume", ref=ref)


async def restore_volume(
    client: Any, image: str, ref: str, tar: AsyncIterator[bytes], *, hold: bool = False
) -> None:
    """Empty the volume, then extract ``tar`` into it; see the module docstring.

    ``hold`` (fault injection ``restore_extract_hold``) stalls the upload after its first piece
    until the restore is cancelled; it is off unless the operator sets the flag."""
    await volume_helper.remove_orphan_helpers(client, ref)
    await volumes.recreate_volume(client, ref)
    async with volume_helper.helper_container(client, image, ref, writable=True) as container:
        source = AbortableSource(tar, asyncio.get_running_loop())
        try:
            await run_bulk(_put_checked, client, container, ref, source, hold)
        except BaseException:
            source.abort()  # a still running upload must end before the helper can be removed
            raise


async def clear_volume(client: Any, ref: str) -> None:
    """Empty the volume by removing it and creating it again, after sweeping orphan helpers."""
    await volume_helper.remove_orphan_helpers(client, ref)
    await volumes.recreate_volume(client, ref)
