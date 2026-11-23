"""Docker implementation of ``ArchiveStreamDriver``: tar streams in and out of a container.

Nothing here ever holds a whole payload: uploads are pulled chunk by chunk from the async
source by the worker thread that performs the HTTP request, downloads are read from the
response in ``CHUNK_BYTES`` pieces. The upload (one thread for its whole duration) and each
download chunk read go through ``run_bulk`` (bulk lane); opening and closing a download stay
on ``run_blocking`` (control lane).
"""

from collections.abc import AsyncIterator, Iterator, Mapping
from typing import Any

import anyio
import anyio.from_thread

from sandfort.drivers.docker.client import DriverReadOnlyPath, run_blocking, translate_errors
from sandfort.drivers.docker.lanes import run_bulk
from sandfort.drivers.errors import DriverError

CHUNK_BYTES = 1024 * 1024  # upper bound for any single chunk in either direction


def _bounded(chunk: bytes) -> Iterator[bytes]:
    for start in range(0, len(chunk), CHUNK_BYTES):
        yield chunk[start : start + CHUNK_BYTES]


class _BlockingSource:
    """Sync iterator over an async byte stream, for use inside a worker thread only.

    The first failure of the async source is remembered so the caller can re-raise the
    real cause instead of whatever the HTTP layer made of the aborted request body.
    """

    def __init__(self, data: AsyncIterator[bytes]) -> None:
        self._data = data
        self._pending: Iterator[bytes] = iter(())
        self.error: BaseException | None = None

    def __iter__(self) -> Iterator[bytes]:
        return self

    def __next__(self) -> bytes:
        while True:
            piece = next(self._pending, None)
            if piece:
                return piece
            if piece is not None:
                continue  # empty piece: an empty chunk would end a chunked body early
            chunk = self._pull()
            if chunk is None:
                raise StopIteration
            self._pending = _bounded(chunk)

    def _pull(self) -> bytes | None:
        try:
            return anyio.from_thread.run(self._next_chunk)
        except BaseException as exc:
            self.error = exc
            raise

    async def _next_chunk(self) -> bytes | None:
        return await anext(self._data, None)


BlockingSource = _BlockingSource  # for the volume transfer, which feeds its own upload body


def _put_blocking(client: Any, ref: str, dest_path: str, source: _BlockingSource) -> None:
    try:
        with translate_errors(ref, "archive.put"):
            accepted = client.api.put_archive(ref, dest_path, source)
    except DriverReadOnlyPath as exc:
        if source.error is not None:
            raise source.error from None
        raise DriverReadOnlyPath.for_path(dest_path, ref=ref) from exc
    except Exception:
        if source.error is not None:
            raise source.error from None
        raise
    if not accepted:
        raise DriverError(f"docker refused the archive for {dest_path}", ref=ref)


async def put_archive(client: Any, ref: str, dest_path: str, data: AsyncIterator[bytes]) -> None:
    """Stream the tar from ``data`` into the directory ``dest_path`` of the container."""
    source = _BlockingSource(data)
    await run_bulk(_put_blocking, client, ref, dest_path, source)


def _open_blocking(client: Any, ref: str, path: str) -> tuple[Iterator[bytes], Mapping[str, Any]]:
    with translate_errors(ref, "archive.get"):
        stream, stat = client.api.get_archive(ref, path, chunk_size=CHUNK_BYTES)
    if not stat:
        raise DriverError(f"docker returned no stat for {path}", ref=ref)
    return iter(stream), dict(stat)


def _next_blocking(ref: str, stream: Iterator[bytes]) -> bytes | None:
    with translate_errors(ref, "archive.read"):
        return next(stream, None)


def _close_blocking(stream: Iterator[bytes]) -> None:
    close = getattr(stream, "close", None)
    if close is not None:
        close()


async def _chunks(ref: str, stream: Iterator[bytes]) -> AsyncIterator[bytes]:
    try:
        while True:
            chunk = await run_bulk(_next_blocking, ref, stream)
            if chunk is None:
                return
            for piece in _bounded(chunk):
                yield piece
    finally:
        with anyio.CancelScope(shield=True):
            await run_blocking(_close_blocking, stream)


async def get_archive_with_stat(
    client: Any, ref: str, path: str
) -> tuple[Mapping[str, Any], AsyncIterator[bytes]]:
    """Return docker's stat mapping for ``path`` and its tar as a bounded chunk iterator."""
    stream, stat = await run_blocking(_open_blocking, client, ref, path)
    return stat, _chunks(ref, stream)
