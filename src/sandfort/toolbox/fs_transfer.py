"""Streaming tar helpers for fs upload and download.

Upload wraps the incoming byte stream into a one-entry tar on the fly: the header is
built from the declared size, the body is forwarded in bounded chunks while bytes are
counted against the declared size and the cap, then padding and the tar trailer follow.
Download pulls the single regular file out of a tar stream without ever writing archive
contents to the host filesystem. No function here holds a whole payload.
"""

import tarfile
from collections.abc import AsyncIterator, Iterator, Mapping
from typing import Any, Literal

from sandfort.drivers.errors import DriverError
from sandfort.errors import Unprocessable
from sandfort.toolbox.fs_range import upload_limit_error

CHUNK_BYTES = 1024 * 1024  # upper bound for any chunk produced by this module
BLOCK_BYTES = 512
TRAILER_BYTES = 2 * BLOCK_BYTES
MAX_PAX_HEADER_BYTES = 64 * 1024

# Docker reports the Go ``os.FileMode``: type flags live in the high bits.
GO_MODE_DIR = 1 << 31
GO_MODE_SYMLINK = 1 << 27

_META_TYPES = frozenset(
    {
        tarfile.XHDTYPE,
        tarfile.XGLTYPE,
        tarfile.GNUTYPE_LONGNAME,
        tarfile.GNUTYPE_LONGLINK,
    }
)


def _bounded(chunk: bytes) -> Iterator[bytes]:
    for start in range(0, len(chunk), CHUNK_BYTES):
        yield chunk[start : start + CHUNK_BYTES]


def _padding(size: int) -> int:
    return -size % BLOCK_BYTES


def archive_kind(stat: Mapping[str, Any]) -> Literal["file", "dir", "symlink"]:
    mode = int(stat.get("mode", 0))
    if mode & GO_MODE_DIR:
        return "dir"
    if mode & GO_MODE_SYMLINK:
        return "symlink"
    return "file"


async def close_stream(stream: AsyncIterator[bytes]) -> None:
    """Close an async generator-backed stream if it can be closed."""
    aclose = getattr(stream, "aclose", None)
    if aclose is not None:
        await aclose()


# -- upload ------------------------------------------------------------------------


def _header(name: str, size: int, mode: int, mtime: int) -> bytes:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = mode
    info.mtime = mtime
    info.type = tarfile.REGTYPE
    return info.tobuf(tarfile.GNU_FORMAT, "utf-8", "surrogateescape")


async def tar_upload_stream(
    source: AsyncIterator[bytes],
    *,
    name: str,
    size: int,
    mode: int,
    mtime: int,
    max_bytes: int,
) -> AsyncIterator[bytes]:
    """Yield a tar holding one file ``name`` whose body is ``source`` (exactly ``size`` bytes).

    Raises ``PayloadTooLarge`` as soon as the cap is crossed and ``Unprocessable`` when
    the stream length differs from the declared ``size``; nothing is buffered.
    """
    if size > max_bytes:
        raise upload_limit_error(max_bytes, size)
    yield _header(name, size, mode, mtime)
    received = 0
    async for chunk in source:
        for piece in _bounded(chunk):
            received += len(piece)
            if received > max_bytes:
                raise upload_limit_error(max_bytes, received, at_least=True)
            if received > size:
                raise Unprocessable("request body is longer than the declared size")
            yield piece
    if received != size:
        raise Unprocessable(f"request body has {received} bytes, declared {size}")
    yield bytes(_padding(size) + TRAILER_BYTES)


# -- download ----------------------------------------------------------------------


class _ChunkReader:
    """Lazy exact-length reads over an async chunk stream (one source chunk buffered)."""

    def __init__(self, source: AsyncIterator[bytes]) -> None:
        self._source = source
        self._pending = b""

    async def _refill(self) -> bool:
        while True:
            chunk = await anext(self._source, None)
            if chunk is None:
                return False
            if chunk:
                self._pending = chunk
                return True

    async def take(self, count: int) -> AsyncIterator[bytes]:
        """Yield exactly ``count`` bytes in pieces; a short stream is a driver error."""
        remaining = count
        while remaining:
            if not self._pending and not await self._refill():
                raise DriverError("archive stream ended inside an entry")
            piece = self._pending[:remaining]
            self._pending = self._pending[len(piece) :]
            remaining -= len(piece)
            yield piece

    async def read_exact(self, count: int) -> bytes:
        return b"".join([piece async for piece in self.take(count)])

    async def skip(self, count: int) -> None:
        async for _ in self.take(count):
            pass


def _pax_size(data: bytes) -> int | None:
    for record in data.split(b"\n"):
        _, _, pair = record.partition(b" ")
        key, _, value = pair.partition(b"=")
        if key == b"size" and value.isdigit():
            return int(value)
    return None


async def _next_file_size(reader: _ChunkReader) -> int:
    """Consume headers up to the first regular file and return its size."""
    size_override: int | None = None
    while True:
        block = await reader.read_exact(BLOCK_BYTES)
        try:
            info = tarfile.TarInfo.frombuf(block, "utf-8", "surrogateescape")
        except tarfile.TarError as exc:
            raise DriverError(f"invalid tar header: {exc}") from exc
        if info.type in _META_TYPES:
            if info.type == tarfile.XHDTYPE and info.size <= MAX_PAX_HEADER_BYTES:
                size_override = _pax_size(await reader.read_exact(info.size))
                await reader.skip(_padding(info.size))
            else:
                await reader.skip(info.size + _padding(info.size))
            continue
        if not info.isreg():
            raise DriverError("archive entry is not a regular file")
        return info.size if size_override is None else size_override


async def extract_file(chunks: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    """Yield exactly the bytes of the (single) regular file inside the tar ``chunks``."""
    reader = _ChunkReader(chunks)
    try:
        size = await _next_file_size(reader)
        async for piece in reader.take(size):
            yield piece
    finally:
        await close_stream(chunks)


async def read_limited(stream: AsyncIterator[bytes], limit: int) -> tuple[bytes, bool]:
    """Read at most ``limit`` bytes; the flag says whether more data was left behind."""
    collected = bytearray()
    truncated = False
    async for piece in stream:
        room = limit - len(collected)
        collected.extend(piece[:room])
        if len(piece) > room:
            truncated = True
            break
    await close_stream(stream)
    return bytes(collected), truncated
