"""Filesystem toolbox facade (``sandbox.fs``): list, stat, mkdir, move, delete and transfers.

Uploads stream the body in bounded chunks with an exact ``Content-Length`` (the server needs
the size up front for the tar header), so a file object is never read whole into memory.
Downloads hand back a closeable iterator of byte chunks; directories arrive as a tar stream.
"""

import asyncio
import io
from collections.abc import AsyncIterator, Iterator
from typing import Any, BinaryIO

import httpx

from sandfort_sdk._requests import area_path
from sandfort_sdk._transport import AsyncByteStream, AsyncTransport, ByteStream, SyncTransport
from sandfort_sdk.exceptions import InvalidResponseError, PayloadTooLarge
from sandfort_sdk.models import (
    DeleteResult,
    DirListing,
    FileEntry,
    MkdirResult,
    MoveResult,
    UploadResult,
)

UPLOAD_CHUNK_BYTES = 64 * 1024
DOWNLOAD_CHUNK_BYTES = 64 * 1024
TAR_MEDIA_TYPE = "application/x-tar"
_OCTET_STREAM = "application/octet-stream"

UploadSource = bytes | bytearray | BinaryIO

MIB = 1024 * 1024
UPLOAD_LIMIT_BYTES = 256 * MIB  # the server's per-upload cap
PARTIAL_CONTENT = 206
# ``(start, end)``: the bytes ``start`` to ``end`` inclusive; ``end`` None reads to the end.
ByteRange = tuple[int, int | None]


def upload_limit_message(limit: int, size: int) -> str:
    """The text of the upload-limit refusal, the same locally and from the server."""
    shown = f"{limit // MIB} MiB ({limit} bytes)" if limit % MIB == 0 else f"{limit} bytes"
    return f"upload limit is {shown}; this upload is {size} bytes"


def check_upload_size(size: int) -> None:
    """Refuse an upload above the limit before any request is sent (413 PAYLOAD_TOO_LARGE)."""
    if size > UPLOAD_LIMIT_BYTES:
        raise PayloadTooLarge(
            upload_limit_message(UPLOAD_LIMIT_BYTES, size),
            status_code=413,
            details={"limit_bytes": UPLOAD_LIMIT_BYTES, "size_bytes": size},
        )


def range_headers(window: ByteRange | None) -> dict[str, str] | None:
    """The ``Range`` header of a byte window, None for the whole file."""
    if window is None:
        return None
    start, end = window
    if isinstance(start, bool) or not isinstance(start, int) or start < 0:
        raise ValueError("range start must be an integer >= 0")
    if end is not None and (isinstance(end, bool) or not isinstance(end, int) or end < start):
        raise ValueError("range end must be None or an integer >= start")
    return {"Range": f"bytes={start}-{'' if end is None else end}"}


def _fs_path(sandbox_id: str, tail: str) -> str:
    return area_path(sandbox_id, "fs", f"/{tail}")


def _source_size(source: BinaryIO, size_bytes: int | None) -> int:
    """Bytes left in ``source``: the explicit ``size_bytes``, else measured by seeking."""
    if size_bytes is not None:
        if size_bytes < 0:
            raise ValueError("size_bytes must be >= 0")
        return size_bytes
    if not source.seekable():
        raise ValueError("size_bytes is required for a non-seekable file object")
    start = source.tell()
    end = source.seek(0, io.SEEK_END)
    source.seek(start)
    return max(end - start, 0)


def iter_file_chunks(source: BinaryIO, size: int, chunk_size: int) -> Iterator[bytes]:
    """Yield exactly ``size`` bytes from ``source``, never more than ``chunk_size`` at a time."""
    remaining = size
    while remaining > 0:
        chunk = source.read(min(chunk_size, remaining))
        if not chunk:
            raise ValueError(f"file object ended {remaining} bytes before the declared size")
        remaining -= len(chunk)
        yield chunk


async def aiter_file_chunks(source: BinaryIO, size: int, chunk_size: int) -> AsyncIterator[bytes]:
    """Async :func:`iter_file_chunks`; blocking reads run in a worker thread."""
    remaining = size
    while remaining > 0:
        chunk = await asyncio.to_thread(source.read, min(chunk_size, remaining))
        if not chunk:
            raise ValueError(f"file object ended {remaining} bytes before the declared size")
        remaining -= len(chunk)
        yield chunk


def _upload_request(
    path: str, size: int, *, overwrite: bool, mode: str
) -> tuple[dict[str, Any], dict[str, str]]:
    params: dict[str, Any] = {
        "path": path,
        "overwrite": overwrite,
        "mode": mode,
        "size_bytes": size,
    }
    headers = {"Content-Length": str(size), "Content-Type": _OCTET_STREAM}
    return params, headers


def _check_chunk_size(chunk_size: int) -> None:
    if chunk_size < 1:
        raise ValueError("chunk_size must be >= 1")


def _checked_download(
    response: httpx.Response, path: str, *, want_tar: bool, ranged: bool = False
) -> None:
    """Fail early when the path kind does not match the call or a range was ignored.

    The caller releases the response on failure. The path kind is checked first, so a ranged
    request for a directory (a tar the server never ranges) reports the kind mismatch. A ranged
    request for a file answered 200 would hand back the whole file where a resume expects the
    tail, so it is refused.
    """
    media_type = response.headers.get("content-type", "").split(";")[0].strip().lower()
    if (media_type == TAR_MEDIA_TYPE) != want_tar:
        expected = "a directory (use download_file)" if want_tar else "a file (use download_dir)"
        raise InvalidResponseError(f"{path!r} is not {expected}: server sent {media_type!r}")
    if ranged and response.status_code != PARTIAL_CONTENT:
        raise InvalidResponseError(
            f"{path!r}: the server ignored the range request (status {response.status_code})"
        )


def _entry(data: Any) -> Any:
    """``/stat`` wraps the entry as ``{"entry": {...}}``."""
    if isinstance(data, dict) and "entry" in data:
        return data["entry"]
    raise InvalidResponseError("stat payload is missing 'entry'")


class Fs:
    """Synchronous filesystem toolbox of one sandbox."""

    def __init__(self, sandbox_id: str, transport: SyncTransport) -> None:
        self._sandbox_id = sandbox_id
        self._transport = transport

    def list_dir(self, path: str = "/") -> DirListing:
        reply = self._transport.request("GET", self._path("list"), params={"path": path})
        return DirListing.from_payload(reply.data)

    def stat(self, path: str) -> FileEntry:
        reply = self._transport.request("GET", self._path("stat"), params={"path": path})
        return FileEntry.from_payload(_entry(reply.data))

    def mkdir(self, path: str, *, mode: str = "755", parents: bool = True) -> MkdirResult:
        body = {"path": path, "mode": mode, "parents": parents}
        reply = self._transport.request("POST", self._path("mkdir"), json=body)
        return MkdirResult.from_payload(reply.data)

    def move(self, source: str, destination: str, *, overwrite: bool = False) -> MoveResult:
        body = {"source": source, "destination": destination, "overwrite": overwrite}
        reply = self._transport.request("POST", self._path("move"), json=body)
        return MoveResult.from_payload(reply.data)

    def delete(self, path: str, *, recursive: bool = False) -> DeleteResult:
        body = {"path": path, "recursive": recursive}
        reply = self._transport.request("POST", self._path("delete"), json=body)
        return DeleteResult.from_payload(reply.data)

    def upload_file(
        self,
        path: str,
        data: UploadSource,
        *,
        size_bytes: int | None = None,
        overwrite: bool = True,
        mode: str = "644",
        chunk_size: int = UPLOAD_CHUNK_BYTES,
    ) -> UploadResult:
        """Upload ``data``: bytes, or a binary file object read in ``chunk_size`` pieces.

        A file object is sent from its current position; ``size_bytes`` is required when it
        is not seekable, and exactly that many bytes are sent.
        """
        _check_chunk_size(chunk_size)
        content: bytes | Iterator[bytes]
        if isinstance(data, bytes | bytearray):
            content = bytes(data)
            size = len(content)
        else:
            size = _source_size(data, size_bytes)
            content = iter_file_chunks(data, size, chunk_size)
        check_upload_size(size)
        params, headers = _upload_request(path, size, overwrite=overwrite, mode=mode)
        reply = self._transport.request(
            "PUT", self._path("upload"), params=params, content=content, headers=headers
        )
        return UploadResult.from_payload(reply.data)

    def download_file(
        self,
        path: str,
        *,
        range: ByteRange | None = None,  # noqa: A002 - the HTTP name of the option
        chunk_size: int = DOWNLOAD_CHUNK_BYTES,
    ) -> ByteStream:
        """Stream a file's bytes; close the iterator (or use ``with``) when stopping early.

        ``range=(start, end)`` streams only those bytes (``end`` inclusive, None for "to the
        end"), for example to resume a download. A start at or past the end of the file, and any
        range on an empty file, raises an ``ApiError`` with status 416; a server that ignores
        the range raises ``InvalidResponseError``.
        """
        return self._download(path, chunk_size, want_tar=False, window=range)

    def read_bytes(
        self,
        path: str,
        *,
        range: ByteRange | None = None,  # noqa: A002
    ) -> bytes:
        """Download a file (or a byte range of it) into memory (convenience for small files)."""
        return self.download_file(path, range=range).read_bytes()

    def download_dir(self, path: str, *, chunk_size: int = DOWNLOAD_CHUNK_BYTES) -> ByteStream:
        """Stream a directory as an uncompressed tar archive."""
        return self._download(path, chunk_size, want_tar=True)

    def _download(
        self, path: str, chunk_size: int, *, want_tar: bool, window: ByteRange | None = None
    ) -> ByteStream:
        _check_chunk_size(chunk_size)
        headers = range_headers(window)
        response = self._transport.open_stream(
            "GET", self._path("download"), params={"path": path}, headers=headers
        )
        try:
            _checked_download(response, path, want_tar=want_tar, ranged=headers is not None)
        except InvalidResponseError:
            response.close()
            raise
        return ByteStream(response, chunk_size)

    def _path(self, tail: str) -> str:
        return _fs_path(self._sandbox_id, tail)


class AsyncFs:
    """Asynchronous filesystem toolbox of one sandbox."""

    def __init__(self, sandbox_id: str, transport: AsyncTransport) -> None:
        self._sandbox_id = sandbox_id
        self._transport = transport

    async def list_dir(self, path: str = "/") -> DirListing:
        reply = await self._transport.request("GET", self._path("list"), params={"path": path})
        return DirListing.from_payload(reply.data)

    async def stat(self, path: str) -> FileEntry:
        reply = await self._transport.request("GET", self._path("stat"), params={"path": path})
        return FileEntry.from_payload(_entry(reply.data))

    async def mkdir(self, path: str, *, mode: str = "755", parents: bool = True) -> MkdirResult:
        body = {"path": path, "mode": mode, "parents": parents}
        reply = await self._transport.request("POST", self._path("mkdir"), json=body)
        return MkdirResult.from_payload(reply.data)

    async def move(self, source: str, destination: str, *, overwrite: bool = False) -> MoveResult:
        body = {"source": source, "destination": destination, "overwrite": overwrite}
        reply = await self._transport.request("POST", self._path("move"), json=body)
        return MoveResult.from_payload(reply.data)

    async def delete(self, path: str, *, recursive: bool = False) -> DeleteResult:
        body = {"path": path, "recursive": recursive}
        reply = await self._transport.request("POST", self._path("delete"), json=body)
        return DeleteResult.from_payload(reply.data)

    async def upload_file(
        self,
        path: str,
        data: UploadSource,
        *,
        size_bytes: int | None = None,
        overwrite: bool = True,
        mode: str = "644",
        chunk_size: int = UPLOAD_CHUNK_BYTES,
    ) -> UploadResult:
        _check_chunk_size(chunk_size)
        content: bytes | AsyncIterator[bytes]
        if isinstance(data, bytes | bytearray):
            content = bytes(data)
            size = len(content)
        else:
            size = _source_size(data, size_bytes)
            content = aiter_file_chunks(data, size, chunk_size)
        check_upload_size(size)
        params, headers = _upload_request(path, size, overwrite=overwrite, mode=mode)
        reply = await self._transport.request(
            "PUT", self._path("upload"), params=params, content=content, headers=headers
        )
        return UploadResult.from_payload(reply.data)

    async def download_file(
        self,
        path: str,
        *,
        range: ByteRange | None = None,  # noqa: A002 - the HTTP name of the option
        chunk_size: int = DOWNLOAD_CHUNK_BYTES,
    ) -> AsyncByteStream:
        """As :meth:`Fs.download_file`, including ``range=(start, end)``."""
        return await self._download(path, chunk_size, want_tar=False, window=range)

    async def read_bytes(
        self,
        path: str,
        *,
        range: ByteRange | None = None,  # noqa: A002
    ) -> bytes:
        return await (await self.download_file(path, range=range)).read_bytes()

    async def download_dir(
        self, path: str, *, chunk_size: int = DOWNLOAD_CHUNK_BYTES
    ) -> AsyncByteStream:
        return await self._download(path, chunk_size, want_tar=True)

    async def _download(
        self, path: str, chunk_size: int, *, want_tar: bool, window: ByteRange | None = None
    ) -> AsyncByteStream:
        _check_chunk_size(chunk_size)
        headers = range_headers(window)
        response = await self._transport.open_stream(
            "GET", self._path("download"), params={"path": path}, headers=headers
        )
        try:
            _checked_download(response, path, want_tar=want_tar, ranged=headers is not None)
        except InvalidResponseError:
            await response.aclose()
            raise
        return AsyncByteStream(response, chunk_size)

    def _path(self, tail: str) -> str:
        return _fs_path(self._sandbox_id, tail)
