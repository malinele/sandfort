"""Incremental filter over a tar byte stream: drops the platform members.

The platform members are the root-level disk reserve file and Docker's ``/.dockerenv`` marker:
``docker export`` materializes the marker even for a never-started container (partner finding
E-001), so an exported image would carry a file its source image does not have.

``drop_platform_members`` reads a tar from an iterator of byte chunks with ``tarfile`` in
stream mode (``r|``) and re-emits it member by member: the header of each kept member is
rebuilt from the parsed ``TarInfo`` in the archive's own format, and a regular file's content
is copied in ``COPY_CHUNK_BYTES`` pieces. Nothing but one header, one copy chunk and the unread
tail of the
current input chunk is held, however large a member is, and the ``TarFile`` member list is
emptied after every member, so memory does not grow with the number of files. Every input byte
is copied a bounded number of times (at most twice) on its way to ``tarfile``. The input must end
with an end-of-archive marker: a stream cut at a header boundary, inside a header or at garbage
raises ``tarfile.ReadError`` instead of ending quietly. The generator is lazy: it reads nothing
until the first ``next``, so it runs in the blocking worker that consumes it.

``rewrite_members`` is the general form: a ``transform`` decides per member which header is
written (or drops the member, or raises); ``tar_policy`` uses it for the volume restore policy.
"""

import posixpath
import tarfile
from collections.abc import Callable, Iterable, Iterator
from typing import Any, Self

# Defined in ``sandfort.drivers.docker.disk_reserve`` (``RESERVE_PATH``); imported from there.
from sandfort.drivers.docker.disk_reserve import RESERVE_PATH

RESERVE_MEMBER_NAME = posixpath.basename(RESERVE_PATH)
DOCKERENV_MEMBER_NAME = ".dockerenv"  # Docker writes it at container CREATION, not start
PLATFORM_MEMBER_NAMES = frozenset({RESERVE_MEMBER_NAME, DOCKERENV_MEMBER_NAME})
COPY_CHUNK_BYTES = 64 * 1024  # size of one member-content read and of one yielded piece
# ``tarfile`` reads a pax or GNU long-name header in ONE ``read`` of its declared size and holds
# it whole (400 MiB declared = 888 MiB of memory); no tool writes a header near this size.
MAX_EXTENDED_HEADER_BYTES = 1024 * 1024
_BLOCK = tarfile.BLOCKSIZE
_END_OF_ARCHIVE = tarfile.NUL * (2 * _BLOCK)
# tarfile raises this for a zero block; the stub lacks the name, the runtime has it.
_EOFHeaderError: type[Exception] = vars(tarfile)["EOFHeaderError"]


class _ChunkReader:
    """A ``read(n)`` file object over an iterator of byte chunks (all ``tarfile`` needs).

    The current chunk is kept whole with a read offset, so a read copies only the bytes it
    returns (plus one join when it spans chunks); ``copied_bytes`` counts those copies.
    """

    def __init__(self, chunks: Iterator[bytes]) -> None:
        self._chunks = chunks
        self._current = b""
        self._offset = 0
        self.copied_bytes = 0

    def _take(self, size: int) -> bytes:
        """Up to ``size`` bytes from the current chunk (``size < 0``: all of what is left)."""
        end = len(self._current) if size < 0 else min(len(self._current), self._offset + size)
        piece = self._current[self._offset : end]
        self._offset = end
        self.copied_bytes += len(piece)
        return piece

    def read(self, size: int = -1) -> bytes:
        parts: list[bytes] = []
        remaining = size
        while size < 0 or remaining > 0:
            if self._offset >= len(self._current):
                chunk = next(self._chunks, None)
                if chunk is None:
                    break
                self._current, self._offset = chunk, 0
                continue
            part = self._take(remaining)
            parts.append(part)
            remaining -= len(part)
        if len(parts) == 1:
            return parts[0]
        data = b"".join(parts)
        self.copied_bytes += len(data)
        return data

    def close(self) -> None:
        close = getattr(self._chunks, "close", None)
        if close is not None:
            close()


class HeaderTooLarge(tarfile.ReadError):
    """``tarfile`` asked for more bytes in one read than ``max_read`` allows (a huge header)."""


class _CappedStream:
    """The ``tarfile`` stream with every single ``read`` bounded by ``cap`` bytes.

    ``tarfile`` itself only ever reads more than a record (10 KiB) at once to load an extended
    header, in one call of its declared size, so bounding the read bounds that buffer however
    the header got its size (ustar, pax ``size``, GNU).
    """

    def __init__(self, stream: Any, cap: int) -> None:
        self._stream = stream
        self._cap = cap

    def read(self, size: int = -1) -> bytes:
        if size < 0 or size > self._cap:
            raise HeaderTooLarge(f"an archive header of {size} bytes is over the {self._cap} limit")
        data: bytes = self._stream.read(size)
        return data

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


class _EndSeeingInfo(tarfile.TarInfo):
    """A ``TarInfo`` that tells its ``TarFile`` when tarfile hit a genuine zero block."""

    @classmethod
    def fromtarfile(cls, tarfile: tarfile.TarFile) -> Self:
        try:
            return super().fromtarfile(tarfile)
        except _EOFHeaderError:
            if isinstance(tarfile, _EndSeeingTar):
                tarfile.saw_end = True
            raise


class _EndSeeingTar(tarfile.TarFile):
    """A ``TarFile`` that records whether the end-of-archive marker was seen."""

    saw_end = False

    def __init__(self, *args: Any, max_read: int | None = None, **kwargs: Any) -> None:
        """The stream (third argument of ``TarFile.open``'s call) is capped BEFORE the base
        class reads the first member from it."""
        if max_read is not None and len(args) > 2:
            args = (*args[:2], _CappedStream(args[2], max_read), *args[3:])
        super().__init__(*args, **kwargs)


def _root_name(name: str) -> str:
    """``name`` without any leading ``./`` and ``/`` prefixes (a root-level member's bare name)."""
    stripped = name
    while stripped.startswith(("./", "/")):
        stripped = stripped[1:] if stripped.startswith("/") else stripped[2:]
    return stripped


def is_reserve_member(name: str) -> bool:
    """True when ``name`` is the reserve file at the filesystem root (``./`` or ``/`` prefix)."""
    return _root_name(name) == RESERVE_MEMBER_NAME


def is_platform_member(name: str) -> bool:
    """True when ``name`` is a platform member at the root (reserve file or ``.dockerenv``)."""
    return _root_name(name) in PLATFORM_MEMBER_NAMES


def _member_content(tar: tarfile.TarFile, member: tarfile.TarInfo) -> Iterator[bytes]:
    """The content of a regular file in pieces of at most ``COPY_CHUNK_BYTES``, then padding."""
    remaining = member.size
    source = tar.extractfile(member)
    if source is not None:
        while remaining > 0:
            piece = source.read(min(COPY_CHUNK_BYTES, remaining))
            if not piece:
                raise tarfile.ReadError(f"unexpected end of data in member {member.name!r}")
            remaining -= len(piece)
            yield piece
    padding = -member.size % _BLOCK
    if padding:
        yield tarfile.NUL * padding


def drop_platform_members(chunks: Iterable[bytes]) -> Iterator[bytes]:
    """Re-emit the tar in ``chunks`` without the root-level platform members, lazily.

    Every other member keeps its name, mode, owner, times and link target; only a regular
    file's content is read (hard and symbolic links, directories and devices carry none).
    Malformed input raises ``tarfile.TarError``.
    """
    return rewrite_members(chunks, _without_platform_members)


def _without_platform_members(member: tarfile.TarInfo) -> tarfile.TarInfo | None:
    return None if is_platform_member(member.name) else member


def rewrite_members(
    chunks: Iterable[bytes],
    transform: Callable[[tarfile.TarInfo], tarfile.TarInfo | None],
    *,
    drain_trailer: bool = False,
    max_read: int | None = None,
) -> Iterator[bytes]:
    """Re-emit the tar in ``chunks`` member by member, lazily; see the module docstring.

    ``transform`` gets each parsed member in order and returns the header to write for it,
    or ``None`` to drop the member (its content is skipped); it may raise to stop the stream.
    The content written is always the original member's, so a transformed header must keep the
    size. With ``drain_trailer`` the input is read to its very end after the end-of-archive
    marker and anything but NUL bytes there raises ``tarfile.ReadError`` (so a source that
    checks its own tail, like a gzip trailer, is always read to the end). With ``max_read`` no
    single read of the parsed stream may be larger (``HeaderTooLarge``, a ``tarfile.ReadError``).
    """
    reader = _ChunkReader(iter(chunks))
    written = 0
    try:
        with _EndSeeingTar.open(  # type: ignore[call-overload]
            fileobj=reader, mode="r|", tarinfo=_EndSeeingInfo, max_read=max_read
        ) as tar:
            while (member := tar.next()) is not None:
                tar.members.clear()  # stream mode never looks back; keep memory bounded
                emitted = transform(member)
                if emitted is None:
                    continue
                header = emitted.tobuf(tar.format, tar.encoding, tar.errors)
                written += len(header)
                yield header
                if member.isreg():
                    for piece in _member_content(tar, member):
                        written += len(piece)
                        yield piece
            if not tar.saw_end:
                raise tarfile.ReadError(
                    f"archive ends without an end-of-archive marker at offset {tar.offset}"
                )
            # tarfile's stream reads ahead in records: its unread buffer is part of the tail
            buffered = bytes(getattr(tar.fileobj, "buf", b""))
        if drain_trailer:
            _require_zero_trailer(buffered, reader)
    finally:
        reader.close()
    written += len(_END_OF_ARCHIVE)
    yield _END_OF_ARCHIVE + tarfile.NUL * (-written % tarfile.RECORDSIZE)


def _require_zero_trailer(buffered: bytes, reader: _ChunkReader) -> None:
    """Read the rest of the input; ``buffered`` and what follows it may hold NUL bytes only."""
    piece = buffered
    while piece:
        if piece.strip(tarfile.NUL):
            raise tarfile.ReadError("data follows the end of the archive")
        piece = reader.read(COPY_CHUNK_BYTES)
