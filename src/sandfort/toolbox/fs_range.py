"""Transfer limits and byte ranges of the fs toolbox: the oversize-upload refusal and the
single ``Range`` of a download.

A ``Range`` the server does not honour (another unit, several ranges, a malformed or reversed
spec, whitespace inside the spec) is ignored, as RFC 9110 allows: the whole file is sent. The
unit is matched case-insensitively. A well-formed range that starts at or past the end of the
file, and any range on an empty file, is unsatisfiable. A number of more than ``MAX_DIGITS``
digits (leading zeros do not count) is read as ``BEYOND``, a value no file reaches: as a start
it is unsatisfiable, as an end it is clamped to the end of the file, as a suffix length it
selects the whole file. The driver's archive stream cannot seek, so a range is served by
skipping and truncating the stream.
"""

import re
from collections.abc import AsyncIterator
from dataclasses import dataclass

from sandfort.errors import MIB as MIB
from sandfort.errors import upload_limit_error as upload_limit_error

_RANGE = re.compile(r"bytes=([0-9]*)-([0-9]*)", re.IGNORECASE)
MAX_DIGITS = 18  # int() refuses long digit strings; 10**18 bytes is beyond any file
BEYOND = 10**MAX_DIGITS


def _number(digits: str) -> int:
    """The value of a run of digits, ``BEYOND`` when it has more than ``MAX_DIGITS``."""
    significant = digits.lstrip("0")
    return BEYOND if len(significant) > MAX_DIGITS else int(significant or "0")


@dataclass(frozen=True, slots=True)
class ByteWindow:
    """The bytes ``first`` to ``last`` (both inclusive) of a file of ``size`` bytes."""

    first: int
    last: int
    size: int

    @property
    def length(self) -> int:
        return self.last - self.first + 1

    @property
    def content_range(self) -> str:
        return f"bytes {self.first}-{self.last}/{self.size}"


class RangeNotSatisfiable(Exception):
    """The range is well formed but lies outside a file of ``size`` bytes."""

    def __init__(self, size: int) -> None:
        super().__init__(f"range not satisfiable for a file of {size} bytes")
        self.size = size


def parse_range(header: str | None, size: int) -> ByteWindow | None:
    """The window a ``Range`` header selects, None when the whole file is to be sent.

    Raises :class:`RangeNotSatisfiable` for ``bytes=a-b``/``a-`` starting at or past the end,
    for the empty suffix ``-0`` and for any well-formed range on an empty file.
    """
    if header is None:
        return None
    match = _RANGE.fullmatch(header.strip())
    if match is None:
        return None
    start_text, end_text = match.groups()
    if not start_text and not end_text:
        return None
    if start_text and end_text and _number(end_text) < _number(start_text):
        return None  # reversed: malformed, so ignored
    if size <= 0:
        raise RangeNotSatisfiable(size)
    if not start_text:  # a suffix: the last n bytes
        suffix = _number(end_text)
        if suffix == 0:
            raise RangeNotSatisfiable(size)
        return ByteWindow(max(size - suffix, 0), size - 1, size)
    start = _number(start_text)
    if start >= size:
        raise RangeNotSatisfiable(size)
    end = _number(end_text) if end_text else size - 1
    return ByteWindow(start, min(end, size - 1), size)


async def window_stream(stream: AsyncIterator[bytes], window: ByteWindow) -> AsyncIterator[bytes]:
    """The bytes of ``window`` out of a stream that starts at byte 0; stops reading at its end."""
    position = 0
    async for chunk in stream:
        end = position + len(chunk)
        if end > window.first:
            piece = chunk[max(window.first - position, 0) : window.last + 1 - position]
            if piece:
                yield piece
        position = end
        if position > window.last:
            return
