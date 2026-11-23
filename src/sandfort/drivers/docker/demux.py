"""Pure helpers for docker exec streams: frame demultiplexing and per-stream output caps.

No docker-py and no I/O here, so the logic is unit-testable without a daemon.
"""

import struct

HEADER_SIZE = 8
STDOUT = "stdout"
STDERR = "stderr"

_HEADER = struct.Struct(">BxxxI")
_STREAM_NAMES = {1: STDOUT, 2: STDERR}


class FrameDemuxer:
    """Incremental parser for Docker's multiplexed stream (8-byte header + payload).

    Frames may be split across ``feed`` calls at any byte boundary. Payloads are
    emitted as they arrive, so a large frame is never buffered whole. Frames of an
    unknown stream type (including stdin echo) are dropped.
    """

    def __init__(self) -> None:
        self._header = bytearray()
        self._stream: str | None = None
        self._remaining = 0

    def feed(self, data: bytes) -> list[tuple[str, bytes]]:
        view = memoryview(data)
        out: list[tuple[str, bytes]] = []
        pos = 0
        while pos < len(view):
            if self._remaining == 0:
                chunk = view[pos : pos + HEADER_SIZE - len(self._header)]
                self._header.extend(chunk)
                pos += len(chunk)
                if len(self._header) < HEADER_SIZE:
                    break
                kind, size = _HEADER.unpack(bytes(self._header))
                self._header.clear()
                self._stream = _STREAM_NAMES.get(kind)
                self._remaining = size
                continue
            chunk = view[pos : pos + self._remaining]
            pos += len(chunk)
            self._remaining -= len(chunk)
            if self._stream is not None:
                out.append((self._stream, bytes(chunk)))
        return out


class OutputCaps:
    """Per-stream byte budget; bytes past the limit are dropped and ``truncated`` is set."""

    def __init__(self, limit: int) -> None:
        self._limit = max(limit, 0)
        self._used = {STDOUT: 0, STDERR: 0}
        self.truncated = False

    def admit(self, stream: str, data: bytes) -> bytes:
        """Return the prefix of ``data`` that still fits within ``stream``'s budget."""
        room = self._limit - self._used[stream]
        if len(data) > room:
            self.truncated = True
            data = data[:room]
        self._used[stream] += len(data)
        return data
