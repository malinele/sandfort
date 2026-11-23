"""Docker implementation of ``LogsDriver``: container logs as timestamped entries (WP 2.5).

docker-py's public ``logs(stream=True)`` drops the stream id of each multiplexed frame, so the
request is issued through the same low-level client calls it uses internally and the response
is read frame by frame (8-byte header, then exactly the payload; never a read past the current
frame, which would block a follow stream). Opening and closing the stream go through
``run_blocking`` (control lane); the frame read, which parks in ``recv`` for as long as the
container is quiet, goes through ``run_bulk`` (bulk lane), so a follower holds one bulk token.

Releasing the stream: a frame read runs as its own task. A consumer that stops while a read is
parked (client disconnect, cancellation) cancels that task natively and gets control back at
once; the socket is shut down right away so the parked ``recv`` returns, the worker thread
ends and its tokens are freed. The generator's ``finally`` then closes the response, also when
the consumer simply ``aclose``s it.
"""

import asyncio
import contextlib
import logging
import re
import socket
import struct
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import anyio

from sandfort.drivers.base import LogEntry
from sandfort.drivers.docker.client import run_blocking, translate_errors
from sandfort.drivers.docker.demux import HEADER_SIZE, STDERR, STDOUT
from sandfort.drivers.docker.lanes import run_bulk
from sandfort.drivers.errors import DriverError

logger = logging.getLogger(__name__)

ALL_LINES = "all"
LOGS_PATH = "/containers/{0}/logs"
LOG_STREAM_FAILED_MESSAGE = "the container log stream failed; the details are in the server log"

_HEADER = struct.Struct(">BxxxI")
_STREAM_NAMES = {1: STDOUT, 2: STDERR}
_EXTRA_FRACTION_DIGITS = re.compile(r"(\.\d{6})\d+")


def parse_timestamp(text: str) -> float:
    """Unix seconds of docker's RFC 3339 nano timestamp (``2026-10-30T19:02:35.123456789Z``)."""
    trimmed = _EXTRA_FRACTION_DIGITS.sub(r"\1", text).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(trimmed)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.timestamp()


def parse_frame(stream: str, payload: bytes) -> list[LogEntry]:
    """Entries of one frame; with ``timestamps=1`` every line starts with ``<timestamp> ``."""
    entries: list[LogEntry] = []
    for raw in payload.split(b"\n"):
        if not raw:
            continue
        text = raw.decode("utf-8", errors="replace")
        stamp, _, line = text.partition(" ")
        try:
            seconds = parse_timestamp(stamp)
        except ValueError:
            seconds, line = time.time(), text  # not stamped: keep the whole line
        entries.append(
            LogEntry(timestamp=datetime.fromtimestamp(seconds, UTC), stream=stream, line=line)
        )
    return entries


def build_params(follow: bool, tail: int | None, since: datetime | None) -> dict[str, Any]:
    """Query parameters of ``GET /containers/{id}/logs``; ``tail=None`` means every line."""
    params: dict[str, Any] = {
        "stdout": 1,
        "stderr": 1,
        "timestamps": 1,
        "follow": 1 if follow else 0,
        "tail": ALL_LINES if tail is None else max(tail, 0),
    }
    if since is not None:
        params["since"] = f"{max(since.timestamp(), 0.0):.6f}"
    return params


class _LogStream:
    """One open logs response, read frame by frame from worker threads."""

    def __init__(self, ref: str, response: Any, sock: Any) -> None:
        self._ref = ref
        self._response = response
        self._sock = sock
        self._closed = False

    def read_frame(self) -> tuple[str, bytes] | None:
        """Next ``(stream, payload)``; ``None`` at EOF or once the stream was shut down."""
        while True:
            header = self._read_exact(HEADER_SIZE)
            if header is None:
                return None
            kind, size = _HEADER.unpack(header)
            payload = self._read_exact(size) if size else b""
            if payload is None:
                return None
            stream = _STREAM_NAMES.get(kind)
            if stream is not None and payload:
                return stream, payload

    def _read_exact(self, size: int) -> bytes | None:
        buffer = bytearray()
        while len(buffer) < size:
            try:
                chunk = self._response.raw.read(size - len(buffer))
            except Exception as exc:
                if self._closed:
                    return None  # shut down under us: a normal end, not a failure
                logger.warning("log stream of %s failed: %s", self._ref, exc)
                raise DriverError(LOG_STREAM_FAILED_MESSAGE, ref=self._ref) from exc
            if not chunk:
                return None
            buffer.extend(chunk)
        return bytes(buffer)

    def wake(self) -> None:
        """Shut the socket down so a read parked in another thread returns; never blocks."""
        self._closed = True
        held = self._sock
        # urllib3 on docker desktop hands back a SocketIO wrapper: no shutdown, raw socket in _sock
        target = held if hasattr(held, "shutdown") else getattr(held, "_sock", None)
        try:
            if target is not None and hasattr(target, "shutdown"):
                target.shutdown(socket.SHUT_RDWR)
            else:
                held.close()
        except (OSError, ValueError):
            pass  # already disconnected or closed; the parked read has returned or will at once

    def close(self) -> None:
        self.wake()
        try:
            self._response.close()
        except Exception:
            logger.debug("closing the log stream of %s failed", self._ref, exc_info=True)


def _open_blocking(
    client: Any, ref: str, follow: bool, tail: int | None, since: datetime | None
) -> _LogStream:
    api = client.api
    response: Any = None
    try:
        with translate_errors(ref, "logs.open"):
            response = api._get(
                api._url(LOGS_PATH, ref), params=build_params(follow, tail, since), stream=True
            )
            api._raise_for_status(response)
            sock = api._get_raw_response_socket(response)
            # docker-py's own streams do the same: a quiet follow must not hit the read timeout
            api._disable_socket_timeout(sock)
    except BaseException:
        if response is not None:
            with contextlib.suppress(Exception):
                response.close()
        raise
    return _LogStream(ref, response, sock)


async def _next_frame(stream: _LogStream) -> tuple[str, bytes] | None:
    read = asyncio.ensure_future(run_bulk(stream.read_frame))
    try:
        return await read
    except asyncio.CancelledError:
        stream.wake()  # the worker thread may still be parked in recv; its tokens stay held
        raise


async def stream_logs(
    client: Any,
    ref: str,
    *,
    follow: bool = False,
    tail: int | None = None,
    since: datetime | None = None,
) -> AsyncIterator[LogEntry]:
    """Yield stdout/stderr lines with docker's timestamps; ``follow`` keeps the stream open."""
    stream = await run_blocking(_open_blocking, client, ref, follow, tail, since)
    try:
        while True:
            frame = await _next_frame(stream)
            if frame is None:
                return
            for entry in parse_frame(*frame):
                yield entry
    finally:
        with anyio.CancelScope(shield=True):
            await run_blocking(stream.close)
