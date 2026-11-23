"""In-process, capped, offset-addressable logs for asynchronous session commands.

A ``CommandLog`` holds the interleaved stdout/stderr chunks of one command. Every chunk
carries the byte offset at which it starts in the combined log, so a follower can resume
from any offset and receive exactly the remaining bytes (a chunk straddling the offset is
sliced). The total is capped at ``MAX_LOG_BYTES``: past the cap nothing is appended and the
log is marked truncated, but the final state and exit code are still recorded.

Consecutive appends on the same stream are coalesced into one chunk (up to
``COALESCE_MAX_BYTES``) so one-byte frames do not cost one Python object each. The store keeps
a byte budget per organisation: past ``STORE_BUDGET_BYTES`` it evicts that organisation's
oldest finished logs, then drops the oldest whole chunks of its running logs. Offsets stay
absolute; a log that lost its head is marked truncated and reads below its new start resume at
the first retained chunk.

``read_lines`` serves the same bytes as one event per line (see ``LogLine``). Event ids stay
byte offsets: a line's id is the offset where the next line starts, so resuming at an id yields
the following line exactly. Nothing about the stored format changed; lines are cut on read.

Mutations take a ``threading.Lock``; waiters are woken with ``call_soon_threadsafe`` so
producers and followers may live on different threads or event loops.
"""

import asyncio
import contextlib
import threading
from bisect import bisect_right
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Self

MAX_LOG_BYTES = 10 * 1024 * 1024
MAX_RETAINED_LOGS = 256
COALESCE_MAX_BYTES = 64 * 1024
MAX_LINE_BYTES = 64 * 1024
STORE_BUDGET_BYTES = 64 * 1024 * 1024
TOTAL_BUDGET_BYTES = 256 * 1024 * 1024
STDOUT = "stdout"
STDERR = "stderr"

type _Waiter = tuple[asyncio.AbstractEventLoop, asyncio.Event]
type _Charge = Callable[[int], None]


@dataclass(frozen=True, slots=True)
class LogChunk:
    stream: str
    offset: int
    data: bytes

    @property
    def end(self) -> int:
        return self.offset + len(self.data)


@dataclass(frozen=True, slots=True)
class LogLine:
    """One output line (its terminator included) or a piece of a very long one."""

    stream: str
    offset: int
    data: bytes

    @property
    def end(self) -> int:
        return self.offset + len(self.data)


@dataclass(frozen=True, slots=True)
class LinePage:
    """The lines from a requested offset.

    ``next_offset`` is where the next read starts (the end of the last line returned);
    ``seen_offset`` is how far the log was inspected, past ``next_offset`` while an unterminated
    fragment is held. A follower waits for bytes past ``seen_offset``.
    """

    lines: tuple[LogLine, ...]
    next_offset: int
    seen_offset: int
    total_bytes: int
    truncated: bool
    finished: bool
    state: str | None
    exit_code: int | None

    @property
    def complete(self) -> bool:
        """True once the command ended and this page reaches the end of the log."""
        return self.finished and self.next_offset >= self.total_bytes


@dataclass(frozen=True, slots=True)
class LogPage:
    """A consistent snapshot of the log from a requested offset."""

    chunks: tuple[LogChunk, ...]
    next_offset: int
    total_bytes: int
    truncated: bool
    finished: bool
    state: str | None
    exit_code: int | None

    @property
    def complete(self) -> bool:
        """True once the command ended and this page reaches the end of the log."""
        return self.finished and self.next_offset >= self.total_bytes


class _Buffer:
    """A mutable chunk under construction; ``LogChunk`` snapshots are cut from it on read."""

    __slots__ = ("data", "offset", "stream")

    def __init__(self, stream: str, offset: int, data: bytes) -> None:
        self.stream = stream
        self.offset = offset
        self.data = bytearray(data)


class CommandLog:
    def __init__(self, cap: int | None = None, charge: _Charge | None = None) -> None:
        self._cap = MAX_LOG_BYTES if cap is None else cap
        self._charge = charge
        self._lock = threading.Lock()
        self._chunks: list[_Buffer] = []
        self._starts: list[int] = []
        self._total = 0
        self._retained = 0
        self._stream_bytes = {STDOUT: 0, STDERR: 0}
        self._truncated = False
        self._finished = False
        self._state: str | None = None
        self._exit_code: int | None = None
        self._waiters: list[_Waiter] = []

    @classmethod
    def closed(cls, state: str | None, exit_code: int | None) -> Self:
        """An empty, already finished log (output that is no longer held in memory)."""
        log = cls()
        log.finish(state, exit_code)
        return log

    @property
    def finished(self) -> bool:
        with self._lock:
            return self._finished

    @property
    def truncated(self) -> bool:
        with self._lock:
            return self._truncated

    @property
    def retained_bytes(self) -> int:
        with self._lock:
            return self._retained

    def stream_bytes(self, stream: str) -> int:
        with self._lock:
            return self._stream_bytes.get(stream, 0)

    def append(self, stream: str, data: bytes) -> None:
        if not data:
            return
        with self._lock:
            if self._finished:
                return
            room = self._cap - self._total
            if len(data) > room:
                self._truncated = True
                data = data[: max(room, 0)]
            if data:
                last = self._chunks[-1] if self._chunks else None
                if (
                    last is not None
                    and last.stream == stream
                    and len(last.data) + len(data) <= COALESCE_MAX_BYTES
                ):
                    last.data.extend(data)
                else:
                    self._starts.append(self._total)
                    self._chunks.append(_Buffer(stream, self._total, data))
                self._total += len(data)
                self._retained += len(data)
                self._stream_bytes[stream] = self._stream_bytes.get(stream, 0) + len(data)
            waiters = self._take_waiters()
        _wake(waiters)
        if data and self._charge is not None:
            self._charge(len(data))

    def drop_oldest(self, wanted: int) -> int:
        """Drop whole chunks from the front (keeping the last one); return the bytes freed."""
        with self._lock:
            freed = 0
            count = 0
            while count < len(self._chunks) - 1 and freed < wanted:
                freed += len(self._chunks[count].data)
                count += 1
            if count:
                del self._chunks[:count]
                del self._starts[:count]
                self._retained -= freed
                self._truncated = True
            return freed

    def mark_truncated(self) -> None:
        with self._lock:
            self._truncated = True

    def finish(self, state: str | None, exit_code: int | None) -> None:
        """Record the final state once; later calls are ignored."""
        with self._lock:
            if self._finished:
                return
            self._finished = True
            self._state = state
            self._exit_code = exit_code
            waiters = self._take_waiters()
        _wake(waiters)

    def read(self, offset: int = 0, max_bytes: int | None = None) -> LogPage:
        """Chunks from byte ``offset`` on, at most ``max_bytes`` of payload when given."""
        start = max(offset, 0)
        with self._lock:
            chunks = self._gather(start, max_bytes)
            return LogPage(
                chunks=tuple(chunks),
                next_offset=chunks[-1].end if chunks else min(start, self._total),
                total_bytes=self._total,
                truncated=self._truncated,
                finished=self._finished,
                state=self._state,
                exit_code=self._exit_code,
            )

    def read_lines(self, offset: int = 0, max_bytes: int | None = None) -> LinePage:
        """One ``LogLine`` per line from byte ``offset`` on, at most ``max_bytes`` of payload.

        ``offset`` is taken as a line start (an event id always is; an offset inside a line
        yields the rest of it). An unterminated tail is held back until more bytes of its stream
        arrive, the other stream writes, or the log finishes. A line longer than
        ``MAX_LINE_BYTES`` is cut into pieces of that size, and a line longer than the read
        budget is cut at the budget, so a page always makes progress.
        """
        start = max(offset, 0)
        with self._lock:
            chunks = self._gather(start, max_bytes)
            gathered_end = chunks[-1].end if chunks else min(start, self._total)
            reached_end = gathered_end >= self._total
            lines = _split_lines(chunks, closed=self._finished and reached_end, whole=reached_end)
            return LinePage(
                lines=lines,
                next_offset=lines[-1].end if lines else min(start, self._total),
                seen_offset=gathered_end,
                total_bytes=self._total,
                truncated=self._truncated,
                finished=self._finished,
                state=self._state,
                exit_code=self._exit_code,
            )

    def _gather(self, start: int, max_bytes: int | None) -> list[LogChunk]:
        """The chunks from ``start`` on (lock held), cut to ``max_bytes`` of payload."""
        index = max(bisect_right(self._starts, start) - 1, 0)
        chunks: list[LogChunk] = []
        budget = max_bytes
        for buf in self._chunks[index:]:
            if buf.offset + len(buf.data) <= start:
                continue
            piece = _cut(buf, start)
            if budget is not None:
                if budget <= 0:
                    break
                if len(piece.data) > budget:
                    piece = LogChunk(piece.stream, piece.offset, piece.data[:budget])
                budget -= len(piece.data)
            chunks.append(piece)
        return chunks

    async def wait_for_change(self, offset: int, timeout_s: float | None = None) -> None:
        """Return when bytes past ``offset`` exist, the log finished, or ``timeout_s`` passed."""
        event = asyncio.Event()
        waiter: _Waiter = (asyncio.get_running_loop(), event)
        with self._lock:
            if self._finished or self._total > offset:
                return
            self._waiters.append(waiter)
        try:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(event.wait(), timeout_s)
        finally:
            with self._lock:
                if waiter in self._waiters:
                    self._waiters.remove(waiter)

    def _take_waiters(self) -> list[_Waiter]:
        waiters, self._waiters = self._waiters, []
        return waiters


def _cut(buf: _Buffer, start: int) -> LogChunk:
    if buf.offset >= start:
        return LogChunk(buf.stream, buf.offset, bytes(buf.data))
    return LogChunk(buf.stream, start, bytes(buf.data[start - buf.offset :]))


def _runs(chunks: list[LogChunk]) -> list[tuple[str, int, bytes]]:
    """Merge contiguous chunks of the same stream: a line may span buffer boundaries."""
    runs: list[tuple[str, int, bytearray]] = []
    for chunk in chunks:
        if runs and runs[-1][0] == chunk.stream and runs[-1][1] + len(runs[-1][2]) == chunk.offset:
            runs[-1][2].extend(chunk.data)
        else:
            runs.append((chunk.stream, chunk.offset, bytearray(chunk.data)))
    return [(stream, offset, bytes(data)) for stream, offset, data in runs]


def _pieces(stream: str, offset: int, data: bytes) -> list[LogLine]:
    """``data`` as lines of at most ``MAX_LINE_BYTES``, never cutting inside a UTF-8 character."""
    pieces: list[LogLine] = []
    pos = 0
    while pos < len(data):
        end = min(pos + MAX_LINE_BYTES, len(data))
        if end < len(data):
            floor = max(end - 3, pos + 1)
            while end > floor and data[end] & 0xC0 == 0x80:
                end -= 1
        pieces.append(LogLine(stream, offset + pos, data[pos:end]))
        pos = end
    return pieces


def _split_lines(chunks: list[LogChunk], *, closed: bool, whole: bool) -> tuple[LogLine, ...]:
    """Cut gathered chunks into lines.

    A run that is followed by the other stream is complete; the last run is complete only when
    the log ``closed`` (finished and fully gathered). Otherwise its unterminated tail is held,
    unless the read budget cut the gathered bytes (``whole`` false) and nothing else was emitted.
    """
    runs = _runs(chunks)
    lines: list[LogLine] = []
    for index, (stream, offset, data) in enumerate(runs):
        last = index == len(runs) - 1
        pos = 0
        while True:
            newline = data.find(b"\n", pos)
            if newline < 0:
                break
            lines.extend(_pieces(stream, offset + pos, data[pos : newline + 1]))
            pos = newline + 1
        while len(data) - pos > MAX_LINE_BYTES:
            piece = _pieces(stream, offset + pos, data[pos : pos + MAX_LINE_BYTES + 3])[0]
            lines.append(piece)
            pos += len(piece.data)
        if pos < len(data) and (not last or closed or (not whole and not lines)):
            lines.append(LogLine(stream, offset + pos, data[pos:]))
    return tuple(lines)


def _wake(waiters: list[_Waiter]) -> None:
    for loop, event in waiters:
        with contextlib.suppress(RuntimeError):  # the waiter's loop already closed
            loop.call_soon_threadsafe(event.set)


class _OrgBucket:
    """The logs of one organisation and the bytes they retain."""

    __slots__ = ("logs", "org_id", "retained")

    def __init__(self, org_id: str) -> None:
        self.org_id = org_id
        self.logs: OrderedDict[str, CommandLog] = OrderedDict()
        self.retained = 0


class CommandLogStore:
    """Logs keyed by command id, budgeted per organisation.

    Each organisation has its own ``max_retained`` log count and ``max_bytes`` byte budget.
    Past either, eviction happens only inside the organisation that produced the output: its
    oldest finished logs go first, then (for bytes) the oldest chunks of its running logs.
    ``max_total_bytes`` is a store-wide ceiling; when it is exceeded the organisation that just
    wrote is squeezed by the overflow, so other organisations never lose logs to its output.
    """

    def __init__(
        self,
        max_retained: int = MAX_RETAINED_LOGS,
        max_bytes: int = STORE_BUDGET_BYTES,
        max_total_bytes: int = TOTAL_BUDGET_BYTES,
    ) -> None:
        self._max_retained = max_retained
        self._max_bytes = max_bytes
        self._max_total = max_total_bytes
        self._lock = threading.Lock()
        self._orgs: dict[str, _OrgBucket] = {}
        self._owner: dict[str, str] = {}
        self._total = 0

    def create(self, command_id: str, org_id: str) -> CommandLog:
        """A fresh log charged to ``org_id``; a log with the same id is replaced."""
        log = CommandLog(charge=lambda delta: self._charge(org_id, command_id, log, delta))
        with self._lock:
            self._forget(command_id)
            bucket = self._orgs.get(org_id)
            if bucket is None:
                bucket = self._orgs[org_id] = _OrgBucket(org_id)
            bucket.logs[command_id] = log
            self._owner[command_id] = org_id
            self._evict(bucket)
        return log

    def get(self, command_id: str) -> CommandLog | None:
        with self._lock:
            org_id = self._owner.get(command_id)
            if org_id is None:
                return None
            return self._orgs[org_id].logs.get(command_id)

    def discard(self, command_id: str) -> None:
        """Drop a command's log and free its bytes (no-op when it is not held)."""
        with self._lock:
            self._forget(command_id)

    def org_count(self) -> int:
        """Organisations that currently hold at least one log."""
        with self._lock:
            return len(self._orgs)

    def _charge(self, org_id: str, command_id: str, log: CommandLog, delta: int) -> None:
        with self._lock:
            bucket = self._orgs.get(org_id)
            if bucket is None or bucket.logs.get(command_id) is not log:
                return  # the log was already dropped; its bytes are not held by the store
            bucket.retained += delta
            self._total += delta
            limit = self._max_bytes
            if self._total > self._max_total:
                limit = min(limit, max(bucket.retained - (self._total - self._max_total), 0))
            if bucket.retained > limit:
                self._enforce_budget(bucket, limit)

    def _enforce_budget(self, bucket: _OrgBucket, limit: int) -> None:
        for command_id in list(bucket.logs):
            if bucket.retained <= limit:
                return
            if bucket.logs[command_id].finished:
                self._remove(bucket, command_id)
        for log in list(bucket.logs.values()):
            if bucket.retained <= limit:
                return
            freed = log.drop_oldest(bucket.retained - limit)
            bucket.retained -= freed
            self._total -= freed

    def _forget(self, command_id: str) -> None:
        org_id = self._owner.get(command_id)
        if org_id is not None:
            self._remove(self._orgs[org_id], command_id)

    def _remove(self, bucket: _OrgBucket, command_id: str) -> None:
        freed = bucket.logs.pop(command_id).retained_bytes
        bucket.retained -= freed
        self._total -= freed
        del self._owner[command_id]
        if not bucket.logs:
            self._total -= bucket.retained  # zero unless a charge raced a removal
            del self._orgs[bucket.org_id]

    def _evict(self, bucket: _OrgBucket) -> None:
        for command_id in list(bucket.logs):
            if len(bucket.logs) <= self._max_retained:
                return
            if bucket.logs[command_id].finished:
                self._remove(bucket, command_id)
