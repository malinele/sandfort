"""Snapshot clients (``client.snapshots``): register, create-from-sandbox, list, get, delete,
declarative builds and their build-log stream.

``build`` accepts an :class:`~sandfort_sdk.image.Image` or a raw spec mapping in the wire form.
``follow_build_logs`` decodes the server-sent-event stream into :class:`BuildLogEvent` values:
one per ``log`` line, ending with the final ``state`` event; closing it early releases the
HTTP response at once.
"""

import asyncio
import json
import time
from collections.abc import AsyncGenerator, AsyncIterator, Generator, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from os import PathLike
from pathlib import Path
from types import TracebackType
from typing import Any, Self

import httpx

from sandfort_sdk._download import asave_stream, save_stream
from sandfort_sdk._requests import (
    DEFAULT_POLL_INTERVAL_S,
    DEFAULT_WAIT_TIMEOUT_S,
    IMAGE_BUILDS_PATH,
    SNAPSHOT_FROM_SANDBOX_PATH,
    SNAPSHOT_READY,
    SNAPSHOTS_PATH,
    build_logs_path,
    image_build_body,
    list_params,
    snapshot_from_sandbox_body,
    snapshot_is_ready,
    snapshot_path,
    snapshot_pause_s,
    snapshot_register_body,
)
from sandfort_sdk._transport import (
    AsyncByteStream,
    AsyncTransport,
    ByteStream,
    Reply,
    SyncTransport,
    stream_read_error,
)
from sandfort_sdk.exceptions import InvalidResponseError, TransportError
from sandfort_sdk.image import Image
from sandfort_sdk.models import (
    Page,
    Resources,
    _as_dict,
    _as_list,
    _optional_str,
    _required,
    _required_timestamp,
)
from sandfort_sdk.process import FOLLOW_IDLE_S, SseDecoder, SseFrame
from sandfort_sdk.volumes import checked_labels

EVENT_LOG = "log"
EVENT_STATE = "state"
STATE_READY = SNAPSHOT_READY
_SSE_HEADERS = {"Accept": "text/event-stream"}
_STREAM_ENDED = "build log stream ended before the final state event"
_TAR_HEADERS = {"Accept": "application/x-tar"}
EXPORT_CHUNK_BYTES = 1 << 20
# The server may work before the first byte (``docker save``): outlast it.
EXPORT_FIRST_BYTE_S = 120.0
PathArg = str | PathLike[str]


def export_path(snapshot_id: str) -> str:
    return f"{snapshot_path(snapshot_id)}/export"


@dataclass(frozen=True, slots=True)
class SnapshotInfo:
    """A snapshot; ``spec_hash`` and ``reused`` are only set by ``build``.

    ``image_ref`` and ``digest`` are ``None`` when the server hides them: it answers null for
    both to a label-scoped API key. ``labels`` is empty when the snapshot has none.
    ``resources`` is the resource spec recorded when the snapshot was taken from a sandbox;
    ``None`` for registered or built images and for snapshots taken before recording existed.
    """

    id: str
    name: str
    state: str  # "pending" | "ready" | "error" | "deleting"
    image_ref: str | None
    layer_count: int
    created_at: datetime
    digest: str | None = None
    source_sandbox_id: str | None = None
    spec_hash: str | None = None
    reused: bool = False
    isolation: str | None = None
    labels: dict[str, str] = field(default_factory=dict)  # empty when the server omits them
    resources: Resources | None = None

    @classmethod
    def from_payload(cls, data: Any) -> "SnapshotInfo":
        raw = _as_dict(data, "snapshot")
        recorded = raw.get("resources")
        snapshot_id, name, state, image_ref, layer_count = _required(
            raw, "snapshot", "id", "name", "state", "image_ref", "layer_count"
        )
        return cls(
            id=snapshot_id,
            name=name,
            state=state,
            image_ref=_optional_str(image_ref, "snapshot image_ref"),
            layer_count=layer_count,
            created_at=_required_timestamp(raw.get("created_at"), "snapshot"),
            digest=_optional_str(raw.get("digest"), "snapshot digest"),
            source_sandbox_id=raw.get("source_sandbox_id"),
            spec_hash=raw.get("spec_hash"),
            reused=bool(raw.get("reused", False)),
            isolation=raw.get("isolation"),
            labels=dict(_as_dict(raw.get("labels") or {}, "snapshot labels")),
            resources=None if recorded is None else Resources.from_payload(recorded),
        )


@dataclass(frozen=True, slots=True)
class BuildLogEvent:
    """One ``log`` line of a build, or the final ``state`` event (``is_final``)."""

    kind: str  # "log" | "state"
    line: str = ""
    index: int | None = None
    state: str | None = None
    snapshot_id: str | None = None
    digest: str | None = None
    reason: str | None = None

    @property
    def is_final(self) -> bool:
        return self.kind == EVENT_STATE

    @property
    def succeeded(self) -> bool:
        return self.is_final and self.state == STATE_READY


def _line_index(event_id: str | None) -> int | None:
    if event_id is None or not event_id.strip():
        return None
    try:
        return int(event_id)
    except ValueError as exc:
        raise InvalidResponseError(f"build log event id is not an index: {event_id!r}") from exc


def build_event_from_frame(frame: SseFrame) -> BuildLogEvent | None:
    """Map one SSE frame to a :class:`BuildLogEvent`; ``None`` for event types ignored here."""
    if frame.event not in (EVENT_LOG, EVENT_STATE):
        return None
    what = f"build {frame.event} event"
    try:
        raw = _as_dict(json.loads(frame.data), what)
    except ValueError as exc:
        raise InvalidResponseError(f"{what} data is not JSON") from exc
    if frame.event == EVENT_LOG:
        (line,) = _required(raw, what, "line")
        if not isinstance(line, str):
            raise InvalidResponseError(f"{what} line is not a string")
        return BuildLogEvent(EVENT_LOG, line=line, index=_line_index(frame.id))
    (state,) = _required(raw, what, "state")
    return BuildLogEvent(
        EVENT_STATE,
        state=state,
        snapshot_id=raw.get("snapshot_id"),
        digest=raw.get("digest"),
        reason=raw.get("reason"),
    )


class BuildLogStream:
    """Iterator of :class:`BuildLogEvent`; stops after the final ``state`` event."""

    def __init__(self, response: httpx.Response) -> None:
        self._response = response
        self._events = self._decode()

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> BuildLogEvent:
        try:
            return next(self._events)
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        self._events.close()
        self._response.close()

    @property
    def closed(self) -> bool:
        return self._response.is_closed

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def _frames(self) -> Iterator[SseFrame]:
        decoder = SseDecoder()
        try:
            for chunk in self._response.iter_bytes():
                yield from decoder.feed(chunk)
        except httpx.HTTPError as exc:
            raise stream_read_error(exc) from exc

    def _decode(self) -> Generator[BuildLogEvent, None, None]:
        for frame in self._frames():
            event = build_event_from_frame(frame)
            if event is None:
                continue
            yield event
            if event.is_final:
                return
        raise TransportError(_STREAM_ENDED)


class AsyncBuildLogStream:
    """Async counterpart of :class:`BuildLogStream`."""

    def __init__(self, response: httpx.Response) -> None:
        self._response = response
        # Async generators nested in ``async for`` are not closed with their consumer.
        self._source = self._frames()
        self._events = self._decode()

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> BuildLogEvent:
        try:
            return await anext(self._events)
        except BaseException:
            await self.aclose()
            raise

    async def aclose(self) -> None:
        await self._events.aclose()
        await self._source.aclose()
        await self._response.aclose()

    @property
    def closed(self) -> bool:
        return self._response.is_closed

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def _frames(self) -> AsyncGenerator[SseFrame, None]:
        decoder = SseDecoder()
        try:
            async for chunk in self._response.aiter_bytes():
                for frame in decoder.feed(chunk):
                    yield frame
        except httpx.HTTPError as exc:
            raise stream_read_error(exc) from exc

    async def _decode(self) -> AsyncGenerator[BuildLogEvent, None]:
        async for frame in self._source:
            event = build_event_from_frame(frame)
            if event is None:
                continue
            yield event
            if event.is_final:
                return
        raise TransportError(_STREAM_ENDED)


def _info(reply: Reply) -> SnapshotInfo:
    return SnapshotInfo.from_payload(reply.data)


def _page(reply: Reply) -> Page[SnapshotInfo]:
    items = _as_list(reply.data, "snapshots")
    return Page(tuple(SnapshotInfo.from_payload(item) for item in items), reply.next_cursor)


class Snapshots:
    """Synchronous snapshot and image-build client."""

    def __init__(self, transport: SyncTransport) -> None:
        self._transport = transport

    def register(
        self, image: str, *, name: str | None = None, labels: Mapping[str, str] | None = None
    ) -> SnapshotInfo:
        """Register a registry image reference (the server pulls it and answers ready).

        ``labels`` (non-blank keys, string values) are server-bounded; a label-scoped key gets
        its scope labels merged in.
        """
        body = snapshot_register_body(image, name, checked_labels(labels))
        return _info(self._transport.request("POST", SNAPSHOTS_PATH, json=body))

    def create_from_sandbox(
        self,
        sandbox_id: str,
        name: str,
        *,
        labels: Mapping[str, str] | None = None,
        wait: bool = False,
        wait_timeout_s: float = DEFAULT_WAIT_TIMEOUT_S,
        poll_interval_s: float = DEFAULT_POLL_INTERVAL_S,
    ) -> SnapshotInfo:
        """Commit a sandbox into a new snapshot (answers pending; poll ``get``).

        ``labels`` are stored on the snapshot; a label-scoped key gets its scope merged in.

        With ``wait`` the call polls ``get`` until the snapshot is ready, raising
        ``SandboxFailedError`` on ``error`` and ``SandboxTimeoutError`` after ``wait_timeout_s``.
        """
        body = snapshot_from_sandbox_body(sandbox_id, name, checked_labels(labels))
        info = _info(self._transport.request("POST", SNAPSHOT_FROM_SANDBOX_PATH, json=body))
        if wait:
            info = self._wait_ready(info, sandbox_id, wait_timeout_s, poll_interval_s)
        return info

    def _wait_ready(
        self, info: SnapshotInfo, sandbox_id: str, timeout_s: float, poll_interval_s: float
    ) -> SnapshotInfo:
        deadline = time.monotonic() + timeout_s
        while not snapshot_is_ready(info.id, info.state, sandbox_id):
            now = time.monotonic()
            time.sleep(snapshot_pause_s(info.id, info.state, deadline, now, poll_interval_s))
            info = self.get(info.id)
        return info

    def list(
        self,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int | None = None,
    ) -> Page[SnapshotInfo]:
        """One page of snapshots; ``labels`` keeps those carrying every given label."""
        params = list_params(None, checked_labels(labels), cursor, limit)
        return _page(self._transport.request("GET", SNAPSHOTS_PATH, params=params))

    def iter(
        self, *, labels: Mapping[str, str] | None = None, limit: int | None = None
    ) -> Iterator[SnapshotInfo]:
        cursor: str | None = None
        while True:
            page = self.list(labels=labels, cursor=cursor, limit=limit)
            yield from page.items
            if page.next_cursor is None:
                return
            cursor = page.next_cursor

    def get(self, snapshot_id: str) -> SnapshotInfo:
        return _info(self._transport.request("GET", snapshot_path(snapshot_id)))

    def delete(self, snapshot_id: str) -> SnapshotInfo:
        """Delete a snapshot; the server answers 409 (``Conflict``) while a sandbox uses it."""
        return _info(self._transport.request("DELETE", snapshot_path(snapshot_id)))

    def build(self, spec: Image | Mapping[str, Any], *, name: str | None = None) -> SnapshotInfo:
        """Start a build (pending) or reuse an identical earlier one (ready, ``reused``)."""
        body = image_build_body(spec, name)
        return _info(self._transport.request("POST", IMAGE_BUILDS_PATH, json=body))

    def export(self, snapshot_id: str, path: PathArg) -> int:
        """Stream a ready snapshot to ``path`` as an image tar; returns the bytes written.

        The tar is what ``docker save`` produces: load it with ``docker load -i <path>``.
        The body is written in chunks, never held in memory; a failed download removes the
        partial file. The server answers 409 (``InvalidState``) unless the snapshot is ready.
        """
        response = self._transport.open_stream(
            "GET", export_path(snapshot_id), headers=_TAR_HEADERS, server_wait_s=EXPORT_FIRST_BYTE_S
        )
        with ByteStream(response, EXPORT_CHUNK_BYTES) as stream:
            return save_stream(stream, Path(path))

    def follow_build_logs(self, snapshot_id: str) -> BuildLogStream:
        response = self._transport.open_stream(
            "GET",
            build_logs_path(snapshot_id),
            headers=_SSE_HEADERS,
            server_wait_s=FOLLOW_IDLE_S,
        )
        return BuildLogStream(response)


class AsyncSnapshots:
    """Asynchronous snapshot and image-build client."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._transport = transport

    async def register(
        self, image: str, *, name: str | None = None, labels: Mapping[str, str] | None = None
    ) -> SnapshotInfo:
        body = snapshot_register_body(image, name, checked_labels(labels))
        return _info(await self._transport.request("POST", SNAPSHOTS_PATH, json=body))

    async def create_from_sandbox(
        self,
        sandbox_id: str,
        name: str,
        *,
        labels: Mapping[str, str] | None = None,
        wait: bool = False,
        wait_timeout_s: float = DEFAULT_WAIT_TIMEOUT_S,
        poll_interval_s: float = DEFAULT_POLL_INTERVAL_S,
    ) -> SnapshotInfo:
        body = snapshot_from_sandbox_body(sandbox_id, name, checked_labels(labels))
        reply = await self._transport.request("POST", SNAPSHOT_FROM_SANDBOX_PATH, json=body)
        info = _info(reply)
        if wait:
            info = await self._wait_ready(info, sandbox_id, wait_timeout_s, poll_interval_s)
        return info

    async def _wait_ready(
        self, info: SnapshotInfo, sandbox_id: str, timeout_s: float, poll_interval_s: float
    ) -> SnapshotInfo:
        deadline = time.monotonic() + timeout_s
        while not snapshot_is_ready(info.id, info.state, sandbox_id):
            now = time.monotonic()
            pause = snapshot_pause_s(info.id, info.state, deadline, now, poll_interval_s)
            await asyncio.sleep(pause)
            info = await self.get(info.id)
        return info

    async def list(
        self,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int | None = None,
    ) -> Page[SnapshotInfo]:
        params = list_params(None, checked_labels(labels), cursor, limit)
        return _page(await self._transport.request("GET", SNAPSHOTS_PATH, params=params))

    async def iter(
        self, *, labels: Mapping[str, str] | None = None, limit: int | None = None
    ) -> AsyncIterator[SnapshotInfo]:
        cursor: str | None = None
        while True:
            page = await self.list(labels=labels, cursor=cursor, limit=limit)
            for item in page.items:
                yield item
            if page.next_cursor is None:
                return
            cursor = page.next_cursor

    async def get(self, snapshot_id: str) -> SnapshotInfo:
        return _info(await self._transport.request("GET", snapshot_path(snapshot_id)))

    async def delete(self, snapshot_id: str) -> SnapshotInfo:
        return _info(await self._transport.request("DELETE", snapshot_path(snapshot_id)))

    async def build(
        self, spec: Image | Mapping[str, Any], *, name: str | None = None
    ) -> SnapshotInfo:
        body = image_build_body(spec, name)
        return _info(await self._transport.request("POST", IMAGE_BUILDS_PATH, json=body))

    async def export(self, snapshot_id: str, path: PathArg) -> int:
        """Async counterpart of :meth:`Snapshots.export`; returns the bytes written."""
        response = await self._transport.open_stream(
            "GET", export_path(snapshot_id), headers=_TAR_HEADERS, server_wait_s=EXPORT_FIRST_BYTE_S
        )
        async with AsyncByteStream(response, EXPORT_CHUNK_BYTES) as stream:
            return await asave_stream(stream, Path(path))

    async def follow_build_logs(self, snapshot_id: str) -> AsyncBuildLogStream:
        response = await self._transport.open_stream(
            "GET",
            build_logs_path(snapshot_id),
            headers=_SSE_HEADERS,
            server_wait_s=FOLLOW_IDLE_S,
        )
        return AsyncBuildLogStream(response)
