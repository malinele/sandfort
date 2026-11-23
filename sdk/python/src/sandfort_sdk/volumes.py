"""Volume clients (``client.volumes``): create, list, get, delete, export and restore volumes.

Mount a volume by passing ``mounts=[VolumeMount(volume_id, "/data")]`` (or plain
``(volume_id, mount_path)`` pairs) to ``create_sandbox``; ``read_only=True`` mounts it
read-only (sent by the synchronous client only, see :class:`VolumeMount`).

``export`` streams a volume to a local ``.tar.gz`` file; ``restore`` replaces a volume's
contents from one. A restore is not atomic: the volume is emptied first, and a restore that
fails after it began leaves the volume empty (the error's ``details["volume_emptied"]`` says
so). The server refuses it with 409 (``Conflict``) while a sandbox mounts the volume.
"""

import asyncio
import io
from collections.abc import AsyncIterator, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from os import PathLike
from pathlib import Path
from typing import Any, BinaryIO

from sandfort_sdk._download import asave_stream, save_stream
from sandfort_sdk._requests import VOLUMES_PATH, list_params, volume_create_body, volume_path
from sandfort_sdk._transport import (
    AsyncByteStream,
    AsyncTransport,
    ByteStream,
    Reply,
    SyncTransport,
)
from sandfort_sdk.exceptions import InvalidResponseError
from sandfort_sdk.fs import (
    UPLOAD_CHUNK_BYTES,
    _source_size,
    aiter_file_chunks,
    check_upload_size,
    iter_file_chunks,
)
from sandfort_sdk.models import Page, _as_dict, _as_list, _required, _required_timestamp

ARCHIVE_MEDIA_TYPE = "application/gzip"
_ARCHIVE_HEADERS = {"Accept": ARCHIVE_MEDIA_TYPE}
EXPORT_CHUNK_BYTES = 1 << 20
# The server may work before the first byte (it starts a helper) or after the last (extract).
EXPORT_FIRST_BYTE_S = 120.0
RESTORE_WAIT_S = 600.0
PathArg = str | PathLike[str]
RestoreSource = PathArg | bytes | bytearray | BinaryIO


def export_path(volume_id: str) -> str:
    return f"{volume_path(volume_id)}/export"


def restore_path(volume_id: str) -> str:
    return f"{volume_path(volume_id)}/restore"


@dataclass(frozen=True, slots=True)
class VolumeMount:
    """Mount ``volume_id`` at the absolute ``mount_path`` inside a new sandbox.

    ``read_only`` mounts it read-only. Iterating gives ``(volume_id, mount_path)`` like a
    plain pair; only :meth:`.client.Client.create_sandbox` sends ``read_only``. Any other
    code that unpacks a read-only mount as a pair raises ``TypeError`` rather than dropping
    the flag and mounting the volume read-write.
    """

    volume_id: str
    mount_path: str
    read_only: bool = False

    def __iter__(self) -> Iterator[str]:
        if self.read_only:
            raise TypeError("a read_only mount cannot be sent as a (volume_id, mount_path) pair")
        yield self.volume_id
        yield self.mount_path


MOUNT_SHAPES = "a VolumeMount or a (volume_id, mount_path) pair (a tuple or list of 2 strings)"


def _as_mount(item: object) -> VolumeMount:
    """``item`` as a :class:`VolumeMount`; anything but the two accepted shapes is refused."""
    if isinstance(item, VolumeMount):
        return item
    if isinstance(item, tuple | list) and len(item) == 2 and all(isinstance(p, str) for p in item):
        return VolumeMount(item[0], item[1])
    raise ValueError(f"each mount must be {MOUNT_SHAPES}, got {type(item).__name__}")


def mounts_wire(mounts: Iterable[VolumeMount | Sequence[str]]) -> list[dict[str, Any]]:
    """The ``volumes`` wire list, the one used by the sync and the async client.

    Each item is a :class:`VolumeMount` or a 2-item tuple or list; ``read_only`` appears only on
    a read-only mount. Any other shape raises ``ValueError`` naming the expected shapes.
    """
    payload: list[dict[str, Any]] = []
    for item in mounts:
        mount = _as_mount(item)
        if not mount.volume_id.strip() or not mount.mount_path.strip():
            raise ValueError("each mount needs a non-empty volume id and mount path")
        entry: dict[str, Any] = {"volume_id": mount.volume_id, "mount_path": mount.mount_path}
        if mount.read_only:
            entry["read_only"] = True
        payload.append(entry)
    return payload


def checked_labels(labels: Mapping[str, str] | None) -> dict[str, str] | None:
    """``labels`` as a dict, ``None`` when empty; keys must be non-blank strings, values strings.

    A blank value is legal (as in a sandbox create). The server enforces the count and length
    bounds.
    """
    if not labels:
        return None
    for key, value in labels.items():
        if not (isinstance(key, str) and key.strip() and isinstance(value, str)):
            raise ValueError("label keys must be non-blank strings and values must be strings")
    return dict(labels)


def _create_body(name: str, labels: Mapping[str, str] | None) -> dict[str, Any]:
    body = volume_create_body(name)
    checked = checked_labels(labels)
    return body if checked is None else {**body, "labels": checked}


def _list_params(
    labels: Mapping[str, str] | None, cursor: str | None, limit: int | None
) -> dict[str, Any]:
    return list_params(None, checked_labels(labels), cursor, limit)


@dataclass(frozen=True, slots=True)
class VolumeInfo:
    id: str
    name: str
    state: str  # "ready" | "deleting"
    created_at: datetime
    size_bytes: int | None = None  # last sampled size; None until first sampled
    labels: dict[str, str] = field(default_factory=dict)  # empty when the server omits them
    max_bytes: int | None = None  # size limit; None when the volume has none (or an old server)
    over_limit: bool = False  # True when the last sampled size is above ``max_bytes``

    @classmethod
    def from_payload(cls, data: Any) -> "VolumeInfo":
        raw = _as_dict(data, "volume")
        volume_id, name, state = _required(raw, "volume", "id", "name", "state")
        created_at = _required_timestamp(raw.get("created_at"), "volume")
        labels = dict(_as_dict(raw.get("labels") or {}, "volume labels"))
        max_bytes = raw.get("max_bytes")
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
            max_bytes = None
        return cls(
            volume_id,
            name,
            state,
            created_at,
            raw.get("size_bytes"),
            labels,
            max_bytes,
            raw.get("over_limit") is True,
        )


@dataclass(frozen=True, slots=True)
class VolumeRestore:
    """The answer of a restore: the volume and the bytes extracted into it.

    ``restored_bytes`` counts tar data (decompressed, headers included), not file bytes.
    """

    volume_id: str
    name: str
    restored_bytes: int

    @classmethod
    def from_payload(cls, data: Any) -> "VolumeRestore":
        raw = _as_dict(data, "volume restore")
        volume_id, name = _required(raw, "volume restore", "volume_id", "name")
        restored = raw.get("restored_bytes")
        if isinstance(restored, bool) or not isinstance(restored, int):
            raise InvalidResponseError("volume restore payload is missing 'restored_bytes'")
        return cls(volume_id, name, restored)


def _open_source(source: RestoreSource) -> tuple[BinaryIO, bool]:
    """The binary file to read an archive from and whether this call opened (and must close) it."""
    if isinstance(source, bytes | bytearray):
        return io.BytesIO(bytes(source)), False
    if isinstance(source, str | PathLike):
        return Path(source).open("rb"), True
    return source, False


def _restore_request(handle: BinaryIO, size_bytes: int | None) -> tuple[int, dict[str, str]]:
    """The size to send (refused above the upload limit) and the request headers."""
    size = _source_size(handle, size_bytes)
    check_upload_size(size)
    return size, {"Content-Length": str(size), "Content-Type": ARCHIVE_MEDIA_TYPE}


def _page(reply: Reply) -> Page[VolumeInfo]:
    items = _as_list(reply.data, "volumes")
    return Page(tuple(VolumeInfo.from_payload(item) for item in items), reply.next_cursor)


class Volumes:
    """Synchronous volume client."""

    def __init__(self, transport: SyncTransport) -> None:
        self._transport = transport

    def create(self, name: str, labels: Mapping[str, str] | None = None) -> VolumeInfo:
        """Create a volume; ``labels`` (non-blank keys, any string value) are server-bounded."""
        body = _create_body(name, labels)
        reply = self._transport.request("POST", VOLUMES_PATH, json=body)
        return VolumeInfo.from_payload(reply.data)

    def list(
        self,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int | None = None,
    ) -> Page[VolumeInfo]:
        """One page of volumes; ``labels`` keeps those carrying every given label."""
        params = _list_params(labels, cursor, limit)
        return _page(self._transport.request("GET", VOLUMES_PATH, params=params))

    def iter(
        self, *, labels: Mapping[str, str] | None = None, limit: int | None = None
    ) -> Iterator[VolumeInfo]:
        cursor: str | None = None
        while True:
            page = self.list(labels=labels, cursor=cursor, limit=limit)
            yield from page.items
            if page.next_cursor is None:
                return
            cursor = page.next_cursor

    def get(self, volume_id: str) -> VolumeInfo:
        reply = self._transport.request("GET", volume_path(volume_id))
        return VolumeInfo.from_payload(reply.data)

    def delete(self, volume_id: str) -> VolumeInfo:
        """Delete a volume; the server answers 409 (``Conflict``) while a sandbox mounts it."""
        reply = self._transport.request("DELETE", volume_path(volume_id))
        return VolumeInfo.from_payload(reply.data)

    def export(self, volume_id: str, path: PathArg) -> int:
        """Stream a volume to ``path`` as a gzipped tar; returns the bytes written.

        The body is written in chunks, never held in memory; a failed download removes the
        partial file. A volume a running sandbox mounts can be exported, but it is read while
        the sandbox may still write, so the archive is not a point-in-time copy.
        """
        response = self._transport.open_stream(
            "GET", export_path(volume_id), headers=_ARCHIVE_HEADERS,
            server_wait_s=EXPORT_FIRST_BYTE_S,
        )  # fmt: skip
        with ByteStream(response, EXPORT_CHUNK_BYTES) as stream:
            return save_stream(stream, Path(path))

    def restore(
        self,
        volume_id: str,
        source: RestoreSource,
        *,
        size_bytes: int | None = None,
        chunk_size: int = UPLOAD_CHUNK_BYTES,
    ) -> VolumeRestore:
        """Replace the volume's contents with the gzipped tar in ``source``.

        ``source`` is a file path, bytes, or a binary file object (sent from its current
        position; ``size_bytes`` is required when it is not seekable). An archive over the
        256 MiB upload limit is refused before any request. The upload is never resent after
        a lost connection: a restore that may have begun must be started again by the caller.
        The volume is emptied first, so a failed restore can leave it empty
        (``details["volume_emptied"]``); the server answers 409 while a sandbox mounts it.
        """
        handle, owned = _open_source(source)
        try:
            size, headers = _restore_request(handle, size_bytes)
            reply = self._transport.request(
                "POST", restore_path(volume_id), content=iter_file_chunks(handle, size, chunk_size),
                headers=headers, server_wait_s=RESTORE_WAIT_S,
            )  # fmt: skip
        finally:
            if owned:
                handle.close()
        return VolumeRestore.from_payload(reply.data)


class AsyncVolumes:
    """Asynchronous volume client."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._transport = transport

    async def create(self, name: str, labels: Mapping[str, str] | None = None) -> VolumeInfo:
        """Create a volume; ``labels`` (non-blank keys, any string value) are server-bounded."""
        body = _create_body(name, labels)
        reply = await self._transport.request("POST", VOLUMES_PATH, json=body)
        return VolumeInfo.from_payload(reply.data)

    async def list(
        self,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int | None = None,
    ) -> Page[VolumeInfo]:
        """One page of volumes; ``labels`` keeps those carrying every given label."""
        params = _list_params(labels, cursor, limit)
        return _page(await self._transport.request("GET", VOLUMES_PATH, params=params))

    async def iter(
        self, *, labels: Mapping[str, str] | None = None, limit: int | None = None
    ) -> AsyncIterator[VolumeInfo]:
        cursor: str | None = None
        while True:
            page = await self.list(labels=labels, cursor=cursor, limit=limit)
            for item in page.items:
                yield item
            if page.next_cursor is None:
                return
            cursor = page.next_cursor

    async def get(self, volume_id: str) -> VolumeInfo:
        reply = await self._transport.request("GET", volume_path(volume_id))
        return VolumeInfo.from_payload(reply.data)

    async def delete(self, volume_id: str) -> VolumeInfo:
        """Delete a volume; the server answers 409 (``Conflict``) while a sandbox mounts it."""
        reply = await self._transport.request("DELETE", volume_path(volume_id))
        return VolumeInfo.from_payload(reply.data)

    async def export(self, volume_id: str, path: PathArg) -> int:
        """Async counterpart of :meth:`Volumes.export`; returns the bytes written."""
        response = await self._transport.open_stream(
            "GET", export_path(volume_id), headers=_ARCHIVE_HEADERS,
            server_wait_s=EXPORT_FIRST_BYTE_S,
        )  # fmt: skip
        async with AsyncByteStream(response, EXPORT_CHUNK_BYTES) as stream:
            return await asave_stream(stream, Path(path))

    async def restore(
        self,
        volume_id: str,
        source: RestoreSource,
        *,
        size_bytes: int | None = None,
        chunk_size: int = UPLOAD_CHUNK_BYTES,
    ) -> VolumeRestore:
        """Async counterpart of :meth:`Volumes.restore`."""
        handle, owned = await asyncio.to_thread(_open_source, source)
        try:
            size, headers = _restore_request(handle, size_bytes)
            reply = await self._transport.request(
                "POST", restore_path(volume_id),
                content=aiter_file_chunks(handle, size, chunk_size),
                headers=headers, server_wait_s=RESTORE_WAIT_S,
            )  # fmt: skip
        finally:
            if owned:
                await asyncio.to_thread(handle.close)
        return VolumeRestore.from_payload(reply.data)
