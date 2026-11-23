"""Snapshot export: a sanitized single-layer ``docker save`` of a stored image.

A snapshot is a ``docker commit`` of a container, so its image config keeps the container's
whole ``Env`` (user values the API masks, the egress proxy url with its signed token) and docker
cannot remove them at commit time. The export therefore never streams the stored image. It
creates a container from it without starting it, pipes that container's filesystem into a
``docker import`` whose config comes only from ``config_changes`` (``CARRIED_ENV`` entries and
the working directory, no labels; the tar is filtered on the way to drop the platform members —
the disk reserve file and Docker's ``/.dockerenv`` marker, see ``tar_filter``), and streams
``docker save`` of that temporary image by its
image id, so the tar carries no repository tag. The temporary container is created with labels
that override the snapshot image's (not managed, no sandbox id), so the reconciler never sees it.

The create, the import and the id lookup run in ONE blocking function. A cancelled caller is
handed back at once while that function keeps running, so ``_Handoff`` decides who removes the
temporary container and image: the function itself when it fails or finishes after the caller
left, the async ``finally`` once the function has returned.

The save stream is read from worker threads. ``GuardedStream`` serializes every read and the
close with one lock; ``close`` first closes the HTTP response outside that lock (this unblocks a
stalled read, the socket timeout being disabled), then closes docker-py's generator under it.
"""

import logging
import threading
import uuid
from collections.abc import AsyncIterator, Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import anyio

from sandfort.drivers.docker.client import map_driver_error, run_blocking, translate_errors
from sandfort.drivers.docker.images import config_changes
from sandfort.drivers.docker.labels import LABEL_MANAGED, LABEL_SANDBOX_ID
from sandfort.drivers.docker.lanes import run_bulk
from sandfort.drivers.docker.tar_filter import drop_platform_members
from sandfort.drivers.errors import DriverError, DriverNotFound

logger = logging.getLogger(__name__)

EXPORT_CHUNK_BYTES = 1024 * 1024  # size of one ``docker save`` read
EXPORT_REPOSITORY = "sandfort-export-tmp"  # temporary images only; never a snapshot repository
_PLACEHOLDER_COMMAND = ["/bin/true"]  # ``create`` refuses an image with neither Cmd nor Entrypoint
# Override the snapshot image's labels: the temporary container is not a managed sandbox.
TEMP_CONTAINER_LABELS: Mapping[str, str] = {LABEL_MANAGED: "false", LABEL_SANDBOX_ID: ""}


class GuardedStream:
    """A blocking chunk iterator whose reads and the iterator close are serialized by one lock.

    ``close`` first closes the HTTP ``response`` outside the lock (that unblocks a read stuck on
    the socket), then waits for the read in flight and closes the iterator (when it has
    ``close``). It never raises: a failure is logged. After ``close`` every read reports the end
    of the stream.
    """

    def __init__(self, chunks: Iterator[bytes], response: Any | None = None) -> None:
        self._chunks = chunks
        self._response = response
        self._lock = threading.Lock()  # serializes reads and the iterator close
        self._claim = threading.Lock()  # held only to decide which close call does the work
        self._closing = False
        self._closed = False

    def read(self) -> bytes | None:
        with self._lock:
            if self._closed:
                return None
            return next(self._chunks, None)

    def close(self) -> None:
        with self._claim:
            if self._closing:
                return
            self._closing = True
        self._close_quietly(getattr(self._response, "close", None), "http response")
        with self._lock:
            self._closed = True
            self._close_quietly(getattr(self._chunks, "close", None), "chunk iterator")

    @staticmethod
    def _close_quietly(close: Callable[[], Any] | None, what: str) -> None:
        if close is None:
            return
        try:
            close()
        except Exception:
            logger.warning("closing the export %s failed", what, exc_info=True)


def open_save_stream(api: Any, reference: str) -> GuardedStream:
    """Blocking: start ``docker save``; a missing image raises here, before any byte.

    Same request as docker-py's ``get_image``, but the response stays in hand to be closed.
    """
    response = api._get(api._url("/images/{0}/get", reference), stream=True)
    try:
        api._raise_for_status(response)
        api._disable_socket_timeout(api._get_raw_response_socket(response))
        chunks = iter(response.iter_content(EXPORT_CHUNK_BYTES, False))
    except BaseException:
        response.close()
        raise
    return GuardedStream(chunks, response)


def _next_chunk(reference: str, stream: GuardedStream) -> bytes | None:
    with translate_errors(reference, "image.export.read"):
        return stream.read()


def _source_config(api: Any, reference: str) -> dict[str, Any]:
    config = api.inspect_image(reference).get("Config") or {}
    return dict(config)


@dataclass(frozen=True)
class _TempNames:
    """The names of the temporary container and image of one export."""

    container: str
    repository: str
    tag: str

    @property
    def image(self) -> str:
        return f"{self.repository}:{self.tag}"


def _create_container(api: Any, reference: str, name: str, has_command: bool) -> str:
    """Blocking: a never-started, network-less, unmanaged container of the image; returns its id."""
    created = api.create_container(
        reference,
        command=None if has_command else _PLACEHOLDER_COMMAND,
        name=name,
        network_disabled=True,
        labels=dict(TEMP_CONTAINER_LABELS),
    )
    return str(created["Id"])


def _import_filtered(
    api: Any, container_id: str, repository: str, tag: str, changes: Sequence[str]
) -> None:
    """Blocking: stream ``docker export`` through the reserve-file filter into ``docker import``.

    The platform's disk reserve file (``/.sandfort-reserve``) means nothing outside Sandfort, so
    the tar is filtered member by member and never buffered whole.
    """
    stream = api.export(container_id)
    try:
        api.import_image(
            src=drop_platform_members(stream),
            repository=repository,
            tag=tag,
            changes=list(changes) or None,
            stream_src=True,
        )
    finally:
        close = getattr(stream, "close", None)
        if close is not None:
            close()


def _remove_quietly(remove: Callable[[], Any], what: str) -> None:
    """Blocking: run a removal; a missing target is expected, any other failure is logged."""
    try:
        remove()
    except Exception as exc:
        if isinstance(map_driver_error(exc), DriverNotFound):  # pure mapper: no log line
            return  # never created, or already gone
        logger.warning("removing the export %s failed", what, exc_info=True)


def _cleanup(api: Any, container_name: str, temp_reference: str) -> None:
    """Blocking: remove the temporary container and image by name; log, never raise."""
    _remove_quietly(lambda: api.remove_container(container_name, v=True, force=True), "container")
    _remove_quietly(lambda: api.remove_image(temp_reference, force=True), "image")


class _Handoff:
    """Decides who removes the temporary container and image of one export.

    The blocking build function keeps running when its caller is cancelled. Exactly one side
    cleans up: the build function when it fails, or when it finishes after the caller left;
    the async side when the function returned before that (``abandon``).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._abandoned = False
        self._state = "new"  # new -> running -> built | cleaned

    def begin(self) -> bool:
        """Thread: False when the caller is already gone, so nothing may be created."""
        with self._lock:
            if self._abandoned:
                return False
            self._state = "running"
            return True

    def failed(self) -> None:
        """Thread: the build failed; the thread removes what it created itself."""
        with self._lock:
            self._state = "cleaned"

    def finished(self) -> bool:
        """Thread: the build succeeded; True when the thread must clean up (caller gone)."""
        with self._lock:
            if self._abandoned:
                self._state = "cleaned"
                return True
            self._state = "built"
            return False

    def abandon(self) -> bool:
        """Async ``finally``: True when the async side must clean up (the build is done)."""
        with self._lock:
            self._abandoned = True
            if self._state != "built":
                return False  # not started (never will), failed (cleaned) or still running
            self._state = "cleaned"
            return True


def _build_temp_image(
    api: Any, handoff: _Handoff, reference: str, names: _TempNames, config: dict[str, Any]
) -> str:
    """Blocking: create the container, import its filesystem, return the temporary image id.

    One function, so what it created is removed here when it fails or is interrupted, however
    late docker answers.
    """
    if not handoff.begin():
        raise DriverError("snapshot export was cancelled before it started")
    has_command = bool(config.get("Cmd") or config.get("Entrypoint"))
    try:
        container_id = _create_container(api, reference, names.container, has_command)
        _import_filtered(api, container_id, names.repository, names.tag, config_changes(config))
        image_id = str(api.inspect_image(names.image)["Id"])
    except BaseException:
        handoff.failed()
        _cleanup(api, names.container, names.image)
        raise
    if handoff.finished():
        _cleanup(api, names.container, names.image)
    return image_id


async def export_image(client: Any, reference: str) -> AsyncIterator[bytes]:
    """Stream a sanitized single-layer ``docker save`` tar of ``reference``.

    The temporary image is built on the first ``anext``, so a missing image raises
    ``DriverNotFound`` before any byte is yielded. It is saved by image id, so the tar names no
    repository. Chunks are at most ``EXPORT_CHUNK_BYTES``; each blocking read runs through
    ``run_bulk``, off the loop.
    """
    api = client.api
    tag = uuid.uuid4().hex
    names = _TempNames(f"{EXPORT_REPOSITORY}-{tag}", EXPORT_REPOSITORY, tag)
    handoff = _Handoff()
    stream: GuardedStream | None = None
    try:
        with translate_errors(reference, "image.export"):
            config = await run_blocking(_source_config, api, reference)
            image_id = await run_bulk(_build_temp_image, api, handoff, reference, names, config)
            stream = await run_blocking(open_save_stream, api, image_id)
        while True:
            chunk = await run_bulk(_next_chunk, reference, stream)
            if chunk is None:
                return
            if chunk:
                yield chunk
    finally:
        with anyio.CancelScope(shield=True):
            if stream is not None:
                await run_blocking(stream.close)
            if handoff.abandon():
                await run_blocking(_cleanup, api, names.container, names.image)
