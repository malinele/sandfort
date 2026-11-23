"""Follows the docker daemon's container "die" events and hands each one to a callback.

``ContainerExitWatcher`` runs one daemon thread that iterates ``client.events`` (docker-py,
``decode=True``, filtered to managed containers) and, for every event, schedules the callback on
the asyncio loop ``start()`` was called from (``call_soon_threadsafe``), so the callback is plain
loop code. It knows nothing about who listens.

The stream ends whenever the daemon restarts or the connection drops. The thread then waits
``RECONNECT_BACKOFF_S`` and reconnects, asking for events ``since`` the moment it lost the
stream, so an exit during the gap is replayed (a repeated event is harmless to a kick).
``stop()`` sets the stop flag, closes the live stream so the blocked read returns, and joins the
thread for at most ``STOP_JOIN_TIMEOUT_S``. Errors are logged at warning level and never escape.
"""

import asyncio
import logging
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any

from sandfort.drivers.docker.labels import managed_filters

logger = logging.getLogger(__name__)

RECONNECT_BACKOFF_S = 2.0  # pause before the stream is reopened after it ended or failed
STOP_JOIN_TIMEOUT_S = 5.0  # how long stop() waits for the thread to leave
EVENT_TYPE = "container"
EVENT_NAME = "die"
THREAD_NAME = "sandfort-docker-events"

ExitCallback = Callable[[Mapping[str, Any]], None]


def die_filters() -> dict[str, list[str]]:
    """Docker ``filters`` for exits of managed containers."""
    return {"type": [EVENT_TYPE], "event": [EVENT_NAME], **managed_filters()}


class ContainerExitWatcher:
    def __init__(
        self,
        client: Any,
        callback: ExitCallback,
        *,
        backoff_s: float = RECONNECT_BACKOFF_S,
    ) -> None:
        self._client = client
        self._callback = callback
        self._backoff_s = backoff_s
        self._stopping = threading.Event()
        self._stream_lock = threading.Lock()
        self._stream: Any | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        """Start following events; call from the loop that should run the callbacks."""
        if self.running:
            return
        self._loop = asyncio.get_running_loop()
        self._stopping.clear()
        self._thread = threading.Thread(target=self._run, name=THREAD_NAME, daemon=True)
        self._thread.start()

    async def stop(self) -> None:
        """End the thread: flag it, close the stream, join without blocking the loop."""
        thread, self._thread = self._thread, None
        self._stopping.set()
        self._close_stream()
        if thread is None:
            return
        await asyncio.to_thread(thread.join, STOP_JOIN_TIMEOUT_S)
        if thread.is_alive():
            logger.warning("docker event watcher did not stop within %ss", STOP_JOIN_TIMEOUT_S)

    def _run(self) -> None:
        since: int | None = None
        try:
            while not self._stopping.is_set():
                self._follow(since)
                since = int(time.time())
                self._stopping.wait(self._backoff_s)
        except Exception:  # the thread must never die loudly into the app
            logger.warning("docker event watcher stopped on an unexpected error", exc_info=True)

    def _follow(self, since: int | None) -> None:
        """One connection: open the stream, dispatch events until it ends, then close it."""
        try:
            options: dict[str, Any] = {"decode": True, "filters": die_filters()}
            if since is not None:
                options["since"] = since
            stream = self._client.events(**options)
            with self._stream_lock:
                self._stream = stream
            if self._stopping.is_set():
                return
            for event in stream:
                if self._stopping.is_set():
                    return
                if isinstance(event, Mapping) and not self._dispatch(event):
                    return
        except Exception as exc:
            if not self._stopping.is_set():
                logger.warning("docker event stream failed: %s", type(exc).__name__, exc_info=True)
        finally:
            self._close_stream()

    def _dispatch(self, event: Mapping[str, Any]) -> bool:
        """Hand ``event`` to the loop; False when the loop is gone and watching is pointless."""
        loop = self._loop
        if loop is None:
            return False
        try:
            loop.call_soon_threadsafe(self._invoke, event)
        except RuntimeError:  # the loop is closed
            logger.warning("docker event watcher: the event loop is closed; stopping")
            self._stopping.set()
            return False
        return True

    def _invoke(self, event: Mapping[str, Any]) -> None:
        try:
            self._callback(event)
        except Exception:
            logger.warning("docker exit callback failed", exc_info=True)

    def _close_stream(self) -> None:
        with self._stream_lock:
            stream, self._stream = self._stream, None
        close = getattr(stream, "close", None)
        if close is None:
            return
        try:
            close()
        except Exception:
            logger.debug("closing the docker event stream failed", exc_info=True)
