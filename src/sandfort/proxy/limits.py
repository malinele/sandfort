"""Concurrency caps of the preview proxy (B33) and the disconnect watch of an HTTP relay.

Every proxied request and websocket bridge holds one slot from routing until the body is sent
or the bridge closes, also on an upstream error or cancellation. A client disconnect frees it
while a response body is relayed or a bridge is open, and while a request without a body waits
for the upstream's response headers. A request with a body is not watched for a disconnect
after its body is sent and before those headers arrive: the header wait bound
(``SANDFORT_PREVIEW_RESPONSE_HEADER_TIMEOUT_S``, 0 is no bound) frees that slot, and the
proxy answers 502. Above the per-sandbox or the process cap the proxy answers 503
``CAPACITY`` with ``Retry-After: 1`` before it opens an upstream connection. A cap of 0 is no
cap.
"""

import logging
from functools import partial
from typing import Self

import anyio
import httpx
from anyio.lowlevel import checkpoint
from starlette.types import Receive, Send

from sandfort.config import Settings
from sandfort.proxy.streaming import _until_done

logger = logging.getLogger(__name__)

CAPACITY = "CAPACITY"
RETRY_AFTER_S = 1
RETRY_AFTER_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"retry-after", str(RETRY_AFTER_S).encode()),
)
SANDBOX_CAP = "sandbox"
PROXY_CAP = "proxy"
SANDBOX_BUSY_MESSAGE = "this preview has too many open requests, retry shortly"
PROXY_BUSY_MESSAGE = "the preview proxy has too many open requests, retry shortly"


class PreviewBusy(Exception):
    """A concurrency cap is reached, answered like a ``_Rejected`` of the proxy app."""

    status: int = 503
    code: str = CAPACITY
    headers: tuple[tuple[bytes, bytes], ...] = RETRY_AFTER_HEADERS

    def __init__(self, cap: str, message: str) -> None:
        super().__init__(message)
        self.cap = cap  # SANDBOX_CAP or PROXY_CAP
        self.message = message


class PreviewSlot:
    """One held slot: released once, by ``release`` or by leaving a ``with`` block."""

    def __init__(self, limits: "PreviewLimits", sandbox_id: str) -> None:
        self._limits = limits
        self._sandbox_id = sandbox_id
        self._held = True

    def release(self) -> None:
        if self._held:
            self._held = False
            self._limits._release(self._sandbox_id)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.release()


class PreviewLimits:
    """Counts the open preview requests and bridges per sandbox and in the process."""

    def __init__(self, per_sandbox: int, total: int, header_timeout_s: float = 0.0) -> None:
        if per_sandbox < 0 or total < 0:
            raise ValueError("preview concurrency caps must be 0 (no cap) or more")
        if header_timeout_s < 0:
            raise ValueError("the preview header wait must be 0 (no bound) or more seconds")
        self.per_sandbox = per_sandbox
        self.total = total
        self.header_timeout_s = header_timeout_s  # seconds, 0 = no bound
        self._by_sandbox: dict[str, int] = {}
        self._active = 0

    @classmethod
    def from_settings(cls, settings: Settings) -> Self:
        return cls(
            settings.preview_max_concurrent_per_sandbox,
            settings.preview_max_concurrent,
            settings.preview_response_header_timeout_s,
        )

    def active(self, sandbox_id: str | None = None) -> int:
        if sandbox_id is None:
            return self._active
        return self._by_sandbox.get(sandbox_id, 0)

    def tracked_sandboxes(self) -> int:
        return len(self._by_sandbox)

    def acquire(self, sandbox_id: str) -> PreviewSlot:
        held = self._by_sandbox.get(sandbox_id, 0)
        if self.per_sandbox and held >= self.per_sandbox:
            raise PreviewBusy(SANDBOX_CAP, SANDBOX_BUSY_MESSAGE)
        if self.total and self._active >= self.total:
            raise PreviewBusy(PROXY_CAP, PROXY_BUSY_MESSAGE)
        self._by_sandbox[sandbox_id] = held + 1
        self._active += 1
        return PreviewSlot(self, sandbox_id)

    def _release(self, sandbox_id: str) -> None:
        left = self._by_sandbox.get(sandbox_id, 0) - 1
        if left > 0:
            self._by_sandbox[sandbox_id] = left
        else:
            self._by_sandbox.pop(sandbox_id, None)
        self._active = max(0, self._active - 1)


async def send_upstream(
    client: httpx.AsyncClient,
    request: httpx.Request,
    receive: Receive,
    *,
    timeout_s: float,
    watch_disconnect: bool,
) -> httpx.Response | None:
    """Send ``request`` with ``stream=True`` and wait for the upstream's response headers.

    ``timeout_s`` bounds that wait (0 is no bound): on expiry ``httpx.ReadTimeout`` is raised,
    which the proxy answers with 502. With ``watch_disconnect`` the wait also ends when the
    client disconnects, and ``None`` is returned (a response that arrived in the same moment is
    closed). It must be false for a request with a body: the body iterator reads ``receive``.
    """
    responses: list[httpx.Response] = []
    failures: list[httpx.HTTPError] = []
    gone: list[bool] = []

    async def deliver() -> None:
        try:
            responses.append(await client.send(request, stream=True))
        except httpx.HTTPError as exc:  # raised below, a task group would wrap it in a group
            failures.append(exc)

    async def watch() -> None:
        await _disconnected(receive)
        gone.append(True)

    with anyio.move_on_after(timeout_s or None) as deadline:
        if watch_disconnect:
            async with anyio.create_task_group() as group:
                group.start_soon(_until_done, group.cancel_scope, deliver)
                group.start_soon(_until_done, group.cancel_scope, watch)
        else:
            await deliver()
    if responses and (gone or deadline.cancelled_caught):
        await responses[0].aclose()
    if gone:
        return None
    if deadline.cancelled_caught:
        raise httpx.ReadTimeout("no response headers from the sandbox in time", request=request)
    if failures:
        raise failures[0]
    return responses[0]


async def relay_response_body(response: httpx.Response, send: Send, receive: Receive) -> None:
    """Send the upstream body until it ends or the client disconnects.

    uvicorn drops writes to a closed connection without cancelling the app, so an endless
    upstream body would keep relaying after the client left. An upstream error mid-body is
    logged and cuts the response.
    """
    async with anyio.create_task_group() as group:
        group.start_soon(_until_done, group.cancel_scope, partial(_relay, response, send))
        group.start_soon(_until_done, group.cancel_scope, partial(_disconnected, receive))


async def _relay(response: httpx.Response, send: Send) -> None:
    try:
        async for chunk in response.aiter_raw():
            await send({"type": "http.response.body", "body": chunk, "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})
    except httpx.HTTPError as exc:  # mid-body: the status is sent, so the response is cut
        logger.warning("preview upstream stream broke: %s", type(exc).__name__)


async def _disconnected(receive: Receive) -> None:
    """Return once the client has gone, unread request body messages are skipped.

    The checkpoint lets the relay run, and lets this task be cancelled, even when ``receive``
    answers without ever waiting (a raw ASGI caller in the tests does that).
    """
    while (await receive())["type"] != "http.disconnect":
        await checkpoint()
