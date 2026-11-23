"""Request body size limit, answered with the 413 ``PAYLOAD_TOO_LARGE`` envelope.

``BodyLimitMiddleware`` refuses a request whose ``Content-Length`` exceeds the limit before
the application reads a byte. A body without a (truthful) length, such as chunked transfer,
is counted as it streams and cut off at the same limit, so the API never buffers more than
the limit in memory. The filesystem upload and the volume restore stream large bodies under
their own cap, so they are exempt.
"""

import re

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sandfort.api.errors import REQUEST_ID_ATTR, error_response
from sandfort.errors import PayloadTooLarge

# Streamed raw bodies under their own cap: the fs upload and the volume restore.
UPLOAD_PATH = re.compile(
    r"/v1/sandboxes/[^/]+/toolbox/fs/upload/?|/v1/volumes/[^/]+/restore/?"
)
BODY_TOO_LARGE_MESSAGE = "request body is too large"


class _BodyTooLargeError(Exception):
    """Raised into the application when a streamed body crosses the limit."""


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        if max_bytes < 1:
            raise ValueError(f"request body limit must be at least 1 byte, got {max_bytes}")
        self.app = app
        self._max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or UPLOAD_PATH.fullmatch(scope["path"]) is not None:
            await self.app(scope, receive, send)
            return
        declared = Headers(scope=scope).get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > self._max_bytes:
            await self._refuse(scope, receive, send)
            return
        await self._serve_counting(scope, receive, send)

    async def _serve_counting(self, scope: Scope, receive: Receive, send: Send) -> None:
        seen = 0
        started = False
        refused = False

        async def counting_send(message: Message) -> None:
            nonlocal started
            if refused:
                return  # the 413 went out already; drop whatever the aborted app answers
            started = started or message["type"] == "http.response.start"
            await send(message)

        async def counting_receive() -> Message:
            nonlocal seen, refused
            message = await receive()
            if message["type"] != "http.request":
                return message
            seen += len(message.get("body", b""))
            if seen > self._max_bytes:
                if not started and not refused:
                    refused = True
                    await self._refuse(scope, receive, send)
                raise _BodyTooLargeError
            return message

        try:
            await self.app(scope, counting_receive, counting_send)
        except _BodyTooLargeError:
            if not refused:
                raise  # the response had started: the aborted stream cannot be answered

    async def _refuse(self, scope: Scope, receive: Receive, send: Send) -> None:
        refusal = PayloadTooLarge(BODY_TOO_LARGE_MESSAGE, details={"max_bytes": self._max_bytes})
        request_id = scope.get("state", {}).get(REQUEST_ID_ATTR)
        await error_response(refusal, request_id=request_id)(scope, receive, send)
