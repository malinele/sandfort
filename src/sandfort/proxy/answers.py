"""Answers the preview proxy sends itself, instead of an upstream's, and request header reads.

``_Rejected`` is raised while a request is routed or handed off, before anything is sent.
``_reject`` sends it as the JSON error envelope with ``PROXY_RESPONSE_HEADERS``, as a denial
response on a websocket handshake that supports one, or else as a websocket close code.
"""

import json
from dataclasses import dataclass

from starlette.types import Scope, Send

from sandfort.api.envelope import fail
from sandfort.proxy.hygiene import PROXY_RESPONSE_HEADERS
from sandfort.proxy.limits import PreviewBusy
from sandfort.proxy.streaming import WS_INTERNAL_ERROR

WS_POLICY_VIOLATION = 1008


@dataclass(eq=False)  # exceptions keep identity semantics (and stay hashable)
class _Rejected(Exception):  # a request the proxy answers itself, instead of the upstream
    status: int
    code: str
    message: str
    headers: tuple[tuple[bytes, bytes], ...] = ()  # extra response headers


def _headers(scope: Scope) -> list[tuple[bytes, bytes]]:
    raw: list[tuple[bytes, bytes]] = scope.get("headers") or []
    return raw


def _header(scope: Scope, name: bytes) -> str | None:
    values = (value.decode("latin-1") for key, value in _headers(scope) if key.lower() == name)
    return next(values, None)


async def _reject(scope: Scope, send: Send, rejected: _Rejected | PreviewBusy) -> None:
    body = json.dumps(fail(rejected.code, rejected.message).model_dump(mode="json")).encode()
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", b"%d" % len(body)),
        *PROXY_RESPONSE_HEADERS,
        *rejected.headers,
    ]
    start = {"status": rejected.status, "headers": headers}
    if scope["type"] == "http":
        await send({"type": "http.response.start", **start})
        await send({"type": "http.response.body", "body": body})
    elif "websocket.http.response" in (scope.get("extensions") or {}):
        await send({"type": "websocket.http.response.start", **start})
        await send({"type": "websocket.http.response.body", "body": body})
    else:
        code = WS_INTERNAL_ERROR if rejected.status >= 500 else WS_POLICY_VIOLATION
        await send({"type": "websocket.close", "code": code})
