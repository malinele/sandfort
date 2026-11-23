"""Response envelope: ``{"success", "data", "error", "meta"}`` (architecture D7).

Streams (SSE, WebSocket, downloads) do not use the envelope.
"""

from typing import Any

from pydantic import BaseModel

from sandfort.api.schemas.common import ErrorBody, Meta


class Envelope[T](BaseModel):
    success: bool
    data: T | None = None
    error: ErrorBody | None = None
    meta: Meta | None = None


def ok[T](data: T, *, meta: Meta | None = None) -> Envelope[T]:
    return Envelope(success=True, data=data, meta=meta)


def fail(
    code: str,
    message: str,
    *,
    details: dict[str, Any] | None = None,
    request_id: str | None = None,
) -> Envelope[None]:
    body = ErrorBody(code=code, message=message, details=details or {}, request_id=request_id)
    return Envelope(success=False, error=body)
