"""Shared transport core: auth headers, envelope unwrapping, sync and async senders.

Streaming endpoints (downloads, server-sent events) skip the envelope on success; their
error statuses still carry one and are raised as typed errors before any byte is handed out.
"""

import asyncio
import importlib.metadata
import random
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from types import TracebackType
from typing import Any, NamedTuple, Self

import httpx

from sandfort_sdk._create_cleanup import CallAttempts, may_have_been_sent, transport_error
from sandfort_sdk._requests import (
    DEFAULT_MAX_RETRIES,
    Outcome,
    checked_max_retries,
    next_pause,
    parse_retry_after,
    parse_retry_after_header,
    plan_call,
)
from sandfort_sdk.exceptions import ApiError, InvalidResponseError, TransportError, error_for

DEFAULT_TIMEOUT_S = 30.0
# Added on top of a server-side wait/exec budget so the HTTP read does not expire first.
HTTP_MARGIN_S = 10.0
PACKAGE_NAME = "sandfort-sdk"
USER_AGENT_PRODUCT = "sandfort-sdk-python"
# Used when the package metadata is missing (an editable checkout run from sys.path). Must equal
# ``sandfort_sdk.__version__`` (it cannot be imported here: the package init imports this
# module); tests/test_client_config_r61.py checks that.
FALLBACK_USER_AGENT = "sandfort-sdk-python/0.1.0"


def build_user_agent() -> str:
    """``sandfort-sdk-python/<installed version>``; the fallback constant without metadata."""
    try:
        version = importlib.metadata.version(PACKAGE_NAME)
    except importlib.metadata.PackageNotFoundError:
        return FALLBACK_USER_AGENT
    if not version:
        return FALLBACK_USER_AGENT
    return f"{USER_AGENT_PRODUCT}/{version}"


_USER_AGENT = build_user_agent()


class Reply(NamedTuple):
    data: Any
    next_cursor: str | None
    request_id: str | None = None  # the ``x-request-id`` header of the reply
    status_code: int = httpx.codes.OK  # HTTP status of the final answer (after any resend)
    replayed: bool = False  # ``Idempotent-Replayed: true``: a stored answer, not a new run
    note: str | None = None  # ``meta.note``: a server warning about the answer, when it sent one


def _is_header_unsafe(api_key: str) -> bool:
    return any(ch.isspace() or not ch.isprintable() for ch in api_key)


def client_kwargs(base_url: str, api_key: str, timeout: float) -> dict[str, Any]:
    base_url = base_url.strip().rstrip("/").strip()
    api_key = api_key.strip()
    if not base_url:
        raise ValueError("base_url must not be empty")
    if not api_key:
        raise ValueError("api_key must not be empty")
    if _is_header_unsafe(api_key):
        # Fixed text only: the key must never be echoed, even when it is malformed.
        raise ValueError("api_key is malformed: it contains whitespace or control characters")
    return {
        "base_url": base_url,
        "headers": {
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "User-Agent": _USER_AGENT,
        },
        "timeout": timeout,
    }


def request_timeout(default: float, server_wait_s: float | None) -> float:
    if server_wait_s is None:
        return default
    return max(default, server_wait_s + HTTP_MARGIN_S)


def parse_response(response: httpx.Response) -> Reply:
    """Unwrap the ``{success, data, error, meta}`` envelope or raise a typed error."""
    try:
        body = response.json()
    except ValueError:
        body = None
    if isinstance(body, dict) and "success" in body:
        if body["success"]:
            meta = body.get("meta")
            cursor = meta.get("next_cursor") if isinstance(meta, dict) else None
            request_id = response.headers.get("x-request-id")
            replayed = response.headers.get("idempotent-replayed", "").lower() == "true"
            note = meta.get("note") if isinstance(meta, dict) else None
            return Reply(
                body.get("data"), cursor, request_id, response.status_code, replayed,
                note if isinstance(note, str) else None,
            )  # fmt: skip
        raise _envelope_error(body.get("error"), response)
    if response.is_error:
        raise error_for(
            f"HTTP_{response.status_code}",
            response.reason_phrase or "http error",
            status_code=response.status_code,
        )
    raise InvalidResponseError("response is not a Sandfort envelope")


def _envelope_error(error: Any, response: httpx.Response) -> ApiError:
    body = error if isinstance(error, dict) else {}
    retry_after = response.headers.get("Retry-After")
    return error_for(
        str(body.get("code", f"HTTP_{response.status_code}")),
        str(body.get("message", "request failed")),
        status_code=response.status_code,
        details=body.get("details") or None,
        request_id=body.get("request_id"),
        retry_after_s=parse_retry_after(retry_after),
        retry_after_header_s=parse_retry_after_header(retry_after),
    )


def _settle(attempts: CallAttempts, outcome: Outcome, now: float) -> Reply:
    if isinstance(outcome, httpx.HTTPError):
        raise attempts.error(outcome, now) from outcome
    return parse_response(outcome)


def _transport_error(method: str, path: str, exc: httpx.HTTPError) -> TransportError:
    return transport_error(method, path, exc, sent=may_have_been_sent(exc))


def stream_read_error(exc: httpx.HTTPError) -> TransportError:
    return TransportError(f"reading the response stream failed: {type(exc).__name__}: {exc}")


def _stream_error(response: httpx.Response) -> ApiError:
    """The typed error for an already-read failed streaming response."""
    try:
        parse_response(response)
    except ApiError as exc:
        return exc
    status = response.status_code
    return error_for(f"HTTP_{status}", "streaming request failed", status_code=status)


class SyncTransport:
    """``request`` resends a repeatable call on 429, 503 or a lost connection; streams never.

    Another call is resent only after a 429 ``RATE_LIMITED`` (the server did not process it).
    A one-shot ``content`` stream (an upload) is never resent: only no ``content`` or bytes,
    bytearray, memoryview (or ``json``) are. ``read_timeout_s`` fixes the timeout; with
    ``deadline`` (monotonic) each attempt gets connect, write, read and pool timeouts of at
    most the time left, none starts after it, and a pause past it is not taken; either way a
    timeout is not resent. A timeout says ``request_sent`` if any attempt may have been
    written. ``sleep``, ``rand`` and ``clock`` can be injected.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: float,
        *,
        max_retries: int = DEFAULT_MAX_RETRIES,
        sleep: Callable[[float], None] = time.sleep,
        rand: Callable[[], float] = random.random,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._timeout = timeout
        self._max_retries = checked_max_retries(max_retries)
        self._sleep = sleep
        self._rand = rand
        self._clock = clock
        self._http = httpx.Client(**client_kwargs(base_url, api_key, timeout))

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        content: Any = None,
        headers: dict[str, str] | None = None,
        server_wait_s: float | None = None,
        read_timeout_s: float | None = None,
        deadline: float | None = None,
    ) -> Reply:
        plan = plan_call(
            method, headers, content, timeout=request_timeout(self._timeout, server_wait_s),
            max_retries=self._max_retries, read_timeout_s=read_timeout_s, deadline=deadline,
        )  # fmt: skip
        attempts = CallAttempts(method, path, plan.deadline)
        attempt = 0
        while True:
            outcome: Outcome
            try:
                outcome = self._http.request(
                    method, path, params=params, json=json, content=content,
                    headers=headers, timeout=attempts.timeout(plan.timeout, self._clock()),
                )  # fmt: skip
            except httpx.HTTPError as exc:
                outcome = exc
            attempts.record(outcome)
            now = self._clock()
            pause = next_pause(plan, outcome, attempt, self._rand, now)
            if pause is None:
                return _settle(attempts, outcome, now)
            self._sleep(pause)
            attempt += 1

    def open_stream(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
        server_wait_s: float | None = None,
    ) -> httpx.Response:
        """Send and return the unread response; the caller must close it."""
        timeout = request_timeout(self._timeout, server_wait_s)
        request = self._http.build_request(
            method, path, params=params, json=json, headers=headers, timeout=timeout
        )
        try:
            response = self._http.send(request, stream=True)
        except httpx.HTTPError as exc:
            raise _transport_error(method, path, exc) from exc
        if not response.is_error:
            return response
        try:
            response.read()
        except httpx.HTTPError as exc:
            raise _transport_error(method, path, exc) from exc
        finally:
            response.close()
        raise _stream_error(response)

    def close(self) -> None:
        self._http.close()


class AsyncTransport:
    """Async counterpart of :class:`SyncTransport`, with the same retry rules."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: float,
        *,
        max_retries: int = DEFAULT_MAX_RETRIES,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        rand: Callable[[], float] = random.random,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._timeout = timeout
        self._max_retries = checked_max_retries(max_retries)
        self._sleep = sleep
        self._rand = rand
        self._clock = clock
        self._http = httpx.AsyncClient(**client_kwargs(base_url, api_key, timeout))

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        content: Any = None,
        headers: dict[str, str] | None = None,
        server_wait_s: float | None = None,
        read_timeout_s: float | None = None,
        deadline: float | None = None,
    ) -> Reply:
        plan = plan_call(
            method, headers, content, timeout=request_timeout(self._timeout, server_wait_s),
            max_retries=self._max_retries, read_timeout_s=read_timeout_s, deadline=deadline,
        )  # fmt: skip
        attempts = CallAttempts(method, path, plan.deadline)
        attempt = 0
        while True:
            outcome: Outcome
            try:
                outcome = await self._http.request(
                    method, path, params=params, json=json, content=content,
                    headers=headers, timeout=attempts.timeout(plan.timeout, self._clock()),
                )  # fmt: skip
            except httpx.HTTPError as exc:
                outcome = exc
            attempts.record(outcome)
            now = self._clock()
            pause = next_pause(plan, outcome, attempt, self._rand, now)
            if pause is None:
                return _settle(attempts, outcome, now)
            await self._sleep(pause)
            attempt += 1

    async def open_stream(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
        server_wait_s: float | None = None,
    ) -> httpx.Response:
        """Send and return the unread response; the caller must close it."""
        timeout = request_timeout(self._timeout, server_wait_s)
        request = self._http.build_request(
            method, path, params=params, json=json, headers=headers, timeout=timeout
        )
        try:
            response = await self._http.send(request, stream=True)
        except httpx.HTTPError as exc:
            raise _transport_error(method, path, exc) from exc
        if not response.is_error:
            return response
        try:
            await response.aread()
        except httpx.HTTPError as exc:
            raise _transport_error(method, path, exc) from exc
        finally:
            await response.aclose()
        raise _stream_error(response)

    async def aclose(self) -> None:
        await self._http.aclose()


class ByteStream:
    """Iterator over a streamed response body; exhausting or closing it releases the response."""

    def __init__(self, response: httpx.Response, chunk_size: int | None = None) -> None:
        self._response = response
        self._chunks = response.iter_bytes(chunk_size)

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> bytes:
        try:
            return next(self._chunks)
        except StopIteration:
            self.close()
            raise
        except httpx.HTTPError as exc:
            self.close()
            raise stream_read_error(exc) from exc

    def read_bytes(self) -> bytes:
        """Drain the remaining body into memory (convenience for small files)."""
        with self:
            return b"".join(self)

    def close(self) -> None:
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


class AsyncByteStream:
    """Async counterpart of :class:`ByteStream`."""

    def __init__(self, response: httpx.Response, chunk_size: int | None = None) -> None:
        self._response = response
        self._chunks: AsyncIterator[bytes] = response.aiter_bytes(chunk_size)

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> bytes:
        try:
            return await anext(self._chunks)
        except StopAsyncIteration:
            await self.aclose()
            raise
        except httpx.HTTPError as exc:
            await self.aclose()
            raise stream_read_error(exc) from exc

    async def read_bytes(self) -> bytes:
        async with self:
            return b"".join([chunk async for chunk in self])

    async def aclose(self) -> None:
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
