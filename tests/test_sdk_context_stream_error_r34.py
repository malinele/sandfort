"""SDK code contexts r34: an ``error`` event in ``run_stream`` raises the mapped exception."""

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
from sandfort_sdk import (  # noqa: E402
    ApiError,
    AsyncCodeContext,
    CodeContext,
    NotFound,
    OutputChunk,
    TransportError,
)
from sandfort_sdk._transport import AsyncTransport, SyncTransport, client_kwargs  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
TIMEOUT_S = 30.0
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
CID = "ctx_0123456789abcdef"

Handler = Callable[[httpx.Request], httpx.Response]


def frame(event: str, payload: dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(payload)}\n\n"


def sse(*frames: str) -> httpx.Response:
    body = ": keepalive\n\n" + "".join(frames)
    return httpx.Response(
        200, content=body.encode(), headers={"Content-Type": "text/event-stream"}
    )


def error_stream(code: str, message: str) -> httpx.Response:
    return sse(
        frame("stdout", {"data": "a\n"}),
        frame("error", {"code": code, "message": message}),
    )


def sync_context(handler: Handler) -> CodeContext:
    transport = SyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    transport._http.close()
    transport._http = httpx.Client(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return CodeContext(SID, CID, "/work", transport)


def async_context(handler: Handler) -> AsyncCodeContext:
    transport = AsyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return AsyncCodeContext(SID, CID, "/work", transport)


def test_sync_error_event_raises_not_found_with_the_server_message() -> None:
    ctx = sync_context(lambda _: error_stream("NOT_FOUND", "code context was removed"))
    stream = ctx.run_stream("x")

    assert next(stream) == OutputChunk("stdout", "a\n")
    with pytest.raises(NotFound) as caught:
        next(stream)

    assert caught.value.message == "code context was removed"
    assert caught.value.code == "NOT_FOUND"
    assert stream.closed


async def test_async_error_event_raises_not_found_with_the_server_message() -> None:
    ctx = async_context(lambda _: error_stream("NOT_FOUND", "code context was removed"))
    stream = await ctx.run_stream("x")

    assert await anext(stream) == OutputChunk("stdout", "a\n")
    with pytest.raises(NotFound) as caught:
        await anext(stream)

    assert caught.value.message == "code context was removed"
    assert caught.value.code == "NOT_FOUND"
    assert stream.closed


def test_sync_error_event_with_an_unknown_code_raises_the_generic_error() -> None:
    ctx = sync_context(lambda _: error_stream("SOMETHING_NEW", "odd failure"))

    with pytest.raises(ApiError) as caught:
        list(ctx.run_stream("x"))

    assert type(caught.value) is ApiError
    assert caught.value.code == "SOMETHING_NEW"
    assert caught.value.message == "odd failure"


async def test_async_error_event_with_an_unknown_code_raises_the_generic_error() -> None:
    ctx = async_context(lambda _: error_stream("SOMETHING_NEW", "odd failure"))

    with pytest.raises(ApiError) as caught:
        async with await ctx.run_stream("x") as events:
            _ = [event async for event in events]

    assert type(caught.value) is ApiError
    assert caught.value.code == "SOMETHING_NEW"
    assert caught.value.message == "odd failure"


def test_sync_stream_without_result_or_error_still_raises_transport_error() -> None:
    ctx = sync_context(lambda _: sse(frame("stdout", {"data": "a\n"})))

    with pytest.raises(TransportError, match="before the result event"):
        list(ctx.run_stream("x"))


async def test_async_stream_without_result_or_error_still_raises_transport_error() -> None:
    ctx = async_context(lambda _: sse(frame("stdout", {"data": "a\n"})))

    with pytest.raises(TransportError, match="before the result event"):
        async with await ctx.run_stream("x") as events:
            _ = [event async for event in events]
