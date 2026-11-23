"""SDK code contexts r34: ``run_stream`` (sync and async) over server-sent events."""

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
    AsyncCodeContext,
    CellResult,
    CodeContext,
    InvalidResponseError,
    NoContainer,
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
RUN = f"/v1/sandboxes/{SID}/toolbox/code-contexts/{CID}/run"

Handler = Callable[[httpx.Request], httpx.Response]

RESULT: dict[str, Any] = {
    "exit_code": 0,
    "stdout": "a\nb\n",
    "stderr": "warn\n",
    "timed_out": False,
    "truncated": False,
    "duration_ms": 12,
    "sandbox_stopped": False,
    "stop_reason": None,
    "result": "42",
    "error": None,
}

EXPECTED_CHUNKS = [
    OutputChunk("stdout", "a\n"),
    OutputChunk("stderr", "warn\n"),
    OutputChunk("stdout", "b\n"),
]


def frame(event: str, payload: dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(payload)}\n\n"


def sse(*frames: str) -> httpx.Response:
    body = ": keepalive\n\n" + "".join(frames)
    return httpx.Response(
        200, content=body.encode(), headers={"Content-Type": "text/event-stream"}
    )


def full_stream() -> httpx.Response:
    return sse(
        frame("stdout", {"data": "a\n"}),
        frame("stderr", {"data": "warn\n"}),
        frame("stdout", {"data": "b\n"}),
        frame("result", RESULT),
    )


def failed(
    status: int, code: str, details: dict[str, Any] | None = None
) -> httpx.Response:
    error = {"code": code, "message": "boom", "details": details or {}, "request_id": "req_1"}
    body = {"success": False, "data": None, "error": error, "meta": None}
    return httpx.Response(status, json=body)


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


def test_run_stream_yields_chunks_in_order_then_the_cell_result() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return full_stream()

    events = list(sync_context(handler).run_stream("print(1)", timeout_s=20))

    assert events[:-1] == EXPECTED_CHUNKS
    assert events[-1] == CellResult.from_payload(RESULT)
    request = requests[0]
    assert (request.method, request.url.path) == ("POST", f"{RUN}/stream")
    assert request.headers["accept"] == "text/event-stream"
    body = {"language": "python", "code": "print(1)", "timeout_s": 20}
    assert json.loads(request.content) == body


def test_run_stream_result_equals_what_run_parses() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/stream"):
            return full_stream()
        return httpx.Response(200, json={"success": True, "data": RESULT, "meta": None})

    ctx = sync_context(handler)

    assert list(ctx.run_stream("x"))[-1] == ctx.run("x")


def test_run_stream_stops_after_the_result_event() -> None:
    response = sse(frame("result", RESULT), frame("stdout", {"data": "late"}))

    events = list(sync_context(lambda _: response).run_stream("x"))

    assert events == [CellResult.from_payload(RESULT)]


def test_run_stream_close_releases_the_response() -> None:
    stream = sync_context(lambda _: full_stream()).run_stream("x")

    assert next(stream) == EXPECTED_CHUNKS[0]
    stream.close()

    assert stream.closed


def test_run_stream_not_found_before_the_stream_raises_not_found() -> None:
    ctx = sync_context(lambda _: failed(404, "NOT_FOUND"))

    with pytest.raises(NotFound):
        ctx.run_stream("x")


def test_run_stream_no_container_before_the_stream_raises_no_container() -> None:
    details = {"reason": "no_container", "state": "stopped"}
    ctx = sync_context(lambda _: failed(409, "CONFLICT", details))

    with pytest.raises(NoContainer) as caught:
        ctx.run_stream("x")
    assert caught.value.state == "stopped"


def test_run_stream_without_a_result_raises_transport_error() -> None:
    response = sse(frame("stdout", {"data": "a"}), frame("stderr", {"data": "b"}))
    stream = sync_context(lambda _: response).run_stream("x")

    assert next(stream) == OutputChunk("stdout", "a")
    assert next(stream) == OutputChunk("stderr", "b")
    with pytest.raises(TransportError, match="before the result"):
        next(stream)
    assert stream.closed


def test_run_stream_with_an_empty_body_raises_transport_error() -> None:
    ctx = sync_context(lambda _: sse())

    with pytest.raises(TransportError):
        list(ctx.run_stream("x"))


def test_run_stream_malformed_output_event_raises_invalid_response() -> None:
    ctx = sync_context(lambda _: sse(frame("stdout", {"text": "a"})))

    with pytest.raises(InvalidResponseError):
        list(ctx.run_stream("x"))


def test_run_stream_ignores_unknown_event_types() -> None:
    ctx = sync_context(lambda _: sse(frame("progress", {"n": 1}), frame("result", RESULT)))

    assert list(ctx.run_stream("x")) == [CellResult.from_payload(RESULT)]


async def test_async_run_stream_yields_chunks_then_the_cell_result() -> None:
    ctx = async_context(lambda _: full_stream())

    stream = await ctx.run_stream("print(1)")
    async with stream:
        events = [event async for event in stream]

    assert events[:-1] == EXPECTED_CHUNKS
    assert events[-1] == CellResult.from_payload(RESULT)
    assert stream.closed


async def test_async_run_stream_without_a_result_raises_transport_error() -> None:
    ctx = async_context(lambda _: sse(frame("stdout", {"data": "a"})))

    with pytest.raises(TransportError, match="before the result"):
        async for _ in await ctx.run_stream("x"):
            pass


async def test_async_run_stream_not_found_before_the_stream_raises() -> None:
    ctx = async_context(lambda _: failed(404, "NOT_FOUND"))

    with pytest.raises(NotFound):
        await ctx.run_stream("x")
