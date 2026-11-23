"""NodeUnavailable envelope and the streaming helpers moved out of the preview proxy."""

import httpx
import pytest
from fastapi import FastAPI
from starlette.types import Message

from sandfort.api.errors import register_exception_handlers
from sandfort.errors import NodeUnavailable, SandfortError
from sandfort.proxy.streaming import (
    HOP_BY_HOP,
    WS_INTERNAL_ERROR,
    WS_NORMAL_CLOSURE,
    _connection_listed,
    _request_body,
    _sendable_close_code,
)

RETRY_AFTER_S = 7


def _app() -> FastAPI:
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/stale")
    async def stale() -> None:
        raise NodeUnavailable(
            "the node that owns this sandbox is not available",
            reason="stale",
            node_id="beta",
            retry_after_s=RETRY_AFTER_S,
        )

    @app.get("/default")
    async def default() -> None:
        raise NodeUnavailable("unreachable", reason="unreachable", node_id="beta")

    return app


async def _get(path: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.get(path)


def test_node_unavailable_is_a_platform_error_with_stable_code() -> None:
    error = NodeUnavailable("down", reason="no_address", node_id="beta")

    assert isinstance(error, SandfortError)
    assert (error.code, error.status) == ("NODE_UNAVAILABLE", 503)
    assert error.details == {"reason": "no_address", "node_id": "beta"}
    assert error.retry_after_s == 1


async def test_node_unavailable_yields_the_standard_envelope() -> None:
    response = await _get("/stale")

    assert response.status_code == 503
    body = response.json()
    assert body["success"] is False
    assert body["error"]["code"] == "NODE_UNAVAILABLE"
    assert body["error"]["details"] == {"reason": "stale", "node_id": "beta"}


async def test_node_unavailable_sends_retry_after() -> None:
    response = await _get("/stale")

    assert response.headers["Retry-After"] == str(RETRY_AFTER_S)


async def test_node_unavailable_default_retry_after_is_one_second() -> None:
    response = await _get("/default")

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "1"


def test_hop_by_hop_set_names_connection_and_transfer_encoding() -> None:
    headers = {"Connection": "keep-alive", "Transfer-Encoding": "chunked", "Accept": "*/*"}

    kept = {key for key in headers if key.lower() not in HOP_BY_HOP}

    assert kept == {"Accept"}
    assert {"connection", "transfer-encoding", "upgrade", "te"} <= HOP_BY_HOP


def test_connection_header_lists_extra_hop_by_hop_names() -> None:
    assert _connection_listed("X-Trace, Keep-Alive ,") == {"x-trace", "keep-alive"}
    assert _connection_listed(None) == set()


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (None, WS_INTERNAL_ERROR),
        (1005, WS_NORMAL_CLOSURE),
        (1006, WS_NORMAL_CLOSURE),
        (1015, WS_NORMAL_CLOSURE),
        (1000, 1000),
        (1013, 1013),
        (4401, 4401),
    ],
)
def test_sendable_close_code_maps_unsendable_codes(code: int | None, expected: int) -> None:
    assert _sendable_close_code(code) == expected


async def test_request_body_yields_chunks_and_stops_on_last() -> None:
    messages: list[Message] = [
        {"type": "http.request", "body": b"ab", "more_body": True},
        {"type": "http.request", "body": b"", "more_body": True},
        {"type": "http.request", "body": b"cd", "more_body": False},
    ]

    async def receive() -> Message:
        return messages.pop(0)

    assert [chunk async for chunk in _request_body(receive)] == [b"ab", b"cd"]


async def test_request_body_stops_on_disconnect() -> None:
    async def receive() -> Message:
        return {"type": "http.disconnect"}

    assert [chunk async for chunk in _request_body(receive)] == []
