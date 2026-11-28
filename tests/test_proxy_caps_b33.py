"""Round 101 (B33): the preview proxy answers 503 above a concurrency cap and frees its slots."""

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from dataclasses import replace
from typing import Any

import httpx
import pytest
from tests.test_proxy import (
    LOOPBACK,
    SETTINGS,
    TIMEOUT_S,
    AsgiWebSocket,
    World,
    call,
    error_code,
    host_for,
)
from websockets.asyncio.server import ServerConnection, serve

from sandfort.proxy.app import create_proxy_app

SSE = {"content-type": "text/event-stream"}
SANDBOX_BUSY = "this preview has too many open requests, retry shortly"
PROXY_BUSY = "the preview proxy has too many open requests, retry shortly"


class EndlessStream(httpx.AsyncByteStream):
    def __init__(self) -> None:
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        while True:
            yield b"data: tick\n\n"
            await asyncio.sleep(0.01)

    async def aclose(self) -> None:
        self.closed = True


class BrokenStream(httpx.AsyncByteStream):
    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield b"first"
        raise httpx.ReadError("upstream went away")


class HoldingTransport(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.release = asyncio.Event()
        self.held = 0
        self.streams: list[EndlessStream] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/hold":
            self.held += 1
            await self.release.wait()
            return httpx.Response(200, stream=httpx.ByteStream(b"held"))
        if request.url.path == "/stream":
            self.streams.append(EndlessStream())
            return httpx.Response(200, headers=SSE, stream=self.streams[-1])
        if request.url.path == "/broken":
            return httpx.Response(200, stream=BrokenStream())
        return httpx.Response(200, stream=httpx.ByteStream(b"ok"))


class RawRequest:
    def __init__(self, app: Any, host: str, path: str) -> None:
        self.sent: list[dict[str, Any]] = []
        self.gone = asyncio.Event()
        self._started = False
        headers = [(b"host", host.encode())]
        scope = {"type": "http", "method": "GET", "path": path, "headers": headers}
        self.task = asyncio.create_task(app(scope, self.receive, self.send))

    async def receive(self) -> dict[str, Any]:
        if not self._started:
            self._started = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await self.gone.wait()
        return {"type": "http.disconnect"}

    async def send(self, message: dict[str, Any]) -> None:
        self.sent.append(message)

    def finished_body(self) -> bool:
        bodies = [m for m in self.sent if m["type"] == "http.response.body"]
        return any(m.get("more_body", False) is False for m in bodies)


def limited(world: World, client: httpx.AsyncClient, *, per_sandbox: int, total: int = 0) -> Any:
    settings = replace(
        SETTINGS, preview_max_concurrent_per_sandbox=per_sandbox, preview_max_concurrent=total
    )
    return create_proxy_app(
        settings, tokens=world.tokens, lookup=world.lookup, driver=world.driver, http_client=client
    )


async def status(proxy: Any, host: str, path: str = "/a") -> int:
    return (await call(proxy, "GET", host, path)).status_code


async def until(condition: Callable[[], bool]) -> None:
    async def poll() -> None:
        while not condition():
            await asyncio.sleep(0.005)

    await asyncio.wait_for(poll(), TIMEOUT_S)


@pytest.fixture
def world() -> World:
    return World()


@pytest.fixture
def transport() -> HoldingTransport:
    return HoldingTransport()


@pytest.fixture
async def holding(transport: HoldingTransport) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(transport=transport) as client:
        yield client


async def test_over_either_cap_is_503_capacity_with_retry_after(
    world: World, holding: httpx.AsyncClient, transport: HoldingTransport
) -> None:
    a, b, c = [await world.add(public=True) for _ in range(3)]
    proxy = limited(world, holding, per_sandbox=2, total=3)
    held = [asyncio.create_task(call(proxy, "GET", host_for(a.id), "/hold")) for _ in range(2)]
    await until(lambda: transport.held == 2)

    by_sandbox = await call(proxy, "GET", host_for(a.id), "/a")
    other = await status(proxy, host_for(b.id))
    held.append(asyncio.create_task(call(proxy, "GET", host_for(b.id), "/hold")))
    await until(lambda: transport.held == 3)
    in_total = await call(proxy, "GET", host_for(c.id), "/a")
    transport.release.set()
    done = await asyncio.gather(*held)
    after = (await status(proxy, host_for(a.id)), await status(proxy, host_for(c.id)))
    for refused in (by_sandbox, in_total):
        assert refused.status_code == 503
        assert error_code(refused) == "CAPACITY"
        assert refused.headers["retry-after"] == "1"
        assert refused.headers.get_list("cache-control") == ["no-store"]
    assert by_sandbox.json()["error"]["message"] == SANDBOX_BUSY
    assert in_total.json()["error"]["message"] == PROXY_BUSY
    assert other == 200
    assert [response.text for response in done] == ["held", "held", "held"]
    assert after == (200, 200)


async def test_a_cancelled_request_frees_its_slot(
    world: World, holding: httpx.AsyncClient, transport: HoldingTransport
) -> None:
    host = host_for((await world.add(public=True)).id)
    proxy = limited(world, holding, per_sandbox=1)
    task = asyncio.create_task(call(proxy, "GET", host, "/hold"))
    await until(lambda: transport.held == 1)

    assert await status(proxy, host) == 503
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert await status(proxy, host) == 200


async def test_a_client_disconnect_mid_stream_frees_the_slot(
    world: World, holding: httpx.AsyncClient, transport: HoldingTransport
) -> None:
    host = host_for((await world.add(public=True)).id)
    proxy = limited(world, holding, per_sandbox=1)
    request = RawRequest(proxy, host, "/stream")
    await until(lambda: len(request.sent) >= 3)

    assert await status(proxy, host) == 503
    request.gone.set()
    await asyncio.wait_for(request.task, TIMEOUT_S)
    assert request.sent[0]["status"] == 200
    assert transport.streams[0].closed is True
    assert not request.finished_body()
    assert await status(proxy, host) == 200


async def test_an_upstream_error_mid_body_frees_the_slot(
    world: World, holding: httpx.AsyncClient
) -> None:
    host = host_for((await world.add(public=True)).id)
    proxy = limited(world, holding, per_sandbox=1)
    request = RawRequest(proxy, host, "/broken")
    await asyncio.wait_for(request.task, TIMEOUT_S)

    bodies = [m["body"] for m in request.sent if m["type"] == "http.response.body"]
    assert request.sent[0]["status"] == 200
    assert bodies == [b"first"]
    assert not request.finished_body()
    assert await status(proxy, host) == 200


async def test_a_websocket_over_the_cap_is_refused_before_the_upstream(
    world: World, holding: httpx.AsyncClient, transport: HoldingTransport
) -> None:
    host = host_for((await world.add(public=True)).id)
    proxy = limited(world, holding, per_sandbox=1)
    task = asyncio.create_task(call(proxy, "GET", host, "/hold"))
    await until(lambda: transport.held == 1)
    extensions: dict[str, Any] = {"websocket.http.response": {}}

    session = AsgiWebSocket(proxy, host, **extensions)
    await session.connect()
    start = await session.next()
    body = await session.next()
    await session.finish()
    transport.release.set()
    await task

    assert start["type"] == "websocket.http.response.start"
    assert start["status"] == 503
    assert (b"retry-after", b"1") in start["headers"]
    assert json.loads(body["body"])["error"]["code"] == "CAPACITY"


async def test_a_websocket_bridge_holds_its_slot_until_it_closes(
    world: World, holding: httpx.AsyncClient
) -> None:
    async def echo_socket(connection: ServerConnection) -> None:
        async for message in connection:
            await connection.send(message)

    async with serve(echo_socket, LOOPBACK, 0) as server:
        port: int = server.sockets[0].getsockname()[1]
        host = host_for((await world.add(public=True, endpoint=(LOOPBACK, port))).id)
        proxy = limited(world, holding, per_sandbox=1)
        session = AsgiWebSocket(proxy, host, "/socket")
        await session.connect()
        accepted = await session.next()

        during = await status(proxy, host)
        await session.push({"type": "websocket.disconnect", "code": 1000})
        await session.finish()
        after = await status(proxy, host)

    assert accepted["type"] == "websocket.accept"
    assert (during, after) == (503, 200)
