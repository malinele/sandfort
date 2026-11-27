"""Egress decision counters through ``EgressProxy.handle`` (backlog B21).

Hermetic: loopback listeners only. The upstream is a loopback echo server and the resolver is a
stub, so no name is looked up and no packet leaves the machine.
"""

import asyncio
import base64
import logging
import socket
import struct
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime

import pytest

from sandfort.egress import proxy as proxy_module
from sandfort.egress.deny_log import DenyLog
from sandfort.egress.metrics import CAP_HITS_TOTAL, DECISIONS_TOTAL
from sandfort.egress.proxy import EgressProxy
from sandfort.egress.tokens import mint_egress_token
from sandfort.webhooks import ssrf

SECRET = "test-egress-secret"
NAME = "upstream.test"
SOURCE = "127.0.0.1"
IO_TIMEOUT_S = 5.0
POLL_STEPS = 250
POLL_INTERVAL_S = 0.02
METHOD_DENY = {"decision": "deny", "status": "405", "reason_class": "method"}
ALLOWED = {"decision": "allow", "status": "200", "reason_class": "allowed"}
CAP_SANDBOX = {"decision": "deny", "status": "429", "reason_class": "cap_sandbox"}
CAP_SOURCE = {"decision": "deny", "status": "429", "reason_class": "cap_source"}
DROPPED = {"decision": "drop", "status": "none", "reason_class": "connection_error"}
MALFORMED = {"decision": "deny", "status": "400", "reason_class": "malformed"}
LABEL_KEYS = {"decision", "status", "reason_class", "scope"}


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class _Raising:
    def labels(self, *args: str, **kwargs: str) -> object:
        raise RuntimeError("boom")


def _denies(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [m for m in caplog.messages if m.startswith("deny ")]


def _auth(sandbox_id: str) -> str:
    token = mint_egress_token(
        SECRET, sandbox_id=sandbox_id, allowlist=[NAME], now=datetime.now(UTC)
    )
    encoded = base64.b64encode(f"{sandbox_id}:{token}".encode()).decode("ascii")
    return f"Proxy-Authorization: Basic {encoded}"


def _permit_all(address: ssrf.IpAddress) -> None:
    """Stands in for the public-address rules so only the counters are under test."""


async def _resolve(host: str) -> list[str]:
    return [SOURCE]


async def _until(check: Callable[[], bool]) -> None:
    for _ in range(POLL_STEPS):
        if check():
            return
        await asyncio.sleep(POLL_INTERVAL_S)
    raise AssertionError("condition was not reached")


@asynccontextmanager
async def _serve(proxy: EgressProxy) -> AsyncIterator[int]:
    server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()


async def _refused_status(port: int) -> int:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"GET / HTTP/1.1\r\n\r\n")
    await writer.drain()
    head = await asyncio.wait_for(reader.readline(), IO_TIMEOUT_S)
    writer.close()
    return int(head.split()[1])


async def _tunnel(
    port: int, upstream: int, sandbox_id: str, writers: list[asyncio.StreamWriter]
) -> int:
    reader, writer = await asyncio.open_connection(SOURCE, port)
    writers.append(writer)
    target = f"{NAME}:{upstream}"
    lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}", _auth(sandbox_id)]
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
    await writer.drain()
    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), IO_TIMEOUT_S)
    return int(head.split(b" ", 2)[1])


@asynccontextmanager
async def _echo_upstream() -> AsyncIterator[int]:
    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            with suppress(OSError):
                while data := await reader.read(1024):
                    writer.write(data)
                    await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(echo, SOURCE, 0)
    try:
        yield int(server.sockets[0].getsockname()[1])
    finally:
        server.close()
        await server.wait_closed()


class _Client:
    """Opens connections against a running proxy and closes all of them at the end."""

    def __init__(self, port: int) -> None:
        self._port = port
        self._writers: list[asyncio.StreamWriter] = []

    async def _connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await asyncio.open_connection(SOURCE, self._port)
        self._writers.append(writer)
        return reader, writer

    async def idle(self) -> asyncio.StreamWriter:
        """A half-open connection: connected, nothing sent."""
        return (await self._connect())[1]

    async def refused(self) -> int:
        """Connect, send nothing, and read the answer a refused connection gets at once."""
        reader, _ = await self._connect()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), IO_TIMEOUT_S)
        return int(head.split(b" ", 2)[1])

    async def drop(self, writer: asyncio.StreamWriter) -> None:
        writer.close()
        with suppress(OSError):
            await writer.wait_closed()

    async def close(self) -> None:
        for writer in self._writers:
            await self.drop(writer)


@asynccontextmanager
async def _client(proxy: EgressProxy) -> AsyncIterator[_Client]:
    server = await proxy.start(SOURCE, 0)
    client = _Client(int(server.sockets[0].getsockname()[1]))
    try:
        yield client
    finally:
        await client.close()
        server.close()
        await server.wait_closed()


async def test_each_refusal_is_counted_even_when_the_log_line_is_suppressed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")
    proxy = EgressProxy(SECRET, deny_log=DenyLog(interval_s=60.0, clock=_Clock()))

    async with _serve(proxy) as port:
        statuses = [await _refused_status(port) for _ in range(5)]

    assert statuses == [405] * 5
    assert proxy.metrics.value(DECISIONS_TOTAL, METHOD_DENY) == 5.0
    assert len(_denies(caplog)) == 1


async def test_an_allowed_tunnel_and_a_per_sandbox_cap_hit_are_counted() -> None:
    proxy = EgressProxy(SECRET, resolver=_resolve, checker=_permit_all, max_connections=1)
    writers: list[asyncio.StreamWriter] = []
    server = await proxy.start(SOURCE, 0)
    port = int(server.sockets[0].getsockname()[1])
    try:
        async with _echo_upstream() as upstream:
            try:
                statuses = [await _tunnel(port, upstream, "sbx_one", writers) for _ in range(3)]
            finally:  # the echo server's wait_closed needs the tunnels gone first
                for writer in writers:
                    writer.close()
                    with suppress(OSError):
                        await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()

    assert statuses == [200, 429, 429]
    metrics = proxy.metrics
    assert metrics.value(DECISIONS_TOTAL, ALLOWED) == 1.0
    assert metrics.value(DECISIONS_TOTAL, CAP_SANDBOX) == 2.0
    assert metrics.value(CAP_HITS_TOTAL, {"scope": "sandbox"}) == 2.0
    assert metrics.value(CAP_HITS_TOTAL, {"scope": "source"}) == 0.0
    assert metrics.value(CAP_HITS_TOTAL, {"scope": "global"}) == 0.0
    for family in metrics.registry.collect():
        for sample in family.samples:
            assert set(sample.labels) <= LABEL_KEYS
            for value in sample.labels.values():
                assert not any(text in value for text in ("sbx_", "upstream", "127.0.0.1"))


async def test_the_preauth_and_global_caps_count_their_own_scope() -> None:
    preauth = EgressProxy(SECRET, max_preauth_per_source=1)
    async with _client(preauth) as client:
        await client.idle()
        await _until(lambda: preauth.unauthenticated_from(SOURCE) == 1)

        assert await client.refused() == 429

    assert preauth.metrics.value(DECISIONS_TOTAL, CAP_SOURCE) == 1.0
    assert preauth.metrics.value(CAP_HITS_TOTAL, {"scope": "source"}) == 1.0

    ceiling = EgressProxy(SECRET, max_total_connections=1)
    async with _client(ceiling) as client:
        await client.idle()
        await _until(lambda: ceiling.open_connections == 1)

        assert await client.refused() == 503

    assert ceiling.metrics.value(CAP_HITS_TOTAL, {"scope": "global"}) == 1.0


async def test_a_request_read_timeout_counts_one_drop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proxy_module, "REQUEST_TIMEOUT_S", 0.05)
    proxy = EgressProxy(SECRET)
    server = await proxy.start(SOURCE, 0)
    port = int(server.sockets[0].getsockname()[1])
    try:
        reader, writer = await asyncio.open_connection(SOURCE, port)
        writer.write(b"CONNECT")  # no newline: the request never completes
        await writer.drain()

        assert await asyncio.wait_for(reader.read(), IO_TIMEOUT_S) == b""

        writer.close()
    finally:
        server.close()
        await server.wait_closed()

    assert proxy.metrics.value(DECISIONS_TOTAL, DROPPED) == 1.0
    assert proxy.metrics.value(DECISIONS_TOTAL, MALFORMED) == 0.0


async def test_a_failing_counter_never_reaches_the_connection(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")
    proxy = EgressProxy(SECRET, deny_log=DenyLog(interval_s=60.0, clock=_Clock()))
    monkeypatch.setattr(proxy.metrics, "_decisions", _Raising())

    async with _serve(proxy) as port:
        statuses = [await _refused_status(port) for _ in range(2)]

    assert statuses == [405, 405]
    assert len(_denies(caplog)) == 1
    assert proxy.metrics.failures == 2
    warnings = [m for m in caplog.messages if m.startswith("egress metrics failed")]
    assert len(warnings) == 1


def _raw_tunnel_request(sandbox_id: str, upstream: int) -> bytes:
    target = f"{NAME}:{upstream}"
    lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}", _auth(sandbox_id)]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


async def _client_that_leaves_early(proxy: EgressProxy, sent: bytes) -> None:
    async with _client(proxy) as client:
        writer = await client.idle()
        if sent:
            writer.write(sent)
            await writer.drain()
        await client.drop(writer)
        await _until(lambda: proxy.metrics.value(DECISIONS_TOTAL, DROPPED) >= 1.0)
        await _until(lambda: proxy.open_connections == 0)


@pytest.mark.parametrize(
    "sent", [b"", b"CONNECT upstream.test:443 HTTP/1.1\r\nHost: x\r\n"], ids=["nothing", "headers"]
)
async def test_a_client_that_closes_before_a_full_request_counts_one_drop(
    sent: bytes, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")
    proxy = EgressProxy(SECRET)

    await _client_that_leaves_early(proxy, sent)

    assert proxy.metrics.value(DECISIONS_TOTAL, DROPPED) == 1.0
    assert proxy.metrics.value(DECISIONS_TOTAL, MALFORMED) == 0.0
    assert len(_denies(caplog)) == 1  # the deny log line is unchanged by the counting


async def test_allow_is_counted_once_while_the_tunnel_is_still_open() -> None:
    proxy = EgressProxy(SECRET, resolver=_resolve, checker=_permit_all)
    writers: list[asyncio.StreamWriter] = []
    server = await proxy.start(SOURCE, 0)
    port = int(server.sockets[0].getsockname()[1])
    try:
        async with _echo_upstream() as upstream:
            try:
                status = await _tunnel(port, upstream, "sbx_open", writers)

                assert status == 200
                assert proxy.open_connections == 1  # the tunnel has not ended
                assert proxy.metrics.value(DECISIONS_TOTAL, ALLOWED) == 1.0
                assert proxy.metrics.value(DECISIONS_TOTAL, DROPPED) == 0.0
            finally:
                for writer in writers:
                    writer.close()
                    with suppress(OSError):
                        await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()


async def test_an_error_after_admission_keeps_the_allow_and_adds_no_drop() -> None:
    proxy = EgressProxy(SECRET, resolver=_resolve, checker=_permit_all)

    async def reset_on_drain(*args: object) -> None:
        raise ConnectionResetError("client went away at the 200")

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.drain = reset_on_drain  # type: ignore[method-assign]
        await proxy.handle(reader, writer)

    async with _echo_upstream() as upstream:
        server = await asyncio.start_server(handle, SOURCE, 0)
        port = int(server.sockets[0].getsockname()[1])
        try:
            reader, writer = await asyncio.open_connection(SOURCE, port)
            writer.write(_raw_tunnel_request("sbx_reset", upstream))
            await writer.drain()
            await asyncio.wait_for(reader.read(), IO_TIMEOUT_S)  # until the proxy closes it
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    assert proxy.metrics.value(DECISIONS_TOTAL, ALLOWED) == 1.0
    assert proxy.metrics.value(DECISIONS_TOTAL, DROPPED) == 0.0


async def test_an_upstream_that_resets_the_tunnel_adds_no_drop() -> None:
    proxy = EgressProxy(SECRET, resolver=_resolve, checker=_permit_all)

    async def reset(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sock = writer.get_extra_info("socket")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        writer.close()  # an RST, not a FIN

    upstream_server = await asyncio.start_server(reset, SOURCE, 0)
    upstream = int(upstream_server.sockets[0].getsockname()[1])
    server = await proxy.start(SOURCE, 0)
    port = int(server.sockets[0].getsockname()[1])
    try:
        reader, writer = await asyncio.open_connection(SOURCE, port)
        writer.write(_raw_tunnel_request("sbx_rst", upstream))
        await writer.drain()
        await asyncio.wait_for(reader.read(), IO_TIMEOUT_S)  # the 200, then the proxy closes
        await _until(lambda: proxy.open_connections == 0)
        writer.close()
        with suppress(OSError):
            await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()
        upstream_server.close()
        await upstream_server.wait_closed()

    assert proxy.metrics.value(DECISIONS_TOTAL, ALLOWED) == 1.0
    assert proxy.metrics.value(DECISIONS_TOTAL, DROPPED) == 0.0
