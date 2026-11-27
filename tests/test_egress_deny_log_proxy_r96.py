"""Deny log throttle through ``EgressProxy.handle`` with authenticated sandboxes (B15).

Hermetic: the upstream is a loopback echo server, the resolver is a stub, and the clock of the
throttle is fake, so no name is looked up and no packet leaves the machine.
"""

import asyncio
import base64
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime

import pytest

from sandfort.egress.deny_log import DenyLog
from sandfort.egress.proxy import EgressProxy
from sandfort.egress.tokens import mint_egress_token
from sandfort.webhooks import ssrf

SECRET = "test-egress-secret"
NAME = "upstream.test"
SOURCE = "127.0.0.1"
IO_TIMEOUT_S = 5.0
CAP_REASON = "too many concurrent connections for sandbox"


class _Clock:
    now = 1000.0

    def __call__(self) -> float:
        return self.now


def _auth(sandbox_id: str) -> str:
    token = mint_egress_token(
        SECRET, sandbox_id=sandbox_id, allowlist=[NAME], now=datetime.now(UTC)
    )
    encoded = base64.b64encode(f"{sandbox_id}:{token}".encode()).decode("ascii")
    return f"Proxy-Authorization: Basic {encoded}"


def _permit_all(address: ssrf.IpAddress) -> None:
    """Stands in for the public-address rules so only the cap is under test."""


async def _resolve(host: str) -> list[str]:
    return [SOURCE]


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


def _cap_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [m for m in caplog.messages if m.startswith("deny ") and CAP_REASON in m]


async def test_connection_cap_deny_is_throttled_per_authenticated_sandbox(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")
    proxy = EgressProxy(
        SECRET,
        resolver=_resolve,
        checker=_permit_all,
        max_connections=1,
        deny_log=DenyLog(interval_s=60.0, clock=_Clock()),
    )
    writers: list[asyncio.StreamWriter] = []
    server = await proxy.start(SOURCE, 0)
    port = int(server.sockets[0].getsockname()[1])
    try:
        async with _echo_upstream() as upstream:
            try:
                for sandbox in ("sbx_one", "sbx_two"):  # each holds its single slot
                    assert await _tunnel(port, upstream, sandbox, writers) == 200

                statuses = [
                    await _tunnel(port, upstream, sandbox, writers)
                    for sandbox in ("sbx_one", "sbx_two", "sbx_one", "sbx_two", "sbx_one")
                ]
            finally:  # the echo server's wait_closed needs the tunnels gone first
                for writer in writers:
                    writer.close()
                    with suppress(OSError):
                        await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()

    assert statuses == [429] * 5  # every refusal is answered
    lines = _cap_lines(caplog)
    assert [line.split()[1] for line in lines] == ["sandbox=sbx_one", "sandbox=sbx_two"]
    assert all("status=429" in line and "suppressed" not in line for line in lines)
