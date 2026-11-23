"""Egress proxy connection limits and node-address discovery (audit r58).

Hermetic: the upstream is a loopback fake, the resolver is a stub and the interface list is
read from fake proc files, so no name is looked up and no packet leaves the machine.
"""

import asyncio
import base64
import ipaddress
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sandfort.egress import proxy as proxy_module
from sandfort.egress.proxy import EgressProxy, ProxyConfig
from sandfort.egress.proxy_limits import (
    DEFAULT_MAX_PREAUTH_PER_SOURCE,
    DEFAULT_MAX_TOTAL_CONNECTIONS,
    ENV_MAX_PREAUTH_PER_SOURCE,
    ENV_MAX_TOTAL_CONNECTIONS,
    SlotTable,
    discover_local_addresses,
    interface_addresses,
)
from sandfort.egress.relay import relay
from sandfort.egress.tokens import mint_egress_token
from sandfort.webhooks import ssrf

SECRET = "test-egress-secret"
SANDBOX = "sbx_test"
NAME = "upstream.test"
SOURCE = "127.0.0.1"
IO_TIMEOUT_S = 5.0
POLL_STEPS = 250
POLL_INTERVAL_S = 0.02

type Resolver = Callable[[str], Awaitable[list[str]]]

FIB_TRIE = """Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 10.0.0.0/24 2 0 2
        |-- 10.0.0.0
           /24 link UNICAST
        |-- 10.0.0.5
           /32 host LOCAL
Local:
  +-- 0.0.0.0/0 3 0 5
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     |-- 10.0.0.5
        /32 host LOCAL
     |-- 10.0.0.255
        /32 link BROADCAST
     |-- 172.17.0.1
        /32 host LOCAL
     |-- not-an-address
        /32 host LOCAL
"""

IF_INET6 = """00000000000000000000000000000001 01 80 10 80       lo
fe800000000000000a0027fffe5c4a3b 02 40 20 80     eth0
20010db8000000000000000000000005 02 40 00 80     eth0
garbage line
"""

PROC_ADDRESSES = {
    "10.0.0.5",
    "127.0.0.1",
    "172.17.0.1",
    "::1",
    "fe80::a00:27ff:fe5c:4a3b",
    "2001:db8::5",
}


def _auth() -> str:
    token = mint_egress_token(SECRET, sandbox_id=SANDBOX, allowlist=[NAME], now=datetime.now(UTC))
    encoded = base64.b64encode(f"{SANDBOX}:{token}".encode()).decode("ascii")
    return f"Proxy-Authorization: Basic {encoded}"


def _permit_all(address: ssrf.IpAddress) -> None:
    """Stands in for the public-address rules so only the limits are under test."""


def _resolve_to(*addresses: str) -> Resolver:
    async def resolve(host: str) -> list[str]:
        return list(addresses)

    return resolve


def _proxy(
    *, max_total_connections: int | None = None, max_preauth_per_source: int | None = None
) -> EgressProxy:
    return EgressProxy(
        SECRET,
        resolver=_resolve_to(SOURCE),
        checker=_permit_all,
        max_total_connections=max_total_connections,
        max_preauth_per_source=max_preauth_per_source,
    )


async def _until(check: Callable[[], bool]) -> None:
    for _ in range(POLL_STEPS):
        if check():
            return
        await asyncio.sleep(POLL_INTERVAL_S)
    raise AssertionError("condition was not reached")


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

    async def tunnel(self, target: str, auth: str | None = None) -> int:
        reader, writer = await self._connect()
        lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}", auth or _auth()]
        writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), IO_TIMEOUT_S)
        return int(head.split(b" ", 2)[1])

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


# ---- global ceiling ------------------------------------------------------------------------


async def test_global_ceiling_refuses_the_next_connection() -> None:
    proxy = _proxy(max_total_connections=2)
    async with _echo_upstream() as upstream, _client(proxy) as client:
        assert await client.tunnel(f"{NAME}:{upstream}") == 200
        assert await client.tunnel(f"{NAME}:{upstream}") == 200

        assert await client.refused() == 503
        await _until(lambda: proxy.open_connections == 2)


async def test_global_ceiling_counts_half_open_connections() -> None:
    proxy = _proxy(max_total_connections=2)
    async with _client(proxy) as client:
        first = await client.idle()
        await client.idle()
        await _until(lambda: proxy.open_connections == 2)

        assert await client.refused() == 503

        await client.drop(first)
        await _until(lambda: proxy.open_connections == 1)


async def test_a_closed_tunnel_frees_its_global_slot() -> None:
    proxy = _proxy(max_total_connections=1)
    async with _echo_upstream() as upstream, _client(proxy) as client:
        assert await client.tunnel(f"{NAME}:{upstream}") == 200
        assert await client.refused() == 503

        await client.close()
        await _until(lambda: proxy.open_connections == 0)

        assert await client.tunnel(f"{NAME}:{upstream}") == 200


async def test_refused_requests_release_every_slot() -> None:
    proxy = _proxy(max_total_connections=2, max_preauth_per_source=2)
    async with _client(proxy) as client:
        for _ in range(6):
            assert await client.tunnel(f"{NAME}:443", auth="X-Nothing: here") == 407
        await client.close()
        await _until(lambda: proxy.open_connections == 0)
        assert proxy.unauthenticated_from(SOURCE) == 0


# ---- pre-authentication limit per source ---------------------------------------------------


async def test_preauth_limit_refuses_another_half_open_connection_from_the_source() -> None:
    proxy = _proxy(max_preauth_per_source=2)
    async with _client(proxy) as client:
        first = await client.idle()
        await client.idle()
        await _until(lambda: proxy.unauthenticated_from(SOURCE) == 2)

        assert await client.refused() == 429
        assert proxy.unauthenticated_from(SOURCE) == 2

        await client.drop(first)
        await _until(lambda: proxy.unauthenticated_from(SOURCE) == 1)


async def test_authenticated_tunnels_do_not_hold_a_preauth_slot() -> None:
    proxy = _proxy(max_preauth_per_source=1)
    async with _echo_upstream() as upstream, _client(proxy) as client:
        assert await client.tunnel(f"{NAME}:{upstream}") == 200
        assert await client.tunnel(f"{NAME}:{upstream}") == 200
        assert proxy.unauthenticated_from(SOURCE) == 0
        assert proxy.open_connections == 2


async def test_a_slow_request_releases_its_preauth_slot_at_the_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(proxy_module, "REQUEST_TIMEOUT_S", 0.2)
    proxy = _proxy(max_preauth_per_source=1)
    async with _client(proxy) as client:
        await client.idle()
        await _until(lambda: proxy.unauthenticated_from(SOURCE) == 1)
        await _until(lambda: proxy.unauthenticated_from(SOURCE) == 0)
        await _until(lambda: proxy.open_connections == 0)


# ---- configuration -------------------------------------------------------------------------


def test_default_ceiling_is_2048_and_preauth_limit_is_16() -> None:
    config = ProxyConfig.from_env({"SANDFORT_EGRESS_SECRET": SECRET})

    assert DEFAULT_MAX_TOTAL_CONNECTIONS == 2048
    assert DEFAULT_MAX_PREAUTH_PER_SOURCE == 16
    assert config.max_total_connections == 2048
    assert config.max_preauth_per_source == 16


def test_limits_are_read_from_the_environment() -> None:
    config = ProxyConfig.from_env(
        {
            "SANDFORT_EGRESS_SECRET": SECRET,
            ENV_MAX_TOTAL_CONNECTIONS: "100",
            ENV_MAX_PREAUTH_PER_SOURCE: "4",
        }
    )

    assert (config.max_total_connections, config.max_preauth_per_source) == (100, 4)


@pytest.mark.parametrize("name", [ENV_MAX_TOTAL_CONNECTIONS, ENV_MAX_PREAUTH_PER_SOURCE])
@pytest.mark.parametrize("raw", ["0", "-1", "abc", "", "1.5", "99999999"])
def test_limit_settings_reject_garbage(name: str, raw: str) -> None:
    with pytest.raises(ValueError, match=name):
        ProxyConfig.from_env({"SANDFORT_EGRESS_SECRET": SECRET, name: raw})


async def test_from_config_applies_the_global_ceiling() -> None:
    environ = {"SANDFORT_EGRESS_SECRET": SECRET, ENV_MAX_TOTAL_CONNECTIONS: "1"}
    config = ProxyConfig.from_env(environ)
    proxy = EgressProxy.from_config(config, resolver=_resolve_to(SOURCE), checker=_permit_all)
    async with _client(proxy) as client:
        await client.idle()
        await _until(lambda: proxy.open_connections == 1)
        assert await client.refused() == 503


def test_slot_table_refuses_past_its_limit_and_forgets_empty_keys() -> None:
    table = SlotTable(1)

    assert table.try_acquire("a")
    assert not table.try_acquire("a")
    assert table.try_acquire("b")
    table.release("a")
    table.release("a")  # an extra release never goes negative

    assert (table.held("a"), table.held("b"), table.total) == (0, 1, 1)


def test_unbounded_slot_table_still_counts() -> None:
    table = SlotTable(None)

    assert all(table.try_acquire("k") for _ in range(5))
    assert table.held("k") == 5


def test_moved_names_stay_importable_from_the_proxy_module() -> None:
    assert proxy_module.relay is relay
    assert proxy_module.discover_local_addresses is discover_local_addresses


# ---- node address discovery ----------------------------------------------------------------


def _proc(tmp_path: Path, fib_trie: str = FIB_TRIE, if_inet6: str = IF_INET6) -> Path:
    (tmp_path / "fib_trie").write_text(fib_trie)
    (tmp_path / "if_inet6").write_text(if_inet6)
    return tmp_path


def _texts(addresses: tuple[ssrf.IpAddress, ...]) -> set[str]:
    return {str(address) for address in addresses}


def test_interface_addresses_come_from_the_kernel_lists(tmp_path: Path) -> None:
    assert _texts(interface_addresses(_proc(tmp_path))) == PROC_ADDRESSES


def test_missing_proc_files_yield_no_interface_addresses(tmp_path: Path) -> None:
    assert interface_addresses(tmp_path / "missing") == ()


def test_discovery_unions_proc_socket_and_fallback(tmp_path: Path) -> None:
    found = discover_local_addresses(
        proc_net=_proc(tmp_path),
        interface_ipv4=lambda: ["192.0.2.40"],
        fallback=lambda: ["198.51.100.4", "::ffff:203.0.113.9", "junk"],
    )

    texts = _texts(found)
    assert PROC_ADDRESSES | {"192.0.2.40", "198.51.100.4"} <= texts
    assert "203.0.113.9" in texts  # ipv4-mapped answers are normalised
    assert len(texts) == len(found)


def test_discovery_falls_back_to_the_probe_without_proc(tmp_path: Path) -> None:
    found = discover_local_addresses(
        proc_net=tmp_path / "missing",
        interface_ipv4=lambda: [],
        fallback=lambda: ["198.51.100.4"],
    )

    assert _texts(found) == {"198.51.100.4"}


def test_discovery_warns_when_only_loopback_is_found(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    loopback_only = "Local:\n     |-- 127.0.0.1\n        /32 host LOCAL\n"
    with caplog.at_level(logging.WARNING, logger="sandfort.egress"):
        found = discover_local_addresses(
            proc_net=_proc(tmp_path, fib_trie=loopback_only, if_inet6=""),
            interface_ipv4=lambda: [],
            fallback=lambda: [],
        )

    assert _texts(found) == {"127.0.0.1"}
    assert "no non-loopback" in caplog.text


def test_discovery_survives_a_failing_interface_source(tmp_path: Path) -> None:
    def broken() -> list[str]:
        raise OSError("no ioctl here")

    found = discover_local_addresses(
        proc_net=_proc(tmp_path), interface_ipv4=broken, fallback=lambda: []
    )

    assert "10.0.0.5" in _texts(found)


def test_startup_logs_the_final_denied_set(caplog: pytest.LogCaptureFixture) -> None:
    config = ProxyConfig.from_env(
        {"SANDFORT_EGRESS_SECRET": SECRET, "SANDFORT_EGRESS_DENIED_CIDRS": "10.0.0.0/8"}
    )
    own = ipaddress.ip_address("192.0.2.77")
    with caplog.at_level(logging.INFO, logger="sandfort.egress"):
        proxy = proxy_module.build_proxy(config, discover=lambda: (own,))

    assert ipaddress.ip_network("192.0.2.77/32") in proxy.denied_networks
    assert "10.0.0.0/8" in caplog.text
    assert "192.0.2.77/32" in caplog.text
