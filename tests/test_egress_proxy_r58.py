"""Egress proxy as a pivot (audit M2): denied networks, ports, tunnel caps, idle, token life.

Hermetic: the upstream is a loopback fake and the resolver is a stub, so no name is looked up
and no packet leaves the machine.
"""

import asyncio
import base64
import ipaddress
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime, timedelta

import pytest

from sandfort.config import egress_limits_from
from sandfort.egress.proxy import EgressProxy, ProxyConfig
from sandfort.egress.tokens import (
    EGRESS_TOKEN_TTL_S,
    InvalidEgressToken,
    mint_egress_token,
    verify_egress_token,
)
from sandfort.webhooks import ssrf

SECRET = "test-egress-secret"
SANDBOX = "sbx_test"
OTHER_SANDBOX = "sbx_other"
NAME = "upstream.test"
IO_TIMEOUT_S = 5.0
TTL_ENV = "SANDFORT_EGRESS_TOKEN_TTL_S"
DAY_S = 24 * 3600
INTERNAL_CIDRS = (
    "127.0.0.0/8",
    "169.254.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
    "fe80::/10",
)

type Resolver = Callable[[str], Awaitable[list[str]]]


def _now() -> datetime:
    return datetime.now(UTC)


def _token(sandbox_id: str = SANDBOX, ttl_s: int | None = None) -> str:
    return mint_egress_token(
        SECRET, sandbox_id=sandbox_id, allowlist=[NAME], now=_now(), ttl_s=ttl_s
    )


def _auth(sandbox_id: str = SANDBOX, token: str | None = None) -> str:
    credential = f"{sandbox_id}:{token or _token(sandbox_id)}"
    encoded = base64.b64encode(credential.encode()).decode("ascii")
    return f"Proxy-Authorization: Basic {encoded}"


def _permit_all(address: ssrf.IpAddress) -> None:
    """Stands in for the public-address rules so only the new checks are under test."""


def _resolve_to(*addresses: str) -> Resolver:
    async def resolve(host: str) -> list[str]:
        return list(addresses)

    return resolve


@asynccontextmanager
async def _streaming_echo() -> AsyncIterator[int]:
    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            with suppress(OSError):
                while data := await reader.read(1024):
                    writer.write(data)
                    await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    try:
        yield int(server.sockets[0].getsockname()[1])
    finally:
        server.close()
        await server.wait_closed()


@asynccontextmanager
async def _running(proxy: EgressProxy) -> AsyncIterator[int]:
    server = await proxy.start("127.0.0.1", 0)
    try:
        yield int(server.sockets[0].getsockname()[1])
    finally:
        server.close()
        await server.wait_closed()


class _Tunnels:
    """Opens CONNECT tunnels against the proxy and closes every one of them at the end."""

    def __init__(self, port: int) -> None:
        self._port = port
        self._writers: list[asyncio.StreamWriter] = []

    async def open(
        self, target: str, auth: str | None = None
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, int]:
        reader, writer = await asyncio.open_connection("127.0.0.1", self._port)
        self._writers.append(writer)
        lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}", auth or _auth()]
        writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), IO_TIMEOUT_S)
        return reader, writer, int(head.split(b" ", 2)[1])

    async def status(self, target: str, auth: str | None = None) -> int:
        return (await self.open(target, auth))[2]

    async def status_once_free(self, target: str, auth: str | None = None) -> int:
        """Poll while the proxy is still releasing a closed tunnel's slot."""
        status = 0
        for _ in range(50):
            status = await self.status(target, auth)
            if status != 429:
                break
            await asyncio.sleep(0.1)
        return status

    async def close(self) -> None:
        for writer in self._writers:
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()


@asynccontextmanager
async def _tunnels(proxy: EgressProxy) -> AsyncIterator[_Tunnels]:
    async with _running(proxy) as port:
        opened = _Tunnels(port)
        try:
            yield opened
        finally:
            await opened.close()


# ---- 1. denied networks --------------------------------------------------------------------


async def test_target_in_a_denied_cidr_is_refused_before_any_connection() -> None:
    proxy = EgressProxy(
        SECRET,
        resolver=_resolve_to("10.1.2.3"),
        checker=_permit_all,
        denied_networks=[ipaddress.ip_network("10.0.0.0/8")],
    )
    async with _tunnels(proxy) as tunnels:
        assert await tunnels.status(f"{NAME}:443") == 403


async def test_one_denied_answer_among_several_refuses_the_target() -> None:
    proxy = EgressProxy(
        SECRET,
        resolver=_resolve_to("198.51.100.7", "10.1.2.3"),
        checker=_permit_all,
        denied_networks=[ipaddress.ip_network("10.0.0.0/8")],
    )
    async with _tunnels(proxy) as tunnels:
        assert await tunnels.status(f"{NAME}:443") == 403


async def test_ipv4_mapped_ipv6_answer_cannot_slip_past_an_ipv4_denial() -> None:
    proxy = EgressProxy(
        SECRET,
        resolver=_resolve_to("::ffff:10.1.2.3"),
        checker=_permit_all,
        denied_networks=[ipaddress.ip_network("10.0.0.0/8")],
    )
    async with _tunnels(proxy) as tunnels:
        assert await tunnels.status(f"{NAME}:443") == 403


def test_default_config_denies_loopback_link_local_and_rfc1918() -> None:
    config = ProxyConfig.from_env({"SANDFORT_EGRESS_SECRET": SECRET})

    denied = {ipaddress.ip_network(cidr) for cidr in config.denied_cidrs}

    assert {ipaddress.ip_network(cidr) for cidr in INTERNAL_CIDRS} <= denied


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "169.254.169.254", "10.9.9.9", "172.20.0.1", "192.168.1.1", "::1", "fe80::1"],
)
async def test_default_proxy_refuses_internal_targets(address: str) -> None:
    config = ProxyConfig.from_env({"SANDFORT_EGRESS_SECRET": SECRET})
    proxy = EgressProxy.from_config(config, resolver=_resolve_to(address), checker=_permit_all)
    async with _tunnels(proxy) as tunnels:
        assert await tunnels.status(f"{NAME}:443") == 403


async def test_nodes_own_interface_address_is_refused() -> None:
    config = ProxyConfig.from_env({"SANDFORT_EGRESS_SECRET": SECRET})
    own = ipaddress.ip_address("192.0.2.77")
    proxy = EgressProxy.from_config(
        config, local_addresses=[own], resolver=_resolve_to("192.0.2.77"), checker=_permit_all
    )
    async with _tunnels(proxy) as tunnels:
        assert await tunnels.status(f"{NAME}:443") == 403


def test_denied_cidrs_setting_is_read_from_the_environment() -> None:
    limits = egress_limits_from({"SANDFORT_EGRESS_DENIED_CIDRS": "100.64.0.0/10, 192.0.2.5"})

    assert limits.denied_cidrs == ("100.64.0.0/10", "192.0.2.5/32")


@pytest.mark.parametrize("raw", ["not-a-cidr", "10.0.0.0/8,oops"])
def test_denied_cidrs_setting_rejects_garbage(raw: str) -> None:
    with pytest.raises(ValueError, match="SANDFORT_EGRESS_DENIED_CIDRS"):
        egress_limits_from({"SANDFORT_EGRESS_DENIED_CIDRS": raw})


# ---- 2. allowed ports ----------------------------------------------------------------------


def test_default_allowed_ports_are_443_and_80() -> None:
    assert egress_limits_from({}).allowed_ports == (443, 80)
    assert ProxyConfig.from_env({"SANDFORT_EGRESS_SECRET": SECRET}).allowed_ports == (443, 80)


@pytest.mark.parametrize("raw", ["", "0", "65536", "http", "443,,80", "-1"])
def test_allowed_ports_setting_rejects_garbage(raw: str) -> None:
    with pytest.raises(ValueError, match="SANDFORT_EGRESS_ALLOWED_PORTS"):
        egress_limits_from({"SANDFORT_EGRESS_ALLOWED_PORTS": raw})


async def test_connect_to_a_port_outside_the_setting_is_refused_without_resolving() -> None:
    calls: list[str] = []

    async def resolve(host: str) -> list[str]:
        calls.append(host)
        return ["127.0.0.1"]

    proxy = EgressProxy(SECRET, resolver=resolve, checker=_permit_all, allowed_ports=(443, 80))
    async with _tunnels(proxy) as tunnels:
        assert await tunnels.status(f"{NAME}:22") == 403
        assert await tunnels.status(f"{NAME}:8080") == 403
    assert calls == []


async def test_connect_to_an_allowed_port_reaches_the_fake_upstream() -> None:
    async with _streaming_echo() as echo_port:
        proxy = EgressProxy(
            SECRET,
            resolver=_resolve_to("127.0.0.1"),
            checker=_permit_all,
            allowed_ports=(echo_port,),
        )
        async with _tunnels(proxy) as tunnels:
            reader, writer, status = await tunnels.open(f"{NAME}:{echo_port}")
            writer.write(b"ping")
            await writer.drain()
            echoed = await asyncio.wait_for(reader.readexactly(4), IO_TIMEOUT_S)

    assert status == 200
    assert echoed == b"ping"


# ---- 3. per-sandbox connection cap and idle timeout ---------------------------------------


def test_default_cap_is_64_and_default_idle_timeout_is_300_seconds() -> None:
    limits = egress_limits_from({})

    assert (limits.max_connections, limits.idle_timeout_s) == (64, 300)


@pytest.mark.parametrize(
    "name", ["SANDFORT_EGRESS_MAX_CONNECTIONS_PER_SANDBOX", "SANDFORT_EGRESS_IDLE_TIMEOUT_S"]
)
@pytest.mark.parametrize("raw", ["0", "-3", "many"])
def test_cap_and_idle_settings_reject_non_positive_or_non_numeric(name: str, raw: str) -> None:
    with pytest.raises(ValueError, match=name):
        egress_limits_from({name: raw})


async def test_a_sandbox_over_its_cap_gets_429_while_others_are_unaffected() -> None:
    async with _streaming_echo() as echo_port:
        proxy = EgressProxy(
            SECRET, resolver=_resolve_to("127.0.0.1"), checker=_permit_all, max_connections=2
        )
        target = f"{NAME}:{echo_port}"
        async with _tunnels(proxy) as tunnels:
            _, first, first_status = await tunnels.open(target)
            _, _, second_status = await tunnels.open(target)
            third_status = await tunnels.status(target)
            other_status = await tunnels.status(target, _auth(OTHER_SANDBOX))
            first.close()
            freed_status = await tunnels.status_once_free(target)

    assert (first_status, second_status) == (200, 200)
    assert third_status == 429
    assert other_status == 200
    assert freed_status == 200


async def test_a_refused_request_does_not_leak_a_slot() -> None:
    proxy = EgressProxy(
        SECRET,
        resolver=_resolve_to("10.0.0.9"),
        checker=_permit_all,
        denied_networks=[ipaddress.ip_network("10.0.0.0/8")],
        max_connections=1,
    )
    async with _tunnels(proxy) as tunnels:
        statuses = [await tunnels.status(f"{NAME}:443") for _ in range(3)]

    assert statuses == [403, 403, 403]


async def test_an_idle_tunnel_is_closed_and_its_slot_freed() -> None:
    async with _streaming_echo() as echo_port:
        proxy = EgressProxy(
            SECRET,
            resolver=_resolve_to("127.0.0.1"),
            checker=_permit_all,
            max_connections=1,
            idle_timeout_s=0.3,
        )
        target = f"{NAME}:{echo_port}"
        async with _tunnels(proxy) as tunnels:
            reader, _, status = await tunnels.open(target)
            closed_with = await asyncio.wait_for(reader.read(), IO_TIMEOUT_S)
            reopened = await tunnels.status_once_free(target)

    assert status == 200
    assert closed_with == b""
    assert reopened == 200


async def test_a_tunnel_that_keeps_moving_bytes_is_not_closed_as_idle() -> None:
    async with _streaming_echo() as echo_port:
        proxy = EgressProxy(
            SECRET, resolver=_resolve_to("127.0.0.1"), checker=_permit_all, idle_timeout_s=0.4
        )
        async with _tunnels(proxy) as tunnels:
            reader, writer, _ = await tunnels.open(f"{NAME}:{echo_port}")
            echoed = b""
            for _ in range(5):  # 5 x 0.2 s outlasts the 0.4 s idle limit
                writer.write(b"x")
                await writer.drain()
                echoed += await asyncio.wait_for(reader.readexactly(1), IO_TIMEOUT_S)
                await asyncio.sleep(0.2)

    assert echoed == b"xxxxx"


# ---- 4. token lifetime ---------------------------------------------------------------------


def test_default_token_lifetime_is_seven_days(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(TTL_ENV, raising=False)
    now = _now()
    token = mint_egress_token(SECRET, sandbox_id=SANDBOX, allowlist=[NAME], now=now)

    claims = verify_egress_token(SECRET, token, now)

    assert claims.expires_at - claims.issued_at == timedelta(days=7)
    assert EGRESS_TOKEN_TTL_S == 7 * DAY_S


def test_token_lifetime_follows_the_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(TTL_ENV, "3600")
    now = _now()
    token = mint_egress_token(SECRET, sandbox_id=SANDBOX, allowlist=[NAME], now=now)

    claims = verify_egress_token(SECRET, token, now)

    assert claims.expires_at - claims.issued_at == timedelta(hours=1)


@pytest.mark.parametrize("raw", ["0", "59", str(401 * DAY_S), "week"])
def test_token_lifetime_setting_is_bounded(raw: str) -> None:
    with pytest.raises(ValueError, match=TTL_ENV):
        egress_limits_from({TTL_ENV: raw})


def test_token_expires_when_its_lifetime_has_passed() -> None:
    now = _now()
    token = mint_egress_token(SECRET, sandbox_id=SANDBOX, allowlist=[NAME], now=now, ttl_s=3600)

    verify_egress_token(SECRET, token, now + timedelta(minutes=59))
    with pytest.raises(InvalidEgressToken):
        verify_egress_token(SECRET, token, now + timedelta(hours=1, seconds=1))


def test_verifier_refuses_a_token_minted_for_longer_than_its_limit() -> None:
    now = _now()
    old_style = mint_egress_token(
        SECRET, sandbox_id=SANDBOX, allowlist=[NAME], now=now, ttl_s=400 * DAY_S
    )

    with pytest.raises(InvalidEgressToken):
        verify_egress_token(SECRET, old_style, now, max_lifetime_s=7 * DAY_S)
    verify_egress_token(SECRET, old_style, now)


async def test_proxy_answers_407_to_a_token_whose_lifetime_exceeds_its_limit() -> None:
    proxy = EgressProxy(
        SECRET,
        resolver=_resolve_to("127.0.0.1"),
        checker=_permit_all,
        max_token_lifetime_s=7 * DAY_S,
    )
    long_lived = _auth(token=_token(ttl_s=400 * DAY_S))
    async with _tunnels(proxy) as tunnels:
        assert await tunnels.status(f"{NAME}:443", long_lived) == 407
