"""Egress v2 round 1 (docs/egress-v2-design.md section 12.1, cases C1 to C16): the proxy.

Hermetic: loopback echo server only, no Docker. Allowed cases replace the upstream dial with a
recorder (the ``_open`` seam) so the dialed address is observable; denied cases assert the
status, the logged reason and how often the resolver ran. The v1 token path carries CIDR
entries in the ``allow`` claim unchanged.
"""

import asyncio
import base64
import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Collection, Sequence
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address, ip_network

import pytest

from sandfort.egress.proxy import EgressProxy
from sandfort.egress.relay import Connection
from sandfort.egress.tokens import mint_egress_token
from sandfort.webhooks import ssrf

SECRET = "cidr-rules-secret"
SANDBOX = "sbx_cidr"
IO_TIMEOUT_S = 5.0
PUBLIC_TARGET = "93.184.216.34"
PRIVATE_TARGET = "10.0.0.5"
STANDARD_PORTS = frozenset({443, 80})

type Resolver = Callable[[str], Awaitable[list[str]]]
type Checker = Callable[[ssrf.IpAddress], None]


def _auth_header(sandbox_id: str, token: str) -> str:
    raw = base64.b64encode(f"{sandbox_id}:{token}".encode()).decode("ascii")
    return f"Proxy-Authorization: Basic {raw}"


@pytest.fixture(autouse=True)
def _strict_vetting(monkeypatch: pytest.MonkeyPatch) -> None:
    """Other tests may opt in to private networks; the proxy tests need the default rules."""
    monkeypatch.setattr(ssrf, "_allow_private_networks", False)


@asynccontextmanager
async def _echo_server() -> AsyncIterator[int]:
    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            data = await reader.read(1024)
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


async def _exchange(port: int, lines: list[str]) -> bytes:
    """Send a raw request and read the answer until the proxy closes the connection."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
        await writer.drain()
        return await asyncio.wait_for(reader.read(), IO_TIMEOUT_S)
    finally:
        writer.close()
        with suppress(OSError):
            await writer.wait_closed()


def _status(raw: bytes) -> int:
    return int(raw.split(b" ", 2)[1])


def _connect(target: str, auth: str | None) -> list[str]:
    lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}"]
    if auth is not None:
        lines.append(auth)
    return lines


def _loopback_resolver(calls: list[str]) -> Resolver:
    async def resolve(host: str) -> list[str]:
        calls.append(host)
        return ["127.0.0.1"]

    return resolve


def _answers_resolver(calls: list[str], answers: Sequence[str]) -> Resolver:
    async def resolve(host: str) -> list[str]:
        calls.append(host)
        return list(answers)

    return resolve


def _permit_all(address: ssrf.IpAddress) -> None:
    """Stands in for the vetting rules where a case must get past them."""


class _Recorder:
    """Records each upstream dial and connects to a loopback echo server instead."""

    def __init__(self, echo_port: int) -> None:
        self._echo_port = echo_port
        self.dialed: list[tuple[list[ssrf.IpAddress], int]] = []

    async def open(self, addresses: list[ssrf.IpAddress], port: int) -> Connection:
        self.dialed.append((list(addresses), port))
        return await asyncio.open_connection("127.0.0.1", self._echo_port)


def _proxy(
    *,
    resolver: Resolver | None = None,
    checker: Checker | None = None,
    allowed_ports: Collection[int] | None = None,
    denied: Sequence[str] = (),
    recorder: _Recorder | None = None,
) -> EgressProxy:
    kwargs: dict[str, object] = {"allowed_ports": allowed_ports}
    kwargs["denied_networks"] = tuple(ip_network(cidr) for cidr in denied)
    if resolver is not None:
        kwargs["resolver"] = resolver
    if checker is not None:
        kwargs["checker"] = checker
    proxy = EgressProxy(SECRET, **kwargs)  # type: ignore[arg-type]
    if recorder is not None:
        proxy._open = recorder.open  # type: ignore[method-assign]  # test seam: no real dial
    return proxy


def _auth(allowlist: Sequence[str]) -> str:
    token = mint_egress_token(
        SECRET, sandbox_id=SANDBOX, allowlist=list(allowlist), now=datetime.now(UTC)
    )
    return _auth_header(SANDBOX, token)


async def _tunnel(proxy: EgressProxy, allowlist: Sequence[str], target: str) -> tuple[int, bytes]:
    """CONNECT, then send ``ping`` through the tunnel; returns (status, echoed bytes)."""
    async with _running(proxy) as port:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            request = "\r\n".join(_connect(target, _auth(allowlist))) + "\r\n\r\n"
            writer.write(request.encode("ascii"))
            await writer.drain()
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), IO_TIMEOUT_S)
            writer.write(b"ping")
            await writer.drain()
            echoed = await asyncio.wait_for(reader.readexactly(4), IO_TIMEOUT_S)
            return _status(head), echoed
        finally:
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()


async def _refused(proxy: EgressProxy, allowlist: Sequence[str], target: str) -> int:
    async with _running(proxy) as port:
        return _status(await _exchange(port, _connect(target, _auth(allowlist))))


def _reason(caplog: pytest.LogCaptureFixture, detail: str) -> bool:
    return f"reason={detail}" in caplog.text


async def test_c1_a_host_rule_admits_the_name_and_dials_the_resolved_address() -> None:
    calls: list[str] = []
    async with _echo_server() as echo_port:
        recorder = _Recorder(echo_port)
        proxy = _proxy(resolver=_loopback_resolver(calls), checker=_permit_all, recorder=recorder)

        status, echoed = await _tunnel(proxy, ("api.example.com",), "api.example.com:443")

    assert (status, echoed) == (200, b"ping")
    assert calls == ["api.example.com"]
    assert recorder.dialed == [([IPv4Address("127.0.0.1")], 443)]


async def test_c2_a_domain_rule_admits_a_subdomain() -> None:
    calls: list[str] = []
    async with _echo_server() as echo_port:
        recorder = _Recorder(echo_port)
        proxy = _proxy(resolver=_loopback_resolver(calls), checker=_permit_all, recorder=recorder)

        status, _ = await _tunnel(proxy, (".example.com",), "a.b.example.com:443")

    assert status == 200
    assert recorder.dialed == [([IPv4Address("127.0.0.1")], 443)]


async def test_c4_a_cidr_rule_admits_a_literal_inside_it_without_resolving() -> None:
    calls: list[str] = []
    async with _echo_server() as echo_port:
        recorder = _Recorder(echo_port)
        proxy = _proxy(resolver=_loopback_resolver(calls), checker=_permit_all, recorder=recorder)

        status, echoed = await _tunnel(proxy, ("198.51.100.0/24",), "198.51.100.7:443")

    assert (status, echoed) == (200, b"ping")
    assert recorder.dialed == [([IPv4Address("198.51.100.7")], 443)]
    assert calls == []


async def test_c7_an_ipv6_cidr_rule_admits_a_bracketed_literal_inside_it() -> None:
    calls: list[str] = []
    async with _echo_server() as echo_port:
        recorder = _Recorder(echo_port)
        proxy = _proxy(resolver=_loopback_resolver(calls), checker=_permit_all, recorder=recorder)

        status, _ = await _tunnel(proxy, ("2001:db8:10::/48",), "[2001:db8:10::5]:443")

    assert status == 200
    assert recorder.dialed == [([IPv6Address("2001:db8:10::5")], 443)]
    assert calls == []


async def test_c3_a_name_that_only_contains_the_domain_is_refused_before_resolving(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="sandfort.egress")
    calls: list[str] = []
    proxy = _proxy(resolver=_loopback_resolver(calls), checker=_permit_all)

    status = await _refused(proxy, (".example.com",), "example.com.evil.test:443")

    assert status == 403
    assert _reason(caplog, "host is not in the allowlist")
    assert calls == []


async def test_c5_a_literal_outside_every_cidr_rule_is_refused(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="sandfort.egress")
    calls: list[str] = []
    proxy = _proxy(resolver=_loopback_resolver(calls), checker=_permit_all)

    status = await _refused(proxy, ("198.51.100.0/24",), "198.51.101.7:443")

    assert status == 403
    assert _reason(caplog, "address is not in the allowlist")
    assert calls == []


async def test_c6_a_cidr_rule_never_admits_a_name(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="sandfort.egress")
    calls: list[str] = []
    proxy = _proxy(resolver=_answers_resolver(calls, ["198.51.100.7"]), checker=_permit_all)

    status = await _refused(proxy, ("198.51.100.0/24",), "name-resolving-into-range.test:443")

    assert status == 403
    assert _reason(caplog, "host is not in the allowlist")
    assert calls == []


async def test_c8_an_ipv4_mapped_literal_folds_to_ipv4_before_rule_match(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="sandfort.egress")
    calls: list[str] = []
    proxy = _proxy(resolver=_loopback_resolver(calls), checker=_permit_all)

    status = await _refused(proxy, ("2001:db8:10::/48",), "[::ffff:10.0.0.1]:443")

    assert status == 403
    assert _reason(caplog, "address is not in the allowlist")
    assert calls == []


async def test_c13_a_loose_number_is_a_name_that_no_rule_admits(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="sandfort.egress")
    calls: list[str] = []
    proxy = _proxy(resolver=_loopback_resolver(calls), checker=_permit_all)

    status = await _refused(proxy, ("api.example.com",), "2130706433:443")

    assert status == 403
    assert _reason(caplog, "host is not in the allowlist")
    assert calls == []


async def test_c16_an_empty_allowlist_denies_names_and_literals(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="sandfort.egress")
    calls: list[str] = []
    proxy = _proxy(resolver=_loopback_resolver(calls), checker=_permit_all)

    name_status = await _refused(proxy, (), "api.example.com:443")
    literal_status = await _refused(proxy, (), "198.51.100.7:443")

    assert (name_status, literal_status) == (403, 403)
    assert _reason(caplog, "host is not in the allowlist")
    assert _reason(caplog, "address is not in the allowlist")
    assert calls == []


@pytest.mark.parametrize(
    ("rule", "target", "detail"),
    [
        ("api.example.com", "api.example.com:22", "port 22 is not allowed"),  # C10
        ("198.51.100.0/24", "198.51.100.7:8443", "port 8443 is not allowed"),  # C11
    ],
)
async def test_c10_c11_the_port_check_runs_before_rule_match(
    caplog: pytest.LogCaptureFixture, rule: str, target: str, detail: str
) -> None:
    caplog.set_level(logging.WARNING, logger="sandfort.egress")
    calls: list[str] = []
    proxy = _proxy(
        resolver=_loopback_resolver(calls), checker=_permit_all, allowed_ports=STANDARD_PORTS
    )

    status = await _refused(proxy, (rule,), target)

    assert status == 403
    assert _reason(caplog, detail)
    assert calls == []


@pytest.mark.parametrize("port", [443, 8443])
async def test_c12_a_zone_id_is_a_400_before_the_port_check(
    caplog: pytest.LogCaptureFixture, port: int
) -> None:
    caplog.set_level(logging.WARNING, logger="sandfort.egress")
    calls: list[str] = []
    proxy = _proxy(
        resolver=_loopback_resolver(calls), checker=_permit_all, allowed_ports=STANDARD_PORTS
    )

    status = await _refused(proxy, ("fe80::/32", "api.example.com"), f"[fe80::1%eth0]:{port}")

    assert status == 400
    assert _reason(caplog, "zone id in target")
    assert calls == []


async def test_c9_a_translation_prefix_is_refused_even_when_a_rule_matches(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="sandfort.egress")
    proxy = _proxy(checker=_permit_all)

    status = await _refused(proxy, ("64:ff9b::/96",), "[64:ff9b::a00:1]:443")

    assert status == 403
    assert _reason(caplog, "blocked address: translation prefix")


async def test_c14_one_denied_answer_refuses_the_whole_request(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="sandfort.egress")
    calls: list[str] = []
    proxy = _proxy(resolver=_answers_resolver(calls, [PUBLIC_TARGET, PRIVATE_TARGET]))

    status = await _refused(proxy, ("api.example.com",), "api.example.com:443")

    assert status == 403
    assert "reason=blocked address" in caplog.text
    assert calls == ["api.example.com"]


async def test_c15_the_node_denied_list_wins_over_a_tenant_rule(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="sandfort.egress")
    proxy = _proxy(checker=_permit_all, denied=("198.51.100.0/24",))

    status = await _refused(proxy, ("198.51.100.0/24",), "198.51.100.7:443")

    assert status == 403
    assert _reason(caplog, "blocked address: in a denied network")
