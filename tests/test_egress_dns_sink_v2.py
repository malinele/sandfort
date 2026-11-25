"""The egress DNS sink (egress v2 round 4; design 6.2, case D1).

Hermetic: the sink binds loopback on an ephemeral port (port 53 needs CAP_NET_BIND_SERVICE or
root, which tests do not assume). Queries are raw DNS wire bytes, so the sink is checked against
the protocol, not against a library that builds the packets.
"""

import asyncio
import logging
import socket
import struct
from collections.abc import AsyncIterator
from contextlib import suppress

import pytest

from sandfort.egress import dns_sink as sink_module
from sandfort.egress.dns_sink import DnsSink, serving_dns_sink
from sandfort.egress.proxy import ProxyConfig, _serve
from sandfort.egress.proxy_limits import ENV_DNS_SINK_LISTEN

LOOPBACK = "127.0.0.1"
SECRET_NAME = "zq7-exfil-payload-4f9c.attacker-example.test"
QUERY_ID = 0x4D2A
RCODE_REFUSED = 5
FLAG_QR = 0x8000
FLAG_RD = 0x0100
IO_TIMEOUT_S = 5.0
SILENCE_S = 0.3


def build_query(
    name: str = SECRET_NAME, *, qtype: int = 1, rd: bool = True, ident: int = QUERY_ID
) -> bytes:
    flags = FLAG_RD if rd else 0
    header = struct.pack("!HHHHHH", ident, flags, 1, 0, 0, 0)
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    return header + labels + b"\x00" + struct.pack("!HH", qtype, 1)


def question_of(query: bytes) -> bytes:
    return query[12:]


def parse_reply(reply: bytes) -> tuple[int, int, tuple[int, int, int, int], bytes]:
    ident, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", reply[:12])
    return ident, flags, (qd, an, ns, ar), reply[12:]


async def udp_exchange(port: int, payload: bytes, *, expect_reply: bool = True) -> bytes | None:
    loop = asyncio.get_running_loop()
    received: asyncio.Future[bytes] = loop.create_future()

    class Client(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr: object) -> None:
            if not received.done():
                received.set_result(data)

    transport, _ = await loop.create_datagram_endpoint(Client, remote_addr=(LOOPBACK, port))
    try:
        transport.sendto(payload)
        timeout = IO_TIMEOUT_S if expect_reply else SILENCE_S
        try:
            return await asyncio.wait_for(received, timeout)
        except TimeoutError:
            if expect_reply:
                raise
            return None
    finally:
        transport.close()


async def tcp_exchange(port: int, payloads: list[bytes]) -> list[bytes]:
    reader, writer = await asyncio.open_connection(LOOPBACK, port)
    replies = []
    try:
        for payload in payloads:
            writer.write(struct.pack("!H", len(payload)) + payload)
            await writer.drain()
            head = await asyncio.wait_for(reader.readexactly(2), IO_TIMEOUT_S)
            size = int.from_bytes(head, "big")
            replies.append(await asyncio.wait_for(reader.readexactly(size), IO_TIMEOUT_S))
    finally:
        writer.close()
        with suppress(OSError):
            await writer.wait_closed()
    return replies


@pytest.fixture
async def sink() -> AsyncIterator[DnsSink]:
    running = DnsSink()
    await running.start(LOOPBACK, 0)
    try:
        yield running
    finally:
        await running.aclose()


def assert_refused(query: bytes, reply: bytes) -> None:
    ident, flags, counts, rest = parse_reply(reply)
    assert ident == QUERY_ID
    assert flags & FLAG_QR
    assert flags & 0x000F == RCODE_REFUSED
    assert flags & FLAG_RD == query_flags(query) & FLAG_RD
    assert not flags & 0x0400  # not authoritative
    assert not flags & 0x0200  # not truncated
    assert not flags & 0x0080  # recursion is not available
    assert counts == (1, 0, 0, 0)
    assert rest == question_of(query)


def query_flags(query: bytes) -> int:
    return struct.unpack("!H", query[2:4])[0]


async def test_udp_query_is_refused_with_the_question_echoed(sink: DnsSink) -> None:
    query = build_query()
    reply = await udp_exchange(sink.udp_port, query)
    assert reply is not None
    assert_refused(query, reply)


async def test_tcp_queries_are_refused_on_one_connection(sink: DnsSink) -> None:
    first, second = build_query(), build_query("example.com", qtype=28)
    replies = await tcp_exchange(sink.tcp_port, [first, second])
    assert_refused(first, replies[0])
    assert_refused(second, replies[1])


async def test_recursion_desired_is_echoed_only_when_set(sink: DnsSink) -> None:
    query = build_query(rd=False)
    reply = await udp_exchange(sink.udp_port, query)
    assert reply is not None
    assert_refused(query, reply)
    assert not parse_reply(reply)[1] & FLAG_RD


async def test_nothing_is_forwarded(sink: DnsSink, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("the sink must not resolve anything")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", forbidden)
    query = build_query()
    reply = await udp_exchange(sink.udp_port, query)
    assert reply is not None
    assert_refused(query, reply)


async def test_counter_rises_per_source_for_udp_and_tcp(sink: DnsSink) -> None:
    await udp_exchange(sink.udp_port, build_query())
    await tcp_exchange(sink.tcp_port, [build_query(), build_query()])
    assert sink.counts == {LOOPBACK: 3}


async def test_report_logs_counts_per_source_and_never_a_name(
    sink: DnsSink, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    await udp_exchange(sink.udp_port, build_query())
    await tcp_exchange(sink.tcp_port, [build_query()])
    interval = sink.report()
    assert interval == {LOOPBACK: 2}
    assert f"{LOOPBACK}=2" in caplog.text
    assert sink.report() == {}  # the interval resets
    assert sink.counts == {}  # and so do the per-source counts: the map is bounded per interval
    everything = caplog.text + repr([(r.msg, r.args) for r in caplog.records])
    for fragment in (SECRET_NAME, "zq7-exfil", "attacker-example"):
        assert fragment not in everything


async def test_the_source_cap_applies_per_interval_not_forever(
    sink: DnsSink, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sink_module, "MAX_SOURCES", 2)
    query = build_query()
    for source in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        sink.answer(query, source)
    assert sink.counts == {"10.0.0.1": 1, "10.0.0.2": 1, sink_module.OTHER_SOURCES: 1}
    sink.report()
    sink.answer(query, "10.0.0.3")  # a new interval: the cap starts over
    assert sink.counts == {"10.0.0.3": 1}


async def test_dropped_packets_are_counted_per_source_and_reported_without_names(
    sink: DnsSink, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    response_like = struct.pack("!HHHHHH", QUERY_ID, FLAG_QR, 1, 0, 0, 0) + b"\x00\x00\x01\x00\x01"
    assert sink.answer(b"\x00\x01", "10.0.0.9") is None
    assert sink.answer(response_like + SECRET_NAME.encode(), "10.0.0.9") is None
    assert sink.answer(build_query(), "10.0.0.8") is not None
    assert sink.drops == {"10.0.0.9": 2}
    assert sink.counts == {"10.0.0.8": 1}
    sink.report()
    assert "10.0.0.9=2" in caplog.text and "dropped packets" in caplog.text
    assert sink.drops == {}
    assert SECRET_NAME not in caplog.text
    await tcp_exchange_oversize(sink.tcp_port)
    assert sink.drops == {LOOPBACK: 1}  # an out-of-range tcp frame is a drop too


async def tcp_exchange_oversize(port: int) -> None:
    reader, writer = await asyncio.open_connection(LOOPBACK, port)
    writer.write(struct.pack("!H", 65535))
    await writer.drain()
    await asyncio.wait_for(reader.read(), IO_TIMEOUT_S)
    writer.close()


async def test_malformed_input_is_dropped_and_the_sink_keeps_serving(sink: DnsSink) -> None:
    assert await udp_exchange(sink.udp_port, b"\x00\x01", expect_reply=False) is None
    response_like = struct.pack("!HHHHHH", QUERY_ID, FLAG_QR, 1, 0, 0, 0) + b"\x00\x00\x01\x00\x01"
    assert await udp_exchange(sink.udp_port, response_like, expect_reply=False) is None
    pointer = struct.pack("!HHHHHH", QUERY_ID, FLAG_RD, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01"
    reply = await udp_exchange(sink.udp_port, pointer)
    assert reply is not None
    ident, flags, counts, rest = parse_reply(reply)
    assert (ident, flags & 0x000F, counts, rest) == (QUERY_ID, RCODE_REFUSED, (0, 0, 0, 0), b"")
    query = build_query()
    good = await udp_exchange(sink.udp_port, query)
    assert good is not None
    assert_refused(query, good)


async def test_oversized_tcp_frame_closes_the_connection(sink: DnsSink) -> None:
    reader, writer = await asyncio.open_connection(LOOPBACK, sink.tcp_port)
    writer.write(struct.pack("!H", 65535))
    await writer.drain()
    assert await asyncio.wait_for(reader.read(), IO_TIMEOUT_S) == b""
    writer.close()


async def test_aclose_releases_both_ports_and_is_repeatable() -> None:
    running = DnsSink()
    await running.start(LOOPBACK, 0)
    tcp_port = running.tcp_port
    idle = await asyncio.open_connection(LOOPBACK, tcp_port)  # an open client must not block close
    await asyncio.wait_for(running.aclose(), IO_TIMEOUT_S)
    await running.aclose()
    with pytest.raises(OSError):
        await asyncio.open_connection(LOOPBACK, tcp_port)
    idle[1].close()


async def test_start_failure_leaves_nothing_bound() -> None:
    first = DnsSink()
    await first.start(LOOPBACK, 0)
    try:
        second = DnsSink()
        with pytest.raises(OSError):
            await second.start(LOOPBACK, first.tcp_port)
    finally:
        await first.aclose()


async def test_serving_dns_sink_is_a_no_op_when_the_address_is_unset() -> None:
    async with serving_dns_sink("") as running:
        assert running is None


async def test_serving_dns_sink_serves_and_closes_on_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sink_module, "DNS_PORT", 0)
    async with serving_dns_sink(LOOPBACK) as running:
        assert running is not None
        query = build_query()
        reply = await udp_exchange(running.udp_port, query)
        assert reply is not None
        assert_refused(query, reply)
        tcp_port = running.tcp_port
    with pytest.raises(OSError):
        await asyncio.open_connection(LOOPBACK, tcp_port)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((LOOPBACK, 0))
        return int(probe.getsockname()[1])


async def test_the_proxy_process_starts_the_sink_when_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    port = free_port()
    monkeypatch.setattr(sink_module, "DNS_PORT", port)
    config = ProxyConfig(host=LOOPBACK, port=0, secret="s", dns_sink_address=LOOPBACK)
    task = asyncio.create_task(_serve(config))
    try:
        query = build_query()
        reply = None
        for _ in range(50):
            try:
                reply = await udp_exchange(port, query, expect_reply=False)
            except OSError:
                reply = None
            if reply is not None:
                break
            await asyncio.sleep(0.05)
        assert reply is not None
        assert_refused(query, reply)
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
    with pytest.raises(OSError):
        await asyncio.open_connection(LOOPBACK, port)


async def test_the_proxy_stays_off_port_53_when_the_sink_is_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started: list[object] = []
    monkeypatch.setattr(DnsSink, "start", lambda self, host, port: started.append(host))
    config = ProxyConfig(host=LOOPBACK, port=0, secret="s")
    task = asyncio.create_task(_serve(config))
    await asyncio.sleep(0.2)
    task.cancel()
    with suppress(asyncio.CancelledError):
        await task
    assert started == []


def test_config_reads_the_sink_address() -> None:
    base = {"SANDFORT_EGRESS_SECRET": "s"}
    assert ProxyConfig.from_env(base).dns_sink_address == ""
    with_sink = ProxyConfig.from_env({**base, ENV_DNS_SINK_LISTEN: " 172.30.0.1 "})
    assert with_sink.dns_sink_address == "172.30.0.1"


@pytest.mark.parametrize("bad", ["::1", "172.30.0.1, 172.30.0.2", "dns.example", "300.1.1.1"])
def test_config_refuses_anything_but_one_ipv4_address(bad: str) -> None:
    environ = {"SANDFORT_EGRESS_SECRET": "s", ENV_DNS_SINK_LISTEN: bad}
    with pytest.raises(ValueError, match=ENV_DNS_SINK_LISTEN):
        ProxyConfig.from_env(environ)
