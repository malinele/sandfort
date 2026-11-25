"""The DNS sink: answers every query REFUSED and forwards nothing (egress v2 design 6.2).

A container on the egress network whose runtime has no network stack of its own (runc) is given
``dns=[SANDFORT_EGRESS_DNS_SINK_ADDRESS]``, so Docker's embedded resolver forwards external names
here instead of to the host's upstream servers. Only the proxy resolves names. The sink serves
udp and tcp port 53, replies with a header that echoes the query id, the opcode and the
recursion-desired bit (QR set, RCODE 5) plus the first question, and holds no resolver, no
upstream and no cache.

It logs how many queries each source address sent and how many packets it dropped (too short,
a response, a bad frame), once a minute, and never a queried name: a name can carry data, and
the host logs are not where it should land. The per-source map covers one interval and is bounded
(``MAX_SOURCES``), so a new minute starts with an empty map. Names are only ever parsed
for their length. Port 53 needs ``CAP_NET_BIND_SERVICE`` or root; nothing here works around that.
"""

import asyncio
import logging
import struct
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from typing import Self, cast

DNS_PORT = 53
REPORT_INTERVAL_S = 60.0
TCP_IDLE_S = 10.0
MAX_TCP_CONNECTIONS = 64
MAX_TCP_QUERIES = 32  # per connection
MAX_TCP_MESSAGE_BYTES = 4096
MAX_SOURCES = 1024  # distinct sources counted per interval; the rest share OTHER_SOURCES
OTHER_SOURCES = "(other)"

HEADER_BYTES = 12
MAX_LABEL_BYTES = 63
MAX_NAME_BYTES = 255
QUESTION_TAIL_BYTES = 4  # qtype and qclass
FLAG_QR = 0x8000
FLAG_OPCODE = 0x7800
FLAG_RD = 0x0100
RCODE_REFUSED = 5

_log = logging.getLogger("sandfort.egress")


def _question_end(query: bytes) -> int | None:
    """Offset just past the first question, or ``None`` if it is not a plain, whole question."""
    position = HEADER_BYTES
    while True:
        if position >= len(query):
            return None
        length = query[position]
        position += 1
        if length == 0:
            break
        if length > MAX_LABEL_BYTES or position - HEADER_BYTES > MAX_NAME_BYTES:
            return None  # a compression pointer or extended label has no place in a question
        position += length
    end = position + QUESTION_TAIL_BYTES
    return end if end <= len(query) else None


def refusal(query: bytes) -> bytes | None:
    """The REFUSED reply to ``query``; ``None`` if it is too short or a response."""
    if len(query) < HEADER_BYTES:
        return None
    ident, flags, qdcount = struct.unpack("!HHH", query[:6])
    if flags & FLAG_QR:
        return None  # never answer a response: two such hosts would loop
    end = _question_end(query) if qdcount == 1 else None
    reply_flags = FLAG_QR | (flags & (FLAG_OPCODE | FLAG_RD)) | RCODE_REFUSED
    header = struct.pack("!HHHHHH", ident, reply_flags, 0 if end is None else 1, 0, 0, 0)
    return header if end is None else header + query[HEADER_BYTES:end]


def _join(per_source: dict[str, int]) -> str:
    return " ".join(f"{source}={count}" for source, count in sorted(per_source.items()))


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, sink: "DnsSink") -> None:
        self._sink = sink
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        reply = self._sink.answer(data, addr[0])
        if reply is not None and self._transport is not None:
            self._transport.sendto(reply, addr)


class DnsSink:
    """One udp endpoint and one tcp server on the same address."""

    def __init__(self, *, report_interval_s: float = REPORT_INTERVAL_S) -> None:
        self._report_interval_s = report_interval_s
        self._tally: dict[str, list[int]] = {}  # source -> [answered, dropped], this interval
        self._udp: asyncio.DatagramTransport | None = None
        self._tcp: asyncio.Server | None = None
        self._clients: set[asyncio.StreamWriter] = set()
        self._reporter: asyncio.Task[None] | None = None

    @property
    def counts(self) -> dict[str, int]:
        """Queries answered per source address in the current interval."""
        return {source: tally[0] for source, tally in self._tally.items() if tally[0]}

    @property
    def drops(self) -> dict[str, int]:
        """Packets dropped without a reply per source address in the current interval."""
        return {source: tally[1] for source, tally in self._tally.items() if tally[1]}

    @property
    def udp_port(self) -> int:
        if self._udp is None:
            raise RuntimeError("the sink is not started")
        return int(self._udp.get_extra_info("sockname")[1])

    @property
    def tcp_port(self) -> int:
        if self._tcp is None or not self._tcp.sockets:
            raise RuntimeError("the sink is not started")
        return int(self._tcp.sockets[0].getsockname()[1])

    async def start(self, host: str, port: int = DNS_PORT) -> Self:
        """Bind udp and tcp ``host:port``; on any failure nothing stays bound."""
        loop = asyncio.get_running_loop()
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UdpProtocol(self), local_addr=(host, port)
            )
            self._udp = transport
            self._tcp = await asyncio.start_server(self._serve_tcp, host, port)
        except OSError:
            await self.aclose()
            raise
        self._reporter = asyncio.create_task(self._report_forever())
        return self

    async def aclose(self) -> None:
        if self._reporter is not None:
            self._reporter.cancel()
            with suppress(asyncio.CancelledError):
                await self._reporter
            self._reporter = None
        if self._udp is not None:
            self._udp.close()
            self._udp = None
        if self._tcp is not None:
            self._tcp.close()
            for writer in tuple(self._clients):
                writer.close()
            await self._tcp.wait_closed()
            self._tcp = None

    def answer(self, query: bytes, source: str) -> bytes | None:
        """Count the query for ``source`` and return the REFUSED reply (``None`` = drop it)."""
        reply = refusal(query)
        self._count(source, answered=reply is not None)
        return reply

    def report(self) -> dict[str, int]:
        """Log and reset the per-source tallies of the interval; an idle interval logs nothing.

        Returns the queries answered per source in the interval.
        """
        answered, dropped = self.counts, self.drops
        self._tally = {}
        if answered:
            _log.info("dns sink refused queries per source: %s", _join(answered))
        if dropped:
            _log.info("dns sink dropped packets per source: %s", _join(dropped))
        return answered

    def _count(self, source: str, *, answered: bool) -> None:
        if source not in self._tally and len(self._tally) >= MAX_SOURCES:
            source = OTHER_SOURCES
        self._tally.setdefault(source, [0, 0])[0 if answered else 1] += 1

    async def _report_forever(self) -> None:
        while True:
            await asyncio.sleep(self._report_interval_s)
            self.report()

    async def _serve_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if len(self._clients) >= MAX_TCP_CONNECTIONS:
            writer.close()
            return
        self._clients.add(writer)
        peer = writer.get_extra_info("peername")
        source = str(peer[0]) if peer else OTHER_SOURCES
        try:
            for _ in range(MAX_TCP_QUERIES):
                head = await asyncio.wait_for(reader.readexactly(2), TCP_IDLE_S)
                size = int.from_bytes(head, "big")
                if not HEADER_BYTES <= size <= MAX_TCP_MESSAGE_BYTES:
                    self._count(source, answered=False)
                    break
                body = await asyncio.wait_for(reader.readexactly(size), TCP_IDLE_S)
                reply = self.answer(body, source)
                if reply is None:
                    break
                writer.write(len(reply).to_bytes(2, "big") + reply)
                await writer.drain()
        except (asyncio.IncompleteReadError, TimeoutError, OSError):
            pass
        finally:
            self._clients.discard(writer)
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()


@asynccontextmanager
async def serving_dns_sink(
    address: str, *, port: int | None = None
) -> AsyncIterator[DnsSink | None]:
    """Run a sink on ``address`` for the duration of the block; ``""`` runs nothing."""
    if not address:
        yield None
        return
    sink = DnsSink()
    bind_port = DNS_PORT if port is None else port
    try:
        await sink.start(address, bind_port)
    except OSError:
        _log.error(
            "dns sink cannot bind %s:%d (port 53 needs root or CAP_NET_BIND_SERVICE)",
            address,
            bind_port,
        )
        raise
    _log.info("dns sink listening on %s:%d (udp and tcp)", address, bind_port)
    try:
        yield sink
    finally:
        await sink.aclose()
