"""The opt-in loopback listener that serves the egress counters (backlog B21).

``SANDFORT_EGRESS_METRICS_LISTEN`` names one loopback IPv4 address and port, such as
``127.0.0.1:9464``; unset, nothing listens. Anything else is refused at startup (a wildcard, a
non-loopback address, IPv6, a hostname, the proxy's own port and port 53), so no sandbox can
reach the listener whatever its network mode. It answers ``GET /metrics`` with the Prometheus
text of ``sandfort.egress.metrics.EgressMetrics`` and nothing else, takes no token, and is
bounded: at most ``MAX_SCRAPES`` scrapes at once and ``SCRAPE_READ_TIMEOUT_S`` to send the
request. Answering a scrape never counts as an egress decision.

This module must not import ``sandfort.egress.admission``: ``admission`` imports
``proxy_limits``, which imports this module.
"""

import asyncio
import ipaddress
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from typing import Final

from prometheus_client import CONTENT_TYPE_LATEST

from sandfort.egress.dns_sink import DNS_PORT
from sandfort.egress.metrics import EgressMetrics
from sandfort.egress.relay import MAX_LINE_BYTES, Deny, close_writer, read_request, send_error

ENV_METRICS_LISTEN: Final = "SANDFORT_EGRESS_METRICS_LISTEN"
METRICS_PATH: Final = "/metrics"
MAX_SCRAPES: Final = 4
SCRAPE_READ_TIMEOUT_S: Final = 5.0
MAX_PORT: Final = 65535

type MetricsListen = tuple[str, int]

_log = logging.getLogger("sandfort.egress")


def _refusal() -> ValueError:
    return ValueError(
        f"{ENV_METRICS_LISTEN} must be a loopback IPv4 address and port, such as"
        " 127.0.0.1:9464, and not the proxy port or 53"
    )


def parse_metrics_listen(raw: str, *, proxy_port: int) -> MetricsListen | None:
    """``(host, port)`` to listen on, ``None`` for an empty value; ``ValueError`` otherwise."""
    text = raw.strip()
    if not text:
        return None
    host_text, _, port_text = text.rpartition(":")
    if not (port_text.isascii() and port_text.isdigit()) or not 1 <= int(port_text) <= MAX_PORT:
        raise _refusal()
    port = int(port_text)
    if port in (proxy_port, DNS_PORT):
        raise _refusal()
    try:
        address = ipaddress.IPv4Address(host_text)
    except ValueError:
        raise _refusal() from None
    if not address.is_loopback:
        raise _refusal()
    return (str(address), port)


async def _refuse(writer: asyncio.StreamWriter, deny: Deny) -> None:
    with suppress(OSError):
        await send_error(writer, deny)


class MetricsListener:
    """Serves ``GET /metrics``; never touches the counters it renders."""

    def __init__(
        self,
        metrics: EgressMetrics,
        *,
        read_timeout_s: float = SCRAPE_READ_TIMEOUT_S,
        max_scrapes: int = MAX_SCRAPES,
    ) -> None:
        self._metrics = metrics
        self._read_timeout_s = read_timeout_s
        self._max_scrapes = max_scrapes
        self._active = 0

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._active >= self._max_scrapes:
            await _refuse(writer, Deny(503, "Service Unavailable", "too many scrapes"))
            await close_writer(writer)
            return
        self._active += 1
        try:
            await self._answer(reader, writer)
        finally:
            self._active -= 1
            await close_writer(writer)

    async def _answer(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request = await asyncio.wait_for(read_request(reader), self._read_timeout_s)
            if request.method != "GET":
                raise Deny(405, "Method Not Allowed", "method is not GET", {"Allow": "GET"})
            if request.target.partition("?")[0] != METRICS_PATH:
                raise Deny(404, "Not Found", "no such path")
            body = self._metrics.render()
            head = (
                f"HTTP/1.1 200 OK\r\nContent-Type: {CONTENT_TYPE_LATEST}\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            )
            writer.write(head.encode("ascii") + body)
            await writer.drain()
        except Deny as deny:
            await _refuse(writer, deny)
        except (OSError, TimeoutError):
            _log.debug("egress metrics scrape ended by a connection error or timeout")
        except Exception:
            _log.exception("egress metrics scrape failed")
            await _refuse(writer, Deny(500, "Internal Server Error", "scrape failed"))

    async def start(self, host: str, port: int) -> asyncio.Server:
        return await asyncio.start_server(self.handle, host, port, limit=MAX_LINE_BYTES)


@asynccontextmanager
async def serving_metrics(
    listen: MetricsListen | None,
    metrics: EgressMetrics,
    *,
    read_timeout_s: float = SCRAPE_READ_TIMEOUT_S,
) -> AsyncIterator[asyncio.Server | None]:
    """Run the listener for the duration of the block; ``None`` runs nothing."""
    if listen is None:
        yield None
        return
    host, port = listen
    listener = MetricsListener(metrics, read_timeout_s=read_timeout_s)
    try:
        server = await listener.start(host, port)
    except OSError:
        _log.error("egress metrics cannot bind %s:%d", host, port)
        raise
    bound_host, bound_port = server.sockets[0].getsockname()[:2]
    _log.info("egress metrics listening on %s:%d", bound_host, bound_port)
    try:
        yield server
    finally:
        server.close()
        await server.wait_closed()
