"""Wire handling for one egress tunnel: the CONNECT request, error answers and the byte relay.

``read_request`` reads the request line and headers under fixed size limits; ``Deny`` carries
an http refusal that ``send_error`` writes back. ``relay`` copies bytes both ways until either
direction ends or no byte has moved for ``idle_timeout_s``; ``close_writer`` closes one side
without raising on a dead peer.
"""

import asyncio
import ipaddress
from contextlib import suppress
from dataclasses import dataclass

from sandfort.webhooks.ssrf import IpAddress

RELAY_CHUNK_BYTES = 64 * 1024
MAX_LINE_BYTES = 16 * 1024
MAX_HEADER_LINES = 100
AUTH_CHALLENGE = 'Basic realm="sandfort-egress"'
UNKNOWN_SOURCE = "-"

type Connection = tuple[asyncio.StreamReader, asyncio.StreamWriter]


class Deny(Exception):
    """A request refused; carries the http answer. The detail is for the log only."""

    def __init__(
        self, status: int, reason: str, detail: str, headers: dict[str, str] | None = None
    ) -> None:
        super().__init__(detail)
        self.status = status
        self.reason = reason
        self.detail = detail
        self.headers = headers or {}


def auth_required(detail: str) -> Deny:
    """A 407 answer carrying the Basic challenge."""
    return Deny(
        407, "Proxy Authentication Required", detail, {"Proxy-Authenticate": AUTH_CHALLENGE}
    )


def source_of(writer: asyncio.StreamWriter) -> str:
    """The client's address as text, or ``UNKNOWN_SOURCE`` when the transport has none."""
    peer = writer.get_extra_info("peername")
    if isinstance(peer, tuple) and peer:
        return str(peer[0])
    return UNKNOWN_SOURCE


@dataclass(frozen=True, slots=True)
class Request:
    method: str
    target: str
    proxy_authorization: str | None


async def _read_line(reader: asyncio.StreamReader) -> bytes:
    try:
        line = await reader.readline()
    except ValueError:  # a line longer than the stream limit
        raise Deny(400, "Bad Request", "request line or header too long") from None
    if not line:
        raise Deny(400, "Bad Request", "connection closed before the request was complete")
    return line


async def read_request(reader: asyncio.StreamReader) -> Request:
    parts = (await _read_line(reader)).decode("latin-1").split()
    if len(parts) != 3:
        raise Deny(400, "Bad Request", "malformed request line")
    authorization: str | None = None
    for _ in range(MAX_HEADER_LINES):
        raw = (await _read_line(reader)).decode("latin-1")
        if raw in ("\r\n", "\n"):
            return Request(method=parts[0], target=parts[1], proxy_authorization=authorization)
        name, _, value = raw.partition(":")
        if name.strip().lower() == "proxy-authorization":
            authorization = value.strip()
    raise Deny(431, "Request Header Fields Too Large", "too many header lines")


def parse_target(target: str) -> tuple[str, int]:
    host, sep, port_text = target.rpartition(":")
    if not sep or not host or not (port_text.isascii() and port_text.isdigit()):
        raise Deny(400, "Bad Request", "target must be host:port")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    elif ":" in host:
        raise Deny(400, "Bad Request", "target must be host:port")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise Deny(400, "Bad Request", "port out of range")
    return host, port


def parse_address(text: str) -> IpAddress:
    try:
        address = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        raise Deny(502, "Bad Gateway", "resolver returned a non-address") from None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


async def send_error(writer: asyncio.StreamWriter, deny: Deny) -> None:
    lines = [f"HTTP/1.1 {deny.status} {deny.reason}", "Content-Length: 0", "Connection: close"]
    lines.extend(f"{name}: {value}" for name, value in deny.headers.items())
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
    with suppress(OSError):
        await writer.drain()


@dataclass(slots=True)
class _Activity:
    """When bytes last moved in either direction of one tunnel (event-loop clock)."""

    last: float


async def _pump(
    source: asyncio.StreamReader, sink: asyncio.StreamWriter, activity: _Activity
) -> None:
    loop = asyncio.get_running_loop()
    while chunk := await source.read(RELAY_CHUNK_BYTES):
        activity.last = loop.time()
        sink.write(chunk)
        await sink.drain()
        activity.last = loop.time()


async def _watch_idle(activity: _Activity, idle_timeout_s: float) -> None:
    """Return once the tunnel has moved no bytes for ``idle_timeout_s``."""
    loop = asyncio.get_running_loop()
    while (remaining := activity.last + idle_timeout_s - loop.time()) > 0:
        await asyncio.sleep(remaining)


async def relay(client: Connection, upstream: Connection, idle_timeout_s: float | None) -> None:
    """Copy bytes both ways until either direction ends or the tunnel goes idle."""
    activity = _Activity(last=asyncio.get_running_loop().time())
    tasks = [
        asyncio.create_task(_pump(client[0], upstream[1], activity)),
        asyncio.create_task(_pump(upstream[0], client[1], activity)),
    ]
    if idle_timeout_s is not None:
        tasks.append(asyncio.create_task(_watch_idle(activity, idle_timeout_s)))
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with suppress(OSError):
        await writer.wait_closed()
