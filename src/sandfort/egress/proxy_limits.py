"""Egress proxy configuration, connection-slot accounting and node-address discovery.

``ProxyConfig`` reads the proxy's environment (see ``sandfort.egress.proxy`` for the full list).
Two limits live only here, since only the proxy process reads them:
``SANDFORT_EGRESS_MAX_TOTAL_CONNECTIONS`` (default 2048) caps every open client connection, and
``SANDFORT_EGRESS_MAX_PREAUTH_PER_SOURCE`` (default 16) caps the connections one source address
may hold before it has authenticated, so half-open connections cannot exhaust descriptors.
``SlotTable`` counts those slots; ``host_allowed`` and ``in_network`` are the allowlist and
denied-network matchers.

``discover_local_addresses`` finds the node's own addresses, which the proxy always denies:
the kernel's interface lists (``/proc/net/fib_trie`` and ``/proc/net/if_inet6``, plus one
``SIOCGIFADDR`` per interface from ``socket.if_nameindex``), the hostname's addresses and the
source address of one route probe per family. All of it is best effort and offline.
"""

import fcntl
import ipaddress
import logging
import socket
import struct
import sys
from collections.abc import Callable, Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Self

from sandfort.config import (
    DEFAULT_EGRESS_ALLOWED_PORTS,
    DEFAULT_EGRESS_DENIED_CIDRS,
    DEFAULT_EGRESS_IDLE_TIMEOUT_S,
    DEFAULT_EGRESS_MAX_CONNECTIONS,
    DEFAULT_EGRESS_TOKEN_TTL_S,
    egress_limits_from,
)
from sandfort.webhooks.ssrf import IpAddress

ENV_SECRET = "SANDFORT_EGRESS_SECRET"
ENV_LISTEN_HOST = "SANDFORT_EGRESS_LISTEN_HOST"
ENV_LISTEN_PORT = "SANDFORT_EGRESS_LISTEN_PORT"
ENV_MAX_TOTAL_CONNECTIONS = "SANDFORT_EGRESS_MAX_TOTAL_CONNECTIONS"
ENV_MAX_PREAUTH_PER_SOURCE = "SANDFORT_EGRESS_MAX_PREAUTH_PER_SOURCE"
DEFAULT_LISTEN_HOST = "127.0.0.1"
DEFAULT_LISTEN_PORT = 3128
DEFAULT_MAX_TOTAL_CONNECTIONS = 2048
DEFAULT_MAX_PREAUTH_PER_SOURCE = 16
MAX_CONNECTION_LIMIT = 1_000_000

PROBE_V4 = "192.0.2.1"  # TEST-NET-1: connecting a UDP socket sends nothing, it only picks a route
PROBE_V6 = "2001:db8::1"
PROC_NET = Path("/proc/net")
SIOCGIFADDR = 0x8915  # Linux ioctl: an interface's primary IPv4 address
IFREQ_BYTES = 256
IFNAME_BYTES = 15
IFREQ_ADDRESS = slice(20, 24)
FIB_LOCAL_MARK = "/32 host LOCAL"
FIB_ENTRY_PREFIX = "|-- "

type IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
type AddressSource = Callable[[], Iterable[str]]

_log = logging.getLogger("sandfort.egress")


def _limit(environ: Mapping[str, str], name: str, default: int) -> int:
    raw = environ.get(name)
    if raw is None:
        return default
    text = raw.strip()
    if not (text.isascii() and text.isdigit()) or not 1 <= int(text) <= MAX_CONNECTION_LIMIT:
        raise ValueError(f"{name} must be an integer 1..{MAX_CONNECTION_LIMIT}")
    return int(text)


@dataclass(frozen=True, slots=True)
class ProxyConfig:
    host: str
    port: int
    secret: str = field(repr=False)
    denied_cidrs: tuple[str, ...] = DEFAULT_EGRESS_DENIED_CIDRS
    allowed_ports: tuple[int, ...] = DEFAULT_EGRESS_ALLOWED_PORTS
    max_connections: int = DEFAULT_EGRESS_MAX_CONNECTIONS
    idle_timeout_s: int = DEFAULT_EGRESS_IDLE_TIMEOUT_S
    token_ttl_s: int = DEFAULT_EGRESS_TOKEN_TTL_S
    max_total_connections: int = DEFAULT_MAX_TOTAL_CONNECTIONS
    max_preauth_per_source: int = DEFAULT_MAX_PREAUTH_PER_SOURCE

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> Self:
        """Read the configuration; raise ``ValueError`` (never echoing the secret) if invalid."""
        secret = environ.get(ENV_SECRET, "")
        if not secret:
            raise ValueError(f"{ENV_SECRET} must be set")
        port_text = environ.get(ENV_LISTEN_PORT, str(DEFAULT_LISTEN_PORT))
        if not (port_text.isascii() and port_text.isdigit() and 0 <= int(port_text) <= 65535):
            raise ValueError(f"{ENV_LISTEN_PORT} must be a port number")
        host = environ.get(ENV_LISTEN_HOST, DEFAULT_LISTEN_HOST)
        limits = egress_limits_from(environ)
        return cls(
            host=host or DEFAULT_LISTEN_HOST,
            port=int(port_text),
            secret=secret,
            denied_cidrs=limits.denied_cidrs,
            allowed_ports=limits.allowed_ports,
            max_connections=limits.max_connections,
            idle_timeout_s=limits.idle_timeout_s,
            token_ttl_s=limits.token_ttl_s,
            max_total_connections=_limit(
                environ, ENV_MAX_TOTAL_CONNECTIONS, DEFAULT_MAX_TOTAL_CONNECTIONS
            ),
            max_preauth_per_source=_limit(
                environ, ENV_MAX_PREAUTH_PER_SOURCE, DEFAULT_MAX_PREAUTH_PER_SOURCE
            ),
        )


def in_network(address: IpAddress, network: IpNetwork) -> bool:
    if address.version != network.version:
        return False
    return int(network.network_address) <= int(address) <= int(network.broadcast_address)


def host_allowed(host: str, allowlist: Iterable[str]) -> bool:
    """True when ``host`` equals an entry, or falls under a leading-dot entry.

    ``.example.com`` admits ``example.com`` and every subdomain of it; ``example.com`` admits
    that name only.
    """
    name = host.lower().rstrip(".")
    if not name:
        return False
    for entry in allowlist:
        if entry.startswith("."):
            domain = entry[1:]
            if domain and (name == domain or name.endswith(entry)):
                return True
        elif name == entry:
            return True
    return False


class SlotTable:
    """Counts slots held per key and refuses one past ``limit`` (``None`` = unbounded).

    Keys whose count drops to zero are forgotten, so the table only grows with live holders.
    """

    def __init__(self, limit: int | None) -> None:
        self._limit = limit
        self._held: dict[str, int] = {}
        self._total = 0

    @property
    def total(self) -> int:
        return self._total

    def held(self, key: str) -> int:
        return self._held.get(key, 0)

    def try_acquire(self, key: str) -> bool:
        count = self._held.get(key, 0)
        if self._limit is not None and count >= self._limit:
            return False
        self._held[key] = count + 1
        self._total += 1
        return True

    def release(self, key: str) -> None:
        count = self._held.get(key, 0)
        if count <= 0:
            return
        if count == 1:
            del self._held[key]
        else:
            self._held[key] = count - 1
        self._total -= 1


def _normalise(text: str) -> IpAddress | None:
    try:
        parsed = ipaddress.ip_address(text.strip().split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped
    return parsed


def _unique(texts: Iterable[str]) -> tuple[IpAddress, ...]:
    found: dict[str, IpAddress] = {}
    for text in texts:
        address = _normalise(text)
        if address is not None:
            found.setdefault(str(address), address)
    return tuple(found.values())


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="ascii", errors="replace")
    except OSError:
        return ""


def _fib_trie_locals(text: str) -> list[str]:
    """The ``/32 host LOCAL`` entries of ``/proc/net/fib_trie``: the node's IPv4 addresses."""
    found: list[str] = []
    previous = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == FIB_LOCAL_MARK and previous.startswith(FIB_ENTRY_PREFIX):
            found.append(previous.removeprefix(FIB_ENTRY_PREFIX))
        previous = stripped
    return found


def _if_inet6_addresses(text: str) -> list[str]:
    """The first column of ``/proc/net/if_inet6``: 32 hex digits per IPv6 address."""
    found: list[str] = []
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        with suppress(ValueError):
            found.append(str(ipaddress.IPv6Address(bytes.fromhex(fields[0]))))
    return found


def interface_addresses(proc_net: Path = PROC_NET) -> tuple[IpAddress, ...]:
    """Every address the kernel lists on an interface; empty where ``/proc`` is absent."""
    texts = _fib_trie_locals(_read(proc_net / "fib_trie"))
    texts += _if_inet6_addresses(_read(proc_net / "if_inet6"))
    return _unique(texts)


def _ioctl_ipv4() -> list[str]:
    """Each interface's primary IPv4 address via ``SIOCGIFADDR`` (Linux only)."""
    if not sys.platform.startswith("linux"):
        return []
    found: list[str] = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as query:
        for _index, name in socket.if_nameindex():
            request = struct.pack(f"{IFREQ_BYTES}s", name.encode()[:IFNAME_BYTES])
            with suppress(OSError):
                reply = fcntl.ioctl(query.fileno(), SIOCGIFADDR, request)
                found.append(socket.inet_ntoa(reply[IFREQ_ADDRESS]))
    return found


def _hostname_and_probe() -> list[str]:
    """The hostname's addresses and each family's routed source address; no packet is sent."""
    found: list[str] = []
    with suppress(OSError):
        found.extend(str(info[4][0]) for info in socket.getaddrinfo(socket.gethostname(), None))
    for family, probe in ((socket.AF_INET, PROBE_V4), (socket.AF_INET6, PROBE_V6)):
        with suppress(OSError), socket.socket(family, socket.SOCK_DGRAM) as probe_socket:
            probe_socket.connect((probe, 9))
            found.append(str(probe_socket.getsockname()[0]))
    return found


def discover_local_addresses(
    *,
    proc_net: Path = PROC_NET,
    interface_ipv4: AddressSource = _ioctl_ipv4,
    fallback: AddressSource = _hostname_and_probe,
) -> tuple[IpAddress, ...]:
    """The addresses this node answers on. Best effort and offline; called once at startup.

    The interface enumeration covers Linux; the hostname lookup and route probe are always
    added too, so a host without ``/proc`` still denies its routed addresses. Logs a warning
    when nothing but loopback was found.
    """
    texts = [str(address) for address in interface_addresses(proc_net)]
    for source in (interface_ipv4, fallback):
        try:
            texts.extend(source())
        except OSError as exc:
            _log.info("node address source unavailable: %s", exc)
    addresses = _unique(texts)
    if not any(not address.is_loopback for address in addresses):
        _log.warning(
            "no non-loopback address found for this node; only the configured denied"
            " networks keep tunnels off it"
        )
    return addresses
