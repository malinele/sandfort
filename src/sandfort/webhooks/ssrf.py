"""SSRF guard: URL admission for webhook endpoints and for every delivery attempt.

A URL is admitted when it is ``http`` or ``https``, carries no userinfo, has no port or one of
80, 443 and 8000-9000, and every address its host resolves to is publicly routable. Loopback,
private, link-local, unique-local, reserved and the cloud metadata addresses are rejected,
including IPv4-mapped IPv6 forms. A literal IP in the URL is vetted directly.

``vet_url`` returns the vetted IP. The delivery layer connects to exactly that IP and sends the
original host in the ``Host`` header, so a second DNS answer (rebinding) can never redirect the
request after the check.

Name resolution has three outcomes. An answer is vetted. NXDOMAIN or NoData (``EAI_NONAME``,
``EAI_NODATA``, ``EAI_ADDRFAMILY`` or an empty answer) is a verdict: ``HostNotResolved``, a
``UrlRejected``. Anything else (a timeout, SERVFAIL, ``EAI_AGAIN``, another ``OSError``) is not a
verdict about the URL: the lookup is retried once after ``RETRY_PAUSE_S``, and a second failure
raises ``ResolverUnavailable``, which is not a ``UrlRejected`` and never says the host does not
resolve. Each attempt is capped at ``ATTEMPT_TIMEOUT_S``, so a validation takes at most
2 * 2.5 + 0.5 = 5.5 s.
"""

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

MAX_URL_CHARS = 2048
ATTEMPT_TIMEOUT_S = 2.5  # one name lookup; a slower resolver counts as a transient failure
RETRY_PAUSE_S = 0.5  # pause before the single retry of a transient lookup failure
NOT_RESOLVED_MESSAGE = "host does not resolve"
# getaddrinfo errors that are an answer ("no such name / no address"), not a resolver failure.
# EAI_NODATA and EAI_ADDRFAMILY do not exist on every platform.
_NO_SUCH_HOST_ERRNOS = frozenset(
    getattr(socket, name)
    for name in ("EAI_NONAME", "EAI_NODATA", "EAI_ADDRFAMILY")
    if hasattr(socket, name)
)
ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_PORTS = {"http": 80, "https": 443}
ALLOWED_PORTS = frozenset({80, 443})
ALLOWED_PORT_RANGE = range(8000, 9001)
METADATA_ADDRESSES = frozenset(
    ipaddress.ip_address(text) for text in ("169.254.169.254", "fd00:ec2::254", "100.100.100.200")
)

type IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_allow_private_networks = False  # opt-in for self-hosted receivers on private networks
_require_https = False  # when set, plain http webhook URLs are rejected


class UrlRejected(ValueError):
    """The URL is not admissible; the message names the rule, never the URL."""


class HostNotResolved(UrlRejected):
    """The name has no address (NXDOMAIN or NoData): a verdict on the URL."""

    def __init__(self) -> None:
        super().__init__(NOT_RESOLVED_MESSAGE)


class ResolverUnavailable(Exception):
    """The lookup failed twice for a reason that says nothing about the host (not a verdict)."""


@dataclass(frozen=True, slots=True)
class VettedUrl:
    url: str
    scheme: str
    host: str
    port: int
    ip: str
    target: str  # path and query, always starting with "/"

    @property
    def host_header(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return host if DEFAULT_PORTS[self.scheme] == self.port else f"{host}:{self.port}"

    @property
    def connect_url(self) -> str:
        ip = f"[{self.ip}]" if ":" in self.ip else self.ip
        return f"{self.scheme}://{ip}:{self.port}{self.target}"


async def resolve_host(host: str) -> list[str]:
    """Every address ``host`` resolves to (a seam tests replace)."""
    infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


def _parse_ip(text: str) -> IpAddress:
    try:
        address = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        raise UrlRejected("resolved address is not an IP address") from None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def configure(*, allow_private_networks: bool, require_https: bool = False) -> None:
    """Set the process-wide private-network opt-in and https requirement.

    The settings are ``webhook_allow_private_networks`` and ``webhook_require_https``.
    """
    global _allow_private_networks, _require_https
    _allow_private_networks = allow_private_networks
    _require_https = require_https


def check_address(address: IpAddress) -> None:
    """Raise ``UrlRejected`` unless ``address`` is publicly routable.

    With the private-network opt-in, loopback, private, link-local and unique-local addresses
    are admitted too; the cloud metadata addresses are rejected either way.
    """
    if address in METADATA_ADDRESSES:
        raise UrlRejected("address is a cloud metadata address")
    if _allow_private_networks and (
        address.is_loopback or address.is_link_local or address.is_private
    ):
        return
    if address.is_loopback:
        raise UrlRejected("address is loopback")
    if address.is_link_local:
        raise UrlRejected("address is link-local")
    if address.is_private:
        raise UrlRejected("address is private")
    if address.is_multicast or address.is_unspecified or not address.is_global:
        raise UrlRejected("address is not publicly routable")


def _check_port(scheme: str, port: int | None) -> int:
    if port is None:
        return DEFAULT_PORTS[scheme]
    if port in ALLOWED_PORTS or port in ALLOWED_PORT_RANGE:
        return port
    raise UrlRejected("port must be 80, 443 or within 8000-9000")


async def _lookup_once(host: str) -> list[str]:
    """One capped lookup: the answer, ``HostNotResolved`` for no such name, or the failure.

    A transient failure (timeout, SERVFAIL, any other ``OSError``) is raised as ``OSError``
    (``TimeoutError`` included) for ``_lookup`` to retry.
    """
    try:
        async with asyncio.timeout(ATTEMPT_TIMEOUT_S):
            resolved = await resolve_host(host)
    except socket.gaierror as exc:
        if exc.errno in _NO_SUCH_HOST_ERRNOS:
            raise HostNotResolved from None
        raise
    if not resolved:
        raise HostNotResolved
    return resolved


async def _lookup(host: str) -> list[str]:
    """Resolve ``host``; a transient failure is retried once, then ``ResolverUnavailable``."""
    try:
        return await _lookup_once(host)
    except OSError:  # TimeoutError is an OSError
        await asyncio.sleep(RETRY_PAUSE_S)
    try:
        return await _lookup_once(host)
    except OSError:  # TimeoutError is an OSError
        raise ResolverUnavailable("DNS lookup failed") from None


async def _addresses(host: str) -> list[IpAddress]:
    try:
        return [_parse_ip(host)]
    except UrlRejected:
        pass  # not a literal IP: resolve the name
    return [_parse_ip(text) for text in await _lookup(host)]


async def vet_url(url: str) -> VettedUrl:
    """Admit ``url``; returns the vetted IP to connect to.

    Raises ``UrlRejected`` for a URL the guard refuses and ``ResolverUnavailable`` when the
    name could not be looked up (see the module docstring).
    """
    if len(url) > MAX_URL_CHARS:
        raise UrlRejected("url is too long")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise UrlRejected("url is malformed") from None
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UrlRejected("scheme must be http or https")
    if _require_https and scheme != "https":
        raise UrlRejected("webhook URLs must use https on this server")
    if "@" in parts.netloc:
        raise UrlRejected("url must not contain userinfo")
    host = parts.hostname
    if not host:
        raise UrlRejected("url has no host")
    checked_port = _check_port(scheme, port)
    addresses = await _addresses(host)
    for address in addresses:  # every answer must pass, not just the one we connect to
        check_address(address)
    target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    return VettedUrl(
        url=url,
        scheme=scheme,
        host=host,
        port=checked_port,
        ip=str(addresses[0]),
        target=target,
    )
