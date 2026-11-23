"""CONNECT-method forward proxy that enforces a per-sandbox egress allowlist.

Credentials arrive as ``Proxy-Authorization: Basic base64(<sandbox_id>:<egress token>)``. The
token (see ``sandfort.egress.tokens``) carries the sandbox's allowlist, so no lookup is needed.
For ``CONNECT host:port`` the proxy verifies the token, matches ``host`` against the allowlist
(exact name, or the domain and its subdomains under a leading-dot entry), refuses ports
outside the allowed-ports setting, resolves the name itself and vets every resolved address
with ``sandfort.webhooks.ssrf.check_address`` and against the denied CIDRs (loopback,
link-local, RFC 1918 and the node's own interface addresses by default), so a tenant that
controls DNS for an allowlisted name cannot make the proxy dial the host itself. It then
connects to a vetted address, so a second DNS answer cannot redirect the connection, and
relays bytes both ways (``sandfort.egress.relay``) until either side closes or the tunnel is
idle for too long. One sandbox may hold only a bounded number of tunnels at once; the whole
proxy holds a bounded number of connections, and one source address a bounded number of
connections that have not yet authenticated.

The proxy fails closed: a bad or missing credential (407), a name outside the allowlist or a
blocked address or port (403), too many tunnels or unauthenticated connections (429), the
global ceiling (503), an unresolvable name or unreachable upstream (502) and any method other
than CONNECT (405) are answered with an error and the connection is closed. Decisions are
logged to stderr with the sandbox id and target host, never the credential.

Configuration comes from the environment: ``SANDFORT_EGRESS_SECRET`` (required),
``SANDFORT_EGRESS_LISTEN_HOST`` (default ``127.0.0.1``), ``SANDFORT_EGRESS_LISTEN_PORT``
(default ``3128``), ``SANDFORT_EGRESS_DENIED_CIDRS`` (comma-separated; the node's own
addresses are always added), ``SANDFORT_EGRESS_ALLOWED_PORTS`` (default ``443,80``),
``SANDFORT_EGRESS_MAX_CONNECTIONS_PER_SANDBOX`` (default 64), ``SANDFORT_EGRESS_IDLE_TIMEOUT_S``
(default 300), ``SANDFORT_EGRESS_MAX_TOTAL_CONNECTIONS`` (default 2048),
``SANDFORT_EGRESS_MAX_PREAUTH_PER_SOURCE`` (default 16) and ``SANDFORT_EGRESS_TOKEN_TTL_S``
(default 7 days; longer-lived tokens are refused, except tokens issued before
``LEGACY_TOKEN_CUTOVER``, which earlier releases minted for up to 400 days: those are accepted
until they expire and logged once per sandbox). ``ProxyConfig`` lives in
``sandfort.egress.proxy_limits`` and is re-exported here.

``EgressProxy`` itself is permissive until told otherwise (no denied networks, any port, no
caps); ``ProxyConfig`` and ``EgressProxy.from_config`` carry the restrictive defaults.
"""

import asyncio
import base64
import binascii
import hmac
import ipaddress
import logging
import os
import sys
from collections.abc import Awaitable, Callable, Collection, Iterable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Self

from sandfort.egress.proxy_limits import (
    DEFAULT_LISTEN_HOST,
    DEFAULT_LISTEN_PORT,
    ENV_LISTEN_HOST,
    ENV_LISTEN_PORT,
    ENV_SECRET,
    PROBE_V4,
    PROBE_V6,
    IpNetwork,
    ProxyConfig,
    SlotTable,
    discover_local_addresses,
    host_allowed,
    in_network,
)
from sandfort.egress.relay import (
    MAX_HEADER_LINES,
    MAX_LINE_BYTES,
    RELAY_CHUNK_BYTES,
    Connection,
    Deny,
    auth_required,
    close_writer,
    parse_address,
    parse_target,
    read_request,
    relay,
    send_error,
    source_of,
)
from sandfort.egress.tokens import (
    LEGACY_TOKEN_CUTOVER,
    EgressClaims,
    InvalidEgressToken,
    exceeds_lifetime,
    is_legacy,
    verify_egress_token,
)
from sandfort.webhooks.ssrf import IpAddress, UrlRejected, check_address, resolve_host

__all__ = [
    "DEFAULT_LISTEN_HOST",
    "DEFAULT_LISTEN_PORT",
    "ENV_LISTEN_HOST",
    "ENV_LISTEN_PORT",
    "ENV_SECRET",
    "MAX_HEADER_LINES",
    "MAX_LINE_BYTES",
    "PROBE_V4",
    "PROBE_V6",
    "RELAY_CHUNK_BYTES",
    "Connection",
    "EgressProxy",
    "IpNetwork",
    "ProxyConfig",
    "build_proxy",
    "discover_local_addresses",
    "host_allowed",
    "main",
    "relay",
]

REQUEST_TIMEOUT_S = 15.0
CONNECT_TIMEOUT_S = 10.0
ALL_CONNECTIONS = ""  # the single key of the global slot table

type Resolver = Callable[[str], Awaitable[list[str]]]
type AddressCheck = Callable[[IpAddress], None]

_log = logging.getLogger("sandfort.egress")


@dataclass(slots=True)
class _Seen:
    """What the log line may say and which slots this connection holds."""

    sandbox_id: str = "-"
    host: str = "-"
    slot_held: bool = False
    admitted: bool = False  # holds a global slot
    preauth_source: str | None = None  # holds a pre-authentication slot for this source


class EgressProxy:
    """The CONNECT proxy. ``resolver`` and ``checker`` are seams for tests.

    ``denied_networks``, ``allowed_ports`` (``None`` = any), ``max_connections`` (per sandbox),
    ``max_total_connections``, ``max_preauth_per_source`` (``None`` = unbounded),
    ``idle_timeout_s`` and ``max_token_lifetime_s`` default to no restriction here;
    ``from_config`` applies the configured, restrictive values. ``legacy_cutover`` (``None``
    here, ``LEGACY_TOKEN_CUTOVER`` from ``from_config``) exempts tokens issued before it from
    the lifetime limit.
    """

    def __init__(
        self,
        secret: str,
        *,
        resolver: Resolver = resolve_host,
        checker: AddressCheck = check_address,
        denied_networks: Sequence[IpNetwork] = (),
        allowed_ports: Collection[int] | None = None,
        max_connections: int | None = None,
        max_total_connections: int | None = None,
        max_preauth_per_source: int | None = None,
        idle_timeout_s: float | None = None,
        max_token_lifetime_s: int | None = None,
        legacy_cutover: datetime | None = None,
    ) -> None:
        self._secret = secret
        self._resolver = resolver
        self._checker = checker
        self._denied = tuple(denied_networks)
        self._ports = None if allowed_ports is None else frozenset(allowed_ports)
        self._idle_timeout_s = idle_timeout_s
        self._max_token_lifetime_s = max_token_lifetime_s
        self._legacy_cutover = legacy_cutover
        self._legacy_noted: set[str] = set()  # sandboxes already logged for a legacy token
        self._per_sandbox = SlotTable(max_connections)
        self._total = SlotTable(max_total_connections)
        self._preauth = SlotTable(max_preauth_per_source)

    @classmethod
    def from_config(
        cls,
        config: ProxyConfig,
        *,
        local_addresses: Iterable[IpAddress] = (),
        resolver: Resolver = resolve_host,
        checker: AddressCheck = check_address,
    ) -> Self:
        """Build a proxy with the configured limits; the node's own addresses are denied too."""
        networks: list[IpNetwork] = [ipaddress.ip_network(c) for c in config.denied_cidrs]
        networks.extend(ipaddress.ip_network(address) for address in local_addresses)
        return cls(
            config.secret,
            resolver=resolver,
            checker=checker,
            denied_networks=networks,
            allowed_ports=config.allowed_ports,
            max_connections=config.max_connections,
            max_total_connections=config.max_total_connections,
            max_preauth_per_source=config.max_preauth_per_source,
            idle_timeout_s=config.idle_timeout_s,
            max_token_lifetime_s=config.token_ttl_s,
            legacy_cutover=LEGACY_TOKEN_CUTOVER,
        )

    @property
    def denied_networks(self) -> tuple[IpNetwork, ...]:
        return self._denied

    @property
    def allowed_ports(self) -> frozenset[int] | None:
        """The CONNECT target ports this proxy accepts (``None`` = any)."""
        return self._ports

    @property
    def open_connections(self) -> int:
        """Client connections currently holding a global slot."""
        return self._total.total

    def unauthenticated_from(self, source: str) -> int:
        """Connections from ``source`` that have not authenticated yet."""
        return self._preauth.held(source)

    async def start(self, host: str, port: int) -> asyncio.Server:
        return await asyncio.start_server(self.handle, host, port, limit=MAX_LINE_BYTES)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        seen = _Seen()
        upstream: Connection | None = None
        try:
            self._enter(writer, seen)
            upstream = await asyncio.wait_for(self._admit(reader, seen), REQUEST_TIMEOUT_S)
            _log.info("allow sandbox=%s host=%r", seen.sandbox_id, seen.host)
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await relay((reader, writer), upstream, self._idle_timeout_s)
        except Deny as deny:
            _log.warning(
                "deny sandbox=%s host=%r status=%d reason=%s",
                seen.sandbox_id,
                seen.host,
                deny.status,
                deny.detail,
            )
            await send_error(writer, deny)
        except (OSError, TimeoutError):
            _log.info("drop sandbox=%s host=%r reason=connection error", seen.sandbox_id, seen.host)
        finally:
            self._leave(seen)
            if upstream is not None:
                await close_writer(upstream[1])
            await close_writer(writer)

    def _enter(self, writer: asyncio.StreamWriter, seen: _Seen) -> None:
        """Take a global slot and a pre-authentication slot for the source, or refuse."""
        if not self._total.try_acquire(ALL_CONNECTIONS):
            raise Deny(503, "Service Unavailable", "global connection ceiling reached")
        seen.admitted = True
        source = source_of(writer)
        if not self._preauth.try_acquire(source):
            raise Deny(429, "Too Many Requests", "too many unauthenticated connections")
        seen.preauth_source = source

    def _end_preauth(self, seen: _Seen) -> None:
        if seen.preauth_source is not None:
            self._preauth.release(seen.preauth_source)
            seen.preauth_source = None

    def _leave(self, seen: _Seen) -> None:
        """Release every slot this connection still holds; runs on every exit path."""
        self._end_preauth(seen)
        if seen.slot_held:
            self._per_sandbox.release(seen.sandbox_id)
            seen.slot_held = False
        if seen.admitted:
            self._total.release(ALL_CONNECTIONS)
            seen.admitted = False

    async def _admit(self, reader: asyncio.StreamReader, seen: _Seen) -> Connection:
        request = await read_request(reader)
        if request.method != "CONNECT":
            raise Deny(405, "Method Not Allowed", "method is not CONNECT", {"Allow": "CONNECT"})
        sandbox_id, allowlist = self._authenticate(request.proxy_authorization)
        seen.sandbox_id = sandbox_id
        self._end_preauth(seen)
        host, port = parse_target(request.target)
        seen.host = host.lower().rstrip(".")
        if self._ports is not None and port not in self._ports:
            raise Deny(403, "Forbidden", f"port {port} is not allowed")
        if not host_allowed(host, allowlist):
            raise Deny(403, "Forbidden", "host is not in the allowlist")
        if not self._per_sandbox.try_acquire(sandbox_id):
            raise Deny(429, "Too Many Requests", "too many concurrent connections for sandbox")
        seen.slot_held = True
        addresses = await self._vet(host)
        return await self._open(addresses, port)

    def _authenticate(self, header: str | None) -> tuple[str, tuple[str, ...]]:
        if header is None:
            raise auth_required("no credential")
        scheme, _, encoded = header.partition(" ")
        if scheme.lower() != "basic":
            raise auth_required("credential is not basic")
        try:
            decoded = base64.b64decode(encoded.strip(), validate=True).decode("utf-8")
        except (binascii.Error, ValueError):
            raise auth_required("credential is not decodable") from None
        username, sep, token = decoded.partition(":")
        if not sep:
            raise auth_required("credential has no password")
        now = datetime.now(UTC)
        try:
            claims = verify_egress_token(
                self._secret,
                token,
                now,
                self._max_token_lifetime_s,
                legacy_before=self._legacy_cutover,
            )
        except InvalidEgressToken:
            raise auth_required("invalid token") from None
        if not hmac.compare_digest(username.encode(), claims.sandbox_id.encode()):
            raise auth_required("username does not match the token")
        self._note_legacy(claims, now)
        return claims.sandbox_id, claims.allowlist

    def _note_legacy(self, claims: EgressClaims, now: datetime) -> None:
        """Log, once per sandbox, a token accepted only because it predates the cut-over."""
        limit, cutover = self._max_token_lifetime_s, self._legacy_cutover
        if limit is None or cutover is None or claims.sandbox_id in self._legacy_noted:
            return
        if is_legacy(claims, cutover) and exceeds_lifetime(claims, limit, now):
            self._legacy_noted.add(claims.sandbox_id)
            _log.warning(
                "accepted legacy egress token sandbox=%s issued_at=%s expires_at=%s",
                claims.sandbox_id,
                claims.issued_at.isoformat(),
                claims.expires_at.isoformat(),
            )

    async def _vet(self, host: str) -> list[IpAddress]:
        try:
            texts = await self._resolver(host)
        except OSError:
            raise Deny(502, "Bad Gateway", "host does not resolve") from None
        if not texts:
            raise Deny(502, "Bad Gateway", "host does not resolve")
        addresses = [parse_address(text) for text in texts]
        for address in addresses:  # every answer must pass, not just the one we connect to
            if any(in_network(address, network) for network in self._denied):
                raise Deny(403, "Forbidden", "blocked address: in a denied network")
            try:
                self._checker(address)
            except UrlRejected as exc:
                raise Deny(403, "Forbidden", f"blocked address: {exc}") from None
        return addresses

    async def _open(self, addresses: list[IpAddress], port: int) -> Connection:
        for address in addresses:
            try:
                return await asyncio.wait_for(
                    asyncio.open_connection(str(address), port), CONNECT_TIMEOUT_S
                )
            except (OSError, TimeoutError):
                continue
        raise Deny(502, "Bad Gateway", "upstream connection failed")


def build_proxy(
    config: ProxyConfig,
    *,
    discover: Callable[[], Iterable[IpAddress]] = discover_local_addresses,
) -> EgressProxy:
    """The startup proxy: configured limits plus the node's own addresses, denied set logged."""
    proxy = EgressProxy.from_config(config, local_addresses=discover())
    denied = ", ".join(str(network) for network in proxy.denied_networks)
    _log.info("egress denied networks: %s", denied or "(none)")
    _log.info("egress allowed ports: %s", ",".join(str(port) for port in config.allowed_ports))
    return proxy


async def _serve(config: ProxyConfig) -> None:
    proxy = build_proxy(config)
    server = await proxy.start(config.host, config.port)
    _log.info("egress proxy listening on %s:%d", config.host, config.port)
    async with server:
        await server.serve_forever()


def main(environ: Mapping[str, str] | None = None) -> int:
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(asctime)s egress %(levelname)s %(message)s",
    )
    try:
        config = ProxyConfig.from_env(os.environ if environ is None else environ)
    except ValueError as exc:
        _log.error("configuration error: %s", exc)
        return 2
    with suppress(KeyboardInterrupt):
        asyncio.run(_serve(config))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
