"""CONNECT-method forward proxy that enforces a per-sandbox egress allowlist.

Credentials arrive as ``Proxy-Authorization: Basic base64(<sandbox_id>:<egress token>)``
(``sandfort.egress.auth``). A v1 token (``sandfort.egress.tokens``) carries the sandbox's
allowlist; a v2 token (``sandfort.egress.tokens_v2``) names the sandbox and a credential epoch,
and the policy is looked up through ``sandfort.egress.policy_client`` when
``SANDFORT_EGRESS_POLICY_URL`` is set (then v1 tokens are looked up too and the stored row
decides; ``sandfort.egress.admission`` has the decision table, ``sandfort.egress.tunnels``
closes open tunnels a changed policy no longer admits).
For ``CONNECT host:port`` the proxy verifies the token, matches ``host`` against the allowlist
(``sandfort.egress.rules``), refuses ports outside the allowed-ports setting, resolves the name
itself and vets every resolved address with ``sandfort.webhooks.ssrf.check_address`` and the
denied CIDRs (loopback, link-local, RFC 1918, the node's own addresses by default), so a tenant
that controls DNS for an allowlisted name cannot make the proxy dial the host itself. It
connects to a vetted address and keeps that set pinned for the sandbox and name for
``dns_pin_s`` seconds (``sandfort.egress.pinning``), so a second DNS answer cannot redirect a
later connection, then relays bytes both ways (``sandfort.egress.relay``) until either side
closes or the tunnel is idle for too long. Tunnels per sandbox, connections in total and
unauthenticated connections per source are all bounded.

The proxy fails closed: a bad or missing credential (407), a name outside the allowlist or a
blocked address or port (403), too many tunnels or unauthenticated connections (429), the
global ceiling or an unavailable policy (503), an unresolvable name or unreachable upstream
(502) and any method other than CONNECT (405) are answered with an error and the connection is
closed. Decisions are logged to stderr with the sandbox id, target host and policy generation
(``gen=``), never the credential. A name the policy refused is logged as its length and a keyed
digest only (``sandfort.egress.logname``); repeated denies of one sandbox and reason are
logged once per interval with a suppressed count (``sandfort.egress.deny_log``). Reading the
request is bounded by ``REQUEST_TIMEOUT_S``; everything after it by ``admission_cap_s``.

Configuration comes from the environment (``SANDFORT_EGRESS_SECRET`` is required; the other
``SANDFORT_EGRESS_*`` settings are in ``sandfort.egress.proxy_limits`` and docs/operations.md).
``EgressProxy`` itself is permissive until told otherwise; ``ProxyConfig`` (re-exported here)
and ``EgressProxy.from_config`` carry the restrictive defaults.
"""

import asyncio
import ipaddress
import logging
import os
import sys
import time
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from contextlib import aclosing, suppress
from datetime import UTC, datetime
from typing import Self

from sandfort.egress.admission import (
    NO_POLICY_WARNING,
    Seen,
    admission_cap_s,
    admit_target,
    policy_client_from,
    wire_policy,
)
from sandfort.egress.auth import EgressCredential, authenticate, note_legacy
from sandfort.egress.deny_log import DenyLog
from sandfort.egress.dns_sink import serving_dns_sink
from sandfort.egress.logname import redacted_name
from sandfort.egress.pinning import PinStore
from sandfort.egress.policy_client import PolicyClient, PolicyEntry
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
    discover_local_addresses,
    host_allowed,
)
from sandfort.egress.relay import (
    MAX_HEADER_LINES,
    MAX_LINE_BYTES,
    RELAY_CHUNK_BYTES,
    Connection,
    Deny,
    Request,
    close_writer,
    parse_target,
    read_request,
    relay,
    send_error,
)
from sandfort.egress.rules import target_address
from sandfort.egress.slots import ConnectionSlots
from sandfort.egress.tokens import LEGACY_TOKEN_CUTOVER
from sandfort.egress.tunnels import TunnelRegistry, stop_sweeper, sweep_while_serving
from sandfort.egress.upstream import (
    CONNECT_TIMEOUT_S as CONNECT_TIMEOUT_S,  # re-export: proxy.CONNECT_TIMEOUT_S still resolves
)
from sandfort.egress.upstream import (
    AddressCheck,
    Resolver,
    open_pinned,
    open_tunnel,
    vet_address,
)
from sandfort.webhooks.ssrf import IpAddress, check_address, resolve_host

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

REQUEST_TIMEOUT_S = 15.0  # bounds reading the request line and headers only

_log = logging.getLogger("sandfort.egress")


class EgressProxy:
    """The CONNECT proxy. ``resolver`` and ``checker`` are seams for tests.

    ``denied_networks``, ``allowed_ports`` (``None`` = any), ``max_connections`` (per sandbox),
    ``max_total_connections``, ``max_preauth_per_source`` (``None`` = unbounded),
    ``idle_timeout_s`` and ``max_token_lifetime_s`` default to no restriction here;
    ``from_config`` applies the configured, restrictive values. ``legacy_cutover`` (``None``
    here, ``LEGACY_TOKEN_CUTOVER`` from ``from_config``) exempts tokens issued before it from
    the lifetime limit. ``policy_client`` (``None`` = policy channel off) is the policy lookup.
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
        policy_client: PolicyClient | None = None,
        dns_pin_s: float = 0,
        deny_log: DenyLog | None = None,
    ) -> None:
        self._secret = secret
        self._deny_log = deny_log or DenyLog()
        self._resolver = resolver
        self._checker = checker
        self._denied = tuple(denied_networks)
        self._ports = None if allowed_ports is None else frozenset(allowed_ports)
        self._idle_timeout_s = idle_timeout_s
        self._max_token_lifetime_s = max_token_lifetime_s
        self._legacy_cutover = legacy_cutover
        self._legacy_noted: set[str] = set()  # sandboxes already logged for a legacy token
        self._slots = ConnectionSlots(
            max_connections, max_total_connections, max_preauth_per_source
        )
        self._policy = policy_client
        self._tunnels, lookup_s = wire_policy(policy_client)
        self._pins = PinStore(dns_pin_s, policy_client.clock if policy_client else time.monotonic)
        if policy_client is not None:  # one change callback: the registry and the pins both hear it
            policy_client.set_on_change(self._policy_changed)
        self._sweeper: asyncio.Task[None] | None = None
        self._admission_cap_s = admission_cap_s(lookup_s)

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
            policy_client=policy_client_from(config),
            dns_pin_s=config.dns_pin_s,
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
        return self._slots.open_connections

    @property
    def tunnels(self) -> TunnelRegistry:
        """The registry of admitted, still open tunnels."""
        return self._tunnels

    def _policy_changed(self, sandbox_id: str, entry: PolicyEntry) -> None:
        self._tunnels.recheck_sandbox(sandbox_id, entry)
        self._pins.recheck_sandbox(sandbox_id, entry)  # also when the sandbox holds no tunnel

    def unauthenticated_from(self, source: str) -> int:
        """Connections from ``source`` that have not authenticated yet."""
        return self._slots.unauthenticated_from(source)

    async def sweep_once(self) -> None:
        """Refresh the policy of every sandbox with tunnels and close what it no longer admits."""
        if self._policy is not None:
            await self._tunnels.sweep_once(self._policy)

    async def start(self, host: str, port: int) -> asyncio.Server:
        server = await asyncio.start_server(self.handle, host, port, limit=MAX_LINE_BYTES)
        if self._policy is not None:
            sweep = sweep_while_serving(self._tunnels, self._policy, server.is_serving)
            self._sweeper = asyncio.create_task(sweep)
        return server

    async def aclose(self) -> None:
        await stop_sweeper(self._sweeper, self._policy)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        seen = Seen()
        try:
            self._slots.enter(writer, seen)
            request = await asyncio.wait_for(read_request(reader), REQUEST_TIMEOUT_S)
            upstream = await asyncio.wait_for(self._admit(request, seen), self._admission_cap_s)
            _log.info("allow sandbox=%s host=%r gen=%s", seen.sandbox_id, seen.host, seen.gen)
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await relay((reader, writer), upstream, self._idle_timeout_s)
        except Deny as deny:
            self._deny_log.log(seen.sandbox_id, deny, seen.gen, lambda: self._logged_host(seen))
            await send_error(writer, deny)
        except (OSError, TimeoutError):
            _log.info(
                "drop sandbox=%s host=%s reason=connection error",
                seen.sandbox_id,
                self._logged_host(seen),
            )
        finally:
            self._leave(seen)
            if seen.upstream is not None:
                await close_writer(seen.upstream[1])
            await close_writer(writer)

    def _logged_host(self, seen: Seen) -> str:
        """The raw name once it matched a rule (a slot is held), else only its length and digest."""
        if seen.slot_held or seen.host == "-":
            return repr(seen.host)
        return redacted_name(self._secret, seen.host)

    def _leave(self, seen: Seen) -> None:
        """Release every slot this connection still holds; runs on every exit path."""
        if seen.tunnel is not None:
            self._tunnels.unregister(seen.tunnel)
            seen.tunnel = None
        self._slots.leave(seen)

    async def _admit(self, request: Request, seen: Seen) -> Connection:
        """Steps 2 to 12 of docs/egress-v2-design.md section 4.1 (the request is read)."""
        if request.method != "CONNECT":
            raise Deny(405, "Method Not Allowed", "method is not CONNECT", {"Allow": "CONNECT"})
        credential = self._authenticate(request.proxy_authorization)
        sandbox_id = seen.sandbox_id = credential.sandbox_id
        self._slots.end_preauth(seen)
        host, port = parse_target(request.target)
        seen.host = host.lower().rstrip(".")
        address = target_address(host)  # a zone id is a 400 here, before the port check
        if self._ports is not None and port not in self._ports:
            raise Deny(403, "Forbidden", f"port {port} is not allowed")
        return await admit_target(
            credential,
            seen,
            policy=self._policy,
            tunnels=self._tunnels,
            host=host,
            address=address,
            port=port,
            take_slot=lambda: self._slots.take(sandbox_id),
            dial=lambda: self._dial(sandbox_id, host, address, port),
        )

    async def _dial(
        self, sandbox_id: str, host: str, address: IpAddress | None, port: int
    ) -> tuple[Connection, list[IpAddress]]:
        """Steps 8 to 10: vet or resolve (through the sandbox's DNS pin) and connect."""
        if address is None:
            return await open_pinned(
                sandbox_id,
                host,
                port,
                pins=self._pins,
                resolver=self._resolver,
                checker=self._checker,
                denied=self._denied,
                opener=self._open,
            )
        vet_address(address, checker=self._checker, denied=self._denied)
        return await self._open([address], port), [address]

    def _authenticate(self, header: str | None) -> EgressCredential:
        now = datetime.now(UTC)
        credential = authenticate(
            self._secret,
            header,
            now=now,
            max_lifetime_s=self._max_token_lifetime_s,
            legacy_before=self._legacy_cutover,
        )
        note_legacy(
            self._legacy_noted,
            credential,
            now,
            max_lifetime_s=self._max_token_lifetime_s,
            cutover=self._legacy_cutover,
        )
        return credential

    async def _open(self, addresses: list[IpAddress], port: int) -> Connection:
        return await open_tunnel(addresses, port)


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
    if not config.policy_url:
        _log.warning(NO_POLICY_WARNING)
    return proxy


async def _serve(config: ProxyConfig) -> None:
    proxy = build_proxy(config)
    server = await proxy.start(config.host, config.port)
    _log.info("egress proxy listening on %s:%d", config.host, config.port)
    async with server, aclosing(proxy), serving_dns_sink(config.dns_sink_address):
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
