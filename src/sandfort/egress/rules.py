"""Allowlist rules of the egress proxy (docs/egress-v2-design.md section 3.1).

A sandbox's allowlist entries are of three kinds: a host name (exact match), a leading-dot
domain (the domain and its subdomains) and a CIDR range (an IP-literal target inside it).
``EgressRules`` keeps them apart on purpose: a name is admitted only by a host or domain rule
and an address only by a CIDR rule, so a name never reaches an address through a range and a
literal never passes as a name.

``target_address`` classifies a CONNECT target host. Only a strict literal (as
``ipaddress.ip_address`` reads it) is an address; ``2130706433``, ``0x7f.0.0.1`` and
``010.0.0.1`` stay names, and no rule admits them. An IPv4-mapped IPv6 literal folds to IPv4
before anything else, as resolver answers do (``sandfort.egress.relay.parse_address``).
``TRANSLATION_PREFIXES`` are the IPv6 ranges that embed an IPv4 address (IPv4-compatible,
SIIT, NAT64, 6to4, Teredo) plus deprecated site-local space; the proxy always refuses them,
and no denied-networks setting can remove them. ``::`` and ``::1`` are excepted from the
``::/96`` block so they keep their own refusal reasons downstream.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)
from typing import Final, Self

from sandfort.domain.egress_entries import is_cidr_candidate
from sandfort.egress.relay import Deny
from sandfort.webhooks.ssrf import IpAddress

type Network = IPv4Network | IPv6Network

TRANSLATION_PREFIXES: Final = tuple(
    IPv6Network(cidr)
    for cidr in (
        "::/96",
        "::ffff:0:0:0/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "2002::/16",
        "2001::/32",
        "fec0::/10",
    )
)
_TRANSLATION_EXCEPTIONS: Final = (IPv6Address("::"), IPv6Address("::1"))
DOMAIN_MARKER: Final = "."


def is_translation_address(address: IpAddress) -> bool:
    """True for an IPv6 address inside an always-refused prefix; IPv4 never is.

    ``::`` and ``::1`` fall inside ``::/96`` but are excepted: the denied-networks list and
    the address check refuse them with their own reasons, as before.
    """
    if not isinstance(address, IPv6Address):
        return False
    if address in _TRANSLATION_EXCEPTIONS:
        return False
    return any(address in prefix for prefix in TRANSLATION_PREFIXES)


def _contains(network: Network, address: IpAddress) -> bool:
    """Containment within one family; an address of the other family is never inside."""
    if isinstance(network, IPv4Network) and isinstance(address, IPv4Address):
        return address in network
    if isinstance(network, IPv6Network) and isinstance(address, IPv6Address):
        return address in network
    return False


def target_address(host: str) -> IpAddress | None:
    """The address a CONNECT target host names, or ``None`` when it is a name.

    A zone id (``%``) is refused with a 400: it is part of target parsing, not of rule match.
    """
    if "%" in host:
        raise Deny(400, "Bad Request", "zone id in target")
    try:
        address = ip_address(host)
    except ValueError:
        return None
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


@dataclass(frozen=True, slots=True)
class EgressRules:
    """The parsed allowlist of one sandbox: host names, domain suffixes and networks."""

    hosts: frozenset[str] = frozenset()
    domains: tuple[str, ...] = ()  # each with its leading dot
    networks: tuple[Network, ...] = ()

    @classmethod
    def from_entries(cls, entries: Iterable[str]) -> Self:
        hosts: set[str] = set()
        domains: list[str] = []
        networks: list[Network] = []
        for entry in entries:
            if is_cidr_candidate(entry):
                networks.append(ip_network(entry, strict=False))
            elif entry.startswith(DOMAIN_MARKER):
                domains.append(entry)
            else:
                hosts.add(entry)
        return cls(frozenset(hosts), tuple(domains), tuple(networks))

    def admits_name(self, host: str) -> bool:
        """True when ``host`` equals a host rule or falls under a domain rule.

        ``.example.com`` admits ``example.com`` and every subdomain of it; ``example.com``
        admits that name only. Case and trailing dots are folded; network rules never match.
        """
        name = host.lower().rstrip(".")
        if not name:
            return False
        if name in self.hosts:
            return True
        return any(
            len(entry) > len(DOMAIN_MARKER) and (name == entry[1:] or name.endswith(entry))
            for entry in self.domains
        )

    def admits_address(self, address: IpAddress) -> bool:
        """True when a network rule of the same family contains ``address`` (already folded)."""
        return any(_contains(network, address) for network in self.networks)
