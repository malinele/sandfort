"""CIDR entries of an egress allowlist (docs/egress-v2-design.md sections 3.1 and 12.1).

An allowlist entry that parses as a network (it contains ``/``) is validated here, not as a
hostname. The rules are strict and nothing is normalized: a CIDR must already be canonical,
must name the network address, must be at least ``/8`` (IPv4) or ``/32`` (IPv6), must be
entirely global (no overlap with any special-purpose range) and must not overlap a network the
server denies. Standard library only: the domain layer imports nothing else.
"""

from collections.abc import Callable
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Final

EGRESS_CIDR_MIN_PREFIX_V4: Final = 8
EGRESS_CIDR_MIN_PREFIX_V6: Final = 32

type Network = IPv4Network | IPv6Network

# Special-purpose ranges that are not publicly routable (IANA registries). A tenant range that
# overlaps any of them is refused, so it cannot name loopback, private, shared, link-local,
# multicast, reserved, documentation, translation or tunnel space.
NON_GLOBAL_NETWORKS_V4: Final = tuple(
    IPv4Network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
)
NON_GLOBAL_NETWORKS_V6: Final = tuple(
    IPv6Network(cidr)
    for cidr in (
        "::/96",
        "::ffff:0:0/96",
        "::ffff:0:0:0/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
        "5f00::/16",
        "fc00::/7",
        "fe80::/10",
        "fec0::/10",
        "ff00::/8",
    )
)

_HOST_BITS = "has host bits set (write the network address)"
_CANONICAL = "must be a canonical CIDR (compressed lowercase IPv6, no leading zeros)"
_NOT_GLOBAL = (
    "must be entirely global (no loopback, link-local, private, shared, multicast, "
    "reserved or documentation addresses)"
)
_DENIED_OVERLAP = "overlaps a denied network"


def _overlaps(first: Network, second: Network) -> bool:
    """Whether two networks share an address; networks of different families never do."""
    if isinstance(first, IPv4Network) and isinstance(second, IPv4Network):
        return first.overlaps(second)
    if isinstance(first, IPv6Network) and isinstance(second, IPv6Network):
        return first.overlaps(second)
    return False


def network_is_global(network: Network) -> bool:
    """True only when ``network`` overlaps no special-purpose range of its family.

    The stdlib ``is_global`` property is true for a network that merely straddles a special
    range, so the overlap with every listed range decides instead.
    """
    special = NON_GLOBAL_NETWORKS_V4 if network.version == 4 else NON_GLOBAL_NETWORKS_V6
    return not any(_overlaps(network, other) for other in special)


def is_cidr_candidate(entry: str) -> bool:
    """True when ``entry`` has a ``/`` and parses as a network (host bits aside).

    An entry that does not parse as a network, such as ``example.com/v1``, stays on the
    hostname path and keeps its hostname message.
    """
    if "/" not in entry:
        return False
    try:
        ip_network(entry, strict=False)
    except ValueError:
        return False
    return True


def _parse(entry: str) -> Network | str:
    """The strict network for ``entry``, or the phrase saying why it is not one."""
    try:
        return ip_network(entry, strict=True)
    except ValueError:
        pass
    try:
        ip_network(entry, strict=False)
    except ValueError:
        return _CANONICAL
    return _HOST_BITS


def _minimum_prefix(network: Network) -> int:
    return EGRESS_CIDR_MIN_PREFIX_V4 if network.version == 4 else EGRESS_CIDR_MIN_PREFIX_V6


def _overlaps_denied(network: Network, denied: tuple[str, ...]) -> bool:
    for text in denied:
        try:
            other = ip_network(text, strict=False)
        except ValueError:
            continue  # the server settings validate their own list; skip what cannot parse
        if _overlaps(network, other):
            return True
    return False


def cidr_problem(
    entry: str,
    denied: tuple[str, ...] = (),
    is_global: Callable[[Network], bool] = network_is_global,
) -> str | None:
    """Why ``entry`` is not an acceptable CIDR entry, or ``None`` when it is one.

    The first problem wins, in this order: zone id (counts as canonical form), host bits,
    canonical form, minimum prefix, global address space, overlap with a ``denied`` network.
    The caller prefixes the entry.
    """
    if "%" in entry:
        return _CANONICAL
    parsed = _parse(entry)
    if isinstance(parsed, str):
        return parsed
    if str(parsed) != entry:
        return _CANONICAL
    minimum = _minimum_prefix(parsed)
    if parsed.prefixlen < minimum:
        return f"needs a prefix of at least /{minimum}"
    if not is_global(parsed):
        return _NOT_GLOBAL
    if _overlaps_denied(parsed, denied):
        return _DENIED_OVERLAP
    return None
