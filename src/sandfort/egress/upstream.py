"""Resolve, vet and connect: the upstream half of an egress CONNECT.

``resolve_and_vet`` resolves a host name through the resolver seam and vets every answer;
``vet_address`` vets one address (an answer, or an IP-literal target that a CIDR rule admitted);
``open_tunnel`` dials a vetted address; ``open_pinned`` puts the per-sandbox pin store
(``sandfort.egress.pinning``) in front of both. Vetting refuses, in this order: an IPv6 translation
prefix (NAT64, 6to4, Teredo; fixed, the denied list cannot remove it), an address inside a
denied network, and anything ``sandfort.webhooks.ssrf.check_address`` rejects. The node's
denied list therefore wins over a tenant's rule.
"""

import asyncio
from collections.abc import Awaitable, Callable, Sequence

from sandfort.egress.pinning import PinStore
from sandfort.egress.proxy_limits import IpNetwork, in_network
from sandfort.egress.relay import Connection, Deny, parse_address
from sandfort.egress.rules import is_translation_address
from sandfort.webhooks.ssrf import IpAddress, UrlRejected

CONNECT_TIMEOUT_S = 10.0  # one connect attempt, per address
RESOLVE_TIMEOUT_S = 5.0  # one resolution
CONNECT_ROUND_S = 12.0  # one pass over an address set, however many addresses

type Resolver = Callable[[str], Awaitable[list[str]]]
type AddressCheck = Callable[[IpAddress], None]
type Opener = Callable[[list[IpAddress], int], Awaitable[Connection]]


def vet_address(address: IpAddress, *, checker: AddressCheck, denied: Sequence[IpNetwork]) -> None:
    """Raise ``Deny`` (403) unless ``address`` may be dialed."""
    if is_translation_address(address):
        raise Deny(403, "Forbidden", "blocked address: translation prefix")
    if any(in_network(address, network) for network in denied):
        raise Deny(403, "Forbidden", "blocked address: in a denied network")
    try:
        checker(address)
    except UrlRejected as exc:
        raise Deny(403, "Forbidden", f"blocked address: {exc}") from None


async def resolve_and_vet(
    host: str, *, resolver: Resolver, checker: AddressCheck, denied: Sequence[IpNetwork]
) -> list[IpAddress]:
    """Resolve ``host`` and vet every answer: one denied answer refuses the whole request."""
    try:
        texts = await asyncio.wait_for(resolver(host), RESOLVE_TIMEOUT_S)
    except (OSError, TimeoutError):
        raise Deny(502, "Bad Gateway", "host does not resolve") from None
    if not texts:
        raise Deny(502, "Bad Gateway", "host does not resolve")
    addresses = [parse_address(text) for text in texts]
    for address in addresses:  # every answer must pass, not just the one we connect to
        vet_address(address, checker=checker, denied=denied)
    return addresses


async def open_tunnel(addresses: list[IpAddress], port: int) -> Connection:
    """Connect to the first reachable vetted address; ``Deny`` (502) when none answers.

    Each attempt gets ``CONNECT_TIMEOUT_S``, never more than what is left of the whole round
    (``CONNECT_ROUND_S``): the round bounds the loop however many addresses there are.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + CONNECT_ROUND_S
    for address in addresses:
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(str(address), port), min(CONNECT_TIMEOUT_S, remaining)
            )
        except (OSError, TimeoutError):
            continue
    raise Deny(502, "Bad Gateway", "upstream connection failed")


async def open_pinned(
    sandbox_id: str,
    host: str,
    port: int,
    *,
    pins: PinStore,
    resolver: Resolver,
    checker: AddressCheck,
    denied: Sequence[IpNetwork],
    opener: Opener = open_tunnel,
) -> tuple[Connection, list[IpAddress]]:
    """Steps 8 to 10 for a name: the pinned set first, else resolve, vet and connect.

    Inside the pin window the pinned set is dialed without a query. When no pinned address
    connects, the pin is dropped and the name is resolved and vetted once more, with a fresh
    connect round (``admission_cap_s`` allows two resolutions and two rounds). A set is pinned
    only after it was reached, so a resolver error, an empty or denied answer, or an
    unreachable set is never pinned. ``opener`` is the connect seam.
    """
    pinned = pins.get(sandbox_id, host)
    if pinned is not None:
        try:
            return await opener(pinned, port), pinned
        except Deny:  # no pinned address answered: the pin is stale
            pins.drop(sandbox_id, host)
    addresses = await resolve_and_vet(host, resolver=resolver, checker=checker, denied=denied)
    connection = await opener(addresses, port)
    pins.put(sandbox_id, host, addresses)
    return connection, addresses
