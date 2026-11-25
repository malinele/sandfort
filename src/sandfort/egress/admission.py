"""Admission decisions of the egress proxy (docs/egress-v2-design.md sections 4.1 to 4.2.1, 5.5).

``decide`` is step 5: it turns a verified ``EgressCredential`` and the policy entry (or no entry
when the policy URL is unset) into the ``EgressRules`` to match and the ``gen=`` log value. A
v2 credential needs the policy channel (503 without it) and an equal epoch; a v1 credential
follows its claims when the channel is off, and with the channel on it is decided by the
stored row: generation 0 means the row's rules (the claims are ignored), generation 1 or more
means the sandbox was reset onto a v2 credential and the v1 token is superseded (407).
``match_rules`` is step 6. ``recheck`` is step 11: it reads the CURRENT cache entry (refreshing
a stale one first) and repeats steps 5 and 6, so a policy that changed while the proxy was
resolving and connecting still decides the request. ``register`` is step 12. The proxy runs on
one event loop and has no await between ``recheck`` and ``register``, so no cache update can
land in between.

``admission_cap_s`` is the sum of the per-phase budgets (section 4.1.1): the request read is
bounded separately by ``REQUEST_TIMEOUT_S`` and everything after it by this cap.
"""

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from ipaddress import ip_address

from sandfort.egress.auth import EgressCredential
from sandfort.egress.policy_client import PolicyClient, PolicyEntry, PolicyUnavailable
from sandfort.egress.proxy_limits import DEFAULT_POLICY_TIMEOUT_S, ProxyConfig
from sandfort.egress.relay import Connection, Deny, auth_required, close_writer
from sandfort.egress.rules import EgressRules
from sandfort.egress.tunnels import TunnelRecord, TunnelRegistry
from sandfort.egress.upstream import CONNECT_ROUND_S, RESOLVE_TIMEOUT_S
from sandfort.webhooks.ssrf import IpAddress

POLICY_UNAVAILABLE = "egress policy unavailable"
NO_POLICY_WARNING = (
    "egress policy URL is not set: v2 tokens get 503 and v1 tokens follow their claims"
    " with no revocation"
)
NO_GENERATION = "-"  # the gen= log value when no lookup decided the request


def admission_cap_s(lookup_timeout_s: float) -> float:
    """Whole admission after the request is read: two lookups, two resolutions, two rounds."""
    return 2 * lookup_timeout_s + 2 * RESOLVE_TIMEOUT_S + 2 * CONNECT_ROUND_S


def policy_unavailable() -> Deny:
    return Deny(503, "Service Unavailable", POLICY_UNAVAILABLE)


def generation_label(entry: PolicyEntry | None) -> str:
    return NO_GENERATION if entry is None else str(entry.generation)


def _rules(entries: tuple[str, ...]) -> EgressRules:
    try:
        return EgressRules.from_entries(entries)
    except ValueError:  # a signed policy that does not parse is a server fault: fail closed
        raise policy_unavailable() from None


def decide(
    credential: EgressCredential, entry: PolicyEntry | None, *, policy_configured: bool
) -> tuple[EgressRules, str]:
    """Rules and ``gen=`` value for ``credential``, or the ``Deny`` of the decision table.

    ``entry`` is None exactly when the policy URL is unset.
    """
    if not policy_configured:
        if credential.version == 2:
            raise policy_unavailable()
        return _rules(credential.allowlist), NO_GENERATION
    if entry is None:
        raise policy_unavailable()
    if not entry.found:
        raise auth_required("no policy for sandbox")
    if credential.version == 2:
        if credential.epoch != entry.epoch:
            raise auth_required("credential epoch mismatch")
    elif entry.generation >= 1:
        raise auth_required("v1 token superseded")
    return _rules(entry.rules), generation_label(entry)


def match_rules(rules: EgressRules, host: str, address: IpAddress | None) -> None:
    """Step 6: an IP literal needs a CIDR rule, a name a host or domain rule."""
    if address is not None:
        if not rules.admits_address(address):
            raise Deny(403, "Forbidden", "address is not in the allowlist")
    elif not rules.admits_name(host):
        raise Deny(403, "Forbidden", "host is not in the allowlist")


async def current_entry(client: PolicyClient, sandbox_id: str) -> PolicyEntry:
    """The fresh policy entry of a sandbox; a failed or slow lookup is the 503."""
    try:
        return await client.lookup(sandbox_id)
    except (PolicyUnavailable, TimeoutError):
        raise policy_unavailable() from None


async def recheck(
    credential: EgressCredential,
    client: PolicyClient | None,
    *,
    sandbox_id: str,
    host: str,
    address: IpAddress | None,
    seen: "Seen | None" = None,
) -> PolicyEntry | None:
    """Step 11: decide again under the current policy; ``address`` is the literal target.

    Raises the ``Deny`` of steps 5 and 6 when the policy no longer admits the target; the
    caller closes the upstream connection first. ``seen.gen`` (when given) is set to the
    generation that decided before the rules are matched, so a refusal logs the deciding one.
    Without a policy client (URL unset) only the v1 claims rules are matched again and there is
    nothing to refresh.
    """
    if client is None:
        rules, _ = decide(credential, None, policy_configured=False)
        match_rules(rules, host, address)
        return None
    entry = await current_entry(client, sandbox_id)
    if seen is not None:
        seen.gen = generation_label(entry)
    rules, _ = decide(credential, entry, policy_configured=True)
    match_rules(rules, host, address)
    return entry


def connected_address(upstream: Connection, fallback: IpAddress) -> IpAddress:
    """The address the upstream connection reached, or ``fallback`` when it does not say."""
    peer = upstream[1].get_extra_info("peername")
    if isinstance(peer, tuple) and peer:
        try:
            parsed = ip_address(str(peer[0]).split("%", 1)[0])
        except ValueError:
            return fallback
        mapped = getattr(parsed, "ipv4_mapped", None)
        return mapped if mapped is not None else parsed
    return fallback


def register(
    registry: TunnelRegistry,
    credential: EgressCredential,
    entry: PolicyEntry | None,
    *,
    host: str,
    address: IpAddress,
    port: int,
) -> TunnelRecord:
    """Step 12: record the tunnel with the handler's task. Call it with no await since recheck."""
    task = asyncio.current_task()
    if task is None:
        raise RuntimeError("an egress tunnel registers from inside its handler task")
    return registry.register(
        TunnelRecord(
            sandbox_id=credential.sandbox_id,
            host=host,
            address=address,
            port=port,
            generation=0 if entry is None else entry.generation,
            token_version=credential.version,
            epoch=credential.epoch,
            task=task,
        )
    )


@dataclass(slots=True)
class Seen:
    """What the log line may say and which slots this connection holds."""

    sandbox_id: str = "-"
    host: str = "-"
    gen: str = NO_GENERATION  # the policy generation that decided the request
    slot_held: bool = False
    admitted: bool = False  # holds a global slot
    preauth_source: str | None = None  # holds a pre-authentication slot for this source
    upstream: Connection | None = None  # the upstream connection, once opened
    tunnel: TunnelRecord | None = None  # the registry record, once admitted


async def admit_target(
    credential: EgressCredential,
    seen: Seen,
    *,
    policy: PolicyClient | None,
    tunnels: TunnelRegistry,
    host: str,
    address: IpAddress | None,
    port: int,
    take_slot: Callable[[], None],
    dial: Callable[[], Awaitable[tuple[Connection, list[IpAddress]]]],
) -> Connection:
    """Steps 5 to 12 for a parsed target: policy, rules, slot, connect, re-check, register.

    ``take_slot`` raises the 429 ``Deny`` when the sandbox is at its tunnel cap; ``dial`` vets
    and connects and returns the upstream connection with the vetted addresses.
    """
    entry = None if policy is None else await current_entry(policy, credential.sandbox_id)
    rules, seen.gen = decide(credential, entry, policy_configured=policy is not None)
    match_rules(rules, host, address)
    take_slot()
    seen.slot_held = True
    upstream, addresses = await dial()
    seen.upstream = upstream
    try:
        entry = await recheck(
            credential,
            policy,
            sandbox_id=credential.sandbox_id,
            host=host,
            address=address,
            seen=seen,
        )
    except Deny:
        seen.upstream = None
        await close_writer(upstream[1])  # the upstream goes first, then the refusal
        raise
    seen.gen = generation_label(entry)
    # no await from the re-check to the registration: no cache update lands in between
    reached = connected_address(upstream, addresses[0])
    seen.tunnel = register(tunnels, credential, entry, host=host, address=reached, port=port)
    return upstream


def policy_client_from(config: ProxyConfig) -> PolicyClient | None:
    """The policy lookup client for ``config``, or None when the policy URL is unset."""
    if not config.policy_url:
        return None
    return PolicyClient(
        config.policy_url,
        config.secret,
        cache_s=config.policy_cache_s,
        timeout_s=config.policy_timeout_s,
        max_stale_s=config.policy_max_stale_s,
    )


def wire_policy(client: PolicyClient | None) -> tuple[TunnelRegistry, float]:
    """The tunnel registry for a proxy and its lookup timeout (for ``admission_cap_s``).

    With a client the registry shares its clock and the client's change callback re-checks the
    sandbox's tunnels; without one the registry stays empty-handed and the default applies.
    """
    if client is None:
        return TunnelRegistry(), DEFAULT_POLICY_TIMEOUT_S
    registry = TunnelRegistry(client.clock)
    client.set_on_change(registry.recheck_sandbox)
    client.set_has_tunnels(registry.has_tunnels)
    return registry, client.timeout_s
