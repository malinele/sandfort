"""The shared bridge network for sandboxes that may reach the outside."""

import logging
import os
from typing import Any

import anyio

from sandfort.drivers.docker.client import (
    HTTP_CONFLICT,
    docker_errors,
    run_blocking,
    translate_errors,
)
from sandfort.drivers.docker.labels import LABEL_MANAGED
from sandfort.drivers.errors import DriverUnsupported

NETWORK_NAME = "sf-net"
# Bridge for sandboxes with an egress allowlist; deploy/host-setup.sh restricts it to the proxy.
# ``ensure_network(client, EGRESS_NETWORK_NAME)`` creates it the same way as the main network.
EGRESS_NETWORK_NAME = "sf-egress-net"
ICC_OPTION = "com.docker.network.bridge.enable_icc"
BRIDGE_NAME_OPTION = "com.docker.network.bridge.name"
# Interface names deploy/host-setup.sh writes its firewall rules for. A network recreated
# with a random br-<id> name matches no rule, so the egress rules would fail open.
BRIDGE_INTERFACES = {NETWORK_NAME: "sf-br0", EGRESS_NETWORK_NAME: "sf-br1"}
# The host script's variables that rename those interfaces; an operator who set them there
# sets the same ones for the server so the expected names agree.
BRIDGE_INTERFACE_ENV = {
    NETWORK_NAME: "SF_BRIDGE_IFACE",
    EGRESS_NETWORK_NAME: "SF_EGRESS_BRIDGE_IFACE",
}

logger = logging.getLogger(__name__)
_create_lock = anyio.Lock()
# Network names already warned about: the check runs on every create, the warning once.
_warned: set[str] = set()


def expected_bridge_interface(name: str) -> str | None:
    """The bridge interface the host firewall rules expect for ``name`` (None if unmanaged)."""
    default = BRIDGE_INTERFACES.get(name)
    if default is None:
        return None
    return os.environ.get(BRIDGE_INTERFACE_ENV[name], "").strip() or default


async def _find(client: Any, name: str) -> Any | None:
    # The ``names`` filter is a substring match, so compare exactly.
    found = await run_blocking(client.networks.list, names=[name])
    return next((network for network in found if network.name == name), None)


def _has_ipv6(network: Any, name: str) -> bool:
    """True for an egress net with IPv6 enabled (the main network is not subject to the rule)."""
    if name != EGRESS_NETWORK_NAME:
        return False
    attrs = getattr(network, "attrs", None) or {}
    return bool(attrs.get("EnableIPv6"))


def _refuse_ipv6(network: Any, name: str) -> None:
    """The egress net stays IPv4-only (egress v2 design 4.5): adopting one with IPv6 is refused.

    The host IPv6 INPUT chain has no guard and the proxy's denied list is not applied to
    addresses a sandbox could reach directly, so an IPv6-enabled egress bridge fails closed.
    """
    if _has_ipv6(network, name):
        raise DriverUnsupported(
            f"network {name} has IPv6 enabled; the egress network must be IPv4-only:"
            " remove it and let the server recreate it"
        )


def _warn_if_bridge_mismatch(network: Any, name: str) -> None:
    expected = expected_bridge_interface(name)
    if expected is None or name in _warned:
        return
    attrs = getattr(network, "attrs", None) or {}
    actual = (attrs.get("Options") or {}).get(BRIDGE_NAME_OPTION)
    if actual != expected:
        _warned.add(name)
        logger.warning(
            "network %s has bridge interface %s, expected %s: the host firewall rules "
            "from deploy/host-setup.sh do not match it; recreate the network",
            name,
            actual or "(generated br-<id>)",
            expected,
        )


async def _refuse_created_ipv6(created: Any, name: str) -> None:
    """Fail closed at create: docker-py sends ``EnableIPv6`` only when true, so a daemon that
    defaults bridges to IPv6 can hand back an IPv6-enabled egress net. Remove it and refuse.
    """
    if not _has_ipv6(created, name):
        return
    await run_blocking(created.remove)
    _refuse_ipv6(created, name)


async def ensure_network(client: Any, name: str = NETWORK_NAME) -> str:
    """Ensure the bridge network (icc=false, fixed bridge name) exists; return its name."""
    errors = docker_errors()
    with translate_errors(name, "network.ensure"):
        existing = await _find(client, name)
        if existing is not None:
            _refuse_ipv6(existing, name)
            _warn_if_bridge_mismatch(existing, name)
            return name
        async with _create_lock:
            existing = await _find(client, name)
            if existing is not None:
                _refuse_ipv6(existing, name)
                _warn_if_bridge_mismatch(existing, name)
                return name
            options = {ICC_OPTION: "false"}
            expected = expected_bridge_interface(name)
            if expected is not None:
                options[BRIDGE_NAME_OPTION] = expected
            try:
                created = await run_blocking(
                    client.networks.create,
                    name,
                    driver="bridge",
                    enable_ipv6=False,
                    options=options,
                    labels={LABEL_MANAGED: "true"},
                )
            except errors.APIError as exc:
                if exc.status_code != HTTP_CONFLICT:  # lost a race with another creator: fine
                    raise
            else:
                await _refuse_created_ipv6(created, name)
    return name
