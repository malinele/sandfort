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


async def ensure_network(client: Any, name: str = NETWORK_NAME) -> str:
    """Ensure the bridge network (icc=false, fixed bridge name) exists; return its name."""
    errors = docker_errors()
    with translate_errors(name, "network.ensure"):
        existing = await _find(client, name)
        if existing is not None:
            _warn_if_bridge_mismatch(existing, name)
            return name
        async with _create_lock:
            existing = await _find(client, name)
            if existing is not None:
                _warn_if_bridge_mismatch(existing, name)
                return name
            options = {ICC_OPTION: "false"}
            expected = expected_bridge_interface(name)
            if expected is not None:
                options[BRIDGE_NAME_OPTION] = expected
            try:
                await run_blocking(
                    client.networks.create,
                    name,
                    driver="bridge",
                    options=options,
                    labels={LABEL_MANAGED: "true"},
                )
            except errors.APIError as exc:
                if exc.status_code != HTTP_CONFLICT:  # lost a race with another creator: fine
                    raise
    return name
