"""Isolation tiers a sandbox can pick, and how a deployment maps them onto docker runtimes.

A tier is a name the API exposes (``container``, ``gvisor``, ``microvm``); a deployment maps
each tier it offers to a docker runtime (``SANDFORT_ISOLATION_RUNTIMES``, e.g.
``container=,gvisor=runsc,microvm=kata``; an empty runtime is the daemon default). With no
map configured, the only tier is the deployment default, on the ``container_runtime`` setting.

A sandbox records its tier in the reserved ``sandfort.isolation`` label (hidden from user
labels like every ``sandfort.`` key); a sandbox without the label reports the default tier.
"""

import re
from collections.abc import Mapping
from typing import Literal, get_args

IsolationTier = Literal["container", "gvisor", "microvm"]
type TierRuntimes = tuple[tuple[str, str], ...]  # (tier, runtime) pairs; "" = daemon default

CONTAINER = "container"
GVISOR = "gvisor"
MICROVM = "microvm"
TIERS: tuple[str, ...] = get_args(IsolationTier)
DEFAULT_TIER = CONTAINER
# Uses the platform's reserved ``sandfort.`` label prefix (``services.volumes``).
ISOLATION_LABEL = "sandfort.isolation"
PAIR_SEPARATOR = ","
TIER_SEPARATOR = "="
_RUNTIME_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")


def parse_tier_runtimes(raw: str) -> TierRuntimes:
    """Parse ``tier=runtime`` pairs; raise ``ValueError`` on a malformed pair or unknown tier.

    Blank input means "no map configured" and yields ``()``. A tier may appear once.
    """
    if not raw.strip():
        return ()
    pairs: list[tuple[str, str]] = []
    for item in raw.split(PAIR_SEPARATOR):
        tier, separator, runtime = (part.strip() for part in item.partition(TIER_SEPARATOR))
        malformed_runtime = bool(runtime) and _RUNTIME_NAME.fullmatch(runtime) is None
        if not separator or not tier or malformed_runtime:
            raise ValueError(f"malformed pair {item.strip()!r}: expected tier=runtime")
        if tier not in TIERS:
            raise ValueError(f"unknown tier {tier!r}; valid tiers: {', '.join(TIERS)}")
        if any(tier == seen for seen, _ in pairs):
            raise ValueError(f"tier {tier!r} is listed more than once")
        pairs.append((tier, runtime))
    return tuple(pairs)


def check_default_tier(pairs: TierRuntimes, default: str) -> None:
    """Raise ``ValueError`` unless ``default`` is a tier name this deployment offers."""
    if default not in TIERS:
        raise ValueError(f"unknown tier {default!r}; valid tiers: {', '.join(TIERS)}")
    offered = [tier for tier, _ in pairs]
    if pairs and default not in offered:
        raise ValueError(
            f"default tier {default!r} is not available; available: {', '.join(offered)}"
        )


def available_runtimes(pairs: TierRuntimes, default: str, fallback_runtime: str) -> dict[str, str]:
    """Tier -> runtime this deployment offers; no map means the default tier on the fallback."""
    if not pairs:
        return {default: fallback_runtime.strip()}
    return dict(pairs)


def tier_of(labels: Mapping[str, str], default: str) -> str:
    """The tier a sandbox recorded, or ``default`` for one created before tiers existed."""
    return labels.get(ISOLATION_LABEL) or default


def recorded_tier(labels: Mapping[str, str]) -> str | None:
    """The tier a sandbox recorded, or ``None`` when it carries no isolation label."""
    return labels.get(ISOLATION_LABEL) or None


def isolation_labels(tier: str) -> dict[str, str]:
    """The reserved label recording ``tier`` on the sandbox row."""
    return {ISOLATION_LABEL: tier}
