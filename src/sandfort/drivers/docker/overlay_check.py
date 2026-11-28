"""Startup advisory: the gvisor tier's runsc runtime should be registered with --overlay2=none.

Without it, files written in a gvisor sandbox can be lost on stop and missing from a snapshot.
The runtime arguments are read from docker info and the finding is only logged. It never
refuses startup and never becomes an isolation gap.
"""

import logging
from collections.abc import Mapping, Sequence
from typing import Any

from sandfort.config import GVISOR_RUNTIME_PREFIX, Settings
from sandfort.domain.isolation import GVISOR
from sandfort.drivers.docker.client import run_blocking

logger = logging.getLogger(__name__)

RUNTIME_ARGS_KEY = "runtimeArgs"
OVERLAY_FINDING = (
    "gvisor tier runtime {runtime!r}: docker info lists the runtime arguments {args} without"
    " --overlay2=none, so files written in a gvisor sandbox can be lost on stop and missing from"
    " a snapshot. Register runsc with --overlay2=none (deploy/node-setup.sh). Advisory only,"
    " this does not refuse startup"
)


def overlay2_disabled(args: Sequence[str]) -> bool:
    """True when the runtime arguments switch the runsc overlay off (``overlay2=none``)."""
    cleaned = [str(arg).lstrip("-") for arg in args]
    if "overlay2=none" in cleaned:
        return True
    return any(
        first == "overlay2" and second == "none"
        for first, second in zip(cleaned, cleaned[1:], strict=False)
    )


def gvisor_overlay_finding(info: Mapping[str, Any], settings: Settings) -> str | None:
    """The advisory text when the registered gvisor runtime lacks overlay2=none, else None."""
    runtime = settings.isolation_tiers().get(GVISOR, "").strip()
    if not runtime.lower().startswith(GVISOR_RUNTIME_PREFIX):
        return None
    registered = info.get("Runtimes")
    entry = registered.get(runtime) if isinstance(registered, Mapping) else None
    if not isinstance(entry, Mapping):
        return None
    raw = entry.get(RUNTIME_ARGS_KEY)
    args = [str(arg) for arg in raw] if isinstance(raw, list | tuple) else []
    if overlay2_disabled(args):
        return None
    return OVERLAY_FINDING.format(runtime=runtime, args=args)


async def warn_gvisor_overlay(client: Any, settings: Settings) -> None:
    """Log the finding once, never raises and never refuses startup."""
    if GVISOR not in settings.isolation_tiers():
        return
    try:
        info = await run_blocking(client.api.info)
    except Exception:
        logger.debug("gvisor overlay2 check skipped: docker info unreadable", exc_info=True)
        return
    if not isinstance(info, Mapping):
        return
    finding = gvisor_overlay_finding(info, settings)
    if finding is not None:
        logger.warning("isolation advisory (does not refuse startup): %s", finding)
