"""The exit code the Docker daemon recorded for a dead container (``State.ExitCode``).

Read from a container inspect, for every runtime tier: the daemon records the exit status of
the container's init process whatever the isolation. A container that is still running, or one
the daemon cannot be asked about, has no exit code (``None``); neither case raises.
"""

import logging
from typing import Any

from sandfort.drivers.docker.client import run_blocking

logger = logging.getLogger(__name__)


def container_exit_code_blocking(client: Any, ref: str) -> int | None:
    try:
        attrs = client.api.inspect_container(ref)
    except Exception:
        logger.debug("could not inspect %s for an exit code", ref, exc_info=True)
        return None
    state = attrs.get("State") or {}
    code = state.get("ExitCode")
    if state.get("Running") is not False or isinstance(code, bool) or not isinstance(code, int):
        return None
    return code


async def container_exit_code(client: Any, ref: str) -> int | None:
    """``container_exit_code_blocking`` on the control lane; never raises."""
    try:
        return await run_blocking(container_exit_code_blocking, client, ref)
    except Exception:
        return None
