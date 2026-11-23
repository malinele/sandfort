"""Is the container behind a running exec still up? Rate-limited, and free for runc.

The Kata shim keeps an exec's attach stream open after its guest VM died, and runsc can do the
same, so ``exec_stream`` would only stop at its deadline. While no output arrives it asks a
``ContainerLiveness`` whether docker still reports the container running. The container's
runtime is inspected once and cached: for any runtime without its own kernel (runc) the checker
answers "alive" without touching docker again. For runsc and kata it inspects at most once per
``LIVENESS_CHECK_INTERVAL_S``, the first time one interval after the checker was created, so
short execs never pay for it. Inspection errors count as alive.

``has_own_network_stack`` is defined in ``exec.py`` (which imports this module), so the caller
hands it in instead of this module importing it back.
"""

import logging
import time
from collections.abc import Callable
from typing import Any

from sandfort.drivers.docker.client import run_blocking

logger = logging.getLogger(__name__)

LIVENESS_CHECK_INTERVAL_S = 2.0


class ContainerLiveness:
    """Answers whether docker still reports ``ref`` running; see the module docstring."""

    def __init__(
        self,
        client: Any,
        ref: str,
        has_own_kernel: Callable[[str], bool],
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = client
        self._ref = ref
        self._has_own_kernel = has_own_kernel
        self._clock = clock
        self._runtime: str | None = None
        self._next_check = clock() + LIVENESS_CHECK_INTERVAL_S

    async def is_running(self) -> bool:
        """False only when docker reports an own-kernel container as not running."""
        if self._runtime is not None and not self._has_own_kernel(self._runtime):
            return True
        now = self._clock()
        if now < self._next_check:
            return True
        self._next_check = now + LIVENESS_CHECK_INTERVAL_S
        try:
            return await run_blocking(self._inspect_blocking)
        except Exception:
            logger.debug("could not inspect %s for liveness", self._ref, exc_info=True)
            return True

    def _inspect_blocking(self) -> bool:
        attrs = self._client.api.inspect_container(self._ref)
        runtime = str((attrs.get("HostConfig") or {}).get("Runtime") or "")
        self._runtime = runtime
        if not self._has_own_kernel(runtime):
            return True
        return (attrs.get("State") or {}).get("Running") is not False
