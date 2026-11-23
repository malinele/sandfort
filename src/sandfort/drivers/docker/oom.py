"""Out-of-memory evidence for the Docker driver, read without running anything in the sandbox.

Two signals, both only for runtimes that share the host kernel (runc, the container tier):

* ``container_oom_killed``: the daemon's own verdict for a dead container (``State.OOMKilled``
  of the container inspect, with the container not running);
* ``OomCounter``: the ``oom_kill`` counter of the container's cgroup v2 ``memory.events``,
  read from the host. ``exec_stream`` reads it before an exec and again when the exec ended
  with SIGKILL; a higher count means the kernel OOM-killed a process of the container meanwhile.

The cgroup is found by the container id under the two layouts Docker uses (the systemd driver's
``system.slice/docker-<id>.scope`` and the cgroupfs driver's ``docker/<id>``), so the baseline
costs no daemon call. The runtime is inspected only after a SIGKILL exit, to confirm the tier.

gVisor and Kata keep their own kernel: the host cgroup does not see their guest's kills and
the daemon does not flag them, so both signals answer "not observable" there (``False``) and
callers keep their earlier answer. The counter is also unobservable when the server cannot see
the daemon's host (a remote daemon, a server in its own cgroup namespace, cgroup v1): never an
error.
"""

import logging
import re
from pathlib import Path
from typing import Any

from sandfort.drivers.docker.client import run_blocking
from sandfort.drivers.docker.hardening import GVISOR_RUNTIME

logger = logging.getLogger(__name__)

CGROUP_ROOT = Path("/sys/fs/cgroup")
CGROUP_DIR_TEMPLATES = ("system.slice/docker-{ref}.scope", "docker/{ref}")
MEMORY_EVENTS = "memory.events"
OOM_KILL_KEY = "oom_kill"
KATA_RUNTIME_PREFIX = "kata"
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}")


def shares_host_kernel(runtime: str) -> bool:
    """``True`` for runtimes whose processes are ordinary host processes (runc)."""
    return runtime != GVISOR_RUNTIME and not runtime.startswith(KATA_RUNTIME_PREFIX)


def parse_oom_kill(events_text: str) -> int | None:
    """The ``oom_kill`` value of a ``memory.events`` text; ``None`` when absent or unreadable."""
    for line in events_text.splitlines():
        key, _, value = line.partition(" ")
        if key == OOM_KILL_KEY:
            return int(value) if value.strip().isdecimal() else None
    return None


def memory_events_file(ref: str) -> Path | None:
    """The container's cgroup ``memory.events`` on this host; ``None`` when not visible."""
    if not _CONTAINER_ID.fullmatch(ref):
        return None
    for template in CGROUP_DIR_TEMPLATES:
        candidate = CGROUP_ROOT / template.format(ref=ref) / MEMORY_EVENTS
        if candidate.is_file():
            return candidate
    return None


def _read_count(events: Path) -> int | None:
    try:
        return parse_oom_kill(events.read_text())
    except (OSError, ValueError):
        logger.debug("could not read %s", events, exc_info=True)
        return None


def _runtime_of(attrs: dict[str, Any]) -> str:
    return str((attrs.get("HostConfig") or {}).get("Runtime") or "")


class OomCounter:
    """The container cgroup's ``oom_kill`` count before an exec, and whether it rose since.

    ``start`` records the baseline (nothing when the cgroup is not visible); ``rose`` answers
    ``False`` without it, and for a runtime with its own kernel. Neither ever raises.
    """

    def __init__(self, client: Any, ref: str) -> None:
        self._client = client
        self._ref = ref
        self._events: Path | None = None
        self._before: int | None = None

    async def start(self) -> None:
        try:
            await run_blocking(self._start_blocking)
        except Exception:
            logger.debug("oom_kill baseline of %s failed", self._ref, exc_info=True)

    def _start_blocking(self) -> None:
        events = memory_events_file(self._ref)
        before = None if events is None else _read_count(events)
        if before is not None:
            self._events, self._before = events, before

    async def rose(self) -> bool:
        """``True`` when the count is above the baseline and the tier shares the host kernel."""
        if self._events is None:
            return False
        try:
            return await run_blocking(self._rose_blocking)
        except Exception:
            logger.debug("oom_kill check of %s failed", self._ref, exc_info=True)
            return False

    def _rose_blocking(self) -> bool:
        assert self._events is not None and self._before is not None
        attrs = self._client.api.inspect_container(self._ref)
        if not shares_host_kernel(_runtime_of(attrs)):
            return False
        after = _read_count(self._events)
        return after is not None and after > self._before


def container_oom_killed_blocking(client: Any, ref: str) -> bool:
    """``True`` when the container is not running and the daemon says it was OOM-killed."""
    try:
        attrs = client.api.inspect_container(ref)
    except Exception:
        logger.debug("could not inspect %s for an OOM verdict", ref, exc_info=True)
        return False
    if not shares_host_kernel(_runtime_of(attrs)):
        return False
    state = attrs.get("State") or {}
    return state.get("OOMKilled") is True and state.get("Running") is False


async def container_oom_killed(client: Any, ref: str) -> bool:
    """``container_oom_killed_blocking`` on the control lane; never raises."""
    try:
        return await run_blocking(container_oom_killed_blocking, client, ref)
    except Exception:
        return False
