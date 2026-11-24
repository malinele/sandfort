"""Settle a sandbox death soon after an exec that returned normally.

A background fork bomb lets ``exec`` answer exit 0 and kills the container a moment later; the
row would read ``started`` until the next exec or the reconciler pass. On the ``gvisor`` and
``microvm`` tiers the exec route calls ``schedule_death_probe`` after such an answer: one task
per sandbox inspects the instance after each of ``PROBE_DELAYS_S`` (counted from the latest
exec) and settles a dead one through ``Reconciler.mark_stopped_unexpectedly``. A new exec
extends the pending probe instead of adding a task. The probe is best effort: it never raises
into the exec route and the reconciler pass stays the safety net.
"""

import asyncio
import logging
from dataclasses import dataclass

from fastapi import Request

from sandfort.api.dead_sandbox import instance_is_dead
from sandfort.api.deps import SETTINGS_ATTR
from sandfort.api.wiring import RECONCILER_ATTR
from sandfort.config import Settings
from sandfort.domain.isolation import GVISOR, MICROVM, tier_of
from sandfort.domain.sandbox import Sandbox
from sandfort.drivers.base import SandboxDriver
from sandfort.workers.reconciler import Reconciler

DEATH_PROBES_ATTR = "death_probes"
PROBE_DELAYS_S: tuple[float, ...] = (2.0, 6.0, 15.0)  # after the latest exec
PROBED_TIERS = frozenset({GVISOR, MICROVM})

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class _Probe:
    sandbox: Sandbox
    driver: SandboxDriver
    last_exec: float
    task: asyncio.Task[None] | None = None


class DeathProbes:
    """The pending probes of one app, one per sandbox id."""

    def __init__(self) -> None:
        self._probes: dict[str, _Probe] = {}

    def pending(self) -> frozenset[str]:
        """Ids of the sandboxes with a probe task still running."""
        return frozenset(
            sandbox_id
            for sandbox_id, probe in self._probes.items()
            if probe.task is not None and not probe.task.done()
        )

    def task_of(self, sandbox_id: str) -> asyncio.Task[None] | None:
        probe = self._probes.get(sandbox_id)
        return None if probe is None else probe.task

    def last_exec_of(self, sandbox_id: str) -> float | None:
        probe = self._probes.get(sandbox_id)
        return None if probe is None else probe.last_exec

    def schedule(self, reconciler: Reconciler, driver: SandboxDriver, sandbox: Sandbox) -> None:
        """Start the probe of ``sandbox``, or extend its pending one from now. No awaits."""
        now = asyncio.get_running_loop().time()
        existing = self._probes.get(sandbox.id)
        if existing is not None and existing.task is not None and not existing.task.done():
            existing.sandbox = sandbox
            existing.driver = driver
            existing.last_exec = now
            return
        probe = _Probe(sandbox, driver, now)
        self._probes[sandbox.id] = probe
        probe.task = asyncio.create_task(
            self._run(reconciler, probe), name=f"death-probe-{sandbox.id}"
        )
        probe.task.add_done_callback(lambda _task: self._discard(probe))

    async def cancel_all(self) -> None:
        """Cancel every probe task and wait until they are all finished."""
        tasks = [probe.task for probe in self._probes.values() if probe.task is not None]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._probes.clear()

    def _discard(self, probe: _Probe) -> None:
        if self._probes.get(probe.sandbox.id) is probe:
            del self._probes[probe.sandbox.id]

    async def _run(self, reconciler: Reconciler, probe: _Probe) -> None:
        loop = asyncio.get_running_loop()
        delays = PROBE_DELAYS_S
        index = 0
        seen = probe.last_exec
        try:
            while index < len(delays):
                if probe.last_exec != seen:  # a newer exec: count the delays from it again
                    seen, index = probe.last_exec, 0
                    continue
                wait = probe.last_exec + delays[index] - loop.time()
                if wait > 0:
                    await asyncio.sleep(wait)
                    continue
                if await _settled_when_dead(reconciler, probe):
                    return
                index += 1
        except Exception:
            logger.exception("death probe of sandbox %s failed", probe.sandbox.id)
        finally:  # also reached on cancellation, which is left to propagate
            self._discard(probe)


async def _settled_when_dead(reconciler: Reconciler, probe: _Probe) -> bool:
    """``True`` when the probe is over: the instance was dead (settled or declined) or unknown."""
    sandbox = probe.sandbox
    if not sandbox.driver_ref:
        return True
    if not await instance_is_dead(probe.driver, sandbox.driver_ref):
        return False
    if await reconciler.mark_stopped_unexpectedly(sandbox):
        logger.info("sandbox %s: died after an exec; row marked stopped", sandbox.id)
    return True


def schedule_death_probe(request: Request, driver: SandboxDriver, sandbox: Sandbox) -> None:
    """Probe ``sandbox`` for a death after an exec that did not report one; never raises.

    Only the tiers in ``PROBED_TIERS`` are probed. Missing state, labels or ``driver_ref``
    mean no probe. Synchronous: no awaits and no driver calls happen before it returns.
    """
    try:
        state = request.app.state
        settings = getattr(state, SETTINGS_ATTR, None)
        reconciler = getattr(state, RECONCILER_ATTR, None)
        if not isinstance(settings, Settings) or not isinstance(reconciler, Reconciler):
            return
        if not sandbox.driver_ref:
            return
        if tier_of(sandbox.labels, settings.default_isolation) not in PROBED_TIERS:
            return
        probes = getattr(state, DEATH_PROBES_ATTR, None)
        if not isinstance(probes, DeathProbes):
            probes = DeathProbes()
            setattr(state, DEATH_PROBES_ATTR, probes)
        probes.schedule(reconciler, driver, sandbox)
    except Exception:
        logger.debug("could not schedule a death probe", exc_info=True)
