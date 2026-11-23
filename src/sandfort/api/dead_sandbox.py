"""Settle a ``started`` row whose instance the runtime already reports dead.

After a sandbox dies (OOM, fork bomb, a container removed behind the platform's back) the row
says ``started`` until a reconciler pass sees the drift. The routes that learn of a death
earlier settle the row through the reconciler's ``mark_stopped_unexpectedly`` (which still
honours the recent-reset rule), so a following ``start()`` really starts the container:

- ``settle_dead_sandbox`` waits up to ``SETTLE_TIMEOUT_S`` for the runtime to agree (the
  toolbox process routes, right after an exec saw the sandbox die);
- ``settle_if_dead`` inspects once and never waits (the start route, before the service
  would treat ``started`` as already reached).
"""

import asyncio
import logging

from fastapi import Request

from sandfort.api.wiring import RECONCILER_ATTR
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.drivers.base import InstanceState, SandboxDriver
from sandfort.drivers.errors import DriverNotFound
from sandfort.workers.reconciler import Reconciler

SETTLE_POLL_INTERVAL_S = 0.25  # how often a dead-sandbox signal re-inspects the instance
SETTLE_TIMEOUT_S = 5.0  # give up settling the row before responding after this long

logger = logging.getLogger(__name__)


def _reconciler(request: Request) -> Reconciler | None:
    reconciler = getattr(request.app.state, RECONCILER_ATTR, None)
    return reconciler if isinstance(reconciler, Reconciler) else None


async def instance_is_dead(driver: SandboxDriver, ref: str) -> bool:
    """``True`` when the instance is gone or exited, the drift the reconciler settles as dead.

    Any other state is alive: a snapshot pauses a started sandbox's container while it commits,
    and the reconciler's ``_classify_drift`` does not treat that as a stop.
    """
    try:
        info = await driver.inspect(ref)
    except DriverNotFound:
        return True
    return info.state is InstanceState.EXITED


async def settle_dead_sandbox(request: Request, driver: SandboxDriver, sandbox: Sandbox) -> bool:
    """Mark the row stopped once the runtime reports the instance dead; ``True`` when settled.

    A client that calls ``start()`` right after ``sandbox_stopped`` must not find the row still
    ``started``. Waits up to ``SETTLE_TIMEOUT_S`` for the runtime to catch up. Any failure, a
    missing reconciler or a timeout returns ``False`` so the caller falls back to the kicks.
    """
    reconciler = _reconciler(request)
    if reconciler is None or not sandbox.driver_ref:
        return False
    try:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + SETTLE_TIMEOUT_S
        while not await instance_is_dead(driver, sandbox.driver_ref):
            if loop.time() >= deadline:
                logger.warning("sandbox %s still reported running; leaving it to kicks", sandbox.id)
                return False
            await asyncio.sleep(SETTLE_POLL_INTERVAL_S)
        await reconciler.mark_stopped_unexpectedly(sandbox)
    except Exception:
        logger.exception("could not settle dead sandbox %s before responding", sandbox.id)
        return False
    return True


async def settle_if_dead(request: Request, driver: SandboxDriver, sandbox: Sandbox) -> bool:
    """Single-shot settle: one inspect, then ``mark_stopped_unexpectedly`` when dead.

    ``True`` only when the row was marked stopped. A row that is not ``started``, has no
    ``driver_ref``, a missing reconciler, a live instance, a recent reset of the row's
    container (the reconciler declines) or any failure returns ``False`` without waiting.
    """
    reconciler = _reconciler(request)
    if reconciler is None or sandbox.state is not SandboxState.STARTED or not sandbox.driver_ref:
        return False
    try:
        if not await instance_is_dead(driver, sandbox.driver_ref):
            return False
        marked = await reconciler.mark_stopped_unexpectedly(sandbox)
    except Exception:
        logger.exception("could not settle dead sandbox %s", sandbox.id)
        return False
    if marked:
        logger.info("sandbox %s: container was dead; row marked stopped", sandbox.id)
    return marked
