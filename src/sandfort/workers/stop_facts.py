"""What the host knows about a container that stopped under a sandbox (round 96, B8).

The reconciler records these in the ``sandbox.drift_detected`` audit row so the log explains the
stop without a host check. They are gathered from the driver BEFORE the unit of work that writes
the row opens (driver calls never run inside an open transaction).

Convention: ``None`` is "unknown", never a stand-in for "no".

* ``exit_code``: the recorded exit status, ``None`` when the driver has no
  ``ExitStatusDriver`` member, has no ref to ask about, cannot read the runtime, or raises.
* ``oom_killed``: ``True`` when the runtime flagged an out-of-memory kill. Otherwise ``None``:
  the ``OomObservableDriver`` answer ``False`` means "not flagged or not observable" (gVisor,
  Kata), so it cannot be told from "not an OOM" and is never written as ``False``.
"""

import logging
from dataclasses import dataclass
from typing import Any

from sandfort.drivers.base import OomObservableDriver
from sandfort.drivers.exit_status import ExitStatusDriver

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class StopFacts:
    oom_killed: bool | None
    exit_code: int | None

    def as_details(self) -> dict[str, Any]:
        """Audit-detail keys: plain JSON values, no tenant text."""
        return {"oom_killed": self.oom_killed, "exit_code": self.exit_code}


async def gather_stop_facts(driver: object, ref: str | None, sandbox_id: str) -> StopFacts:
    """Ask the driver what it knows about the dead container ``ref``; never raises."""
    if not ref:
        return StopFacts(oom_killed=None, exit_code=None)
    return StopFacts(
        oom_killed=True if await _oom_flagged(driver, ref, sandbox_id) else None,
        exit_code=await _exit_code(driver, ref, sandbox_id),
    )


async def _oom_flagged(driver: object, ref: str, sandbox_id: str) -> bool:
    if not isinstance(driver, OomObservableDriver):
        return False
    try:
        return await driver.container_oom_killed(ref)
    except Exception:
        logger.exception("could not read the OOM verdict of sandbox %s", sandbox_id)
        return False


async def _exit_code(driver: object, ref: str, sandbox_id: str) -> int | None:
    if not isinstance(driver, ExitStatusDriver):
        return None
    try:
        code = await driver.container_exit_code(ref)
    except Exception:
        logger.exception("could not read the exit code of sandbox %s", sandbox_id)
        return None
    return code if isinstance(code, int) and not isinstance(code, bool) else None
