"""Toolbox guards: resolve the sandbox inside the caller's org, require it started, touch activity.

A sandbox of another org is indistinguishable from a missing one (``NotFound``). The
unit of work is only used to read and to refresh ``last_activity_at``; callers must
close it before calling the driver (intent-then-act).
"""

from sandfort.clock import Clock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.sandbox import Sandbox, SandboxState, visible_stop_cause
from sandfort.errors import NO_CONTAINER, Conflict, NotFound, no_container_conflict

_DELETED_STATES = frozenset({SandboxState.DESTROYING, SandboxState.DESTROYED})


async def load_started_sandbox(
    uow: UnitOfWorkPort, org_id: str, sandbox_id: str, clock: Clock
) -> Sandbox:
    sandbox = await uow.sandboxes.get(org_id, sandbox_id)
    if sandbox is None:
        raise NotFound(f"sandbox {sandbox_id} not found")
    if sandbox.state in _DELETED_STATES:
        # Same wording as the toolbox modules' own no_container conflict.
        raise no_container_conflict(sandbox.state.value, visible_stop_cause(sandbox))
    if sandbox.state is not SandboxState.STARTED or sandbox.driver_ref is None:
        details = {"state": sandbox.state.value}
        if (cause := visible_stop_cause(sandbox)) is not None:
            details["stop_cause"] = cause
        raise Conflict(
            f"sandbox is {sandbox.state.value}; toolbox calls require a started sandbox",
            reason=NO_CONTAINER,
            details=details,
        )
    return await _touch_activity(uow, org_id, sandbox, clock)


async def _touch_activity(
    uow: UnitOfWorkPort, org_id: str, sandbox: Sandbox, clock: Clock
) -> Sandbox:
    now = clock.now()
    touched = sandbox.model_copy(update={"last_activity_at": now, "updated_at": now})
    try:
        saved = await uow.sandboxes.update(org_id, touched, expected_version=sandbox.version)
        await uow.commit()
    except Conflict:
        # Best effort: a concurrent writer changed the row (usually another toolbox call
        # refreshing the same timestamp). The call proceeds; the driver rejects a sandbox
        # that was stopped in the meantime.
        return sandbox
    return saved
