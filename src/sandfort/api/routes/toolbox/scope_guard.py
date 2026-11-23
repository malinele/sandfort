"""Router-level guard: a label-scoped key reaches a toolbox route only for a sandbox it can see.

Most toolbox handlers load the sandbox through the label-scoped sandbox repository, so a
sandbox outside the key's label scope answers 404. Handlers that look up session, command or
pty records by id never load it; this dependency runs before every handler of a toolbox router
so those routes (and any added later) are covered too. An unscoped key costs no database read.
"""

from typing import Annotated

from fastapi import Depends

from sandfort.api.deps import get_uow
from sandfort.auth.authenticate import authenticate
from sandfort.auth.label_scope import current_label_scope
from sandfort.auth.principal import Principal
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.errors import NotFound


async def require_visible_sandbox(
    sandbox_id: str,
    principal: Annotated[Principal, Depends(authenticate)],
    # Not cached: handlers that depend on ``get_uow`` enter their own unit of work, and the
    # guard's must be closed before they run.
    uow: Annotated[UnitOfWorkPort, Depends(get_uow, use_cache=False)],
) -> None:
    """Raise ``NotFound`` when the key's label scope hides ``sandbox_id``; no-op when unscoped."""
    if current_label_scope() is None:
        return
    async with uow:
        sandbox = await uow.sandboxes.get(principal.org_id, sandbox_id)
    if sandbox is None:
        raise NotFound(f"sandbox {sandbox_id} not found")
