"""Batch read behind the internal egress policy route (docs/egress-v2-design.md section 3.6).

The proxy asks for the policy of the sandboxes it serves; this module answers from the sandboxes
table, across all orgs (the caller is the proxy, authenticated by its MAC, not a tenant). A
sandbox is ``found`` when it exists, is not ``destroying`` or ``destroyed`` and has an allowlist.
A legacy row (generation 0) is reported like any other, with its stored rules: the proxy
decides a v1 token from the row, never from the token's own allowlist claim.
"""

from collections.abc import Callable, Sequence
from typing import Any

from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.sandbox import Sandbox, SandboxState

_GONE = (SandboxState.DESTROYING, SandboxState.DESTROYED)


def policy_record(sandbox_id: str, sandbox: Sandbox | None) -> dict[str, Any]:
    """The response record of one requested id (``sandbox`` is ``None`` when it is missing)."""
    if sandbox is None or sandbox.state in _GONE or sandbox.egress_allowlist is None:
        return {"sandbox_id": sandbox_id, "found": False}
    return {
        "sandbox_id": sandbox_id,
        "found": True,
        "generation": sandbox.egress_policy_generation,
        "epoch": sandbox.egress_credential_epoch,
        "rules": list(sandbox.egress_allowlist),
    }


async def read_policies(
    uow_factory: Callable[[], UnitOfWorkPort], sandbox_ids: Sequence[str]
) -> list[dict[str, Any]]:
    """One record per requested id, in request order."""
    async with uow_factory() as uow:
        rows = await uow.sandboxes.list_for_egress_policy(list(dict.fromkeys(sandbox_ids)))
    by_id = {sandbox.id: sandbox for sandbox in rows}
    return [policy_record(sandbox_id, by_id.get(sandbox_id)) for sandbox_id in sandbox_ids]
