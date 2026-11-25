"""Mint an allowlisted sandbox's egress token on the node that creates it (design 7.2).

In jobs mode the api stores the sandbox without proxy variables: the node that will run the
container owns the proxy address and the secret its sandbox must use, and nodes can sit on
different ``sf-egress-net`` subnets. Before ``driver.create`` the create job calls
``provision_egress_env``. It mints in its own unit of work and commits, so a crash between the
mint and the driver call leaves the token in the row and a retry finds it (intent-then-act).
"""

from collections.abc import Callable, Mapping, Sequence

from sandfort.clock import Clock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.sandbox import Sandbox
from sandfort.drivers.errors import DriverError
from sandfort.egress.env import (
    NO_PROXY_VARIABLES,
    PROXY_VARIABLES,
    EgressReminting,
    reminted_proxy_env,
)
from sandfort.errors import NotFound

UNAVAILABLE_MESSAGE = (
    "this node has no egress proxy settings, so an egress-allowlisted sandbox cannot run here"
)


class EgressUnavailable(DriverError):
    """The node cannot give an allowlisted sandbox a proxy; nothing was created anywhere."""


def without_proxy_variables(env: Mapping[str, str]) -> dict[str, str]:
    """``env`` minus the variables the egress proxy environment owns."""
    managed = (*PROXY_VARIABLES, *NO_PROXY_VARIABLES)
    return {name: value for name, value in env.items() if name not in managed}


def needs_egress_stack(egress_allowlist: Sequence[str] | None, block_all: bool) -> bool:
    """True when a sandbox needs the egress stack: a proxy credential and an egress-ready node.

    The rule is ``egress_allowlist is not None and not block_all``. A create with ``[]`` forces
    ``block_all`` and can never be PATCHed to a non-empty list, so it never needs a proxy. A row
    with ``[]`` and ``block_all`` false (reachable only by PATCH to ``[]``) can be widened again,
    so it does need a credential; its empty policy denies everything until then.
    """
    return egress_allowlist is not None and not block_all


def needs_egress_env(sandbox: Sandbox) -> bool:
    """True when the sandbox needs the egress stack and its env carries no proxy variable yet.

    A stored variable means an inline create or an earlier job attempt already minted.
    """
    if not needs_egress_stack(sandbox.egress_allowlist, sandbox.network.block_all):
        return False
    return not any(name in sandbox.env for name in PROXY_VARIABLES)


async def provision_egress_env(
    uow_factory: Callable[[], UnitOfWorkPort],
    reminting: EgressReminting | None,
    clock: Clock,
    sandbox: Sandbox,
) -> Sandbox:
    """``sandbox`` with proxy variables stored, minting them when it has none.

    Returns ``sandbox`` itself when nothing is needed. Raises ``EgressUnavailable`` when a mint
    is needed and ``reminting`` is ``None``. The write is committed before this returns.
    """
    if not needs_egress_env(sandbox):
        return sandbox
    if reminting is None:
        raise EgressUnavailable(UNAVAILABLE_MESSAGE)
    async with uow_factory() as uow:
        current = await uow.sandboxes.get(sandbox.org_id, sandbox.id)
        if current is None:
            raise NotFound(f"sandbox {sandbox.id} not found")
        if not needs_egress_env(current):
            return current  # another attempt minted between the load and now
        now = clock.now()
        env = reminted_proxy_env(
            current.env,
            reminting,
            current.id,
            now,
            current.auto_delete_minutes,
            epoch=current.egress_credential_epoch,
        )
        updated = current.model_copy(update={"env": env, "updated_at": now})
        saved = await uow.sandboxes.update(
            current.org_id, updated, expected_version=current.version
        )
        await uow.commit()
    return saved
