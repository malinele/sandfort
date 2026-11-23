"""Scope catalog constants and the ``require_scopes`` dependency (403 on a missing scope)."""

from collections.abc import Awaitable, Callable, Iterable
from typing import Annotated

from fastapi import Depends

from sandfort.auth.authenticate import authenticate
from sandfort.auth.principal import Principal
from sandfort.domain.org import Scope
from sandfort.errors import Forbidden

ALL_SCOPES: frozenset[Scope] = frozenset(Scope)


def check_scopes(principal: Principal, required: Iterable[Scope]) -> None:
    """Raise Forbidden listing every scope in ``required`` the principal lacks."""
    missing = sorted(scope.value for scope in set(required) - principal.scopes)
    if missing:
        raise Forbidden(
            f"API key is missing required scope(s): {', '.join(missing)}",
            details={"missing_scopes": missing},
        )


def require_scopes(*scopes: Scope) -> Callable[..., Awaitable[Principal]]:
    """Build a dependency that raises Forbidden (403) when a scope is missing."""
    required = frozenset(scopes)

    async def dependency(principal: Annotated[Principal, Depends(authenticate)]) -> Principal:
        check_scopes(principal, required)
        return principal

    return dependency
