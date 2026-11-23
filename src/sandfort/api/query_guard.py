"""Reject unknown query parameters on read routes.

FastAPI ignores query keys a route does not declare, so a misspelt filter (``?requestid=...``)
would answer an unfiltered 200. These dependencies answer 422 instead, with the body-validation
shape: code ``VALIDATION_ERROR`` and one ``extra_forbidden`` entry per unknown parameter in
``details.errors`` (``type``, ``loc`` = ``["query", name]``, ``msg``; the value is not echoed).

Declare the guard *after* the auth dependency in the endpoint signature: FastAPI resolves
dependencies in declaration order, so unauthenticated callers get 401/403 before 422::

    async def list_things(principal: Reader, _known: KnownQuery, limit: int = 50): ...
"""

from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, Request
from fastapi.dependencies.models import Dependant
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute

from sandfort.errors import Unprocessable


class UnknownQueryParams(Unprocessable):
    """422 with the body-validation shape (see the module docstring)."""

    code = "VALIDATION_ERROR"


def _declared_query_names(dependant: Dependant) -> set[str]:
    """Query parameter names (aliases) declared by the endpoint and its sub-dependencies."""
    names = {field.alias for field in dependant.query_params}
    for sub in dependant.dependencies:
        names |= _declared_query_names(sub)
    return names


def _reject_unknown(request: Request, accepted: frozenset[str]) -> None:
    unknown = sorted(set(request.query_params.keys()) - accepted)
    if not unknown:
        return
    names = ", ".join(f"`{name}`" for name in unknown)
    noun = "parameter" if len(unknown) == 1 else "parameters"
    shown = ", ".join(sorted(accepted)) if accepted else "none"
    errors = [
        {
            "type": "extra_forbidden",
            "loc": ["query", name],
            "msg": "Extra inputs are not permitted",
        }
        for name in unknown
    ]
    raise UnknownQueryParams(
        f"unknown query {noun} {names}; accepted: {shown}",
        details={"errors": errors},
    )


async def known_query_params(request: Request) -> None:
    """Answer 422 for any query key the matched route does not declare.

    The accepted set is read from the route's own signature: every ``Query`` parameter of the
    endpoint and of its dependencies (so ``cursor``, ``limit`` and ``order`` are accepted only
    on routes that declare them).
    """
    route = request.scope.get("route")
    if not isinstance(route, APIRoute):
        raise RuntimeError("known_query_params needs a matched APIRoute")
    _reject_unknown(request, frozenset(_declared_query_names(route.dependant)))


def only_params(accepted: frozenset[str]) -> Callable[[Request], Awaitable[None]]:
    """A dependency that answers 422 for any query key outside the explicit ``accepted`` set."""

    async def check(request: Request) -> None:
        _reject_unknown(request, accepted)

    return check


KnownQuery = Annotated[None, Depends(known_query_params)]


def require_single_values(request: Request, names: tuple[str, ...]) -> None:
    """Answer 422 when a single-value query parameter in ``names`` is given more than once.

    FastAPI keeps the last value of a repeated scalar parameter, so ``?path=/a&path=/b`` would
    silently read ``/b``. The answer has the body-validation shape (``VALIDATION_ERROR``, one
    entry per repeated name with ``loc`` = ``["query", name]`` and the message
    ``<name> must be given once``).
    """
    issues = [
        {"type": "value_error", "loc": ("query", name), "msg": f"{name} must be given once"}
        for name in names
        if len(request.query_params.getlist(name)) > 1
    ]
    if issues:
        raise RequestValidationError(issues)


def single_valued(*names: str) -> Callable[[Request], Awaitable[None]]:
    """A dependency that answers 422 when any of the single-value parameters ``names`` repeats.

    Declare it after the auth dependency (and ``KnownQuery``) so unauthenticated callers still
    get 401/403 first::

        Once = Annotated[None, Depends(single_valued("limit", "cursor"))]
    """

    async def check(request: Request) -> None:
        require_single_values(request, names)

    return check


STRICT_BOOLS = frozenset({"true", "false"})


def strict_bool_query(*names: str) -> Callable[[Request], Awaitable[None]]:
    """A dependency that answers 422 unless each given ``names`` is exactly ``true`` or ``false``.

    A boolean query parameter is parsed leniently (``yes``, ``on``, ``1`` and ``TRUE`` all
    read as true), while a body field needs a real JSON boolean. The answer has the
    body-validation shape: ``loc`` = ``["query", name]``, ``bool_parsing``. A parameter that is
    absent is fine (the route's default applies). Declare it after the auth dependency.
    """

    async def check(request: Request) -> None:
        issues = [
            {
                "type": "bool_parsing",
                "loc": ("query", name),
                "msg": "Input should be 'true' or 'false' (lowercase)",
            }
            for name in names
            for value in request.query_params.getlist(name)
            if value not in STRICT_BOOLS
        ]
        if issues:
            raise RequestValidationError(issues)

    return check
