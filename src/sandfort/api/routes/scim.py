"""``/scim/v2``: SCIM 2.0 ``Users`` plus discovery for identity providers.

See docs/scim-design.md section 4. Every request is authenticated by the SCIM bearer token only
(``auth/scim.py``): an API key or a session token is a 401 here, and the token is a 401 on every
other route. When ``app.state`` carries a rate limiter, each request takes one token from the
bucket of the SCIM token id (429). Discovery needs the token too.

Every write goes through the ``UserAdminService`` entry points, so the last-admin guard, the
role ceiling of the token and the audit record hold unchanged. Deactivation (``active`` false by
PATCH or PUT, and DELETE) removes the membership and keeps the user row; the deactivating PATCH
or PUT answers 200 with the resource as it was, ``active`` false. ``ScimRoute`` renders every
failure, dependencies included, as a SCIM Error body. Responses use ``application/scim+json``;
a request body is parsed when sent as ``application/scim+json`` or ``application/json``.

``app.py`` mounts the router only when ``scim_enabled`` is set, and no route is part of the
exported OpenAPI document (OpenAPI export policy), as in ``routes/nodes.py``.
"""

import json
from collections.abc import Callable, Coroutine, Mapping, Sequence
from typing import Annotated, Any, Final

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.routing import APIRoute

from sandfort.api.deps import get_settings
from sandfort.api.middleware.rate_limit import RATE_LIMITER_ATTR, RateLimiter
from sandfort.api.routes.users import get_user_admin_service
from sandfort.api.safe_json import SafeJSONResponse
from sandfort.api.scim.discovery import resource_types, schemas, service_provider_config
from sandfort.api.scim.errors import ScimFailure, ScimValidationError, describe_failure
from sandfort.api.scim.filters import parse_user_filter
from sandfort.api.scim.patch import INVALID_SYNTAX, INVALID_VALUE, PatchChange, parse_patch
from sandfort.api.scim.resources import (
    SCIM_MEDIA_TYPE,
    ensure_patch_unchanged,
    ensure_unchanged,
    list_response,
    member_to_resource,
    parse_user_resource,
)
from sandfort.auth.principal import Principal
from sandfort.auth.scim import authenticate_scim
from sandfort.config import Settings
from sandfort.domain.user import OrgRole
from sandfort.errors import InvalidState, RateLimited
from sandfort.services.user_admin import UNSET, Member, Unset, UserAdminService

SCIM_PREFIX: Final = "/scim/v2"
RATE_LIMITED_MESSAGE: Final = "rate limit exceeded for this SCIM token"
JSON_MEDIA_TYPES: Final = frozenset({"application/json", SCIM_MEDIA_TYPE})

# Out of the exported spec (docs/scim-design.md, OpenAPI export policy), as in routes/nodes.py,
# so the pinned openapi/sandfort.v1.json and its drift test stay valid.
_IN_SCHEMA = False

_UNSUPPORTED_MEDIA_DETAIL: Final = "Content-Type must be application/scim+json or application/json"
_BAD_JSON_DETAIL: Final = "request body is not valid JSON"
_INACTIVE_CREATE_DETAIL: Final = "a user cannot be created with active false"
_DISABLED_DETAIL: Final = "the user is disabled for every org and cannot be activated by SCIM"


def scim_response(
    body: Mapping[str, Any], status_code: int = 200, headers: Mapping[str, str] | None = None
) -> SafeJSONResponse:
    """``body`` as JSON with the media type ``application/scim+json``."""
    return SafeJSONResponse(
        content=dict(body), status_code=status_code, headers=headers, media_type=SCIM_MEDIA_TYPE
    )


def failure_response(failure: ScimFailure) -> SafeJSONResponse:
    """The SCIM Error body for ``failure`` with its status and extra headers."""
    return scim_response(failure.body(), failure.status, failure.headers)


class ScimRoute(APIRoute):
    """An ``APIRoute`` whose failures, dependencies included, answer as SCIM Error bodies."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        handler = super().get_route_handler()

        async def scim_handler(request: Request) -> Response:
            try:
                return await handler(request)
            except Exception as exc:  # every failure answers in the SCIM shape, 500 included
                return failure_response(describe_failure(exc))

        return scim_handler


async def scim_principal(request: Request) -> Principal:
    """The SCIM token's principal; then one token from its rate-limit bucket when one is wired."""
    principal = await authenticate_scim(request)
    limiter: RateLimiter | None = getattr(request.app.state, RATE_LIMITER_ATTR, None)
    if limiter is None:
        return principal
    decision = await limiter.acquire(principal.key_id)
    if not decision.allowed:
        raise RateLimited(RATE_LIMITED_MESSAGE, retry_after_s=decision.retry_after_s)
    return principal


router = APIRouter(
    prefix=SCIM_PREFIX,
    tags=["scim"],
    dependencies=[Depends(scim_principal)],
    route_class=ScimRoute,
)

Token = Annotated[Principal, Depends(scim_principal)]
Service = Annotated[UserAdminService, Depends(get_user_admin_service)]
Config = Annotated[Settings, Depends(get_settings)]


def scim_base_url(request: Request) -> str:
    """The ``/scim/v2`` URL of this server, as the client reached it."""
    return f"{str(request.base_url).rstrip('/')}{SCIM_PREFIX}"


async def read_json(request: Request) -> object:
    """The decoded request body; only the SCIM and plain JSON media types are parsed."""
    content_type = request.headers.get("content-type", "")
    media_type = content_type.partition(";")[0].strip().lower()
    if media_type not in JSON_MEDIA_TYPES:
        raise ScimValidationError(INVALID_SYNTAX, _UNSUPPORTED_MEDIA_DETAIL)
    try:
        return json.loads(await request.body())
    except (ValueError, RecursionError):  # bad JSON, bad UTF-8 or absurd nesting
        raise ScimValidationError(INVALID_SYNTAX, _BAD_JSON_DETAIL) from None


def _resource(member: Member, request: Request) -> dict[str, Any]:
    return member_to_resource(member, base_url=scim_base_url(request))


def _ensure_activatable(member: Member, active: bool | None) -> None:
    """``active`` true cannot lift the global ``disabled_at``, which SCIM never writes (409)."""
    if active is True and member.user.disabled_at is not None:
        raise InvalidState(_DISABLED_DETAIL)


async def _deactivate(
    service: UserAdminService, principal: Principal, user_id: str, request: Request
) -> SafeJSONResponse:
    """Remove the membership; answer 200 with the resource as it was, ``active`` false."""
    member = await service.update_member(principal, user_id, deactivate=True)
    return scim_response({**_resource(member, request), "active": False})


def _patched_external_id(change: PatchChange) -> str | None | Unset:
    """``None`` clears the external id, ``UNSET`` leaves it alone."""
    if change.clear_external_id:
        return None
    return UNSET if change.external_id is None else change.external_id


async def _matching_members(
    service: UserAdminService, org_id: str, filter_text: str | None
) -> Sequence[Member]:
    """Every member, or the one ``userName eq`` names (none is an empty list, not a 404)."""
    if filter_text is None:
        return await service.list_members(org_id)
    wanted = parse_user_filter(filter_text)
    member = await service.find_member_by_email(org_id, wanted.user_name)
    return [] if member is None else [member]


# --- discovery ----------------------------------------------------------------------------


@router.get("/ServiceProviderConfig", include_in_schema=_IN_SCHEMA)
async def get_service_provider_config(request: Request) -> Response:
    return scim_response(service_provider_config(scim_base_url(request)))


@router.get("/ResourceTypes", include_in_schema=_IN_SCHEMA)
async def get_resource_types(request: Request) -> Response:
    return scim_response(resource_types(scim_base_url(request)))


@router.get("/Schemas", include_in_schema=_IN_SCHEMA)
async def get_schemas(request: Request) -> Response:
    return scim_response(schemas(scim_base_url(request)))


# --- Users --------------------------------------------------------------------------------


@router.get("/Users", include_in_schema=_IN_SCHEMA)
async def list_users(
    request: Request,
    principal: Token,
    service: Service,
    filter_text: Annotated[str | None, Query(alias="filter")] = None,
    start_index: Annotated[int | None, Query(alias="startIndex")] = None,
    count: Annotated[int | None, Query(alias="count")] = None,
) -> Response:
    members = await _matching_members(service, principal.org_id, filter_text)
    body = list_response(
        members, base_url=scim_base_url(request), start_index=start_index, count=count
    )
    return scim_response(body)


@router.get("/Users/{user_id}", include_in_schema=_IN_SCHEMA)
async def get_user(user_id: str, request: Request, principal: Token, service: Service) -> Response:
    member = await service.get_member(principal.org_id, user_id)
    return scim_response(_resource(member, request))


@router.post("/Users", status_code=201, include_in_schema=_IN_SCHEMA)
async def create_user(
    request: Request, principal: Token, service: Service, settings: Config
) -> Response:
    requested = parse_user_resource(await read_json(request))
    if requested.active is False:
        raise ScimValidationError(INVALID_VALUE, _INACTIVE_CREATE_DETAIL)
    role = requested.role if requested.role is not None else OrgRole(settings.scim_default_role)
    member = await service.create_member(
        principal,
        requested.user_name,
        requested.new_display_name,
        role,
        external_id=requested.external_id,
    )
    resource = _resource(member, request)
    return scim_response(resource, 201, {"Location": str(resource["meta"]["location"])})


@router.put("/Users/{user_id}", include_in_schema=_IN_SCHEMA)
async def replace_user(
    user_id: str, request: Request, principal: Token, service: Service
) -> Response:
    requested = parse_user_resource(await read_json(request))
    current = await service.get_member(principal.org_id, user_id)
    ensure_unchanged(
        current.user, user_name=requested.user_name, display_name=requested.display_name
    )
    if requested.active is False:
        return await _deactivate(service, principal, user_id, request)
    _ensure_activatable(current, requested.active)
    # Replace never clears an omitted external id; only a PATCH remove does.
    external_id: str | Unset = UNSET if requested.external_id is None else requested.external_id
    member = await service.update_member(
        principal, user_id, role=requested.role, external_id=external_id
    )
    return scim_response(_resource(member, request))


@router.patch("/Users/{user_id}", include_in_schema=_IN_SCHEMA)
async def patch_user(
    user_id: str, request: Request, principal: Token, service: Service
) -> Response:
    change = parse_patch(await read_json(request))
    current = await service.get_member(principal.org_id, user_id)
    ensure_patch_unchanged(current.user, change)
    if change.active is False:
        return await _deactivate(service, principal, user_id, request)
    _ensure_activatable(current, change.active)
    member = await service.update_member(
        principal, user_id, role=change.role, external_id=_patched_external_id(change)
    )
    return scim_response(_resource(member, request))


@router.delete("/Users/{user_id}", status_code=204, include_in_schema=_IN_SCHEMA)
async def delete_user(user_id: str, principal: Token, service: Service) -> Response:
    await service.update_member(principal, user_id, deactivate=True)
    return Response(status_code=204)
