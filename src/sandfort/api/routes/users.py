"""``/v1/org/members``: add, list, re-role and remove members of the caller's org.

Adding, re-roling and removing a member need the admin scope (like the api key routes);
listing needs ``org:read``. A known email reuses the existing user; a second membership in
the same org is a 409, and so is a change that would leave the org without an admin.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response

from sandfort.api.envelope import Envelope, ok
from sandfort.api.query_guard import KnownQuery
from sandfort.api.schemas.users import (
    CreateMemberRequest,
    MemberResponse,
    UpdateMemberRequest,
    member_response,
)
from sandfort.api.wiring import USER_ADMIN_SERVICE_ATTR
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import require_scopes
from sandfort.domain.org import Scope
from sandfort.errors import InternalError
from sandfort.services.user_admin import UserAdminService

router = APIRouter(prefix="/v1/org/members", tags=["org"])

_ITEM_IN_SCHEMA = True


def get_user_admin_service(request: Request) -> UserAdminService:
    value = getattr(request.app.state, USER_ADMIN_SERVICE_ATTR, None)
    if not isinstance(value, UserAdminService):
        raise InternalError("user admin service is misconfigured")
    return value


Reader = Annotated[Principal, Depends(require_scopes(Scope.ORG_READ))]
Admin = Annotated[Principal, Depends(require_scopes(Scope.API_KEYS_ADMIN))]
Service = Annotated[UserAdminService, Depends(get_user_admin_service)]


@router.post("", status_code=201)
async def create_member(
    body: CreateMemberRequest, principal: Admin, service: Service
) -> Envelope[MemberResponse]:
    member = await service.create_member(principal, body.email, body.display_name, body.role)
    return ok(member_response(member))


@router.get("")
async def list_members(
    principal: Reader, _known: KnownQuery, service: Service
) -> Envelope[list[MemberResponse]]:
    members = await service.list_members(principal.org_id)
    return ok([member_response(member) for member in members])


@router.patch("/{user_id}", include_in_schema=_ITEM_IN_SCHEMA)
async def update_member(
    user_id: str, body: UpdateMemberRequest, principal: Admin, service: Service
) -> Envelope[MemberResponse]:
    member = await service.change_member_role(principal, user_id, body.role)
    return ok(member_response(member))


@router.delete("/{user_id}", status_code=204, include_in_schema=_ITEM_IN_SCHEMA)
async def remove_member(user_id: str, principal: Admin, service: Service) -> Response:
    await service.remove_member(principal, user_id)
    return Response(status_code=204)
