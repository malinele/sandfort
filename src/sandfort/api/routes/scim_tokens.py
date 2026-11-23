"""``/v1/org/scim-tokens``: mint (plaintext shown once), list (metadata only) and revoke.

See docs/scim-design.md section 4 (token management). Every route needs ``api_keys:admin`` and
is org scoped, through the ordinary platform authentication. ``app.py`` mounts the router only
when ``scim_enabled`` is set. A token can carry only a ``max_role`` whose scopes the minter
holds (403 otherwise). Revoking is idempotent: a repeat answers 200 with the revoked token.
No response carries the stored hash.
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from sandfort.api.envelope import Envelope, ok
from sandfort.api.query_guard import KnownQuery
from sandfort.api.schemas.common import RequestModel
from sandfort.api.wiring import SCIM_TOKEN_SERVICE_ATTR
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import require_scopes
from sandfort.domain.org import Scope
from sandfort.domain.scim import ScimToken
from sandfort.domain.user import OrgRole
from sandfort.errors import InternalError
from sandfort.services.scim_tokens import MAX_NAME_CHARS, CreatedScimToken, ScimTokenService

router = APIRouter(prefix="/v1/org/scim-tokens", tags=["scim-tokens"])

# Out of the exported spec (docs/scim-design.md, OpenAPI export policy), as in routes/nodes.py,
# so the pinned openapi/sandfort.v1.json and its drift test stay valid.
_IN_SCHEMA = False


class CreateScimTokenRequest(RequestModel):
    name: str = Field(min_length=1, max_length=MAX_NAME_CHARS)
    max_role: OrgRole


class ScimTokenResponse(BaseModel):
    id: str
    name: str
    prefix: str
    max_role: OrgRole
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None
    created_by: str | None


class ScimTokenWithSecretResponse(ScimTokenResponse):
    token: str


def scim_token_response(token: ScimToken) -> ScimTokenResponse:
    return ScimTokenResponse(
        id=token.id,
        name=token.name,
        prefix=token.prefix,
        max_role=token.max_role,
        created_at=token.created_at,
        last_used_at=token.last_used_at,
        revoked_at=token.revoked_at,
        created_by=token.created_by,
    )


def created_scim_token_response(created: CreatedScimToken) -> ScimTokenWithSecretResponse:
    fields = scim_token_response(created.record).model_dump()
    return ScimTokenWithSecretResponse(**fields, token=created.token)


def get_scim_token_service(request: Request) -> ScimTokenService:
    value = getattr(request.app.state, SCIM_TOKEN_SERVICE_ATTR, None)
    if not isinstance(value, ScimTokenService):
        raise InternalError("scim token service is misconfigured")
    return value


Admin = Annotated[Principal, Depends(require_scopes(Scope.API_KEYS_ADMIN))]
Service = Annotated[ScimTokenService, Depends(get_scim_token_service)]


@router.post("", status_code=201, include_in_schema=_IN_SCHEMA)
async def create_scim_token(
    body: CreateScimTokenRequest, principal: Admin, service: Service
) -> Envelope[ScimTokenWithSecretResponse]:
    created = await service.mint(principal, body.name, body.max_role)
    return ok(created_scim_token_response(created))


@router.get("", include_in_schema=_IN_SCHEMA)
async def list_scim_tokens(
    principal: Admin, _known: KnownQuery, service: Service
) -> Envelope[list[ScimTokenResponse]]:
    tokens = await service.list_tokens(principal.org_id)
    return ok([scim_token_response(token) for token in tokens])


@router.delete("/{token_id}", include_in_schema=_IN_SCHEMA)
async def revoke_scim_token(
    token_id: str, principal: Admin, service: Service
) -> Envelope[ScimTokenResponse]:
    return ok(scim_token_response(await service.revoke(principal, token_id)))
