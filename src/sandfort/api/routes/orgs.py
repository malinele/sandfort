"""``/v1/org/quota``: effective limits with reserved totals, admin update, ledger recount.

Reads need ``org:read``. Replacing the limits is a platform operation (admin scope plus a
platform-admin key, so a tenant cannot lift its own quota) and writes a ``quota.updated``
audit event. The recount only compares ledger and recomputed totals, so it stays on
``org:read``.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from sandfort.api.envelope import Envelope, ok
from sandfort.api.query_guard import KnownQuery
from sandfort.api.schemas.orgs import (
    QuotaLimitsBody,
    QuotaResponse,
    RecountResponse,
    quota_response,
    recount_response,
)
from sandfort.api.schemas.quota_view import QuotaView, org_quota_view, scoped_quota_view
from sandfort.api.wiring import QUOTA_SERVICE_ATTR
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import require_scopes
from sandfort.domain.org import Scope
from sandfort.errors import Forbidden, InternalError
from sandfort.services.quota import QuotaService

router = APIRouter(prefix="/v1/org/quota", tags=["org"])


def get_quota_service(request: Request) -> QuotaService:
    value = getattr(request.app.state, QUOTA_SERVICE_ATTR, None)
    if not isinstance(value, QuotaService):
        raise InternalError("quota service is misconfigured")
    return value


Reader = Annotated[Principal, Depends(require_scopes(Scope.ORG_READ))]
_require_admin_scope = require_scopes(Scope.API_KEYS_ADMIN)


async def require_platform_admin(
    principal: Annotated[Principal, Depends(_require_admin_scope)],
) -> Principal:
    """403 unless the admin-scoped caller holds a platform-admin key."""
    if not principal.is_platform_admin:
        raise Forbidden(
            "replacing quota limits is a platform operation: a platform-admin key is required"
        )
    return principal


PlatformAdmin = Annotated[Principal, Depends(require_platform_admin)]
Service = Annotated[QuotaService, Depends(get_quota_service)]


@router.get("")
async def get_quota(principal: Reader, _known: KnownQuery, service: Service) -> Envelope[QuotaView]:
    """The org's effective limits next to what is reserved; a scoped key sees its own view.

    Two shapes, one model (`limits`, `reserved`, optional `scope`):

    * Org-wide key: `limits` and `reserved` are the org snapshot and `scope` is null.
    * Key limited to labelled sandboxes (`sandbox_labels`): `limits` stays the org's limits
      (policy, not usage), `reserved` covers only the sandboxes inside the key's scope, and
      `scope` carries `labels`, the key's own `max_sandboxes` cap (null when it has none),
      `sandboxes` (live sandboxes inside the scope, the number that counts to the cap) and
      `remaining` (cap minus `sandboxes`, never below 0; null without a cap). The org-wide
      reserved totals and other teams' usage are never in a scoped answer.
    """
    scope = principal.sandbox_labels
    if scope is None:
        return ok(org_quota_view(await service.get(principal.org_id)))
    view = await service.get_scoped(principal.org_id, scope, principal.max_sandboxes)
    return ok(scoped_quota_view(view))


@router.put("")
async def put_quota(
    body: QuotaLimitsBody, principal: PlatformAdmin, service: Service
) -> Envelope[QuotaResponse]:
    usage = await service.set_limits(principal.org_id, principal.key_id, body.to_domain())
    return ok(quota_response(usage))


@router.get("/recount")
async def get_recount(
    principal: Reader, _known: KnownQuery, service: Service
) -> Envelope[RecountResponse]:
    return ok(recount_response(await service.recount(principal.org_id)))
