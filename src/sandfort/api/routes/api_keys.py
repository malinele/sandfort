"""``/v1/api-keys``: create (plaintext shown once), list (metadata only) and revoke.

Every route needs the admin scope (like the quota update) and is org scoped; another org's key
is a 404. A key can only grant scopes its creator holds (403 otherwise). Revoking is
idempotent: a repeat answers 200 with the already revoked key. Revoking never touches the
key's descendants unless the request says ``cascade`` (body or query, default false).
"""

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Body, Depends, Query, Request

from sandfort.api.deps import get_audit_recorder
from sandfort.api.envelope import Envelope, ok
from sandfort.api.query_guard import KnownQuery, single_valued, strict_bool_query
from sandfort.api.schemas.api_keys import (
    ApiKeyResponse,
    ApiKeyWithSecretResponse,
    CreateApiKeyRequest,
    RevokeApiKeyRequest,
    RevokedApiKeyResponse,
    api_key_response,
    created_api_key_response,
    revoked_api_key_response,
)
from sandfort.api.wiring import API_KEY_ADMIN_SERVICE_ATTR
from sandfort.auth.authenticate import AUTH_STATE_ATTR, AuthContext
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import require_scopes
from sandfort.domain.org import Scope
from sandfort.errors import InternalError
from sandfort.services.api_key_admin import ApiKeyAdminService
from sandfort.services.audit import AuditRecorder

router = APIRouter(prefix="/v1/api-keys", tags=["api-keys"])


def get_api_key_admin_service(request: Request) -> ApiKeyAdminService:
    value = getattr(request.app.state, API_KEY_ADMIN_SERVICE_ATTR, None)
    if not isinstance(value, ApiKeyAdminService):
        raise InternalError("api key admin service is misconfigured")
    return value


def get_now(request: Request) -> datetime:
    """The current time from the clock authentication uses, so ``status`` agrees with it."""
    context = getattr(request.app.state, AUTH_STATE_ATTR, None)
    if not isinstance(context, AuthContext):
        raise InternalError("authentication is not configured")
    return context.clock.now()


Admin = Annotated[Principal, Depends(require_scopes(Scope.API_KEYS_ADMIN))]
Service = Annotated[ApiKeyAdminService, Depends(get_api_key_admin_service)]
Recorder = Annotated[AuditRecorder, Depends(get_audit_recorder)]
Now = Annotated[datetime, Depends(get_now)]
ListOnce = Annotated[None, Depends(single_valued("status"))]
RevokeOnce = Annotated[None, Depends(single_valued("cascade"))]
RevokeStrict = Annotated[None, Depends(strict_bool_query("cascade"))]


@router.post("", status_code=201)
async def create_api_key(
    body: CreateApiKeyRequest, principal: Admin, service: Service, recorder: Recorder, now: Now
) -> Envelope[ApiKeyWithSecretResponse]:
    created = await service.create(
        principal,
        body.name,
        body.scopes,
        body.expires_at,
        body.sandbox_labels,
        body.max_sandboxes,
        recorder,
        body.shared_volume_labels,
    )
    return ok(
        created_api_key_response(created, now=now, caller_label_scoped=_label_scoped(principal))
    )


@router.get("")
async def list_api_keys(
    principal: Admin,
    service: Service,
    now: Now,
    _known: KnownQuery,
    _once: ListOnce,
    status: Annotated[
        Literal["active", "revoked"] | None,
        Query(
            description=(
                "Optional filter. `active` returns keys that are neither revoked nor expired;"
                " `revoked` returns only revoked keys. Without it every key is returned,"
                " revoked and expired ones included. Any other value answers 422."
            )
        ),
    ] = None,
) -> Envelope[list[ApiKeyResponse]]:
    """List the org's API keys (metadata only), optionally filtered by ``status``.

    ``status=active`` keeps keys that are not revoked and not expired at the same instant the
    ``status`` field of each returned row is computed from; ``status=revoked`` keeps revoked
    keys only. Without the parameter every key is returned.

    The list is unpaginated: it returns every key of the org in one response, with no `limit`
    or `cursor`. Revoked and expired keys stay in it, so it grows with the org's key history.
    """
    keys = await service.list_keys(principal)
    scoped = _label_scoped(principal)
    rows = [api_key_response(key, now=now, caller_label_scoped=scoped) for key in keys]
    if status is not None:
        rows = [row for row in rows if row.status.value == status]
    return ok(rows)


@router.delete("/{key_id}")
async def revoke_api_key(
    key_id: str,
    principal: Admin,
    service: Service,
    recorder: Recorder,
    now: Now,
    _known: KnownQuery,
    _once: RevokeOnce,
    _strict: RevokeStrict,
    body: Annotated[RevokeApiKeyRequest | None, Body()] = None,
    cascade: Annotated[
        bool,
        Query(description="Same as the body field: also revoke the key's live descendants."),
    ] = False,
) -> Envelope[RevokedApiKeyResponse]:
    """Revoke a key; its live descendants are revoked only with ``cascade`` (default false).

    ``cascade`` comes from the JSON body or the query string (either one being true counts).
    The query value must be given once and must be exactly ``true`` or ``false`` (lowercase):
    a repeated ``cascade``, or ``yes``, ``on``, ``1`` or ``TRUE``, answers 422.
    The response lists the live descendants as ``dependants``: with ``cascade`` they were just
    revoked, without it they are untouched and would die with the key only if revoked later.
    """
    wanted = cascade or (body is not None and body.cascade)
    revoked = await service.revoke(principal, key_id, recorder, cascade=wanted)
    scoped = _label_scoped(principal)
    return ok(revoked_api_key_response(revoked, now=now, caller_label_scoped=scoped))


def _label_scoped(principal: Principal) -> bool:
    """A label-scoped caller does not see ``created_by`` (the minting admin key's id)."""
    return principal.sandbox_labels is not None
