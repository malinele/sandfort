"""``POST /v1/sandboxes/{sandbox_id}/preview-tokens``: mint a preview token and its URL.

A preview token is multi-use until it expires and is bound to the caller's org, the sandbox
and one port. The preview proxy accepts it as the ``sandfort_preview_token`` query parameter
or cookie; public sandboxes need none. Minting issues a credential, so it takes
``sandboxes:write``. The sandbox must belong to the caller's org (else 404) and be started
(round 57): any other state, or a started row without a container, answers the toolbox's 409
``no_container`` with ``state`` and the visible ``stop_cause`` in the details, since the proxy
refuses such a sandbox on every request and a minted token cannot be revoked. The proxy still
checks the state on every request.
"""

from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from sandfort.api.deps import get_audit_recorder, get_sandbox_service, get_settings, get_uow
from sandfort.api.envelope import Envelope, ok
from sandfort.api.schemas.common import NoBool, RequestModel
from sandfort.api.wiring import get_preview_tokens
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import require_scopes
from sandfort.config import Settings
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.events import ActorType
from sandfort.domain.org import Scope
from sandfort.domain.sandbox import Sandbox, SandboxState, visible_stop_cause
from sandfort.errors import no_container_conflict
from sandfort.proxy.routing import MAX_PORT, MIN_PORT, preview_host
from sandfort.proxy.tokens import DEFAULT_TTL, TOKEN_PARAM, PreviewTokenStore
from sandfort.services.audit import AuditRecorder
from sandfort.services.sandboxes import SandboxService

router = APIRouter(prefix="/v1/sandboxes", tags=["sandboxes"])

CREATED = 201
PREVIEW_TOKEN_CREATED = "sandbox.preview_token_created"
HTTP_DEFAULT_PORT = 80
MIN_TTL_S = 60
MAX_TTL_S = 7 * 24 * 3600
DEFAULT_TTL_S = int(DEFAULT_TTL.total_seconds())

Writer = Annotated[Principal, Depends(require_scopes(Scope.SANDBOXES_WRITE))]
Service = Annotated[SandboxService, Depends(get_sandbox_service)]
Tokens = Annotated[PreviewTokenStore, Depends(get_preview_tokens)]
ServerSettings = Annotated[Settings, Depends(get_settings)]
Uow = Annotated[UnitOfWorkPort, Depends(get_uow)]
Recorder = Annotated[AuditRecorder, Depends(get_audit_recorder)]


class MintPreviewTokenRequest(RequestModel):
    port: NoBool[int] = Field(ge=MIN_PORT, le=MAX_PORT, description="Port inside the sandbox.")
    ttl_seconds: NoBool[int] = Field(default=DEFAULT_TTL_S, ge=MIN_TTL_S, le=MAX_TTL_S)


class PreviewTokenResponse(BaseModel):
    token: str
    url: str
    port: int
    expires_at: datetime


def preview_url(settings: Settings, sandbox_id: str, port: int, token: str) -> str:
    """``http://<port>-<sandbox-id>.<preview domain>[:<proxy port>]?<token param>=<token>``.

    With ``public_preview_url`` set (TLS terminated in front of the proxy) the scheme comes
    from that origin, and so does the port, but only when the origin names one.
    """
    host = preview_host(port, sandbox_id, settings.preview_domain)
    query = f"?{TOKEN_PARAM}={token}"
    if settings.public_preview_url:
        scheme, _, authority = settings.public_preview_url.partition("://")
        _, has_port, public_port = authority.partition(":")
        return f"{scheme}://{host}{has_port}{public_port}{query}"
    suffix = "" if settings.proxy_port == HTTP_DEFAULT_PORT else f":{settings.proxy_port}"
    return f"http://{host}{suffix}{query}"


def _require_started(sandbox: Sandbox) -> None:
    """Refuse a sandbox the proxy would refuse: not started, or no container (round 57)."""
    if sandbox.state is not SandboxState.STARTED or not sandbox.driver_ref:
        raise no_container_conflict(sandbox.state.value, visible_stop_cause(sandbox))


@router.post(
    "/{sandbox_id}/preview-tokens",
    status_code=CREATED,
    response_model=Envelope[PreviewTokenResponse],
    description=(
        "Mint a preview token for a port of a started sandbox. A sandbox that is not started "
        "answers 409 `no_container` with its `state` and `stop_cause` in the error details."
    ),
)
async def mint_preview_token(
    sandbox_id: str,
    body: MintPreviewTokenRequest,
    principal: Writer,
    service: Service,
    tokens: Tokens,
    settings: ServerSettings,
    uow: Uow,
    recorder: Recorder,
) -> Envelope[PreviewTokenResponse]:
    sandbox = await service.get(principal.org_id, sandbox_id)  # 404 when missing or foreign
    _require_started(sandbox)  # 409 no_container before any token exists
    ttl = timedelta(seconds=body.ttl_seconds)
    token = await tokens.mint(principal.org_id, sandbox.id, body.port, ttl)
    grant = await tokens.redeem(token)
    # The store is in memory: there is no state change to commit with the row. The row is
    # written before the token leaves, so no credential is handed out without one. Its details
    # name the port and the lifetime only, never the token or the URL that carries it.
    details: dict[str, Any] = {
        "port": grant.port,
        "ttl_seconds": body.ttl_seconds,
        "expires_at": grant.expires_at.isoformat(),
    }
    async with uow:
        await recorder.record(
            uow,
            org_id=principal.org_id,
            actor_type=ActorType.API_KEY,
            actor_id=principal.key_id,
            action=PREVIEW_TOKEN_CREATED,
            target_type="sandbox",
            target_id=sandbox.id,
            details=details,
        )
        await uow.commit()
    return ok(
        PreviewTokenResponse(
            token=token,
            url=preview_url(settings, sandbox.id, grant.port, token),
            port=grant.port,
            expires_at=grant.expires_at,
        )
    )
