"""``/v1/auth/sso/exchange``: trade an OIDC identity token for a short-lived user session.

This is the login, so it carries no authentication dependency: the identity token itself is
the credential. Every refusal is a 401 that does not say whether the email is known.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from sandfort.api.envelope import Envelope, ok
from sandfort.api.schemas.sso import (
    SsoExchangeRequest,
    SsoExchangeResponse,
    sso_exchange_response,
)
from sandfort.api.wiring import SSO_SERVICE_ATTR
from sandfort.errors import InternalError
from sandfort.services.sso import SsoService

router = APIRouter(prefix="/v1/auth", tags=["auth"])


def get_sso_service(request: Request) -> SsoService:
    value = getattr(request.app.state, SSO_SERVICE_ATTR, None)
    if not isinstance(value, SsoService):
        raise InternalError("single sign-on service is misconfigured")
    return value


Service = Annotated[SsoService, Depends(get_sso_service)]


@router.post("/sso/exchange")
async def exchange(body: SsoExchangeRequest, service: Service) -> Envelope[SsoExchangeResponse]:
    session = await service.exchange(body.id_token)
    return ok(sso_exchange_response(session))
