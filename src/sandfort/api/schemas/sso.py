"""Request/response models for ``/v1/auth/sso/exchange``."""

from datetime import datetime

from pydantic import BaseModel, Field

from sandfort.api.schemas.common import RequestModel
from sandfort.domain.user import OrgRole
from sandfort.services.sso import SsoSession

MAX_IDENTITY_TOKEN_LENGTH = 16 * 1024  # generous for an RS256 identity token, bounds parsing


class SsoExchangeRequest(RequestModel):
    id_token: str = Field(min_length=1, max_length=MAX_IDENTITY_TOKEN_LENGTH)


class SsoExchangeResponse(BaseModel):
    session_token: str
    expires_at: datetime
    role: OrgRole


def sso_exchange_response(session: SsoSession) -> SsoExchangeResponse:
    return SsoExchangeResponse(
        session_token=session.token, expires_at=session.expires_at, role=session.role
    )
