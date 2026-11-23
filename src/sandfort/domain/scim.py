"""SCIM token entity; see docs/scim-design.md section 4 (the SCIM token)."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from sandfort.domain.user import OrgRole


class ScimToken(BaseModel):
    """Stored SCIM token metadata: prefix plus HMAC hash, never the token itself.

    ``max_role`` is the role ceiling of the token. There is no expiry; ``revoked_at`` ends it.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    org_id: str
    name: str
    prefix: str
    secret_hash: str = Field(repr=False)
    max_role: OrgRole
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None
    created_by: str | None = None
    created_at: datetime
