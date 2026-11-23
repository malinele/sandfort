"""Human identities, per-org roles and the mapping from roles onto the scope catalog."""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator

from sandfort.domain.org import Scope


class OrgRole(StrEnum):
    ADMIN = "admin"
    DEVELOPER = "developer"
    VIEWER = "viewer"


class User(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    email: str
    display_name: str
    created_at: datetime
    disabled_at: datetime | None = None

    @field_validator("email")
    @classmethod
    def _normalise_email(cls, value: str) -> str:
        return value.strip().lower()


class OrgMembership(BaseModel):
    model_config = ConfigDict(frozen=True)

    user_id: str
    org_id: str
    role: OrgRole
    created_at: datetime
    external_id: str | None = None


_DEVELOPER_EXCLUDED = frozenset({Scope.API_KEYS_ADMIN, Scope.AUDIT_READ})
_VIEWER_SCOPES = frozenset(
    {
        Scope.ORG_READ,
        Scope.SANDBOXES_READ,
        Scope.SNAPSHOTS_READ,
        Scope.VOLUMES_READ,
        Scope.USAGE_READ,
    }
)


def role_scopes(role: OrgRole) -> frozenset[Scope]:
    """Scopes a member holding ``role`` is granted within the org."""
    everything = frozenset(Scope)
    if role is OrgRole.ADMIN:
        return everything
    if role is OrgRole.DEVELOPER:
        return everything - _DEVELOPER_EXCLUDED
    return _VIEWER_SCOPES
