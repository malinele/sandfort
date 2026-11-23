"""FROZEN: organization, API key entity and scope catalog."""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Scope(StrEnum):
    ORG_READ = "org:read"
    SANDBOXES_READ = "sandboxes:read"
    SANDBOXES_WRITE = "sandboxes:write"
    TOOLBOX = "toolbox:use"
    SNAPSHOTS_READ = "snapshots:read"
    SNAPSHOTS_WRITE = "snapshots:write"
    VOLUMES_READ = "volumes:read"
    VOLUMES_WRITE = "volumes:write"
    API_KEYS_ADMIN = "api_keys:admin"
    WEBHOOKS_WRITE = "webhooks:write"
    USAGE_READ = "usage:read"
    AUDIT_READ = "audit:read"


class OrgStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"


class Org(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    slug: str
    status: OrgStatus = OrgStatus.ACTIVE
    created_at: datetime


class ApiKey(BaseModel):
    """Stored key metadata: prefix plus HMAC hash, never the key itself."""

    model_config = ConfigDict(frozen=True)

    id: str
    org_id: str
    name: str
    prefix: str
    secret_hash: str = Field(repr=False)
    scopes: frozenset[Scope] = frozenset()
    is_platform_admin: bool = False
    # None = unscoped; otherwise the key reaches only sandboxes carrying every pair.
    sandbox_labels: dict[str, str] | None = None
    # None = no cap; otherwise the most live sandboxes inside ``sandbox_labels`` the key may hold.
    max_sandboxes: int | None = None
    # None = none; otherwise the key may list, get and mount read-only the volumes whose labels
    # contain every pair (only meaningful together with ``sandbox_labels``).
    shared_volume_labels: dict[str, str] | None = None
    last_used_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    created_by: str | None = None
    created_at: datetime

    @field_validator("sandbox_labels", "shared_volume_labels")
    @classmethod
    def _empty_scope_is_unscoped(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        return value or None
