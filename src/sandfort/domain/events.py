"""FROZEN: event type catalog, outbox event and audit event entities."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventType(StrEnum):
    SANDBOX_CREATED = "sandbox.created"
    SANDBOX_STARTED = "sandbox.started"
    SANDBOX_STOPPED = "sandbox.stopped"
    SANDBOX_DELETED = "sandbox.deleted"
    SANDBOX_ERROR = "sandbox.error"
    SANDBOX_AUTO_STOPPED = "sandbox.auto_stopped"
    SNAPSHOT_CREATED = "snapshot.created"
    SNAPSHOT_ACTIVE = "snapshot.active"
    SNAPSHOT_ERROR = "snapshot.error"
    SNAPSHOT_DELETED = "snapshot.deleted"
    VOLUME_CREATED = "volume.created"
    VOLUME_DELETED = "volume.deleted"
    QUOTA_EXCEEDED = "quota.exceeded"


class SandboxEventPayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    sandbox_id: str
    state: str
    reason: str | None = None


class Event(BaseModel):
    """Outbox row; delivered at least once."""

    model_config = ConfigDict(frozen=True)

    id: str
    org_id: str
    type: EventType
    subject_type: str
    subject_id: str
    payload: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime
    dispatched_at: datetime | None = None


class ActorType(StrEnum):
    API_KEY = "api_key"
    SYSTEM = "system"
    PLATFORM_ADMIN = "platform_admin"


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    DENIED = "denied"
    ERROR = "error"


class AuditEvent(BaseModel):
    """Append-only audit record; ``details`` is already redacted."""

    model_config = ConfigDict(frozen=True)

    id: str
    org_id: str
    actor_type: ActorType
    actor_id: str | None = None
    action: str
    target_type: str | None = None
    target_id: str | None = None
    outcome: AuditOutcome = AuditOutcome.SUCCESS
    request_id: str | None = None
    ip: str | None = None
    user_agent: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime
