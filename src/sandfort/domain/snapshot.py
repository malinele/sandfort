"""FROZEN: Snapshot entity and state enum."""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class SnapshotState(StrEnum):
    PENDING = "pending"
    READY = "ready"
    ERROR = "error"
    DELETING = "deleting"


class Snapshot(BaseModel):
    """A named, immutable image an org can start sandboxes from."""

    model_config = ConfigDict(frozen=True)

    id: str
    org_id: str
    name: str
    image_ref: str
    digest: str
    layer_count: int = Field(ge=0)
    state: SnapshotState = SnapshotState.PENDING
    source_sandbox_id: str | None = None
    spec_hash: str | None = None
    isolation: str | None = None  # tier of the source sandbox; None for image-based snapshots
    labels: dict[str, str] = Field(default_factory=dict)
    created_at: datetime
