"""FROZEN: Volume entity and state enum."""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class VolumeState(StrEnum):
    READY = "ready"
    DELETING = "deleting"


class Volume(BaseModel):
    """A persistent named volume; ``provider_volume_name`` is the driver-side name."""

    model_config = ConfigDict(frozen=True)

    id: str
    org_id: str
    name: str
    provider_volume_name: str
    state: VolumeState = VolumeState.READY
    sampled_size_bytes: int | None = Field(default=None, ge=0)
    labels: dict[str, str] = Field(default_factory=dict)
    # Set while a restore extracts into the volume; a value found at server start means that
    # restore never finished (the process died), so the volume may hold part of the archive.
    restoring_since: datetime | None = None
    created_at: datetime
