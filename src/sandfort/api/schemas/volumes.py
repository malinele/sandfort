"""Request/response models for ``/v1/volumes`` (architecture.md section 3)."""

from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from sandfort.api.schemas.common import RequestModel
from sandfort.api.schemas.sandboxes import RequestLabels
from sandfort.api.schemas.text_checks import (
    check_label_content,
    check_reserved_labels,
)
from sandfort.domain.volume import Volume, VolumeState
from sandfort.services.volume_limit import effective_limit, is_over_limit, reported_limit

NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]*$"
MAX_NAME_LENGTH = 63


class CreateVolumeRequest(RequestModel):
    name: str = Field(min_length=1, max_length=MAX_NAME_LENGTH, pattern=NAME_PATTERN)
    labels: RequestLabels = Field(
        default_factory=dict,
        description="Labels (same bounds and rules as sandbox labels); a label-scoped key "
        "gets its scope labels merged in.",
    )

    @field_validator("labels")
    @classmethod
    def valid_labels(cls, value: dict[str, str]) -> dict[str, str]:
        check_label_content(value)
        check_reserved_labels(value)
        return value


class VolumeResponse(BaseModel):
    id: str
    name: str
    state: VolumeState
    labels: dict[str, str]
    size_bytes: int | None = None
    max_bytes: int | None = Field(
        default=None,
        description="Soft size limit in bytes (SANDFORT_VOLUME_MAX_BYTES); null when unlimited.",
    )
    over_limit: bool = Field(
        default=False,
        description="True when the sampled size exceeds the limit; a read-write mount is then "
        "refused (422 VOLUME_OVER_LIMIT), a read-only one is not.",
    )
    created_at: datetime


class RestoreResponse(BaseModel):
    volume_id: str
    name: str
    restored_bytes: int = Field(
        description="Bytes of tar data extracted into the volume (decompressed, headers included)."
    )


def volume_response(volume: Volume, max_bytes: int | None = None) -> VolumeResponse:
    """The response for ``volume``.

    An explicit ``max_bytes`` wins (``0`` means no limit). Otherwise the limit is the one the
    service that returned ``volume`` enforces and tagged it with; a plain volume has none.
    There is no process-wide limit, so two wirings in one process never disagree.
    """
    limit = reported_limit(volume) if max_bytes is None else effective_limit(max_bytes)
    return VolumeResponse(
        id=volume.id,
        name=volume.name,
        state=volume.state,
        labels=dict(volume.labels),
        size_bytes=volume.sampled_size_bytes,
        max_bytes=limit,
        over_limit=is_over_limit(volume.sampled_size_bytes, limit),
        created_at=volume.created_at,
    )
