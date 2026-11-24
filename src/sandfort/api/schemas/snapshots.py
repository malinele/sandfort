"""Request/response models for ``/v1/snapshots`` (architecture.md section 3)."""

from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from sandfort.api.schemas.common import RequestModel
from sandfort.api.schemas.sandboxes import RequestLabels
from sandfort.api.schemas.text_checks import check_label_content, check_reserved_labels
from sandfort.auth.label_scope import current_label_scope
from sandfort.domain.resources import ResourceSpec
from sandfort.domain.snapshot import Snapshot, SnapshotState

# Image references and snapshot names: registry host, path, tag and digest characters.
REFERENCE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]*$"
MAX_REFERENCE_LENGTH = 255  # an unnamed registration uses the reference as its name
MAX_NAME_LENGTH = 255
MAX_ID_LENGTH = 64
LABELS_DESCRIPTION = (
    "Labels (same bounds and rules as volume labels); a label-scoped key gets its scope "
    "labels merged in."
)


class _LabelledRequest(RequestModel):
    labels: RequestLabels = Field(default_factory=dict, description=LABELS_DESCRIPTION)

    @field_validator("labels")
    @classmethod
    def valid_labels(cls, value: dict[str, str]) -> dict[str, str]:
        check_label_content(value)
        check_reserved_labels(value)
        return value


class RegisterSnapshotRequest(_LabelledRequest):
    image: str = Field(min_length=1, max_length=MAX_REFERENCE_LENGTH, pattern=REFERENCE_PATTERN)
    name: str | None = Field(
        default=None, min_length=1, max_length=MAX_NAME_LENGTH, pattern=REFERENCE_PATTERN
    )


class CreateSnapshotFromSandboxRequest(_LabelledRequest):
    sandbox_id: str = Field(min_length=1, max_length=MAX_ID_LENGTH)
    name: str = Field(min_length=1, max_length=MAX_NAME_LENGTH, pattern=REFERENCE_PATTERN)


class SnapshotResponse(BaseModel):
    id: str
    name: str
    state: SnapshotState
    image_ref: str | None = Field(
        description=(
            "Registry reference of the image behind this snapshot. Null when the caller is a "
            "label-scoped key: it names the operator's registry host and path, like "
            "source_sandbox_id. Org-wide keys see it."
        ),
    )
    digest: str | None = Field(
        default=None,
        description=(
            "Content digest of the image, null until it is known. Also null when the caller is "
            "a label-scoped key, like source_sandbox_id. Org-wide keys see it."
        ),
    )
    layer_count: int
    source_sandbox_id: str | None = Field(
        default=None,
        description=(
            "Id of the sandbox this snapshot was committed from; null for registered or built "
            "images. Also null when the caller is a label-scoped key: the source may be a "
            "sandbox outside its scope. Org-wide keys see it."
        ),
    )
    isolation: str | None = None
    resources: ResourceSpec | None = Field(
        default=None,
        description=(
            "Resources (cpu_millicores, memory_mib, disk_gib) of the sandbox this snapshot was "
            "committed from, as they were at snapshot time. Null for registered or built "
            "images and for snapshots taken before this was recorded. A sandbox create can "
            "adopt them with `inherit_resources`."
        ),
    )
    labels: dict[str, str]
    created_at: datetime


def snapshot_response(snapshot: Snapshot) -> SnapshotResponse:
    """The API view of ``snapshot``.

    ``source_sandbox_id`` is withheld (null) from a label-scoped caller: it is an internal id
    that can name a sandbox outside that caller's scope. ``image_ref`` and ``digest`` are
    withheld too, since they expose the operator's registry host and path.
    """
    label_scoped = current_label_scope() is not None
    return SnapshotResponse(
        id=snapshot.id,
        name=snapshot.name,
        state=snapshot.state,
        image_ref=None if label_scoped else snapshot.image_ref,
        digest=None if label_scoped else (snapshot.digest or None),
        layer_count=snapshot.layer_count,
        source_sandbox_id=None if label_scoped else snapshot.source_sandbox_id,
        isolation=snapshot.isolation,
        resources=snapshot.resources,
        labels=dict(snapshot.labels),
        created_at=snapshot.created_at,
    )
