"""Request/response models for ``/v1/images/builds``."""

from typing import Any

from pydantic import Field

from sandfort.api.schemas.common import RequestModel
from sandfort.api.schemas.snapshots import (
    MAX_NAME_LENGTH,
    REFERENCE_PATTERN,
    SnapshotResponse,
    snapshot_response,
)
from sandfort.domain.snapshot import Snapshot, SnapshotState


class BuildImageRequest(RequestModel):
    """``spec`` is the wire form defined by ``images.sdk_dsl_schema``; the service validates it."""

    spec: dict[str, Any]
    name: str | None = Field(
        default=None, min_length=1, max_length=MAX_NAME_LENGTH, pattern=REFERENCE_PATTERN
    )


class BuildImageResponse(SnapshotResponse):
    spec_hash: str | None = None
    reused: bool = False


def build_response(snapshot: Snapshot) -> BuildImageResponse:
    """A new build is always pending, so a ready row can only be a cache hit.

    ``image_ref``, ``digest`` and ``source_sandbox_id`` come from ``snapshot_response`` so a
    label-scoped caller gets the same withholding as on ``/v1/snapshots``.
    """
    base = snapshot_response(snapshot)
    return BuildImageResponse(
        id=snapshot.id,
        name=snapshot.name,
        state=snapshot.state,
        image_ref=base.image_ref,
        digest=base.digest,
        layer_count=snapshot.layer_count,
        source_sandbox_id=base.source_sandbox_id,
        labels=base.labels,
        created_at=snapshot.created_at,
        spec_hash=snapshot.spec_hash,
        reused=snapshot.state is SnapshotState.READY,
    )
