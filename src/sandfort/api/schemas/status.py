"""Response model of ``GET /v1/status`` (public, no authentication)."""

from typing import Literal

from pydantic import BaseModel, Field


class StatusNotice(BaseModel):
    """The operator notice read from the status notice file."""

    message: str = Field(description="The notice text, without any `degraded:` prefix.")
    updated_at: str = Field(description="When the notice file last changed (ISO 8601, UTC).")


class StatusResponse(BaseModel):
    """The public status document."""

    status: Literal["ok", "degraded"] = Field(
        description="`degraded` while the operator notice starts with `degraded:`, else `ok`."
    )
    version: str = Field(description="The installed Sandfort package version.")
    build_sha: str | None = Field(
        description="The commit the operator configured for this build; null when unset."
    )
    image_sha: str | None = Field(
        description="The commit baked into the container image; null when not baked in."
    )
    build_matches_image: bool | None = Field(
        description="Whether build_sha equals image_sha; null when either is unknown."
    )
    started_at: str = Field(description="When this API process started (ISO 8601, UTC).")
    notice: StatusNotice | None = Field(
        description="The current operator notice; null when there is none."
    )
    audit_public_key: str | None = Field(
        description=(
            "Ed25519 public key (urlsafe base64) that verifies signed audit heads; published "
            "only while heads are signed, i.e. both audit keys set, else null."
        )
    )
    audit_key_fingerprint: str | None = Field(
        description=(
            "First 16 hex characters of sha256 over the raw public key, to pin out of band; "
            "published only while heads are signed, i.e. both audit keys set, else null."
        )
    )
