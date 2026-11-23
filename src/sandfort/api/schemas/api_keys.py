"""Request/response models for ``/v1/api-keys``.

The plaintext key appears in exactly one response: the one that creates it. No response ever
carries the stored hash.
"""

from datetime import datetime
from enum import StrEnum
from typing import Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    field_validator,
    model_validator,
)

from sandfort.api.schemas.common import NoBool
from sandfort.api.schemas.text_checks import (
    check_content,
    check_label_bounds,
    check_label_content,
    check_reserved_labels,
    check_visible_text,
    plain_error,
)
from sandfort.domain.org import ApiKey, Scope
from sandfort.services.api_key_admin import CreatedApiKey, RevokedApiKey

MAX_NAME_LENGTH = 255
MAX_SANDBOX_LABELS = 8
MAX_KEY_SANDBOX_CAP = 1000
VALID_SCOPES = tuple(scope.value for scope in Scope)


class CreateApiKeyRequest(BaseModel):
    # An unknown field (say a misspelt ``max_sandbox``) is a 422, not a silently ignored promise.
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=MAX_NAME_LENGTH)
    scopes: list[Scope] = Field(min_length=1, max_length=len(Scope))
    expires_at: AwareDatetime | None = None
    sandbox_labels: dict[str, str] | None = Field(
        default=None,
        max_length=MAX_SANDBOX_LABELS,
        description=(
            "Restrict the key to sandboxes carrying every one of these labels; "
            "absent or empty means the key is not label scoped."
        ),
    )
    max_sandboxes: NoBool[int | None] = Field(
        default=None,
        ge=1,
        le=MAX_KEY_SANDBOX_CAP,
        description=(
            "Hard cap on the live sandboxes inside the key's label scope; a create under the "
            "key at the cap answers 429. Requires sandbox_labels."
        ),
    )

    shared_volume_labels: dict[str, str] | None = Field(
        default=None,
        max_length=MAX_SANDBOX_LABELS,
        description=(
            "Volumes whose labels contain every one of these may be listed, fetched and "
            "mounted read-only by this key, in addition to the volumes of its own label scope. "
            "It can never update, delete or write them, and it cannot create a volume that "
            "carries all of these labels (403). Matching is by subset, so any volume whose "
            "labels include these pairs is shared, even a private one. Use a label only shared "
            "data carries, for example {\"share\": \"cs101-data\"}, not one that private "
            "volumes also carry. Requires sandbox_labels; absent or empty means none."
        ),
    )

    @field_validator("scopes", mode="before")
    @classmethod
    def known_scopes(cls, value: object) -> object:
        """Name the unknown scope and list the valid ones, instead of a positional message."""
        if not isinstance(value, list):
            return value
        for item in value:
            if isinstance(item, str) and item not in VALID_SCOPES:
                raise plain_error(
                    f"unknown scope '{item}'; the valid scopes are {', '.join(VALID_SCOPES)}"
                )
        return value

    @field_validator("name")
    @classmethod
    def visible_name(cls, value: str) -> str:
        """No control characters, and not only invisible format characters (round 53)."""
        return check_content(check_visible_text(value), "name")

    @field_validator("sandbox_labels", "shared_volume_labels")
    @classmethod
    def valid_sandbox_labels(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        """The sandbox label rules, through the shared checks in ``text_checks``.

        Bounded keys and values (round 59), visible keys (round 53) and no reserved
        ``sandfort.`` names (the one ``RESERVED_LABEL`` refusal).
        """
        check_label_bounds(value, MAX_SANDBOX_LABELS)
        check_label_content(value)
        check_reserved_labels(value)
        return value

    @model_validator(mode="after")
    def require_labels_for_shared(self) -> Self:
        """Shared volumes extend a label scope, so they need one."""
        if self.shared_volume_labels and not self.sandbox_labels:
            raise plain_error(
                "shared_volume_labels requires a non-empty sandbox_labels: it adds read-only "
                "volumes to the key's label scope"
            )
        return self

    @model_validator(mode="after")
    def require_labels_for_cap(self) -> Self:
        """The cap counts the sandboxes inside the label scope, so it needs one."""
        if self.max_sandboxes is not None and not self.sandbox_labels:
            raise plain_error(
                "max_sandboxes requires a non-empty sandbox_labels: the cap counts the "
                "sandboxes inside the key's label scope"
            )
        return self


class ApiKeyStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


STATUS_DESCRIPTION = (
    "Computed by the server from revoked_at and expires_at: `revoked` once revoked_at is set,"
    " else `expired` once expires_at is at or before the time of the response, else `active`."
    " Revoked wins over expired."
)


def key_status(key: ApiKey, now: datetime) -> ApiKeyStatus:
    """``revoked`` once revoked, else ``expired`` once past ``expires_at``, else ``active``."""
    if key.revoked_at is not None:
        return ApiKeyStatus.REVOKED
    if key.expires_at is not None and key.expires_at <= now:
        return ApiKeyStatus.EXPIRED
    return ApiKeyStatus.ACTIVE


class ApiKeyResponse(BaseModel):
    id: str
    name: str
    prefix: str
    scopes: list[Scope]
    sandbox_labels: dict[str, str] | None
    max_sandboxes: int | None
    shared_volume_labels: dict[str, str] | None
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None
    revoked_at: datetime | None
    status: ApiKeyStatus = Field(description=STATUS_DESCRIPTION)
    created_by: str | None = Field(
        description=(
            "Id of the key that minted this one. Null when the caller is a label-scoped key: "
            "the id is of no use to it and would identify the admin key. Org-wide keys see it."
        )
    )


class ApiKeyWithSecretResponse(ApiKeyResponse):
    key: str


class RevokeApiKeyRequest(BaseModel):
    """Optional body of ``DELETE /v1/api-keys/{id}``; ``?cascade=true`` is equivalent."""

    model_config = ConfigDict(extra="forbid")

    cascade: StrictBool = Field(
        default=False,
        description=(
            "Also revoke every live key minted (directly or transitively) by this key. "
            "Default false: only this key is revoked and the live descendants are listed "
            "in `dependants` but left alive."
        ),
    )


class RevokedApiKeyResponse(ApiKeyResponse):
    cascade: bool = Field(description="True when the descendants in `dependants` were revoked.")
    dependants: list[ApiKeyResponse] = Field(
        description=(
            "Live keys minted (directly or transitively) by this key: revoked by this call "
            "when `cascade` is true, otherwise still alive and affected only if revoked later."
        )
    )


def api_key_response(
    key: ApiKey, *, now: datetime, caller_label_scoped: bool = False
) -> ApiKeyResponse:
    """The metadata of ``key``; ``created_by`` is withheld from a label-scoped caller.

    ``status`` is computed at ``now``, which the caller takes from the application's clock (the
    one authentication compares ``expires_at`` against), never from the wall clock.
    """
    return ApiKeyResponse(
        id=key.id,
        name=key.name,
        prefix=key.prefix,
        scopes=sorted(key.scopes),
        sandbox_labels=None if key.sandbox_labels is None else dict(key.sandbox_labels),
        max_sandboxes=key.max_sandboxes,
        shared_volume_labels=(
            None if key.shared_volume_labels is None else dict(key.shared_volume_labels)
        ),
        created_at=key.created_at,
        last_used_at=key.last_used_at,
        expires_at=key.expires_at,
        revoked_at=key.revoked_at,
        status=key_status(key, now),
        created_by=None if caller_label_scoped else key.created_by,
    )


def revoked_api_key_response(
    revoked: RevokedApiKey, *, now: datetime, caller_label_scoped: bool = False
) -> RevokedApiKeyResponse:
    """The revoked key's metadata plus ``cascade`` and the ``dependants`` it concerns.

    Dependants are shown as they are after the call: revoked ones carry the revoke time.
    """
    scoped = caller_label_scoped
    record = api_key_response(revoked.record, now=now, caller_label_scoped=scoped)
    rows = [
        api_key_response(key, now=now, caller_label_scoped=scoped) for key in revoked.dependants
    ]
    return RevokedApiKeyResponse(**record.model_dump(), cascade=revoked.cascade, dependants=rows)


def created_api_key_response(
    created: CreatedApiKey, *, now: datetime, caller_label_scoped: bool = False
) -> ApiKeyWithSecretResponse:
    record = api_key_response(created.record, now=now, caller_label_scoped=caller_label_scoped)
    fields = record.model_dump()
    return ApiKeyWithSecretResponse(**fields, key=created.key)
