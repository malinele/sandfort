"""Canonical JSON schema of the image spec wire form; the SDK DSL serializes to exactly this.

``IMAGE_SPEC_SCHEMA`` is the published contract (draft 2020-12). ``validate_image_spec_payload``
enforces it with pydantic and returns the domain ``ImageSpec``. Structural problems raise
``InvalidImageSpec``; unsafe values (shell metacharacters and the like) are rejected later by
the Dockerfile compiler, which is the single authority on what may reach an instruction.
"""

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictStr, ValidationError

from sandfort.domain.image_spec import ImageFile, ImageSpec
from sandfort.images.dockerfile import InvalidImageSpec

SCHEMA_VERSION = "1"
MAX_BASE_IMAGE_CHARS = 255
MAX_PACKAGES = 200
MAX_PACKAGE_CHARS = 200
MAX_ENV_ENTRIES = 100
MAX_ENV_CHARS = 4096
MAX_FILES = 64
MAX_PATH_CHARS = 1024
MAX_FILE_CONTENT_CHARS = 262_144

_PACKAGE_LIST: dict[str, Any] = {
    "type": "array",
    "maxItems": MAX_PACKAGES,
    "items": {"type": "string", "minLength": 1, "maxLength": MAX_PACKAGE_CHARS},
    "default": [],
}

IMAGE_SPEC_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://sandfort.dev/schemas/image-spec/v1.json",
    "title": "ImageSpec",
    "type": "object",
    "additionalProperties": False,
    "required": ["base_image"],
    "properties": {
        "schema_version": {"const": SCHEMA_VERSION},
        "base_image": {"type": "string", "minLength": 1, "maxLength": MAX_BASE_IMAGE_CHARS},
        "pip_packages": _PACKAGE_LIST,
        "apt_packages": _PACKAGE_LIST,
        "env": {
            "type": "object",
            "maxProperties": MAX_ENV_ENTRIES,
            "propertyNames": {"minLength": 1, "maxLength": MAX_ENV_CHARS},
            "additionalProperties": {"type": "string", "maxLength": MAX_ENV_CHARS},
            "default": {},
        },
        "workdir": {"type": ["string", "null"], "maxLength": MAX_PATH_CHARS, "default": None},
        "files": {
            "type": "array",
            "maxItems": MAX_FILES,
            "default": [],
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["destination", "content"],
                "properties": {
                    "destination": {"type": "string", "minLength": 1, "maxLength": MAX_PATH_CHARS},
                    "content": {"type": "string", "maxLength": MAX_FILE_CONTENT_CHARS},
                },
            },
        },
    },
}


class _WireFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    destination: StrictStr = Field(min_length=1, max_length=MAX_PATH_CHARS)
    content: StrictStr = Field(max_length=MAX_FILE_CONTENT_CHARS)


class _WireSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: StrictStr = SCHEMA_VERSION
    base_image: StrictStr = Field(min_length=1, max_length=MAX_BASE_IMAGE_CHARS)
    pip_packages: list[StrictStr] = Field(default_factory=list, max_length=MAX_PACKAGES)
    apt_packages: list[StrictStr] = Field(default_factory=list, max_length=MAX_PACKAGES)
    env: dict[StrictStr, StrictStr] = Field(default_factory=dict, max_length=MAX_ENV_ENTRIES)
    workdir: StrictStr | None = Field(default=None, max_length=MAX_PATH_CHARS)
    files: list[_WireFile] = Field(default_factory=list, max_length=MAX_FILES)


def validate_image_spec_payload(payload: Mapping[str, Any]) -> ImageSpec:
    """Validate a wire payload against the schema and return the domain spec."""
    try:
        wire = _WireSpec.model_validate(dict(payload))
    except ValidationError as exc:
        issues = [
            {"loc": [str(part) for part in err["loc"]], "msg": err["msg"], "type": err["type"]}
            for err in exc.errors(include_input=False, include_url=False)
        ]
        raise InvalidImageSpec(
            "image spec does not match the schema", details={"errors": issues}
        ) from exc
    if wire.schema_version != SCHEMA_VERSION:
        raise InvalidImageSpec(
            f"unsupported image spec schema_version {wire.schema_version!r}",
            details={"supported": SCHEMA_VERSION},
        )
    return ImageSpec(
        base_image=wire.base_image,
        pip_packages=wire.pip_packages,
        apt_packages=wire.apt_packages,
        env=wire.env,
        workdir=wire.workdir,
        files=[ImageFile(destination=f.destination, content=f.content) for f in wire.files],
    )
