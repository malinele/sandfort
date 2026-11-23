"""Compile a frozen ``ImageSpec`` into a deterministic Dockerfile and its build context.

Equal specs (list order and env order never matter) always compile to byte-identical text.
Everything that reaches an instruction is validated first: package names and pins, environment
keys and values, the base image reference and every path. A violation raises
``InvalidImageSpec`` (422) so no shell metacharacter or newline can ever reach a ``RUN`` line.
Pip requirements are additionally single-quoted because ``<``, ``>`` and ``!`` are shell syntax.
"""

import re

from sandfort.domain.image_spec import ImageFile, ImageSpec
from sandfort.errors import Unprocessable

DOCKERFILE_NAME = "Dockerfile"
CONTEXT_FILE_PREFIX = "file-"
MAX_BASE_IMAGE_CHARS = 255
SNAPSHOT_REPOSITORY = "sandfort-snapshot"  # local repository committed snapshot images live in
ID_REFERENCE_MESSAGE = "image IDs are not accepted; pass an image name such as python:3.12-slim"
DANGLING_REPOSITORY = "moby-dangling"  # containerd image store name of untagged images
RESERVED_REPOSITORIES = (SNAPSHOT_REPOSITORY, DANGLING_REPOSITORY)
RESERVED_IMAGE_MESSAGE = (
    "images in the sandfort-snapshot repository are reserved; pass the snapshot id instead"
)
DANGLING_IMAGE_MESSAGE = (
    "untagged images (moby-dangling) are not accepted; pass an image name such as python:3.12-slim"
)
EMPTY_REFERENCE_MESSAGE = "image reference must not be empty"

_HEX_ID = re.compile(r"(?:sha256:)?[0-9a-f]{1,64}", re.IGNORECASE)
_SHA256_PREFIX = "sha256:"

_BASE_IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]*")
_APT_PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
_PIP_PACKAGE = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]*(?:(?:==|>=|<=|~=|!=|<|>)[A-Za-z0-9][A-Za-z0-9._*+!-]*)?"
)
_ENV_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_PATH = re.compile(r"/[A-Za-z0-9._+@:/-]*")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class InvalidImageSpec(Unprocessable):
    """The spec (or its wire payload) is malformed or contains an unsafe value."""


def _require(pattern: re.Pattern[str], value: str, what: str) -> str:
    if not pattern.fullmatch(value):
        raise InvalidImageSpec(f"invalid {what}: {value!r}", details={"field": what})
    return value


def reserved_repository(reference: str) -> str | None:
    """The reserved repository ``reference`` names, or ``None`` when it names none.

    The reserved repositories are the platform snapshot repository and ``moby-dangling``, the
    name Docker's containerd image store gives untagged images (``moby-dangling@sha256:<digest>``):
    a leaked digest would otherwise run another org's image. Compared case-insensitively on the
    part before the tag or digest; a registry-prefixed form ending in ``/<repository>`` counts
    too. Snapshot images are reached by snapshot id only.
    """
    name = reference.strip().split("@", 1)[0]
    slash, colon = name.rfind("/"), name.rfind(":")
    if colon > slash:
        name = name[:colon]
    repository = name.lower()
    for reserved in RESERVED_REPOSITORIES:
        if repository == reserved or repository.endswith(f"/{reserved}"):
            return reserved
    return None


def is_reserved_image_reference(reference: str) -> bool:
    """True when ``reference`` names a repository users may never run or build from."""
    return reserved_repository(reference) is not None


def is_image_id_reference(reference: str) -> bool:
    """True when ``reference`` has no repository name and so can only mean a local image ID."""
    stripped = reference.strip()
    if _HEX_ID.fullmatch(stripped):
        return True
    if stripped.lower().startswith(_SHA256_PREFIX):
        return True
    return "@" in stripped and not stripped.split("@", 1)[0]


def check_user_image_reference(ref: str) -> None:
    """Raise ``Unprocessable`` (422) unless ``ref`` is an image name a user may run or build from.

    Docker resolves a raw reference against the LOCAL image store first, and also resolves image
    IDs, so an ID or the reserved ``sandfort-snapshot`` repository would reach another org's
    committed snapshot image. ``name@sha256:...`` with a repository name stays valid. An untagged
    image (``moby-dangling``) gets its own message, since the snapshot repository text would
    mislead.
    """
    if not ref.strip():
        raise Unprocessable(EMPTY_REFERENCE_MESSAGE)
    if is_image_id_reference(ref):
        raise Unprocessable(ID_REFERENCE_MESSAGE)
    reserved = reserved_repository(ref)
    if reserved == DANGLING_REPOSITORY:
        raise Unprocessable(DANGLING_IMAGE_MESSAGE)
    if reserved is not None:
        raise Unprocessable(RESERVED_IMAGE_MESSAGE)


def _require_base_image(value: str) -> str:
    """``value`` when it is a safe image name; image IDs and the reserved repository are refused.

    The classic build resolves ``FROM`` against the local image store, so an ID or a snapshot
    image would copy another sandbox's filesystem into a new snapshot.
    """
    _require(_BASE_IMAGE, value, "base_image")
    try:
        check_user_image_reference(value)
    except Unprocessable as exc:
        raise InvalidImageSpec(exc.message, details={"field": "base_image"}) from exc
    return value


def _require_path(value: str, what: str) -> str:
    _require(_PATH, value, what)
    if ".." in value.split("/"):
        raise InvalidImageSpec(f"invalid {what}: {value!r}", details={"field": what})
    return value


def _env_value(value: str) -> str:
    if _CONTROL_CHARS.search(value):
        raise InvalidImageSpec(
            "invalid environment value: control characters", details={"field": "env value"}
        )
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
    return f'"{escaped}"'


def _sorted_files(spec: ImageSpec) -> list[ImageFile]:
    return sorted(spec.files, key=lambda item: (item.destination, item.content))


def context_file_name(index: int) -> str:
    return f"{CONTEXT_FILE_PREFIX}{index:04d}"


def compile_dockerfile(spec: ImageSpec) -> str:
    """The Dockerfile text for ``spec``; raises ``InvalidImageSpec`` on any unsafe value."""
    if len(spec.base_image) > MAX_BASE_IMAGE_CHARS:
        raise InvalidImageSpec("base image reference is too long", details={"field": "base_image"})
    lines = [f"FROM {_require_base_image(spec.base_image)}"]
    for key in sorted(spec.env):
        lines.append(f"ENV {_require(_ENV_KEY, key, 'env key')}={_env_value(spec.env[key])}")
    apt = sorted({_require(_APT_PACKAGE, name, "apt package") for name in spec.apt_packages})
    if apt:
        lines.append(
            "RUN apt-get update && apt-get install -y --no-install-recommends "
            + " ".join(apt)
            + " && rm -rf /var/lib/apt/lists/*"
        )
    pip = sorted({_require(_PIP_PACKAGE, name, "pip package") for name in spec.pip_packages})
    if pip:
        lines.append("RUN pip install --no-cache-dir " + " ".join(f"'{name}'" for name in pip))
    for index, item in enumerate(_sorted_files(spec)):
        destination = _require_path(item.destination, "file destination")
        if destination.endswith("/"):
            raise InvalidImageSpec(
                f"file destination must name a file: {destination!r}",
                details={"field": "file destination"},
            )
        lines.append(f"COPY {context_file_name(index)} {destination}")
    if spec.workdir is not None:
        lines.append(f"WORKDIR {_require_path(spec.workdir, 'workdir')}")
    return "\n".join(lines) + "\n"


def build_context(spec: ImageSpec) -> dict[str, bytes]:
    """The in-memory build context: the Dockerfile plus one entry per inline file."""
    context = {DOCKERFILE_NAME: compile_dockerfile(spec).encode("utf-8")}
    for index, item in enumerate(_sorted_files(spec)):
        context[context_file_name(index)] = item.content.encode("utf-8")
    return context
