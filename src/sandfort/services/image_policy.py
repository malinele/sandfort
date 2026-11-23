"""What a user-supplied raw image reference may name (the service-layer entry point).

A raw reference reaches Docker, which resolves it against the LOCAL image store before any pull
and also resolves image IDs (``sha256:<hex>``, a bare 64-hex id, a short hex prefix). An ID or the
reserved ``sandfort-snapshot`` repository would therefore run another org's committed snapshot
image. ``check_user_image_reference`` refuses both for every user-supplied reference: the sandbox
create path and the build ``base_image``. ``name@sha256:...`` with a repository name stays valid.

An optional allowed-registries list (``Settings.allowed_registries``, loaded and validated once
from ``SANDFORT_ALLOWED_REGISTRIES``; empty means any registry) refuses a reference whose registry
is not listed, with the same 422. Callers without a ``Settings`` in hand fall back to the
environment, which the startup settings load has already validated.

The ID and reserved-repository checks live in ``sandfort.images.dockerfile`` because the
``images`` layer sits below ``services`` and must apply them without importing upward; this
module re-exports them so there is exactly one implementation.
"""

import os
from collections.abc import Iterable, Mapping

from sandfort.config import ALLOWED_REGISTRIES_ENV
from sandfort.errors import Unprocessable
from sandfort.images.dockerfile import (
    EMPTY_REFERENCE_MESSAGE,
    ID_REFERENCE_MESSAGE,
    RESERVED_IMAGE_MESSAGE,
    SNAPSHOT_REPOSITORY,
    is_image_id_reference,
    is_reserved_image_reference,
)
from sandfort.images.dockerfile import (
    check_user_image_reference as _check_reference_shape,
)

DEFAULT_REGISTRY = "docker.io"
_DOCKER_HUB_ALIASES = frozenset(
    {"index.docker.io", "registry-1.docker.io", "registry.hub.docker.com"}
)
REGISTRY_NOT_ALLOWED_MESSAGE = "images from the registry {registry!r} are not allowed"

__all__ = [
    "ALLOWED_REGISTRIES_ENV",
    "EMPTY_REFERENCE_MESSAGE",
    "ID_REFERENCE_MESSAGE",
    "RESERVED_IMAGE_MESSAGE",
    "SNAPSHOT_REPOSITORY",
    "allowed_registries_from_env",
    "check_user_image_reference",
    "image_registry",
    "is_image_id_reference",
    "is_reserved_image_reference",
    "normalize_registry",
]


def normalize_registry(registry: str) -> str:
    """Lowercase registry host (with port), Docker Hub aliases folded to ``docker.io``."""
    host = registry.strip().lower()
    return DEFAULT_REGISTRY if host in _DOCKER_HUB_ALIASES else host


def image_registry(reference: str) -> str:
    """The registry an image reference resolves to, by Docker's rule: the first path component
    names a registry only when it contains ``.`` or ``:`` or is ``localhost``; otherwise the
    reference lives on Docker Hub (``docker.io``)."""
    name = reference.strip().split("@", 1)[0]
    head, separator, _ = name.partition("/")
    if separator and ("." in head or ":" in head or head.lower() == "localhost"):
        return normalize_registry(head)
    return DEFAULT_REGISTRY


def _normalized(registries: Iterable[str] | None) -> frozenset[str] | None:
    if registries is None:
        return None
    names = frozenset(normalize_registry(item) for item in registries if item.strip())
    return names or None


def allowed_registries_from_env(environ: Mapping[str, str] | None = None) -> frozenset[str] | None:
    """The configured registry allowlist, or ``None`` (any registry) when unset or empty."""
    raw = (os.environ if environ is None else environ).get(ALLOWED_REGISTRIES_ENV, "")
    return _normalized(raw.split(","))


def check_user_image_reference(ref: str, allowed_registries: Iterable[str] | None = None) -> None:
    """Raise ``Unprocessable`` (422) unless ``ref`` is an image name a user may run or build from.

    Applies the ID and reserved-repository rules, then the registry allowlist:
    ``allowed_registries`` when given, else ``SANDFORT_ALLOWED_REGISTRIES``; with neither set,
    any registry is accepted.
    """
    _check_reference_shape(ref)
    if allowed_registries is None:
        allowed = allowed_registries_from_env()
    else:
        allowed = _normalized(allowed_registries)
    if allowed is None:
        return
    registry = image_registry(ref)
    if registry not in allowed:
        raise Unprocessable(REGISTRY_NOT_ALLOWED_MESSAGE.format(registry=registry))
