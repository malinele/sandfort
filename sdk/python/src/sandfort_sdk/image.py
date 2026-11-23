"""Fluent, immutable image DSL: every builder method returns a new :class:`Image`.

``serialize`` produces exactly the server's image spec wire form (``schema_version`` "1"), so
``client.snapshots.build(image)`` posts it unchanged. Structural limits and unsafe values are
enforced by the server; the DSL only rejects values that can never be valid (empty names).
"""

import dataclasses
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Self

SCHEMA_VERSION = "1"
DEBIAN_SLIM_BASE = "python:3.12-slim"


def _non_empty(value: object, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{what} must be a non-empty string")
    return value


def _flatten(items: tuple[str | Iterable[str], ...], what: str) -> tuple[str, ...]:
    """Accept ``pip_install("a", "b")`` as well as ``pip_install(["a", "b"])``."""
    flat: list[str] = []
    for item in items:
        group = [item] if isinstance(item, str) else list(item)
        flat.extend(_non_empty(name, what) for name in group)
    return tuple(flat)


def _merged(existing: tuple[str, ...], added: tuple[str, ...]) -> tuple[str, ...]:
    """Append ``added`` in order, skipping names already present (re-adding is a no-op)."""
    return tuple(dict.fromkeys((*existing, *added)))


@dataclass(frozen=True, slots=True)
class ImageFile:
    """A file written into the image: ``destination`` path plus inline text ``content``."""

    destination: str
    content: str


@dataclass(frozen=True, slots=True)
class Image:
    """Declarative image spec; start with ``Image.debian_slim()`` or ``Image.from_image``."""

    base_image: str
    pip_packages: tuple[str, ...] = ()
    apt_packages: tuple[str, ...] = ()
    environment: tuple[tuple[str, str], ...] = ()
    working_dir: str | None = None
    files: tuple[ImageFile, ...] = ()

    @classmethod
    def debian_slim(cls) -> Self:
        """Debian slim with Python 3.12 (the pinned ``python:3.12-slim`` base)."""
        return cls(base_image=DEBIAN_SLIM_BASE)

    @classmethod
    def from_image(cls, reference: str) -> Self:
        """Start from any registry image reference."""
        return cls(base_image=_non_empty(reference, "image reference"))

    def pip_install(self, *packages: str | Iterable[str]) -> Self:
        added = _flatten(packages, "pip package")
        return dataclasses.replace(self, pip_packages=_merged(self.pip_packages, added))

    def apt_install(self, *packages: str | Iterable[str]) -> Self:
        added = _flatten(packages, "apt package")
        return dataclasses.replace(self, apt_packages=_merged(self.apt_packages, added))

    def add_file(self, destination: str, content: str) -> Self:
        """Write ``content`` to ``destination``; a later file at the same path replaces it."""
        _non_empty(destination, "file destination")
        if not isinstance(content, str):
            raise ValueError("file content must be a string")
        kept = tuple(item for item in self.files if item.destination != destination)
        return dataclasses.replace(self, files=(*kept, ImageFile(destination, content)))

    def env(self, values: Mapping[str, str] | None = None, **more: str) -> Self:
        """Set environment variables; later values win over earlier ones."""
        merged = dict(self.environment)
        for name, value in {**(values or {}), **more}.items():
            if not isinstance(value, str):
                raise ValueError(f"env value for {name!r} must be a string")
            merged[_non_empty(name, "env name")] = value
        return dataclasses.replace(self, environment=tuple(merged.items()))

    def workdir(self, path: str) -> Self:
        return dataclasses.replace(self, working_dir=_non_empty(path, "workdir"))

    def serialize(self) -> dict[str, Any]:
        """The image spec wire form accepted by ``POST /v1/images/builds``."""
        return {
            "schema_version": SCHEMA_VERSION,
            "base_image": self.base_image,
            "pip_packages": list(self.pip_packages),
            "apt_packages": list(self.apt_packages),
            "env": dict(self.environment),
            "workdir": self.working_dir,
            "files": [
                {"destination": item.destination, "content": item.content} for item in self.files
            ],
        }
