"""Which build an installed SDK came from.

The release tooling writes ``_build_info.json`` into the ``sandfort_sdk`` package directory
just before building the wheel and removes it afterwards. A wheel built by the maintainer
therefore carries the file; a source checkout normally does not, and then every field of
:func:`build_info` is ``None``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from importlib.resources import files

BUILD_INFO_RESOURCE = "_build_info.json"
SDK_DISTRIBUTION = "sandfort-sdk"
UNKNOWN = "unknown"


@dataclass(frozen=True)
class BuildInfo:
    """Build metadata stamped into a maintainer-built wheel.

    ``commit`` is the source commit, ``tag`` the release tag and ``built_at`` the build
    timestamp, each exactly as the release tooling wrote it. A field is ``None`` when the
    package carries no ``_build_info.json`` (the normal case for a source checkout), when the
    file cannot be read or parsed, or when that key is missing or not a string.
    """

    commit: str | None
    tag: str | None
    built_at: str | None


def _read_resource() -> str | None:
    """Return the text of the packaged ``_build_info.json``, or ``None`` when unreadable.

    The file exists only in a wheel built by the release tooling, which writes it into the
    package directory just before the build and removes it afterwards.
    """
    try:
        return files("sandfort_sdk").joinpath(BUILD_INFO_RESOURCE).read_text(encoding="utf-8")
    except (OSError, ValueError):
        return None


def _string_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def build_info() -> BuildInfo:
    """Return the build metadata of this installed SDK.

    Reads the optional ``_build_info.json`` package resource. The release tooling writes that
    file into the package directory just before building the wheel and removes it afterwards,
    so a wheel built by the maintainer carries it and a source checkout normally does not.
    A missing file, an unreadable file or invalid JSON gives ``BuildInfo(None, None, None)``.
    Unknown keys are ignored, missing keys default to ``None`` and non-string values are
    treated as ``None``.
    """
    empty = BuildInfo(commit=None, tag=None, built_at=None)
    text = _read_resource()
    if text is None:
        return empty
    try:
        data: object = json.loads(text)
    except (OSError, ValueError, RecursionError):
        return empty
    if not isinstance(data, dict):
        return empty
    return BuildInfo(
        commit=_string_or_none(data.get("commit")),
        tag=_string_or_none(data.get("tag")),
        built_at=_string_or_none(data.get("built_at")),
    )


def distribution_version() -> str:
    """Installed version of this SDK from its distribution metadata.

    A wheel built at a release tag reports the version setuptools-scm derived from that tag
    (``v0.1.0-beta.59`` gives ``0.1.0b59``). Without metadata the stamped tag is returned as
    written, and ``unknown`` when there is no stamp either.
    """
    try:
        return version(SDK_DISTRIBUTION)
    except PackageNotFoundError:
        return build_info().tag or UNKNOWN
