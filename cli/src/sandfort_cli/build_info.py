"""Which build an installed CLI came from.

The release tooling writes ``_build_info.json`` into the ``sandfort_cli`` package directory
just before building the wheel and removes it afterwards. A wheel built by the maintainer
therefore carries the file; a source checkout normally does not, and then every field of
:func:`cli_build_info` is ``None``. Mirrors ``sandfort_sdk.build_info`` but reads this
package's own resource, so the CLI reports its own wheel.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from importlib.metadata import PackageNotFoundError, version
from importlib.resources import files
from typing import Protocol

BUILD_INFO_RESOURCE = "_build_info.json"
CLI_DISTRIBUTION = "sandfort-cli"
SDK_DISTRIBUTION = "sandfort-sdk"
UNKNOWN = "unknown"
UNTAGGED = "untagged"
# Characters of the commit shown on a text line; the json output keeps the full value.
SHORT_COMMIT_LENGTH = 12


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


class BuildFields(Protocol):
    """Anything with the three build fields (this module's or the SDK's ``BuildInfo``)."""

    @property
    def commit(self) -> str | None: ...

    @property
    def tag(self) -> str | None: ...

    @property
    def built_at(self) -> str | None: ...


def _read_resource() -> str | None:
    """Return the text of the packaged ``_build_info.json``, or ``None`` when unreadable."""
    try:
        return files("sandfort_cli").joinpath(BUILD_INFO_RESOURCE).read_text(encoding="utf-8")
    except (OSError, ValueError):
        return None


def _string_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def cli_build_info() -> BuildInfo:
    """Return the build metadata of this installed CLI.

    A missing file, an unreadable file, invalid or too deeply nested JSON gives
    ``BuildInfo(None, None, None)``. Unknown keys are ignored, missing keys default to
    ``None`` and non-string values are treated as ``None``.
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


def _stamped_tag(distribution: str) -> str | None:
    """The release tag stamped into the wheel of ``distribution``, when there is one."""
    if distribution == CLI_DISTRIBUTION:
        return cli_build_info().tag
    try:
        import sandfort_sdk
    except ImportError:
        return None
    sdk_build_info = getattr(sandfort_sdk, "build_info", None)
    if sdk_build_info is None:
        return None
    return _string_or_none(sdk_build_info().tag)


def distribution_version(distribution: str) -> str:
    """Installed version of ``distribution`` from its metadata.

    A wheel built at a release tag reports the version setuptools-scm derived from that tag
    (``v0.1.0-beta.59`` gives ``0.1.0b59``). Without metadata the stamped tag is returned as
    written, and ``unknown`` when there is no stamp either.
    """
    try:
        return version(distribution)
    except PackageNotFoundError:
        return _stamped_tag(distribution) or UNKNOWN


def component_payload(info: BuildFields, package_version: str) -> dict[str, str | None]:
    """Json object for one component: the build fields plus ``version``."""
    payload: dict[str, str | None] = asdict(
        BuildInfo(commit=info.commit, tag=info.tag, built_at=info.built_at)
    )
    payload["version"] = package_version
    return payload


def component_line(name: str, info: BuildFields, package_version: str) -> str:
    """``<name> <version> (<short commit or unknown>, <tag or untagged>)``."""
    commit = info.commit[:SHORT_COMMIT_LENGTH] if info.commit else UNKNOWN
    tag = info.tag or UNTAGGED
    return f"{name} {package_version} ({commit}, {tag})"
