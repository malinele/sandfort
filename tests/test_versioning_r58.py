"""Release r58: package versions come from git tags (setuptools-scm).

The mapping tests call setuptools-scm's version helpers directly and never build a wheel.
They are skipped where setuptools-scm is not installed (it is a dev dependency).
"""

import tomllib
from pathlib import Path
from typing import Any

import pytest
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]
PYPROJECTS = {
    "server": ROOT / "pyproject.toml",
    "sdk": ROOT / "sdk" / "python" / "pyproject.toml",
    "cli": ROOT / "cli" / "pyproject.toml",
}
FALLBACK_VERSION = "0.1.0.dev0"


def _version_for(tag: str, distance: int = 0) -> str:
    """Version string setuptools-scm derives for ``distance`` commits after ``tag``."""
    scm: Any = pytest.importorskip("setuptools_scm")
    scm_version: Any = pytest.importorskip("setuptools_scm.version")
    config = scm.Configuration(version_scheme="guess-next-dev", local_scheme="no-local-version")
    node = None if distance == 0 else "g1a2b3c4"
    described = scm_version.meta(tag, distance=distance, node=node, config=config)
    return str(scm_version.format_version(described))


@pytest.mark.parametrize(
    ("tag", "expected"),
    [
        ("v0.1.0-beta.59", "0.1.0b59"),
        ("v0.1.0-beta.1", "0.1.0b1"),
        ("v0.2.0", "0.2.0"),
        ("v1.0.0-rc.2", "1.0.0rc2"),
    ],
)
def test_tag_maps_to_pep440_version(tag: str, expected: str) -> None:
    assert _version_for(tag) == expected
    assert str(Version(expected)) == expected


def test_beta_tag_is_a_prerelease_below_the_final_release() -> None:
    beta = Version(_version_for("v0.1.0-beta.59"))

    assert beta.is_prerelease
    assert beta < Version("0.1.0")
    assert beta > Version(_version_for("v0.1.0-beta.58"))


def test_untagged_commit_after_a_beta_tag_is_a_dev_version() -> None:
    dev = Version(_version_for("v0.1.0-beta.59", distance=3))

    assert dev.is_devrelease
    assert dev.dev == 3
    assert dev.local is None
    assert dev > Version("0.1.0b59")
    assert dev < Version("0.1.0")


def test_untagged_commit_after_a_release_tag_is_a_dev_of_the_next_version() -> None:
    dev = Version(_version_for("v0.2.0", distance=2))

    assert dev.is_devrelease
    assert dev.dev == 2
    assert dev > Version("0.2.0")


@pytest.mark.parametrize("name", sorted(PYPROJECTS))
def test_pyproject_derives_version_from_git(name: str) -> None:
    data = tomllib.loads(PYPROJECTS[name].read_text(encoding="utf-8"))

    assert "version" in data["project"]["dynamic"]
    assert "version" not in data["project"]
    version_cfg = data["tool"]["hatch"]["version"]
    assert version_cfg["source"] == "vcs"
    raw = version_cfg["raw-options"]
    assert raw["fallback_version"] == FALLBACK_VERSION
    assert raw["version_scheme"] == "guess-next-dev"
    assert raw["local_scheme"] == "no-local-version"
    assert "hatch-vcs" in data["build-system"]["requires"]


@pytest.mark.parametrize("name", ["sdk", "cli"])
def test_sub_packages_point_the_scm_root_at_the_repository(name: str) -> None:
    data = tomllib.loads(PYPROJECTS[name].read_text(encoding="utf-8"))
    raw = data["tool"]["hatch"]["version"]["raw-options"]

    assert (PYPROJECTS[name].parent / raw["root"]).resolve() == ROOT
    assert raw["relative_to"] == "pyproject.toml"
