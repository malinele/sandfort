"""SDK r40: ``build_info()`` reports which build an installed SDK came from."""

import dataclasses
import importlib
import json
import sys
from pathlib import Path

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import pytest  # noqa: E402
import sandfort_sdk  # noqa: E402
from sandfort_sdk import BuildInfo, build_info  # noqa: E402
from sandfort_sdk.build_info import BUILD_INFO_RESOURCE  # noqa: E402

# The package re-exports the function ``build_info``, which shadows the submodule attribute,
# so the module object is fetched by name.
build_info_module = importlib.import_module("sandfort_sdk.build_info")

PACKAGE_DIR = SDK_SRC / "sandfort_sdk"
EMPTY = BuildInfo(commit=None, tag=None, built_at=None)


@pytest.fixture
def fake_package(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the resource lookup at ``tmp_path`` so the source tree is never written."""
    monkeypatch.setattr(build_info_module, "files", lambda _package: tmp_path)
    return tmp_path


def _write(directory: Path, payload: object) -> None:
    (directory / BUILD_INFO_RESOURCE).write_text(json.dumps(payload), encoding="utf-8")


def test_plain_checkout_has_no_build_info() -> None:
    assert not (PACKAGE_DIR / BUILD_INFO_RESOURCE).exists()
    assert build_info() == EMPTY


def test_parsed_values_are_returned_and_unknown_keys_ignored(fake_package: Path) -> None:
    _write(
        fake_package,
        {
            "commit": "abc1234def5678",
            "tag": "v0.1.0-r40",
            "built_at": "2026-11-09T09:41:29Z",
            "builder": "ignored",
        },
    )

    assert build_info() == BuildInfo(
        commit="abc1234def5678", tag="v0.1.0-r40", built_at="2026-11-09T09:41:29Z"
    )


def test_missing_keys_default_to_none(fake_package: Path) -> None:
    _write(fake_package, {"commit": "abc"})

    assert build_info() == BuildInfo(commit="abc", tag=None, built_at=None)


def test_missing_file_gives_empty(fake_package: Path) -> None:
    assert build_info() == EMPTY


def test_invalid_json_gives_empty(fake_package: Path) -> None:
    (fake_package / BUILD_INFO_RESOURCE).write_text("{not json", encoding="utf-8")

    assert build_info() == EMPTY


def test_deeply_nested_json_gives_empty(fake_package: Path) -> None:
    (fake_package / BUILD_INFO_RESOURCE).write_text("[" * 100_000, encoding="utf-8")

    assert build_info() == EMPTY


@pytest.mark.parametrize("text", ["[]", '"commit"', "null", "42"])
def test_non_object_json_gives_empty(fake_package: Path, text: str) -> None:
    (fake_package / BUILD_INFO_RESOURCE).write_text(text, encoding="utf-8")

    assert build_info() == EMPTY


def test_non_utf8_file_gives_empty(fake_package: Path) -> None:
    (fake_package / BUILD_INFO_RESOURCE).write_bytes(b"\xff\xfe{\x00")

    assert build_info() == EMPTY


def test_unreadable_file_gives_empty(fake_package: Path) -> None:
    (fake_package / BUILD_INFO_RESOURCE).mkdir()

    assert build_info() == EMPTY


def test_non_string_values_are_none(fake_package: Path) -> None:
    _write(fake_package, {"commit": 1234, "tag": None, "built_at": ["2026-11-09"]})

    assert build_info() == EMPTY


def test_mixed_values_keep_only_strings(fake_package: Path) -> None:
    _write(fake_package, {"commit": "abc", "tag": {"name": "v1"}, "built_at": "2026-11-09"})

    assert build_info() == BuildInfo(commit="abc", tag=None, built_at="2026-11-09")


def test_build_info_is_frozen() -> None:
    info = BuildInfo(commit="abc", tag=None, built_at=None)

    with pytest.raises(dataclasses.FrozenInstanceError):
        info.commit = "other"  # type: ignore[misc]


def test_public_exports() -> None:
    assert "BuildInfo" in sandfort_sdk.__all__
    assert "build_info" in sandfort_sdk.__all__
    assert sandfort_sdk.BuildInfo is build_info_module.BuildInfo
    assert sandfort_sdk.build_info is build_info_module.build_info


def test_wheel_config_ships_the_resource() -> None:
    pyproject = (SDK_SRC.parent / "pyproject.toml").read_text(encoding="utf-8")

    assert f'artifacts = ["src/sandfort_sdk/{BUILD_INFO_RESOURCE}"]' in pyproject
