"""CLI round 41: ``sandfort version`` and the CLI wheel's own build identity.

``cli_build_info()`` mirrors the SDK's ``build_info()`` but reads ``_build_info.json`` from the
``sandfort_cli`` package. The ``version`` command prints one line per component (cli, sdk) with
the installed version and the commit/tag when known, plus a pointer to the server's
``GET /v1/status`` ``build_sha``; ``--json`` prints ``{"cli": {...}, "sdk": {...}}``. No network.
"""

import importlib
import json
import sys
from importlib.metadata import PackageNotFoundError
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import sandfort_sdk  # noqa: E402
from sandfort_cli import build_info as cli_build_info_module  # noqa: E402
from sandfort_cli.build_info import (  # noqa: E402
    BUILD_INFO_RESOURCE,
    BuildInfo,
    cli_build_info,
)
from sandfort_cli.main import create_app  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

# ``sandfort_sdk.build_info`` as an attribute is the re-exported function; load the module.
sdk_build_info = importlib.import_module("sandfort_sdk.build_info")
CLI_SRC = ROOT / "cli" / "src"
EMPTY = BuildInfo(commit=None, tag=None, built_at=None)
COMMIT = "0123456789abcdef0123456789abcdef01234567"
TAG = "v0.1.0"
BUILT_AT = "2026-11-09T10:00:00Z"
FIELDS = {"commit", "tag", "built_at", "version"}


@pytest.fixture
def cli_package(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the CLI resource lookup at a temp dir so the source tree is never written."""
    package = tmp_path / "cli_pkg"
    package.mkdir()
    monkeypatch.setattr(cli_build_info_module, "files", lambda _package: package)
    return package


@pytest.fixture(autouse=True)
def hermetic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No SDK resource and a fixed installed version for both distributions."""
    sdk_package = tmp_path / "sdk_pkg"
    sdk_package.mkdir()
    monkeypatch.setattr(sdk_build_info, "files", lambda _package: sdk_package)
    monkeypatch.setattr(cli_build_info_module, "version", lambda _distribution: "0.1.0")


def _write(directory: Path, text: str) -> None:
    (directory / BUILD_INFO_RESOURCE).write_text(text, encoding="utf-8")


def _invoke(*args: str) -> tuple[int, str]:
    result = CliRunner().invoke(create_app(), list(args))
    return result.exit_code, result.output


def test_text_mode_prints_three_lines_for_a_checkout(cli_package: Path) -> None:
    code, output = _invoke("version")

    assert code == 0
    assert output.splitlines() == [
        "cli 0.1.0 (unknown, untagged)",
        "sdk 0.1.0 (unknown, untagged)",
        "server: use GET /v1/status build_sha",
    ]


def test_json_mode_has_cli_and_sdk_objects(cli_package: Path) -> None:
    code, output = _invoke("--json", "version")

    assert code == 0
    payload = json.loads(output)
    assert set(payload) == {"cli", "sdk"}
    for component in ("cli", "sdk"):
        assert set(payload[component]) == FIELDS
        assert payload[component]["version"] == "0.1.0"
        assert payload[component]["commit"] is None
        assert payload[component]["tag"] is None
        assert payload[component]["built_at"] is None


def test_stamped_resource_shows_commit_and_tag(cli_package: Path) -> None:
    _write(cli_package, json.dumps({"commit": COMMIT, "tag": TAG, "built_at": BUILT_AT}))

    code, output = _invoke("version")

    assert code == 0
    lines = output.splitlines()
    assert lines[0] == f"cli 0.1.0 ({COMMIT[:12]}, {TAG})"
    assert lines[1] == "sdk 0.1.0 (unknown, untagged)"


def test_stamped_resource_in_json_keeps_full_values(cli_package: Path) -> None:
    _write(cli_package, json.dumps({"commit": COMMIT, "tag": TAG, "built_at": BUILT_AT}))

    code, output = _invoke("--json", "version")

    assert code == 0
    assert json.loads(output)["cli"] == {
        "commit": COMMIT,
        "tag": TAG,
        "built_at": BUILT_AT,
        "version": "0.1.0",
    }


def test_sdk_line_reports_the_sdk_build(cli_package: Path, tmp_path: Path) -> None:
    _write(tmp_path / "sdk_pkg", json.dumps({"commit": "fedcba9876", "tag": None}))

    code, output = _invoke("version")

    assert code == 0
    assert output.splitlines()[1] == "sdk 0.1.0 (fedcba9876, untagged)"


def test_missing_metadata_reports_unknown_version(
    cli_package: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def missing(distribution: str) -> str:
        raise PackageNotFoundError(distribution)

    monkeypatch.setattr(cli_build_info_module, "version", missing)

    code, output = _invoke("version")

    assert code == 0
    assert output.splitlines()[0] == "cli unknown (unknown, untagged)"


def test_version_is_listed_in_help() -> None:
    code, output = _invoke("--help")

    assert code == 0
    rows = [line for line in output.splitlines() if line.lstrip(" │").startswith("version")]
    assert len(rows) == 1
    assert "Show the cli and sdk versions and builds" in rows[0]


def test_old_sdk_without_build_info_still_prints_version(
    cli_package: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delattr(sandfort_sdk, "build_info")

    code, output = _invoke("version")
    json_code, json_output = _invoke("--json", "version")

    assert code == 0
    assert output.splitlines()[1] == "sdk 0.1.0 (unknown, untagged)"
    assert json_code == 0
    payload = json.loads(json_output)
    assert payload["sdk"] == {"commit": None, "tag": None, "built_at": None, "version": "0.1.0"}


def test_plain_checkout_resource_is_absent() -> None:
    assert not (CLI_SRC / "sandfort_cli" / BUILD_INFO_RESOURCE).exists()


def test_missing_file_gives_empty(cli_package: Path) -> None:
    assert cli_build_info() == EMPTY


@pytest.mark.parametrize("text", ["{not json", "[1, 2]", '"commit"', "null"])
def test_invalid_or_non_object_json_gives_empty(cli_package: Path, text: str) -> None:
    _write(cli_package, text)

    assert cli_build_info() == EMPTY


def test_deeply_nested_json_gives_empty(cli_package: Path) -> None:
    _write(cli_package, "[" * 100_000 + "]" * 100_000)

    assert cli_build_info() == EMPTY


def test_non_utf8_file_gives_empty(cli_package: Path) -> None:
    (cli_package / BUILD_INFO_RESOURCE).write_bytes(b"\xff\xfe{")

    assert cli_build_info() == EMPTY


def test_unreadable_resource_gives_empty(cli_package: Path) -> None:
    (cli_package / BUILD_INFO_RESOURCE).mkdir()

    assert cli_build_info() == EMPTY


def test_non_string_values_are_none(cli_package: Path) -> None:
    _write(cli_package, json.dumps({"commit": 1, "tag": ["v"], "built_at": "x"}))

    assert cli_build_info() == BuildInfo(commit=None, tag=None, built_at="x")


def test_build_info_is_frozen() -> None:
    with pytest.raises(AttributeError):
        EMPTY.commit = "x"  # type: ignore[misc]


def test_wheel_config_ships_the_resource() -> None:
    pyproject = (ROOT / "cli" / "pyproject.toml").read_text(encoding="utf-8")

    assert f'artifacts = ["src/sandfort_cli/{BUILD_INFO_RESOURCE}"]' in pyproject
