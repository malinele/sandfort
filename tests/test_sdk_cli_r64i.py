"""r64i: ``ok`` is false for truncated or stopped runs; the profile follows XDG_CONFIG_HOME."""

import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk.code_contexts import CellResult  # noqa: E402
from sandfort_sdk.models import ExecResult  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_xdg_key_value_123"
EXEC_PAYLOAD = {
    "exit_code": 0,
    "stdout": "aaaa\n",
    "stderr": "",
    "timed_out": False,
    "truncated": False,
    "duration_ms": 12,
}


# 1) ok ------------------------------------------------------------------------------------


@pytest.mark.parametrize("cls", [ExecResult, CellResult])
def test_a_clean_zero_exit_is_ok(cls: type[ExecResult]) -> None:
    assert cls.from_payload(EXEC_PAYLOAD).ok is True


@pytest.mark.parametrize("cls", [ExecResult, CellResult])
def test_a_truncated_run_with_exit_zero_is_not_ok(cls: type[ExecResult]) -> None:
    payload = {**EXEC_PAYLOAD, "truncated": True}

    assert cls.from_payload(payload).ok is False


@pytest.mark.parametrize("cls", [ExecResult, CellResult])
@pytest.mark.parametrize("reason", ["output_limit", "timeout", "killed", "oom_killed"])
def test_a_stopped_run_with_exit_zero_is_not_ok(cls: type[ExecResult], reason: str) -> None:
    payload = {**EXEC_PAYLOAD, "stop_reason": reason}

    assert cls.from_payload(payload).ok is False


def test_an_output_limit_run_reported_as_exit_zero_is_not_ok() -> None:
    payload = {**EXEC_PAYLOAD, "truncated": True, "stop_reason": "output_limit"}

    result = ExecResult.from_payload(payload)

    assert (result.exit_code, result.ok) == (0, False)


def test_a_timeout_without_a_stop_reason_is_still_not_ok() -> None:
    assert ExecResult.from_payload({**EXEC_PAYLOAD, "timed_out": True}).ok is False


def test_a_nonzero_exit_is_not_ok() -> None:
    assert ExecResult.from_payload({**EXEC_PAYLOAD, "exit_code": 3}).ok is False


def test_sandbox_stopped_alone_does_not_change_ok() -> None:
    assert ExecResult.from_payload({**EXEC_PAYLOAD, "sandbox_stopped": True}).ok is True


def test_the_docstring_and_readme_state_the_rule() -> None:
    doc = ExecResult.ok.__doc__ or ""
    readme = (ROOT / "sdk" / "python" / "README.md").read_text()

    assert "truncated" in doc and "stop_reason" in doc
    assert "truncated" in readme.split("`ExecResult.ok`", 1)[1][:300]


# 3) profile location ----------------------------------------------------------------------


@pytest.fixture
def xdg_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv(config.CONFIG_DIR_ENV, raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    return tmp_path


def test_without_overrides_the_profile_is_under_home(xdg_env: Path) -> None:
    assert config.config_dir() == Path.home() / ".config" / "sandfort"


def test_xdg_config_home_sets_the_profile_directory(
    xdg_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_env / "xdg"))

    assert config.profile_path() == xdg_env / "xdg" / "sandfort" / "profile.json"


def test_sandfort_config_dir_beats_xdg_config_home(
    xdg_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_env / "xdg"))
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(xdg_env / "explicit"))

    assert config.config_dir() == xdg_env / "explicit"


@pytest.mark.parametrize("value", ["", "relative/dir"])
def test_an_empty_or_relative_xdg_config_home_is_ignored(
    xdg_env: Path, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", value)

    assert config.config_dir() == Path.home() / ".config" / "sandfort"


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
def test_login_writes_under_xdg_with_private_modes_and_names_the_path(
    xdg_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_env / "xdg"))
    monkeypatch.setenv(config.API_KEY_ENV, KEY)
    expected = xdg_env / "xdg" / "sandfort" / "profile.json"

    result = CliRunner().invoke(create_app(None), ["login", "--base-url", BASE, "--no-verify"])

    assert result.exit_code == 0, result.output
    assert json.loads(expected.read_text())["api_key"] == KEY
    assert stat.S_IMODE(expected.stat().st_mode) == 0o600
    assert stat.S_IMODE(expected.parent.stat().st_mode) == 0o700
    assert str(expected) in result.output.replace("\n", "")
    assert KEY not in result.output
    assert not (Path.home() / ".config" / "sandfort" / "profile.json").exists()
