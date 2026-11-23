"""Round 61: ``SANDFORT_API_KEY_FILE`` for the CLI and a package-version SDK user agent."""

import importlib.metadata
import json
import os
import shlex
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import sandfort_sdk  # noqa: E402
import typer  # noqa: E402
from sandfort_cli import config, sanitise  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import _transport  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_file_key_do_not_print"
ENV_KEY = "sf_env_key_do_not_print"
# Not key-shaped (no ``sf_`` prefix): only the caller's own key lookup can mask it.
PLAIN_KEY = "filekey-without-the-prefix-9z"
MASK = "***"
FILE_ENV = "SANDFORT_API_KEY_FILE"
PRIVATE_MODE = 0o600
USAGE_EXIT = 2
posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sanitise.cached_file_key.cache_clear()
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "no-profile"))
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    monkeypatch.delenv(FILE_ENV, raising=False)
    monkeypatch.setenv(config.BASE_URL_ENV, BASE)


def key_file(tmp_path: Path, text: str | bytes, mode: int = PRIVATE_MODE) -> Path:
    path = tmp_path / "api-key"
    path.write_bytes(text.encode() if isinstance(text, str) else text)
    path.chmod(mode)
    return path


def use_file(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    monkeypatch.setenv(FILE_ENV, str(path))


def usage_error() -> typer.BadParameter:
    with pytest.raises(typer.BadParameter) as caught:
        config.resolve_settings()
    return caught.value


def test_env_constant_names_the_variable() -> None:
    assert config.API_KEY_FILE_ENV == FILE_ENV


def test_key_is_read_from_the_file(monkeypatch, tmp_path) -> None:
    use_file(monkeypatch, key_file(tmp_path, KEY + "\n"))

    settings = config.resolve_settings()

    assert settings.api_key == KEY
    assert settings.base_url == BASE


def test_whitespace_around_the_key_line_is_stripped(monkeypatch, tmp_path) -> None:
    use_file(monkeypatch, key_file(tmp_path, f"  {KEY} \t\r\n\n"))

    assert config.resolve_settings().api_key == KEY


def test_a_file_without_a_trailing_newline_works(monkeypatch, tmp_path) -> None:
    use_file(monkeypatch, key_file(tmp_path, KEY))

    assert config.resolve_settings().api_key == KEY


def test_the_environment_key_wins_over_the_file(monkeypatch, tmp_path) -> None:
    use_file(monkeypatch, key_file(tmp_path, KEY))
    monkeypatch.setenv(config.API_KEY_ENV, ENV_KEY)

    assert config.resolve_settings().api_key == ENV_KEY


def test_the_environment_key_wins_even_over_a_broken_file(monkeypatch, tmp_path) -> None:
    use_file(monkeypatch, tmp_path / "missing")
    monkeypatch.setenv(config.API_KEY_ENV, ENV_KEY)

    assert config.resolve_settings().api_key == ENV_KEY


def test_the_file_wins_over_the_stored_profile(monkeypatch, tmp_path) -> None:
    profile = tmp_path / "profile-dir"
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(profile))
    profile.mkdir()
    (profile / config.PROFILE_FILENAME).write_text(
        json.dumps({"base_url": BASE, "api_key": "sf_profile_key"})
    )
    use_file(monkeypatch, key_file(tmp_path, KEY))

    assert config.resolve_settings().api_key == KEY


def test_an_empty_variable_is_the_same_as_unset(monkeypatch) -> None:
    monkeypatch.setenv(FILE_ENV, "")

    with pytest.raises(config.CliError, match="not logged in"):
        config.resolve_settings()


def test_a_missing_file_is_a_usage_error_naming_the_variable(monkeypatch, tmp_path) -> None:
    use_file(monkeypatch, tmp_path / "missing")

    error = usage_error()

    assert error.param_hint == FILE_ENV
    assert "does not exist" in error.message


def test_a_directory_is_a_usage_error(monkeypatch, tmp_path) -> None:
    use_file(monkeypatch, tmp_path)

    error = usage_error()

    assert error.param_hint == FILE_ENV
    assert "regular file" in error.message


@posix_only
def test_an_unreadable_file_is_a_usage_error(monkeypatch, tmp_path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root reads any file")
    use_file(monkeypatch, key_file(tmp_path, KEY, mode=0))

    error = usage_error()

    assert error.param_hint == FILE_ENV
    assert "cannot be read" in error.message
    assert KEY not in error.message


@pytest.mark.parametrize("content", ["", "\n", "   \t \n"])
def test_an_empty_first_line_is_a_usage_error(monkeypatch, tmp_path, content) -> None:
    use_file(monkeypatch, key_file(tmp_path, content))

    error = usage_error()

    assert error.param_hint == FILE_ENV
    assert "empty" in error.message


def test_a_file_that_is_not_text_is_a_usage_error(monkeypatch, tmp_path) -> None:
    use_file(monkeypatch, key_file(tmp_path, b"\xff\xfe\x00bad"))

    error = usage_error()

    assert error.param_hint == FILE_ENV
    assert "not valid text" in error.message


@posix_only
@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o660, 0o666, 0o620, 0o607])
def test_a_group_or_world_accessible_file_is_a_usage_error(monkeypatch, tmp_path, mode) -> None:
    use_file(monkeypatch, key_file(tmp_path, KEY, mode=mode))

    error = usage_error()

    assert error.param_hint == FILE_ENV
    assert "group or others" in error.message
    assert "chmod 600" in error.message
    assert KEY not in error.message


@posix_only
@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_owner_only_modes_are_accepted(monkeypatch, tmp_path, mode) -> None:
    use_file(monkeypatch, key_file(tmp_path, KEY, mode=mode))

    assert config.resolve_settings().api_key == KEY


def test_a_malformed_key_in_the_file_is_refused_without_echoing_it(monkeypatch, tmp_path) -> None:
    use_file(monkeypatch, key_file(tmp_path, "sf bad key"))

    error = usage_error()

    assert error.param_hint == FILE_ENV
    assert "malformed" in error.message
    assert "bad" not in error.message


def test_an_overlong_key_in_the_file_is_refused(monkeypatch, tmp_path) -> None:
    use_file(monkeypatch, key_file(tmp_path, "k" * (config.MAX_API_KEY_CHARS + 1)))

    error = usage_error()

    assert error.param_hint == FILE_ENV
    assert "too long" in error.message


@posix_only
def test_the_cli_exits_2_naming_the_variable_and_never_the_key(monkeypatch, tmp_path) -> None:
    use_file(monkeypatch, key_file(tmp_path, KEY, mode=0o644))

    result = CliRunner().invoke(create_app(), ["sandbox", "list"])

    assert result.exit_code == USAGE_EXIT
    assert FILE_ENV in result.output
    assert KEY not in result.output


def test_the_cli_reports_an_empty_file_as_a_usage_error(monkeypatch, tmp_path) -> None:
    use_file(monkeypatch, key_file(tmp_path, ""))

    result = CliRunner().invoke(create_app(), ["sandbox", "list"])

    assert result.exit_code == USAGE_EXIT
    assert FILE_ENV in result.output


def test_the_not_logged_in_hint_mentions_the_key_file() -> None:
    with pytest.raises(config.CliError) as caught:
        config.resolve_settings()

    message = str(caught.value)

    assert "not logged in" in message
    assert "sandfort login" in message
    assert FILE_ENV in message
    assert config.API_KEY_ENV in message


# --- review fixes: the sanitiser's caller_key -------------------------------------------------


def stored_profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, api_key: str) -> None:
    profile = tmp_path / "profile-dir"
    profile.mkdir()
    (profile / config.PROFILE_FILENAME).write_text(
        json.dumps({"base_url": BASE, "api_key": api_key})
    )
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(profile))


def test_caller_key_reads_the_key_file(monkeypatch, tmp_path) -> None:
    use_file(monkeypatch, key_file(tmp_path, PLAIN_KEY + "\n"))

    assert sanitise.caller_key() == PLAIN_KEY


def test_caller_key_prefers_the_environment_key_to_the_file(monkeypatch, tmp_path) -> None:
    use_file(monkeypatch, key_file(tmp_path, PLAIN_KEY))
    monkeypatch.setenv(config.API_KEY_ENV, ENV_KEY)

    assert sanitise.caller_key() == ENV_KEY


def test_caller_key_prefers_the_file_to_the_profile(monkeypatch, tmp_path) -> None:
    stored_profile(monkeypatch, tmp_path, "sf_profile_key")
    use_file(monkeypatch, key_file(tmp_path, PLAIN_KEY))

    assert sanitise.caller_key() == PLAIN_KEY


def test_caller_key_uses_the_profile_without_a_file(monkeypatch, tmp_path) -> None:
    stored_profile(monkeypatch, tmp_path, "sf_profile_key")

    assert sanitise.caller_key() == "sf_profile_key"


def test_caller_key_swallows_key_file_errors(monkeypatch, tmp_path) -> None:
    use_file(monkeypatch, tmp_path / "missing")

    assert sanitise.caller_key() == ""


def test_caller_key_falls_back_to_the_profile_when_the_file_is_broken(
    monkeypatch, tmp_path
) -> None:
    stored_profile(monkeypatch, tmp_path, "sf_profile_key")
    use_file(monkeypatch, tmp_path / "missing")

    assert sanitise.caller_key() == "sf_profile_key"


def test_caller_key_reads_the_file_at_most_once(monkeypatch, tmp_path) -> None:
    use_file(monkeypatch, key_file(tmp_path, PLAIN_KEY))
    real_read = config.read_key_file
    paths: list[str] = []

    def counting(raw_path: str) -> str:
        paths.append(raw_path)
        return real_read(raw_path)

    monkeypatch.setattr(config, "read_key_file", counting)

    assert sanitise.caller_key() == PLAIN_KEY
    assert sanitise.caller_key() == PLAIN_KEY
    assert len(paths) == 1


@pytest.mark.parametrize("as_json", [False, True])
def test_a_usage_error_echoing_the_file_key_prints_it_masked(
    monkeypatch, tmp_path, as_json
) -> None:
    use_file(monkeypatch, key_file(tmp_path, PLAIN_KEY))
    args = (["--json"] if as_json else []) + [PLAIN_KEY]

    result = CliRunner().invoke(create_app(), args)

    assert result.exit_code == USAGE_EXIT
    assert PLAIN_KEY not in result.output
    assert MASK in result.output


# --- review fixes: path handling and file checks ----------------------------------------------


def test_a_home_expansion_that_fails_is_a_usage_error(monkeypatch) -> None:
    monkeypatch.setenv(FILE_ENV, "~no-such-user-r61/key")

    error = usage_error()

    assert error.param_hint == FILE_ENV


def test_the_cli_reports_a_failed_home_expansion_without_a_traceback(monkeypatch) -> None:
    monkeypatch.setenv(FILE_ENV, "~no-such-user-r61/key")

    result = CliRunner().invoke(create_app(), ["sandbox", "list"])

    assert result.exit_code == USAGE_EXIT
    assert FILE_ENV in result.output
    assert not isinstance(result.exception, RuntimeError)


def test_a_path_with_a_nul_byte_is_a_usage_error() -> None:
    with pytest.raises(typer.BadParameter) as caught:
        config.read_key_file("key\x00file")

    assert caught.value.param_hint == FILE_ENV


@posix_only
def test_the_chmod_hint_is_shell_quoted(monkeypatch, tmp_path) -> None:
    path = key_file(tmp_path, KEY, mode=0o644).rename(tmp_path / "my key's file")
    use_file(monkeypatch, path)

    error = usage_error()

    assert f"chmod 600 {shlex.quote(str(path))}" in error.message


@posix_only
def test_the_chmod_hint_has_no_control_characters(monkeypatch, tmp_path) -> None:
    path = key_file(tmp_path, KEY, mode=0o644).rename(tmp_path / "key\x1b[31m\x07file")
    use_file(monkeypatch, path)

    error = usage_error()

    assert "\x1b" not in error.message
    assert "\x07" not in error.message
    assert "chmod 600" in error.message


def test_a_utf8_bom_is_not_part_of_the_key(monkeypatch, tmp_path) -> None:
    use_file(monkeypatch, key_file(tmp_path, b"\xef\xbb\xbf" + KEY.encode() + b"\r\n"))

    assert config.resolve_settings().api_key == KEY


@posix_only
def test_a_file_owned_by_another_user_is_a_usage_error(monkeypatch, tmp_path) -> None:
    path = key_file(tmp_path, KEY)
    use_file(monkeypatch, path)
    other_user = path.stat().st_uid + 1
    monkeypatch.setattr(os, "geteuid", lambda: other_user)

    error = usage_error()

    assert error.param_hint == FILE_ENV
    assert "owned" in error.message
    assert KEY not in error.message


@posix_only
def test_a_symlink_to_a_private_file_is_accepted(monkeypatch, tmp_path) -> None:
    link = tmp_path / "link-to-key"
    link.symlink_to(key_file(tmp_path, KEY))
    use_file(monkeypatch, link)

    assert config.resolve_settings().api_key == KEY


@posix_only
def test_a_fifo_is_refused_without_blocking(monkeypatch, tmp_path) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo, PRIVATE_MODE)
    use_file(monkeypatch, fifo)

    error = usage_error()

    assert error.param_hint == FILE_ENV
    assert "regular file" in error.message


def test_an_overlong_first_line_is_malformed_and_not_echoed(monkeypatch, tmp_path) -> None:
    use_file(monkeypatch, key_file(tmp_path, "k" * (config.KEY_FILE_READ_LIMIT + 1) + "\n"))

    error = usage_error()

    assert error.param_hint == FILE_ENV
    assert "malformed" in error.message
    assert "kkkk" not in error.message


# --- SDK user agent ---------------------------------------------------------------------------


def test_user_agent_uses_the_installed_package_version(monkeypatch) -> None:
    seen: list[str] = []

    def fake_version(name: str) -> str:
        seen.append(name)
        return "0.1.0b65"

    monkeypatch.setattr(importlib.metadata, "version", fake_version)

    assert _transport.build_user_agent() == "sandfort-sdk-python/0.1.0b65"
    assert seen == ["sandfort-sdk"]


def test_user_agent_falls_back_when_the_metadata_is_missing(monkeypatch) -> None:
    def missing(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", missing)

    assert _transport.build_user_agent() == "sandfort-sdk-python/0.1.0"
    assert _transport.build_user_agent() == _transport.FALLBACK_USER_AGENT


def test_user_agent_falls_back_on_an_empty_version(monkeypatch) -> None:
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "")

    assert _transport.build_user_agent() == _transport.FALLBACK_USER_AGENT


def test_the_fallback_user_agent_matches_the_package_version() -> None:
    expected = f"{_transport.USER_AGENT_PRODUCT}/{sandfort_sdk.__version__}"

    assert _transport.FALLBACK_USER_AGENT == expected


def test_the_client_sends_the_computed_user_agent() -> None:
    kwargs = _transport.client_kwargs(BASE, KEY, 5.0)

    sent = kwargs["headers"]["User-Agent"]

    assert sent == _transport.build_user_agent()
    assert sent.startswith("sandfort-sdk-python/")
    assert " " not in sent
