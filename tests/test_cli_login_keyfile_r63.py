"""CLI r63: login reads --key-file, SANDFORT_API_KEY and SANDFORT_API_KEY_FILE before it
prompts; key revoke confirms by name; key list shows blank names as "(unnamed)"."""

import json
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config, login_key  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_file_key_value_123"
OTHER_KEY = "sf_other_key_value_456"
USAGE = 2
RUNNER = CliRunner()
KEYS_URL = "/v1/api-keys"
KEY_ID = "key_01HZZZZZZZZZZZZZZZZZZZZZZA"
REVOKED_AT = "2026-11-06T11:00:00+00:00"


def invoke(args: list[str], *, input_text: str | None = None, as_json: bool = False) -> Any:
    argv = (["--json"] if as_json else []) + args
    return RUNNER.invoke(create_app(None), argv, input=input_text)


def flat(text: str) -> str:
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


def write_key_file(directory: Path, text: str, mode: int = 0o600) -> Path:
    path = directory / "key.txt"
    path.write_text(text)
    path.chmod(mode)
    return path


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    for name in (config.BASE_URL_ENV, config.API_KEY_ENV, config.API_KEY_FILE_ENV):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(login_key, "stdin_is_tty", lambda: True)


@pytest.fixture
def router() -> Iterator[respx.MockRouter]:
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        mock.route().mock(return_value=httpx.Response(404, json={}))
        yield mock


def saved_key() -> str:
    return str(json.loads(config.profile_path().read_text())["api_key"])


LOGIN = ["login", "--base-url", BASE, "--no-verify"]


# 1) login key sources --------------------------------------------------------------------------


def test_key_file_option_supplies_the_key(tmp_path: Path) -> None:
    path = write_key_file(tmp_path, KEY + "\n")

    result = invoke([*LOGIN, "--key-file", str(path)])

    assert result.exit_code == 0, result.output
    assert saved_key() == KEY
    assert "hidden" not in result.output


def test_key_file_option_beats_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_key_file(tmp_path, KEY + "\n")
    monkeypatch.setenv(config.API_KEY_ENV, OTHER_KEY)

    result = invoke([*LOGIN, "--key-file", str(path)])

    assert result.exit_code == 0, result.output
    assert saved_key() == KEY


def test_api_key_variable_beats_the_key_file_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(config.API_KEY_FILE_ENV, str(write_key_file(tmp_path, OTHER_KEY)))
    monkeypatch.setenv(config.API_KEY_ENV, KEY)

    result = invoke(LOGIN)

    assert result.exit_code == 0, result.output
    assert saved_key() == KEY


def test_key_file_variable_is_read_without_a_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(config.API_KEY_FILE_ENV, str(write_key_file(tmp_path, KEY + "\n")))

    result = invoke(LOGIN)

    assert result.exit_code == 0, result.output
    assert saved_key() == KEY
    assert "Api key" not in result.output


def test_api_key_flag_and_key_file_together_are_a_usage_error(tmp_path: Path) -> None:
    path = write_key_file(tmp_path, KEY)

    result = invoke([*LOGIN, "--api-key", OTHER_KEY, "--key-file", str(path)])

    assert result.exit_code == USAGE
    assert not config.profile_path().exists()


@pytest.mark.parametrize("via_option", [True, False], ids=["option", "variable"])
def test_a_loose_key_file_mode_is_refused_with_the_settings_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, via_option: bool
) -> None:
    path = write_key_file(tmp_path, KEY, mode=0o644)
    args = [*LOGIN, "--key-file", str(path)] if via_option else LOGIN
    if not via_option:
        monkeypatch.setenv(config.API_KEY_FILE_ENV, str(path))

    result = invoke(args)

    assert result.exit_code == USAGE
    assert "readable by group or others" in flat(result.stderr)
    assert "chmod 600" in flat(result.stderr)
    assert KEY not in result.output
    assert not config.profile_path().exists()


def test_the_key_file_option_names_itself_in_errors(tmp_path: Path) -> None:
    result = invoke([*LOGIN, "--key-file", str(tmp_path / "missing")])

    assert result.exit_code == USAGE
    assert "--key-file" in flat(result.stderr)
    assert "file does not exist" in flat(result.stderr)


def test_an_empty_key_file_is_refused(tmp_path: Path) -> None:
    result = invoke([*LOGIN, "--key-file", str(write_key_file(tmp_path, "\n"))])

    assert result.exit_code == USAGE
    assert "file is empty" in flat(result.stderr)


def test_an_overlong_key_file_key_is_refused(tmp_path: Path) -> None:
    long_key = "sf_" + "a" * config.MAX_API_KEY_CHARS
    result = invoke([*LOGIN, "--key-file", str(write_key_file(tmp_path, long_key))])

    assert result.exit_code == USAGE
    assert config.TOO_LONG_KEY_MESSAGE in flat(result.stderr)
    assert long_key not in result.output


def test_a_file_not_owned_by_the_user_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_key_file(tmp_path, KEY)
    monkeypatch.setattr(config.os, "geteuid", lambda: 12345)

    result = invoke([*LOGIN, "--key-file", str(path)])

    assert result.exit_code == USAGE
    assert "not owned by the current user" in flat(result.stderr)


# 1b) prompting -------------------------------------------------------------------------------


def assert_no_key_source_error(result: Any) -> None:
    assert result.exit_code == USAGE
    text = flat(result.stderr)
    for source in ("--key-file", "SANDFORT_API_KEY", "SANDFORT_API_KEY_FILE", "stdin"):
        assert source in text
    assert "Api key" not in result.output
    assert not config.profile_path().exists()


@pytest.mark.parametrize("stdin", ["", "\n", "  \t\n\n"], ids=["empty", "newline", "blank"])
def test_without_a_key_source_and_an_empty_stdin_login_fails_fast(stdin: str) -> None:
    assert_no_key_source_error(invoke(LOGIN, input_text=stdin))


def test_on_a_terminal_the_prompt_is_explained_first(tty: None) -> None:
    result = invoke(LOGIN, input_text=KEY + "\n")

    assert result.exit_code == 0, result.output
    assert saved_key() == KEY
    hint = login_key.KEY_PROMPT_HINT
    assert hint == "Paste the API key and press Enter; the input is hidden."
    assert result.stdout.index(hint) < result.stdout.index("Api key")
    assert KEY not in result.stdout


def test_json_mode_still_never_prompts(tty: None) -> None:
    result = invoke(LOGIN, input_text=KEY + "\n", as_json=True)

    assert result.exit_code == USAGE
    assert "missing option '--api-key'" in result.stdout


# 2) key revoke confirms -----------------------------------------------------------------------


def envelope(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data, "error": None, "meta": None}


def key_json(name: str, key_id: str = KEY_ID, **extra: Any) -> dict[str, Any]:
    base = {
        "id": key_id,
        "name": name,
        "prefix": "sf_abcd",
        "scopes": ["sandboxes:read"],
        "sandbox_labels": None,
        "max_sandboxes": None,
        "created_at": "2026-11-06T10:00:00+00:00",
        "last_used_at": None,
        "expires_at": None,
        "revoked_at": None,
        "created_by": None,
    }
    return {**base, **extra}


@pytest.fixture
def api(clean_env: None) -> Iterator[respx.MockRouter]:
    config.save_profile(BASE, "sf_profile_key_do_not_print")
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


def test_revoke_prints_id_and_sanitised_name(api: respx.MockRouter) -> None:
    body = key_json("ci\x1b[31m-bot", revoked_at=REVOKED_AT)
    api.delete(f"{KEYS_URL}/{KEY_ID}").respond(200, json=envelope(body))

    result = invoke(["key", "revoke", KEY_ID])

    assert result.exit_code == 0
    assert result.stdout.splitlines() == [f"revoked {KEY_ID} (ci-bot)"]
    assert "\x1b" not in result.stdout


def test_revoke_json_keeps_fields_and_adds_revoked_true(api: respx.MockRouter) -> None:
    body = key_json("ci", revoked_at=REVOKED_AT)
    api.delete(f"{KEYS_URL}/{KEY_ID}").respond(200, json=envelope(body))

    result = invoke(["key", "revoke", KEY_ID], as_json=True)

    payload = json.loads(result.stdout)
    assert payload["revoked"] is True
    assert payload["id"] == KEY_ID and payload["name"] == "ci"
    assert payload["revoked_at"] == REVOKED_AT and payload["status"] == "revoked"


# 3) unnamed keys ------------------------------------------------------------------------------


def test_list_all_shows_blank_and_invisible_names_as_unnamed(api: respx.MockRouter) -> None:
    keys = [
        key_json("   ", "key_blank"),
        key_json("​‍", "key_invisible", revoked_at=REVOKED_AT),
        key_json("real", "key_real"),
    ]
    api.get(KEYS_URL).respond(200, json=envelope(keys))

    text = invoke(["key", "list", "--all"])
    as_json = json.loads(invoke(["key", "list", "--all"], as_json=True).stdout)

    for key_id in ("key_blank", "key_invisible"):
        line = next(row for row in text.stdout.splitlines() if key_id in row)
        assert "(unnamed)" in line
    assert text.stdout.count("(unnamed)") == 2
    assert [item["name"] for item in as_json] == ["   ", "​‍", "real"] or all(
        "(unnamed)" not in item["name"] for item in as_json
    )


# 4) key files: first non-blank line, exactly one key line ----------------------------------------


@pytest.mark.parametrize("via_option", [True, False], ids=["option", "variable"])
@pytest.mark.parametrize(
    "content",
    ["\n\n" + KEY + "\n", "\n  \n" + KEY, "﻿\n" + KEY + "\n\n\n"],
    ids=["leading-blanks", "whitespace-line", "bom-then-blank"],
)
def test_the_first_non_blank_line_is_the_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, via_option: bool, content: str
) -> None:
    path = write_key_file(tmp_path, content)
    args = [*LOGIN, "--key-file", str(path)] if via_option else LOGIN
    if not via_option:
        monkeypatch.setenv(config.API_KEY_FILE_ENV, str(path))

    result = invoke(args)

    assert result.exit_code == 0, result.output
    assert saved_key() == KEY


@pytest.mark.parametrize("via_option", [True, False], ids=["option", "variable"])
def test_more_than_one_non_blank_line_is_refused_without_echo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, via_option: bool
) -> None:
    path = write_key_file(tmp_path, f"\n{KEY}\n# {OTHER_KEY}\n")
    args = [*LOGIN, "--key-file", str(path)] if via_option else LOGIN
    if not via_option:
        monkeypatch.setenv(config.API_KEY_FILE_ENV, str(path))

    result = invoke(args)

    label = "--key-file" if via_option else config.API_KEY_FILE_ENV
    assert result.exit_code == USAGE
    assert f"{label} must hold exactly one key line" in flat(result.stderr)
    assert KEY not in result.output and OTHER_KEY not in result.output
    assert not config.profile_path().exists()


def test_settings_refuse_a_two_line_key_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(config.API_KEY_FILE_ENV, str(write_key_file(tmp_path, f"{KEY}\nx\n")))
    monkeypatch.setenv(config.BASE_URL_ENV, BASE)

    result = invoke(["sandbox", "list"])

    assert result.exit_code == USAGE
    assert "SANDFORT_API_KEY_FILE must hold exactly one key line" in flat(result.stderr)
    assert KEY not in result.output


# 4) a piped key on stdin ----------------------------------------------------------------------


def test_a_piped_key_is_read_from_stdin_without_a_terminal() -> None:
    result = invoke(LOGIN, input_text=KEY + "\n")

    assert result.exit_code == 0, result.output
    assert saved_key() == KEY
    assert KEY not in result.output
    assert login_key.KEY_PROMPT_HINT not in result.output


@pytest.mark.parametrize(
    "stdin",
    [KEY, f"  {KEY} \t\r\n", f"\ufeff{KEY}\n", f"\n{KEY}\n\n  \n"],
    ids=["no-newline", "padded-crlf", "bom", "blank-lines-around"],
)
def test_the_piped_key_is_stripped_and_bom_tolerant(stdin: str) -> None:
    result = invoke(LOGIN, input_text=stdin)

    assert result.exit_code == 0, result.output
    assert saved_key() == KEY


def test_a_piped_key_follows_a_prompted_base_url() -> None:
    result = invoke(["login", "--no-verify"], input_text=f"{BASE}\n{KEY}\n")

    assert result.exit_code == 0, result.output
    assert saved_key() == KEY
    assert json.loads(config.profile_path().read_text())["base_url"] == BASE


@pytest.mark.parametrize("flag", [[], ["--key-stdin"]], ids=["implicit", "flag"])
def test_more_than_one_piped_line_is_refused_without_echo(flag: list[str]) -> None:
    result = invoke(LOGIN + flag, input_text=f"{KEY}\n{OTHER_KEY}\n")

    assert result.exit_code == USAGE
    assert "stdin must hold exactly one key line" in flat(result.stderr)
    assert KEY not in result.output and OTHER_KEY not in result.output
    assert not config.profile_path().exists()


def test_a_piped_key_that_is_not_text_is_the_malformed_key_error() -> None:
    result = RUNNER.invoke(create_app(None), LOGIN, input=b"sf_secret\xff\xfe\n")

    assert result.exit_code == USAGE
    assert config.MALFORMED_KEY_MESSAGE in flat(result.stderr)
    assert "sf_secret" not in result.output
    assert not config.profile_path().exists()


def test_a_piped_malformed_key_is_refused_without_echo() -> None:
    result = invoke(LOGIN, input_text="sf_a b\n")

    assert result.exit_code == USAGE
    assert "sf_a b" not in result.output
    assert not config.profile_path().exists()


def test_a_key_file_beats_stdin(tmp_path: Path) -> None:
    path = write_key_file(tmp_path, KEY + "\n")

    result = invoke(LOGIN + ["--key-file", str(path)], input_text=OTHER_KEY + "\n")

    assert result.exit_code == 0, result.output
    assert saved_key() == KEY


def test_the_environment_beats_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(config.API_KEY_ENV, KEY)

    result = invoke(LOGIN, input_text=OTHER_KEY + "\n")

    assert result.exit_code == 0, result.output
    assert saved_key() == KEY


def test_key_stdin_reads_the_key_on_a_terminal_too(tty: None) -> None:
    result = invoke(LOGIN + ["--key-stdin"], input_text=KEY + "\n")

    assert result.exit_code == 0, result.output
    assert saved_key() == KEY
    assert login_key.KEY_PROMPT_HINT not in result.output
    assert login_key.KEY_FROM_STDIN_NOTE in result.stdout
    assert KEY not in result.output


def test_key_stdin_beats_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(config.API_KEY_ENV, OTHER_KEY)

    result = invoke(LOGIN + ["--key-stdin"], input_text=KEY + "\n")

    assert result.exit_code == 0, result.output
    assert saved_key() == KEY


@pytest.mark.parametrize("stdin", ["", "\n"], ids=["empty", "newline"])
def test_key_stdin_with_nothing_on_stdin_is_the_usage_error(tty: None, stdin: str) -> None:
    result = invoke(LOGIN + ["--key-stdin"], input_text=stdin)

    assert result.exit_code == USAGE
    text = flat(result.stderr)
    assert "--key-stdin was given but stdin holds no api key" in text
    assert "--key-file" not in text  # r64: the error names the source that was asked for
    assert not config.profile_path().exists()


def test_key_stdin_with_the_api_key_flag_is_a_usage_error() -> None:
    result = invoke(LOGIN + ["--key-stdin", "--api-key", OTHER_KEY], input_text=KEY + "\n")

    assert result.exit_code == USAGE
    assert "--key-stdin" in flat(result.stderr)
    assert KEY not in result.output and OTHER_KEY not in result.output
    assert not config.profile_path().exists()


def test_key_stdin_with_a_key_file_is_a_usage_error(tmp_path: Path) -> None:
    path = write_key_file(tmp_path, OTHER_KEY + "\n")

    result = invoke(LOGIN + ["--key-stdin", "--key-file", str(path)], input_text=KEY + "\n")

    assert result.exit_code == USAGE
    assert "--key-stdin" in flat(result.stderr)
    assert not config.profile_path().exists()


def test_json_mode_reads_a_piped_key() -> None:
    result = invoke(LOGIN, input_text=KEY + "\n", as_json=True)

    assert result.exit_code == 0, result.output
    assert saved_key() == KEY
    assert KEY not in result.output


def test_json_mode_with_an_empty_stdin_is_one_json_usage_error() -> None:
    result = invoke(LOGIN, input_text="", as_json=True)

    assert result.exit_code == USAGE
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "USAGE_ERROR"
    for source in ("--key-file", "SANDFORT_API_KEY", "SANDFORT_API_KEY_FILE", "stdin"):
        assert source in error["message"]
    assert not config.profile_path().exists()


def test_login_help_documents_key_stdin() -> None:
    result = invoke(["login", "--help"])

    assert result.exit_code == 0
    assert "--key-stdin" in flat(result.output)
