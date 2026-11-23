"""CLI round 48, batch 2: usage-error and advice consistency.

* Under ``--require-verified`` no failure advice names ``--verify-key`` or ``--no-verify``.
* A bad ``--expires-at`` and a bad ``KEY=VALUE`` pair are usage errors (exit 2).
* Every locally detected unusable base url is one usage error (exit 2, nothing sent), also on
  the ``--no-verify`` path, and a port that is not a number is caught up front, as are
  malformed brackets, whitespace in the host and any url the local parsers refuse.
* A trailing ``--json`` gets a placement hint unless ``--json`` was also given before the
  command; a command group without arguments is one json usage object under ``--json`` (text
  mode still prints its help).
* ``--wait-timeout 0`` without ``--wait`` reports both problems in one message.
"""

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
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
STATUS_URL = "/v1/status"
SANDBOXES_URL = "/v1/sandboxes"
BUILD_SHA = "4871ea2f0c9d1b3a5e7f8091a2b3c4d5e6f70812"
STATUS_BODY = {
    "success": True,
    "data": {"status": "ok", "version": "0.1.0", "build_sha": BUILD_SHA},
    "error": None,
    "meta": None,
}
RUNNER = CliRunner()
BOTH_MODES = pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
STRICT = "--require-verified"
FORBIDDEN_ADVICE = ("--verify-key", "--no-verify")


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def login_args(*extra: str, base: str = BASE, key: str = KEY) -> list[str]:
    return ["login", "--base-url", base, "--api-key", key, *extra]


def flat(text: str) -> str:
    """``text`` without Rich box borders and line folds, for substring checks."""
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


def failure_message(result: Any, as_json: bool) -> str:
    """The failure text: the json error message on stdout, else the flattened stderr."""
    if as_json:
        return str(json.loads(result.stdout)["error"]["message"])
    return flat(str(result.stderr))


def usage_error(result: Any) -> dict[str, Any]:
    """Assert ``result`` is one json usage-error object (exit 2, nothing on stderr)."""
    assert result.exit_code == 2, result.output
    assert result.stderr == ""
    error: dict[str, Any] = json.loads(result.stdout)["error"]
    assert error["code"] == "USAGE_ERROR" and error["source"] == "client"
    return error


@pytest.fixture(autouse=True)
def profile_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    return tmp_path / "cfg" / config.PROFILE_FILENAME


@pytest.fixture
def router() -> Iterator[Any]:
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        mock.get(STATUS_URL).respond(200, json=STATUS_BODY)
        yield mock


# 1) strict-flag advice -----------------------------------------------------------------------


def assert_no_forbidden_advice(text: str) -> None:
    for flag in FORBIDDEN_ADVICE:
        assert flag not in text, f"{flag!r} named in: {text}"


@BOTH_MODES
@pytest.mark.parametrize(
    ("status", "advice"),
    [
        (500, "retry"),
        (503, "retry"),
        (429, "retry"),
        (404, "check the base url"),
        (302, "redirects"),
    ],
)
def test_strict_key_check_failures_never_name_the_unrelated_flags(
    router: Any, profile_dir: Path, as_json: bool, status: int, advice: str
) -> None:
    router.get(SANDBOXES_URL).respond(status, headers={"location": f"{BASE}/x"}, json={})

    result = invoke(login_args(STRICT), as_json=as_json)

    message = failure_message(result, as_json)
    assert result.exit_code == 1
    assert advice in message
    assert_no_forbidden_advice(message)
    assert f"drop {STRICT}" in message
    assert not profile_dir.exists()


@BOTH_MODES
def test_strict_key_check_with_a_dropped_connection_says_retry(
    router: Any, profile_dir: Path, as_json: bool
) -> None:
    router.get(SANDBOXES_URL).mock(side_effect=httpx.ConnectError("boom"))

    result = invoke(login_args(STRICT), as_json=as_json)

    message = failure_message(result, as_json)
    assert result.exit_code == 1
    assert "retry" in message
    assert_no_forbidden_advice(message)


@BOTH_MODES
def test_strict_dead_url_hint_does_not_suggest_no_verify(
    router: Any, profile_dir: Path, as_json: bool
) -> None:
    router.get(STATUS_URL).mock(side_effect=httpx.ConnectError("refused"))

    result = invoke(login_args(STRICT), as_json=as_json)

    message = failure_message(result, as_json)
    assert result.exit_code == 1
    assert "did not answer" in message and "check the url and retry" in message
    assert_no_forbidden_advice(message)


@BOTH_MODES
def test_strict_redirecting_status_hint_does_not_suggest_no_verify(
    router: Any, profile_dir: Path, as_json: bool
) -> None:
    router.get(STATUS_URL).respond(301, headers={"location": "https://sandfort.test/v1/status"})

    result = invoke(login_args(STRICT), as_json=as_json)

    message = failure_message(result, as_json)
    assert result.exit_code == 1
    assert "redirects are not followed" in message
    assert_no_forbidden_advice(message)


def test_strict_with_verify_key_given_too_still_never_names_the_flags(router: Any) -> None:
    router.get(SANDBOXES_URL).respond(500, json={})

    result = invoke(login_args(STRICT, "--verify-key"))

    assert result.exit_code == 1
    assert_no_forbidden_advice(flat(result.stderr))


def test_without_the_strict_flag_the_advice_is_unchanged(router: Any) -> None:
    router.get(SANDBOXES_URL).respond(500, json={})
    failed_check = invoke(login_args("--verify-key"))
    router.get(STATUS_URL).mock(side_effect=httpx.ConnectError("refused"))
    unreachable = invoke(login_args())

    assert "retry or login without --verify-key" in flat(failed_check.stderr)
    assert "use --no-verify to save it unchecked" in flat(unreachable.stderr)


# 2) bad expires-at and bad pair are usage errors ---------------------------------------------

BAD_INPUT_COMMANDS = {
    "expires-not-a-date": ["key", "create", "ci", "-s", "x", "--expires-at", "not-a-date"],
    "expires-naive": ["key", "create", "ci", "-s", "x", "--expires-at", "2027-01-01T00:00:00"],
    "key-label": ["key", "create", "ci", "-s", "x", "--label", "NOEQUALS"],
    "key-label-no-name": ["key", "create", "ci", "-s", "x", "--label", "=v"],
    "sandbox-label": ["sandbox", "create", "demo", "--label", "NOEQUALS"],
    "sandbox-env": ["sandbox", "create", "demo", "--env", "NOEQUALS"],
}


@pytest.mark.parametrize("args", list(BAD_INPUT_COMMANDS.values()), ids=list(BAD_INPUT_COMMANDS))
def test_bad_local_input_is_one_json_usage_error(router: Any, args: list[str]) -> None:
    result = invoke(args, as_json=True)

    error = usage_error(result)
    assert error["message"]
    assert router.calls.call_count == 0


@pytest.mark.parametrize("args", list(BAD_INPUT_COMMANDS.values()), ids=list(BAD_INPUT_COMMANDS))
def test_bad_local_input_is_a_usage_error_in_text_mode(router: Any, args: list[str]) -> None:
    result = invoke(args)

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "Usage:" in result.stderr
    assert router.calls.call_count == 0


def test_the_bad_expiry_and_pair_messages_name_the_option_and_value() -> None:
    expiry = usage_error(invoke(BAD_INPUT_COMMANDS["expires-not-a-date"], as_json=True))
    naive = usage_error(invoke(BAD_INPUT_COMMANDS["expires-naive"], as_json=True))
    label = usage_error(invoke(BAD_INPUT_COMMANDS["sandbox-label"], as_json=True))

    assert "--expires-at" in expiry["message"] and "ISO 8601" in expiry["message"]
    assert "--expires-at" in naive["message"] and "timezone" in naive["message"]
    assert "--label" in label["message"] and "expected KEY=VALUE" in label["message"]


# 3) the bad-url family is one usage error ----------------------------------------------------

BAD_URLS = {
    "bare-scheme": "http://",
    "triple-slash": "https:///",
    "user-only": "http://user@",
    "bare-port": "http://:80",
    "letters": "http://sandfort.test:abc",
    "non-ascii-digit": "http://sandfort.test:²",
    "too-high": "http://sandfort.test:70000",
    "zero": "http://sandfort.test:0",
    "negative": "http://sandfort.test:-1",
    "ipv6-high": "http://[::1]:99999",
    "ipv6-letters": "http://[::1]:x",
    "userinfo-secret": "http://user:pw7@sandfort.test:-9",
    "ipv6-unclosed": "http://[::1",
    "ipv6-text-after": "http://[::1]x",
    "ipv6-not-an-address": "http://[zz]",
    "stray-bracket": "http://sandfort.test]",
    "space-in-host": "http://sandfort .test",
    "tab-in-host": "http://sand\tfort.test",
    "control-in-path": "http://sandfort.test/a\x1bb",
    "userinfo-bracket": "http://user:pw7@[::1",
}


@BOTH_MODES
@pytest.mark.parametrize("extra", [(), ("--no-verify",)], ids=["verify", "no-verify"])
@pytest.mark.parametrize("url", list(BAD_URLS.values()), ids=list(BAD_URLS))
def test_every_unusable_url_is_a_usage_error_and_nothing_is_sent(
    router: Any, profile_dir: Path, as_json: bool, extra: tuple[str, ...], url: str
) -> None:
    result = invoke(login_args(*extra, base=url), as_json=as_json)

    assert result.exit_code == 2, result.output
    assert router.calls.call_count == 0
    assert not profile_dir.exists()
    message = failure_message(result, as_json)
    assert "is not a valid url" in message and "nothing was sent" in message
    assert "did not answer" not in message and "pw7" not in result.output
    if as_json:
        usage_error(result)


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://user@", "no host"),
        ("http://", "no host"),
        ("http://sandfort.test:abc", "invalid port"),
        ("http://sandfort.test:70000", "port out of range"),
        ("http://sandfort.test:-1", "port out of range"),
        ("http://[::1", "malformed brackets in the host"),
        ("http://[::1]x", "malformed brackets in the host"),
        ("http://sandfort .test", "whitespace or a control character in the host"),
        ("http://sand\tfort.test", "whitespace or a control character in the host"),
        ("http://[zz]", "the url cannot be parsed"),
        ("http://sandfort.test/a\x1bb", "a control character in the url"),
    ],
)
def test_the_usage_error_names_the_reason(url: str, reason: str) -> None:
    error = usage_error(invoke(login_args("--no-verify", base=url), as_json=True))

    assert f"({reason}" in error["message"] and "--base-url" in error["message"]


# 6) the no-verify path rejects a non-numeric port --------------------------------------------


def test_no_verify_does_not_save_a_url_with_a_non_numeric_port(
    router: Any, profile_dir: Path
) -> None:
    result = invoke(login_args("--no-verify", base="http://sandfort.test:80a"))

    assert result.exit_code == 2
    assert "invalid port" in flat(result.stderr)
    assert not profile_dir.exists()


@pytest.mark.parametrize("url", ["http://sandfort.test:8080", "http://sandfort.test:", BASE])
def test_no_verify_still_saves_a_well_formed_url(router: Any, profile_dir: Path, url: str) -> None:
    result = invoke(login_args("--no-verify", base=url))

    assert result.exit_code == 0, result.output
    assert profile_dir.exists()


# 4) a trailing --json flag -------------------------------------------------------------------

TRAILING_JSON = {
    "list": ["sandbox", "list", "--json"],
    "version": ["version", "--json"],
    "group": ["sandbox", "--json"],
    "key-list": ["key", "list", "--json"],
}


@pytest.mark.parametrize("args", list(TRAILING_JSON.values()), ids=list(TRAILING_JSON))
def test_a_trailing_json_flag_gets_a_placement_hint_in_text(args: list[str]) -> None:
    result = invoke(args)

    message = flat(result.stderr)
    assert result.exit_code == 2
    assert "No such option" in message and "--json" in message
    assert "global option" in message and "before the command" in message


@pytest.mark.parametrize("args", list(TRAILING_JSON.values()), ids=list(TRAILING_JSON))
def test_a_trailing_json_flag_also_given_before_the_command_gets_no_placement_hint(
    args: list[str],
) -> None:
    error = usage_error(invoke(args, as_json=True))

    assert "No such option" in error["message"] and "--json" in error["message"]
    assert "global option" not in error["message"]
    assert "before the command" not in error["message"]


@pytest.mark.parametrize("flag", ["--jsn", "--bogus", "--json-output"])
def test_other_unknown_options_get_no_placement_hint(flag: str) -> None:
    text = invoke(["sandbox", "list", flag])
    structured = usage_error(invoke(["sandbox", "list", flag], as_json=True))

    assert text.exit_code == 2
    assert "global option" not in flat(text.stderr)
    assert "global option" not in structured["message"]


# 5) a group without arguments under --json ---------------------------------------------------


@pytest.mark.parametrize("group", ["sandbox", "key", "snapshot", "volume"])
def test_a_group_without_arguments_is_one_json_usage_object_under_json(group: str) -> None:
    result = invoke([group], as_json=True)

    error = usage_error(result)
    assert "text mode" in error["message"] and group in error["message"]
    assert "Usage:" not in result.stdout


@pytest.mark.parametrize("group", ["sandbox", "key", "snapshot", "volume"])
def test_a_group_without_arguments_still_prints_its_help_in_text_mode(group: str) -> None:
    result = invoke([group])

    assert result.exit_code == 2
    assert "Usage:" in result.output
    assert "USAGE_ERROR" not in result.output


# 7) --wait-timeout: both problems in one message ---------------------------------------------


@BOTH_MODES
@pytest.mark.parametrize("value", ["0", "-1", "nan"])
def test_a_zero_wait_timeout_without_wait_reports_both_problems(
    router: Any, as_json: bool, value: str
) -> None:
    result = invoke(["sandbox", "create", "demo", "--wait-timeout", value], as_json=as_json)

    assert result.exit_code == 2
    message = failure_message(result, as_json)
    assert "requires --wait" in message and "greater than 0" in message
    assert router.calls.call_count == 0


def test_the_start_command_reports_both_problems_too(router: Any) -> None:
    result = invoke(["sandbox", "start", "sbx_1", "--wait-timeout", "0"], as_json=True)

    error = usage_error(result)
    assert "requires --wait" in error["message"] and "greater than 0" in error["message"]


def test_a_single_wait_timeout_problem_keeps_its_own_message() -> None:
    missing_wait = usage_error(
        invoke(["sandbox", "create", "demo", "--wait-timeout", "5"], as_json=True)
    )
    bad_range = usage_error(
        invoke(["sandbox", "create", "demo", "--wait", "--wait-timeout", "0"], as_json=True)
    )

    assert "requires --wait" in missing_wait["message"]
    assert "greater than 0" not in missing_wait["message"]
    assert "greater than 0" in bad_range["message"]
    assert "requires --wait" not in bad_range["message"]
