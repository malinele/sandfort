"""CLI round 47: shared sanitising of server text, json completions, strict and usage errors.

* One helper sanitises every server-provided string (relayed message, server code, each missing
  scope, request id, build) before it reaches text output or the json objects.
* The json success object carries the missing scopes and request id of a limited-scope key, and
  says when userinfo was removed from the saved base url.
* ``login --require-verified`` succeeds only on a 2xx key check and saves nothing otherwise.
* An empty key, an empty base url and an unsupported scheme are usage errors (exit 2); so is a
  port outside 1-65535 (an invalid url, nothing sent; since batch 2 the whole family of
  unusable urls exits 2).
* Under ``--json`` every usage error of the CLI is one json object on stdout (exit 2).
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
from sandfort_cli.sandboxes import MAX_RELAYED_CHARS, sanitise_text  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
STATUS_URL = "/v1/status"
SANDBOXES_URL = "/v1/sandboxes"
BUILD_SHA = "4871ea2f0c9d1b3a5e7f8091a2b3c4d5e6f70812"
REQUEST_ID = "req_r47_0123456789"
STATUS_BODY = {
    "success": True,
    "data": {"status": "ok", "version": "0.1.0", "build_sha": BUILD_SHA},
    "error": None,
    "meta": None,
}
LIST_BODY = {"success": True, "data": [], "error": None, "meta": None}
RUNNER = CliRunner()
BOTH_MODES = pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])


def envelope(code: str, message: str, *, details: dict[str, Any] | None = None) -> dict[str, Any]:
    error = {
        "code": code,
        "message": message,
        "details": details or {},
        "request_id": REQUEST_ID,
    }
    return {"success": False, "data": None, "error": error, "meta": None}


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def login_args(*extra: str, base: str = BASE, key: str = KEY) -> list[str]:
    return ["login", "--base-url", base, "--api-key", key, *extra]


def failure_output(result: Any, as_json: bool) -> str:
    """Where a failed login reports: the json object on stdout, else stderr."""
    return str(result.stdout if as_json else result.stderr)


def flat(text: str) -> str:
    """``text`` without Rich box borders and line folds, for substring checks."""
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


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


# --- the shared helper -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "secret"),
    [
        ("see user:s3cret@db.internal:5432 now", "s3cret"),
        ("see //bob:pw2@host/x now", "pw2"),
        ("see //bob@host/x now", "bob"),
        ("see https://al:pw3@host/x now", "pw3"),
        ("see user:p@ss@host:80 now", "ss"),
    ],
    ids=["bare", "scheme-relative", "relative-user-only", "scheme", "at-in-password"],
)
def test_the_helper_masks_userinfo_with_and_without_a_scheme(raw: str, secret: str) -> None:
    clean = sanitise_text(raw)

    assert secret not in clean
    assert clean.startswith("see ") and clean.endswith(" now")
    assert "host" in clean or "db.internal" in clean


@pytest.mark.parametrize(
    "raw",
    [
        "write to mailto:support@example.com for help",
        "contact:ops@example.com or reply",
        "support: help@example.com.",
        "mail help@example.com today",
    ],
    ids=["mailto", "label-email", "label-space-email", "plain-email"],
)
def test_the_helper_keeps_an_email_address_unchanged(raw: str) -> None:
    assert sanitise_text(raw) == raw


@pytest.mark.parametrize(
    ("raw", "secret"),
    [
        ("see //bob:pw2@host now", "pw2"),
        ("see user:pw4@host.internal:8443 now", "pw4"),
        ("see user:pw5@host.internal/path now", "pw5"),
    ],
    ids=["scheme-relative", "bare-with-port", "bare-with-path"],
)
def test_the_helper_still_masks_an_authority_shaped_userinfo(raw: str, secret: str) -> None:
    clean = sanitise_text(raw)

    assert secret not in clean
    assert clean.startswith("see ") and clean.endswith(" now")


def test_the_helper_masks_the_callers_key_wherever_it_appears() -> None:
    clean = sanitise_text(f"key {KEY}, again {KEY}!", api_key=f"  {KEY} ")

    assert clean == "key ***, again ***!"


def test_the_helper_masks_a_key_split_by_control_characters() -> None:
    split = KEY[:5] + "\x1b]0;t\x07" + KEY[5:]

    assert sanitise_text(f"bad {split}", api_key=KEY) == "bad ***"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("a\x1b]0;title\x07b", "ab"),
        ("a\x1b]0;title\x1b\\b", "ab"),
        ("a\x9d0;title\x9cb", "ab"),
        ("a\x1b[31;1mred\x1b[0m", "ared"),
        ("a\x9b31mred", "ared"),
        ("ab\x08\x08c", "abc"),
        ("one\ntwo\r\nthree\tfour", "one two three four"),
        ("a‮b​c", "abc"),
        ("a\x00b\x7fc", "abc"),
    ],
    ids=["osc-bel", "osc-st", "osc-c1", "csi", "csi-c1", "backspace", "whitespace", "bidi", "nul"],
)
def test_the_helper_keeps_plain_printable_text_only(raw: str, expected: str) -> None:
    assert sanitise_text(raw) == expected


def test_the_helper_caps_the_length_with_an_ellipsis() -> None:
    clean = sanitise_text("y" * 5000)

    assert len(clean) == MAX_RELAYED_CHARS
    assert clean.endswith("…")
    assert sanitise_text("short") == "short"


# --- the helper on the login output ----------------------------------------------------------


@BOTH_MODES
def test_scheme_less_userinfo_in_a_relayed_message_is_masked(
    router: Any, profile_dir: Path, as_json: bool
) -> None:
    message = "retry via user:hunter2@backend.internal:8443 or //ops:pw9@edge.internal/x"
    router.get(SANDBOXES_URL).respond(500, json=envelope("INTERNAL", message))

    result = invoke(login_args("--verify-key"), as_json=as_json)

    output = failure_output(result, as_json)
    assert result.exit_code == 1
    assert "hunter2" not in output and "pw9" not in output
    assert "backend.internal" in output and "edge.internal" in output
    assert not profile_dir.exists()


@BOTH_MODES
def test_the_callers_own_key_echoed_by_the_server_is_masked(
    router: Any, profile_dir: Path, as_json: bool
) -> None:
    router.get(SANDBOXES_URL).respond(401, json=envelope("UNAUTHORIZED", f"bad key {KEY} given"))

    result = invoke(login_args("--verify-key"), as_json=as_json)

    output = failure_output(result, as_json)
    assert result.exit_code == 1
    assert KEY not in result.output
    assert "bad key *** given" in output


@BOTH_MODES
def test_escape_sequences_c1_bytes_and_newlines_in_a_message_are_removed(
    router: Any, profile_dir: Path, as_json: bool
) -> None:
    message = "denied\x1b]0;pwned title\x07 by\x1b]2;x\x1b\\ policy\x9b31mred\nsecond\x08\x08 line"
    router.get(SANDBOXES_URL).respond(401, json=envelope("UNAUTHORIZED", message))

    result = invoke(login_args("--verify-key"), as_json=as_json)

    output = failure_output(result, as_json)
    assert result.exit_code == 1
    assert "pwned" not in output
    assert all(char not in result.output for char in "\x1b\x07\x08\x9b")
    assert "denied by policy" in output and "second line" in output
    if as_json:
        assert "\n" not in json.loads(output)["error"]["message"]
    else:
        assert output.strip().count("\n") == 0


@BOTH_MODES
def test_an_overlong_relayed_message_is_capped(
    router: Any, profile_dir: Path, as_json: bool
) -> None:
    router.get(SANDBOXES_URL).respond(500, json=envelope("INTERNAL", "z" * 5000))

    result = invoke(login_args("--verify-key"), as_json=as_json)

    output = failure_output(result, as_json)
    assert result.exit_code == 1
    assert "z" * (MAX_RELAYED_CHARS + 1) not in output
    # json escapes the ellipsis, so compare the decoded message
    text = json.loads(output)["error"]["message"] if as_json else output
    assert "…" in text
    assert len(output) < 2 * MAX_RELAYED_CHARS + 400


@BOTH_MODES
def test_a_poisoned_server_code_is_masked(router: Any, profile_dir: Path, as_json: bool) -> None:
    code = f"BAD\x1b]0;t\x07CODE {KEY} user:pw7@h:80"
    router.get(SANDBOXES_URL).respond(401, json=envelope(code, "no"))

    result = invoke(login_args("--verify-key"), as_json=as_json)

    output = failure_output(result, as_json)
    assert result.exit_code == 1
    assert "BADCODE ***" in output
    assert "pw7" not in result.output and KEY not in result.output
    assert "\x1b" not in result.output
    if as_json:
        assert json.loads(output)["error"]["details"]["server_code"] == "BADCODE *** h:80"


def test_poisoned_missing_scopes_are_masked_in_text(router: Any, profile_dir: Path) -> None:
    scopes = ["sandboxes:read\x1b[31m", "u:pw8@host:80", KEY, "\x1b[2J", "ok\nscope"]
    body = envelope("FORBIDDEN", "no", details={"missing_scopes": scopes})
    router.get(SANDBOXES_URL).respond(403, json=body)

    result = invoke(login_args("--verify-key"))

    assert result.exit_code == 0, result.output
    assert "missing scope(s): sandboxes:read, host:80, ***, ok scope" in result.stdout
    assert "pw8" not in result.output and KEY not in result.output
    assert "\x1b" not in result.output


def test_poisoned_missing_scopes_and_request_id_are_masked_in_json(
    router: Any, profile_dir: Path
) -> None:
    scopes = ["sandboxes:read\x1b[31m", "u:pw8@host:80", KEY, "\x1b[2J"]
    body = envelope("FORBIDDEN", "no", details={"missing_scopes": scopes})
    body["error"]["request_id"] = f"req\x1b]0;t\x07_{KEY}"
    router.get(SANDBOXES_URL).respond(403, json=body)

    result = invoke(login_args("--verify-key"), as_json=True)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["missing_scopes"] == ["sandboxes:read", "host:80", "***"]
    assert payload["request_id"] == "req_***"
    assert KEY not in result.output and "pw8" not in result.output


def test_a_poisoned_build_in_the_status_document_is_cleaned(router: Any, profile_dir: Path) -> None:
    body = {"success": True, "data": {"build_sha": "\x1b]0;x\x07abc\ndef"}}
    router.get(STATUS_URL).respond(200, json=body)

    result = invoke(login_args())

    assert result.exit_code == 0, result.output
    assert "build abc def" in result.stdout
    assert "\x1b" not in result.output


# --- json completions ------------------------------------------------------------------------


def test_the_json_limited_scope_object_carries_the_scopes_and_request_id(
    router: Any, profile_dir: Path
) -> None:
    body = envelope("FORBIDDEN", "no", details={"missing_scopes": ["sandboxes:read", "x:y"]})
    router.get(SANDBOXES_URL).respond(403, json=body)

    result = invoke(login_args("--verify-key"), as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "profile": str(profile_dir),
        "key_verified": "limited-scope",
        "key_status": "limited-scope",
        "missing_scopes": ["sandboxes:read", "x:y"],
        "missing_scopes_beyond_cap": 0,
        "request_id": REQUEST_ID,
    }


def test_the_json_limited_scope_object_without_scopes_has_an_empty_list(
    router: Any, profile_dir: Path
) -> None:
    router.get(SANDBOXES_URL).respond(403, json=envelope("FORBIDDEN", "no"))

    payload = json.loads(invoke(login_args("--verify-key"), as_json=True).stdout)

    assert payload["missing_scopes"] == []
    assert payload["request_id"] == REQUEST_ID


def test_the_json_verified_object_is_unchanged(router: Any, profile_dir: Path) -> None:
    router.get(SANDBOXES_URL).respond(200, json=LIST_BODY)

    result = invoke(login_args("--verify-key"), as_json=True)

    assert json.loads(result.stdout) == {
        "profile": str(profile_dir),
        "key_verified": True,
        "key_status": "verified",
    }


def test_the_json_object_says_when_userinfo_was_removed(router: Any, profile_dir: Path) -> None:
    result = invoke(login_args(base="http://user:pw@sandfort.test"), as_json=True)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["userinfo_removed"] is True
    assert payload["key_status"] == "not-checked"
    assert json.loads(profile_dir.read_text())["base_url"] == BASE


def test_the_json_object_has_no_userinfo_field_for_a_clean_url(
    router: Any, profile_dir: Path
) -> None:
    payload = json.loads(invoke(login_args(), as_json=True).stdout)

    assert "userinfo_removed" not in payload


# --- --require-verified ----------------------------------------------------------------------


def test_require_verified_succeeds_on_a_2xx_check(router: Any, profile_dir: Path) -> None:
    check = router.get(SANDBOXES_URL).respond(200, json=LIST_BODY)

    result = invoke(login_args("--require-verified"))

    assert result.exit_code == 0, result.output
    assert check.call_count == 1
    assert "api key: verified" in result.stdout and "Logged in" in result.stdout
    assert json.loads(profile_dir.read_text()) == {"base_url": BASE, "api_key": KEY}


def test_require_verified_in_json_reports_verified(router: Any, profile_dir: Path) -> None:
    router.get(SANDBOXES_URL).respond(200, json=LIST_BODY)

    result = invoke(login_args("--require-verified"), as_json=True)

    assert json.loads(result.stdout)["key_status"] == "verified"
    assert profile_dir.exists()


def test_require_verified_may_be_given_with_verify_key(router: Any, profile_dir: Path) -> None:
    router.get(SANDBOXES_URL).respond(200, json=LIST_BODY)

    for order in (["--verify-key", "--require-verified"], ["--require-verified", "--verify-key"]):
        assert invoke(login_args(*order)).exit_code == 0


@BOTH_MODES
@pytest.mark.parametrize(
    ("status", "reply", "expected"),
    [
        (403, {"json": envelope("FORBIDDEN", "no", details={"missing_scopes": ["a:b"]})}, "a:b"),
        (403, {"text": "<html>Forbidden by proxy</html>"}, "did not come from the server"),
        (401, {"json": envelope("UNAUTHORIZED", "invalid api key")}, "rejected the api key"),
        (500, {"json": envelope("INTERNAL", "boom")}, "could not verify"),
    ],
    ids=["limited-scope", "non-envelope-403", "401", "500"],
)
def test_require_verified_fails_without_saving_on_any_other_outcome(
    router: Any,
    profile_dir: Path,
    as_json: bool,
    status: int,
    reply: dict[str, Any],
    expected: str,
) -> None:
    router.get(SANDBOXES_URL).respond(status, **reply)

    result = invoke(login_args("--require-verified"), as_json=as_json)

    output = failure_output(result, as_json)
    assert result.exit_code == 1
    assert expected in output
    assert not profile_dir.exists()
    assert "Logged in" not in result.output


@BOTH_MODES
def test_require_verified_names_the_unverified_outcome_for_a_403(
    router: Any, profile_dir: Path, as_json: bool
) -> None:
    body = envelope("FORBIDDEN", "no", details={"missing_scopes": ["sandboxes:read"]})
    router.get(SANDBOXES_URL).respond(403, json=body)

    result = invoke(login_args("--require-verified"), as_json=as_json)

    output = failure_output(result, as_json)
    assert "--require-verified" in output and "was not saved" in output
    assert REQUEST_ID in output
    if as_json:
        error = json.loads(output)["error"]
        assert error["details"]["key_status"] == "limited-scope"
        assert error["details"]["missing_scopes"] == ["sandboxes:read"]
        assert error["request_id"] == REQUEST_ID


def test_require_verified_with_an_unreachable_check_saves_nothing(
    router: Any, profile_dir: Path
) -> None:
    router.get(SANDBOXES_URL).mock(side_effect=httpx.ConnectError("refused"))

    result = invoke(login_args("--require-verified"))

    assert result.exit_code == 1
    assert not profile_dir.exists()


@pytest.mark.parametrize(
    "order",
    [["--require-verified", "--no-verify"], ["--no-verify", "--require-verified"]],
    ids=["flag-first", "no-verify-first"],
)
def test_require_verified_with_no_verify_is_a_usage_error(
    router: Any, profile_dir: Path, order: list[str]
) -> None:
    result = invoke(login_args(*order))

    assert result.exit_code == 2
    assert "cannot be combined with --no-verify" in flat(result.stderr)
    assert "--require-verified" in flat(result.stderr)
    assert router.calls.call_count == 0
    assert not profile_dir.exists()


def test_require_verified_with_no_verify_is_a_json_usage_error(
    router: Any, profile_dir: Path
) -> None:
    result = invoke(login_args("--require-verified", "--no-verify"), as_json=True)

    assert result.exit_code == 2
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "USAGE_ERROR"
    assert "cannot be combined with --no-verify" in error["message"]
    assert result.stderr == ""
    assert router.calls.call_count == 0


def test_verify_key_with_no_verify_is_still_a_usage_error(router: Any) -> None:
    result = invoke(login_args("--verify-key", "--no-verify"))

    assert result.exit_code == 2
    assert "--verify-key" in flat(result.stderr)


def test_a_non_envelope_403_no_longer_leads_with_logged_in(router: Any, profile_dir: Path) -> None:
    router.get(SANDBOXES_URL).respond(403, text="<html>Forbidden by proxy</html>")

    result = invoke(login_args("--verify-key"))

    assert result.exit_code == 0, result.output
    assert "NOT verified" in result.stdout
    assert "Logged in" not in result.stdout
    assert f"Profile saved to {profile_dir}" in result.stdout
    assert "not verified" in result.stdout.splitlines()[-1]
    assert profile_dir.exists()


def test_a_limited_scope_key_still_reports_logged_in(router: Any, profile_dir: Path) -> None:
    router.get(SANDBOXES_URL).respond(403, json=envelope("FORBIDDEN", "no"))

    result = invoke(login_args("--verify-key"))

    assert "Logged in; profile saved to" in result.stdout


# --- error-code consistency inside login -----------------------------------------------------


@BOTH_MODES
@pytest.mark.parametrize("key", ["", "   "], ids=["empty", "blank"])
def test_an_empty_api_key_is_a_usage_error(
    router: Any, profile_dir: Path, as_json: bool, key: str
) -> None:
    result = invoke(login_args(key=key), as_json=as_json)

    assert result.exit_code == 2
    assert router.calls.call_count == 0
    assert not profile_dir.exists()
    if as_json:
        error = json.loads(result.stdout)["error"]
        assert error["code"] == "USAGE_ERROR" and error["source"] == "client"
        assert "--api-key" in error["message"] and "must not be empty" in error["message"]
        assert result.stderr == ""
    else:
        assert "must not be empty" in flat(result.stderr) and "--api-key" in result.stderr


@BOTH_MODES
@pytest.mark.parametrize("url", ["", "   "], ids=["empty", "blank"])
def test_an_empty_base_url_is_a_usage_error(
    router: Any, profile_dir: Path, as_json: bool, url: str
) -> None:
    result = invoke(login_args(base=url), as_json=as_json)

    assert result.exit_code == 2
    assert router.calls.call_count == 0
    assert not profile_dir.exists()
    if as_json:
        error = json.loads(result.stdout)["error"]
        assert error["code"] == "USAGE_ERROR"
        assert "--base-url" in error["message"] and "must not be empty" in error["message"]
    else:
        assert "must not be empty" in flat(result.stderr) and "--base-url" in result.stderr


@BOTH_MODES
@pytest.mark.parametrize(
    "url",
    ["ftp://sandfort.test", "sandfort.test:8080", "ws://sandfort.test", "file:///etc"],
    ids=["ftp", "no-scheme", "ws", "file"],
)
def test_an_unsupported_scheme_is_a_usage_error_with_the_documented_wording(
    router: Any, profile_dir: Path, as_json: bool, url: str
) -> None:
    result = invoke(login_args(base=url), as_json=as_json)

    assert result.exit_code == 2
    assert router.calls.call_count == 0
    assert not profile_dir.exists()
    if as_json:
        error = json.loads(result.stdout)["error"]
        assert error["code"] == "USAGE_ERROR"
        message = error["message"]
    else:
        message = flat(result.stderr)
    assert "is not a valid url" in message
    assert "nothing was sent" in message
    assert "http:// or https://" in message


@BOTH_MODES
def test_an_unsupported_scheme_echo_hides_userinfo(
    router: Any, profile_dir: Path, as_json: bool
) -> None:
    result = invoke(login_args(base="ftp://user:pw5@sandfort.test"), as_json=as_json)

    assert result.exit_code == 2
    assert "pw5" not in result.output


@BOTH_MODES
@pytest.mark.parametrize(
    "url",
    [
        "http://sandfort.test:70000",
        "http://sandfort.test:65536",
        "http://sandfort.test:0",
        "https://sandfort.test:000070000/x",
        "http://[::1]:99999",
        "http://user:pw6@sandfort.test:99999",
    ],
    ids=["70000", "65536", "zero", "leading-zeros", "ipv6", "userinfo"],
)
def test_a_port_out_of_range_is_an_invalid_url_and_nothing_is_sent(
    router: Any, profile_dir: Path, as_json: bool, url: str
) -> None:
    result = invoke(login_args(base=url), as_json=as_json)

    output = failure_output(result, as_json)
    assert result.exit_code == 2
    assert router.calls.call_count == 0
    assert not profile_dir.exists()
    assert "is not a valid url" in flat(output) and "port out of range" in flat(output)
    assert "did not answer" not in output and "pw6" not in output
    if as_json:
        error = json.loads(output)["error"]
        assert error["source"] == "client" and error["code"] == "USAGE_ERROR"


@pytest.mark.parametrize("url", ["http://sandfort.test:65535", "http://sandfort.test:1/"])
def test_the_edges_of_the_port_range_are_accepted(router: Any, profile_dir: Path, url: str) -> None:
    result = invoke(login_args("--no-verify", base=url))

    assert result.exit_code == 0, result.output
    assert profile_dir.exists()


def test_the_port_check_also_applies_without_the_status_probe(
    router: Any, profile_dir: Path
) -> None:
    result = invoke(login_args("--no-verify", base="http://sandfort.test:70000"))

    assert result.exit_code == 2
    assert not profile_dir.exists()


# --- usage errors anywhere in the CLI under --json ---------------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        ["sandbox", "list", "--order", "sideways"],
        ["sandbox", "create", "demo", "--cpu-millicores", "abc"],
        ["sandbox", "create", "demo", "--wait-timeout", "5"],
        ["sandbox", "get"],
        ["sandbox", "nope"],
        ["nope"],
        ["login", "--bogus"],
    ],
    ids=[
        "bad-enum",
        "bad-int",
        "body-check",
        "missing-arg",
        "no-subcommand",
        "no-command",
        "option",
    ],
)
def test_a_usage_error_anywhere_is_one_json_object_under_json(args: list[str]) -> None:
    result = invoke(args, as_json=True)

    assert result.exit_code == 2
    assert result.stderr == ""
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "USAGE_ERROR"
    assert error["source"] == "client"
    assert error["message"]
    assert "Usage:" not in result.stdout


def test_the_json_usage_error_names_the_bad_value() -> None:
    result = invoke(["sandbox", "list", "--order", "sideways"], as_json=True)

    message = json.loads(result.stdout)["error"]["message"]
    assert "--order" in message and "sideways" in message


def test_a_root_option_error_is_json_when_json_leads() -> None:
    result = RUNNER.invoke(create_app(None), ["--json", "--bogus"])

    assert result.exit_code == 2
    assert result.stderr == ""
    assert json.loads(result.stdout)["error"]["code"] == "USAGE_ERROR"


@pytest.mark.parametrize(
    "args",
    [
        ["sandbox", "list", "--order", "sideways"],
        ["sandbox", "create", "demo", "--cpu-millicores", "abc"],
        ["sandbox", "nope"],
        ["login", "--bogus"],
    ],
    ids=["bad-enum", "bad-int", "no-subcommand", "option"],
)
def test_text_mode_keeps_the_usage_box_on_stderr(args: list[str]) -> None:
    result = invoke(args)

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "Usage:" in result.stderr and "Error" in result.stderr


def test_the_json_usage_error_message_is_sanitised(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(config.API_KEY_ENV, KEY)

    result = invoke(["sandbox", "list", "--order", f"{KEY}\x1b]0;t\x07"], as_json=True)

    assert result.exit_code == 2
    assert KEY not in result.output and "\x1b" not in result.output


def test_a_group_without_arguments_is_a_json_usage_object_under_json() -> None:
    result = invoke(["sandbox"], as_json=True)

    assert result.exit_code == 2
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "USAGE_ERROR" and "text mode" in error["message"]
    assert "Usage:" not in result.output


def test_a_group_without_arguments_still_shows_its_help_in_text_mode() -> None:
    result = invoke(["sandbox"])

    assert "Usage:" in result.output
    assert "USAGE_ERROR" not in result.output


def test_a_successful_command_under_json_is_unaffected() -> None:
    result = invoke(["version"], as_json=True)

    assert result.exit_code == 0
    assert set(json.loads(result.stdout)) == {"cli", "sdk"}


def test_a_non_usage_error_under_json_is_not_reformatted_as_a_usage_error(
    router: Any, profile_dir: Path
) -> None:
    body = envelope("FORBIDDEN", "no", details={"missing_scopes": ["sandboxes:read"]})
    router.get(SANDBOXES_URL).respond(403, json=body)

    result = invoke(login_args("--require-verified"), as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == 1
    assert error["code"] != "USAGE_ERROR"
    assert error["code"] == "CLI_ERROR"
    assert error.get("source") != "client"
    assert not profile_dir.exists()


@BOTH_MODES
def test_a_plain_email_in_a_relayed_message_survives_the_sanitiser(
    router: Any, profile_dir: Path, as_json: bool
) -> None:
    message = "quota exceeded, write to mailto:support@example.com or admin@example.com"
    router.get(SANDBOXES_URL).respond(500, json=envelope("INTERNAL", message))

    result = invoke(login_args("--verify-key"), as_json=as_json)

    output = failure_output(result, as_json)
    assert result.exit_code == 1
    assert "mailto:support@example.com" in output
    assert "admin@example.com" in output


# --- key-shape masking has a left boundary ---------------------------------------------------

LONG_KEY_TAIL = "abcdefghijklmnopqrstuvwx"


@pytest.mark.parametrize(
    "identifier",
    [f"xsf_{LONG_KEY_TAIL}", f"build9sf_{LONG_KEY_TAIL}", f"Asf_{LONG_KEY_TAIL}_tail"],
    ids=["letter-before", "digit-before", "capital-before"],
)
def test_key_shape_masking_leaves_an_identifier_that_only_contains_the_prefix(
    identifier: str,
) -> None:
    assert sanitise_text(f"see {identifier} here") == f"see {identifier} here"


@pytest.mark.parametrize(
    "text",
    [
        f"sf_{LONG_KEY_TAIL}",
        f"token=sf_{LONG_KEY_TAIL}",
        f"(sf_{LONG_KEY_TAIL})",
        f"_sf_{LONG_KEY_TAIL}",
        f"-sf_{LONG_KEY_TAIL}",
    ],
    ids=["bare", "after-equals", "after-paren", "after-underscore", "after-hyphen"],
)
def test_key_shape_masking_still_masks_a_token_not_preceded_by_an_alphanumeric(
    text: str,
) -> None:
    assert LONG_KEY_TAIL not in sanitise_text(text)


# --- a profile nested too deeply to parse ----------------------------------------------------

PROFILE_NESTING_DEPTH = 200_000


def test_a_deeply_nested_profile_is_an_unreadable_profile_not_a_traceback(
    router: Any, profile_dir: Path
) -> None:
    profile_dir.parent.mkdir(parents=True, exist_ok=True)
    profile_dir.write_text("[" * PROFILE_NESTING_DEPTH + "]" * PROFILE_NESTING_DEPTH)

    result = invoke(["sandbox", "list"], as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == 1, result.output
    assert error["source"] == "client"
    assert error["message"].startswith(f"profile {profile_dir} is unreadable")
    assert "Traceback" not in result.output
    assert router.calls.call_count == 0
