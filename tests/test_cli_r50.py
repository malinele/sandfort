"""CLI round 50, batch 1: the text sanitiser protects every command, not only login.

* The sanitiser lives in ``sandfort_cli.sanitise``; ``sandfort_cli.sandboxes`` still exports the
  names it exported before the move.
* The shared error presentation (text line and json object) masks, strips and caps what the
  server says on every command: message, code, details values, request id and hints.
* Typer's own text-mode usage errors (extra argument, unknown command, unknown option) echo what
  was typed through the sanitiser, so a key given by mistake is masked like it is under ``--json``.
* The caller's key is masked in its percent-encoded forms too, in the label, env, extra-argument
  and unknown-command echoes, also when it comes from the stored profile.
* The exit codes are unchanged: the remote exit code of ``exec``, 124, 125, 2 and 1.
"""

import json
import re
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config, sandboxes, sanitise  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.output import clean_hint, error_payload, relay_value  # noqa: E402
from sandfort_cli.sanitise import (  # noqa: E402
    ELLIPSIS,
    MASK,
    MAX_RELAYED_CHARS,
    MAX_RELAYED_ENTRIES,
    USAGE_MESSAGE_CHARS,
    caller_key,
    percent_encode_fully,
    sanitise_text,
    scrub_local,
)
from sandfort_sdk import InternalError  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
# Shorter than a key-shaped token: only the caller's own key lookup can mask it.
SHORT_KEY = "sf_short1"
# Key-shaped (prefix plus 16 or more characters) but not the caller's key.
FOREIGN = "sf_foreign9b7c3e1d5a0f2468ace"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOXES_URL = "/v1/sandboxes"
SANDBOX_URL = f"{SANDBOXES_URL}/{SID}"
EXEC_URL = f"{SANDBOX_URL}/toolbox/process/execute"
OSC = "\x1b]0;pwned-title\x07"
CSI = "\x1b[31m"
CRED_URL = "https://admin:hunter2pw@evil.test/path?token=abc123tok"
HUGE = 100_000
PLATFORM_ERROR_EXIT = 125
TIMED_OUT_EXIT = 124
RUNNER = CliRunner()
BOTH_MODES = pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
LEAKS = ("\x1b", "pwned-title", "hunter2pw", "abc123tok", KEY, FOREIGN)


def error_body(
    code: str, message: str, details: dict[str, Any] | None = None, request_id: str | None = None
) -> dict[str, Any]:
    error = {"code": code, "message": message, "details": details or {}, "request_id": request_id}
    return {"success": False, "data": None, "error": error, "meta": None}


def hostile_envelope() -> dict[str, Any]:
    """An error envelope whose every field carries something that must not be printed."""
    message = f"{OSC}boom {CRED_URL} key={KEY} other={FOREIGN} " + "x" * HUGE
    details = {
        "note": f"{OSC}{CRED_URL}",
        "caller": KEY,
        "tokens": [FOREIGN, 7],
        "big": "y" * HUGE,
        "count": 5,
    }
    return error_body(f"BAD{CSI}_CODE", message, details, f"req_{CSI}0123")


def sandbox_body() -> dict[str, Any]:
    data = {
        "id": SID,
        "name": "demo",
        "state": "started",
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
    }
    return {"success": True, "data": data, "error": None, "meta": None}


def exec_body(exit_code: int, *, timed_out: bool = False) -> dict[str, Any]:
    data = {
        "exit_code": exit_code,
        "stdout": "out\n",
        "stderr": "err\n",
        "timed_out": timed_out,
        "truncated": False,
        "duration_ms": 3,
    }
    return {"success": True, "data": data, "error": None, "meta": None}


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def flat(text: str) -> str:
    """``text`` without Rich box borders and line folds, for substring checks."""
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


def logged_in(key: str = KEY) -> None:
    config.save_profile(BASE, key)


@pytest.fixture(autouse=True)
def isolated_profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)


@pytest.fixture
def api() -> Iterator[Any]:
    logged_in()
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        yield router


def with_sandbox(router: Any) -> None:
    """The sandbox fetch that ``exec`` makes before it runs the command."""
    router.get(SANDBOX_URL).respond(200, json=sandbox_body())


def assert_clean(text: str) -> None:
    for leak in LEAKS:
        assert leak not in text, leak


# 1) the module move changes nothing for existing importers -------------------------------------


def test_the_sandboxes_module_still_exports_the_moved_names() -> None:
    assert sandboxes.sanitise_text is sanitise.sanitise_text
    assert sandboxes.MASK == sanitise.MASK
    assert sandboxes.echo_url is sanitise.echo_url
    assert sandboxes.USERINFO_ANYWHERE_RE is sanitise.USERINFO_ANYWHERE_RE


def test_a_login_style_cut_still_ends_in_the_ellipsis() -> None:
    shown = sanitise_text("z" * HUGE)

    assert len(shown) == MAX_RELAYED_CHARS
    assert shown.endswith(ELLIPSIS)


# 2) a hostile error on commands other than login ------------------------------------------------

HOSTILE_COMMANDS = [
    pytest.param("GET", SANDBOXES_URL, 500, ["sandbox", "list"], 1, id="list-500"),
    pytest.param("GET", SANDBOXES_URL, 401, ["sandbox", "list"], 1, id="list-401"),
    pytest.param("GET", SANDBOX_URL, 500, ["sandbox", "get", SID], 1, id="get-500"),
    pytest.param("GET", SANDBOX_URL, 401, ["sandbox", "get", SID], 1, id="get-401"),
    pytest.param("POST", EXEC_URL, 500, ["exec", SID, "true"], PLATFORM_ERROR_EXIT, id="exec-500"),
    pytest.param("POST", EXEC_URL, 401, ["exec", SID, "true"], PLATFORM_ERROR_EXIT, id="exec-401"),
]


@BOTH_MODES
@pytest.mark.parametrize(("verb", "url", "status", "args", "exit_code"), HOSTILE_COMMANDS)
def test_a_hostile_envelope_is_masked_stripped_and_capped_on_every_command(
    api: Any, as_json: bool, verb: str, url: str, status: int, args: list[str], exit_code: int
) -> None:
    if url == EXEC_URL:
        with_sandbox(api)
    api.route(method=verb, path=url).respond(status, json=hostile_envelope())

    result = invoke(args, as_json=as_json)

    assert result.exit_code == exit_code
    if as_json:
        error = json.loads(result.stdout)["error"]
        assert_clean(result.stdout)
        assert error["code"] == "BAD_CODE"
        assert len(error["message"]) <= MAX_RELAYED_CHARS
        assert MASK in error["message"]
        assert error["request_id"] == "req_0123"
        assert error["details"]["count"] == 5
        assert error["details"]["tokens"] == [MASK, 7]
        assert error["details"]["caller"] == MASK
        assert len(error["details"]["big"]) <= MAX_RELAYED_CHARS
        assert "evil.test" in error["details"]["note"]
    else:
        assert result.stdout == ""
        assert_clean(result.stderr)
        assert result.stderr.startswith("error: BAD_CODE: ")
        assert MASK in result.stderr
        assert len(result.stderr) < 4 * MAX_RELAYED_CHARS + 500
        assert result.stderr.count("\n") == 1


@BOTH_MODES
def test_the_key_from_the_environment_is_masked_in_a_server_error(
    api: Any, monkeypatch: pytest.MonkeyPatch, as_json: bool
) -> None:
    secret = "sf_env9"  # too short to look like a key
    monkeypatch.setenv(config.API_KEY_ENV, secret)
    api.get(SANDBOX_URL).respond(500, json=error_body("X", f"bad {secret}"))

    result = invoke(["sandbox", "get", SID], as_json=as_json)

    shown = result.stdout if as_json else result.stderr
    assert secret not in shown
    assert f"bad {MASK}" in shown


def test_the_stored_profile_key_is_masked_when_it_is_not_key_shaped(api: Any) -> None:
    logged_in(SHORT_KEY)
    api.get(SANDBOX_URL).respond(500, json=error_body("X", f"echo {SHORT_KEY}", {"k": SHORT_KEY}))

    result = invoke(["sandbox", "get", SID])

    assert SHORT_KEY not in result.stderr
    assert f"echo {MASK}" in result.stderr
    assert f"k={MASK}" in result.stderr


def test_an_sdk_error_with_hostile_text_is_sanitised_in_the_payload() -> None:
    exc = InternalError(f"{OSC}{CRED_URL} {KEY}", code="E", details={"a": FOREIGN})

    payload = error_payload(exc, hint=f"start it with: sandfort sandbox start {FOREIGN}{CSI}")

    assert_clean(json.dumps(payload))
    assert payload["error"]["hint"] == f"start it with: sandfort sandbox start {MASK}"


def test_a_hint_is_sanitised_and_capped() -> None:
    hint = clean_hint(f"start it with: sandfort sandbox start {OSC}{KEY}{'q' * HUGE}", KEY)

    assert_clean(hint)
    assert hint.startswith("start it with: sandfort sandbox start ")
    assert len(hint) <= USAGE_MESSAGE_CHARS


def test_a_cli_error_keeps_its_text_but_loses_escapes_and_keys() -> None:
    shown = scrub_local(f"line one\nline two {OSC}{KEY}\r{CSI}end", KEY)

    assert shown == f"line one\nline two {MASK}end"


def test_details_are_bounded_in_depth_and_entry_count() -> None:
    deep: Any = {"a": {"b": {"c": {"d": {"e": "x"}}}}}
    many = {str(index): index for index in range(MAX_RELAYED_ENTRIES + 25)}

    cleaned, _ = relay_value({"deep": deep, "many": many}, "")

    shown = json.dumps(cleaned["deep"], ensure_ascii=False)
    assert ELLIPSIS in shown
    assert '"x"' not in shown
    assert len(cleaned["many"]) == MAX_RELAYED_ENTRIES
    assert cleaned["many_beyond_cap"] == 25


def test_the_caller_key_comes_from_the_environment_first(monkeypatch: pytest.MonkeyPatch) -> None:
    logged_in(SHORT_KEY)
    assert caller_key() == SHORT_KEY

    monkeypatch.setenv(config.API_KEY_ENV, KEY)
    assert caller_key() == KEY


def test_without_a_profile_or_environment_there_is_no_caller_key() -> None:
    assert caller_key() == ""


# 3) typer's own text errors ----------------------------------------------------------------------

TYPED_VALUES = [
    pytest.param(SHORT_KEY, id="callers-key"),
    pytest.param(FOREIGN, id="key-shaped"),
    pytest.param(percent_encode_fully(SHORT_KEY), id="callers-key-encoded"),
    pytest.param("sf%5fshort1", id="callers-key-lower-hex"),
    pytest.param(percent_encode_fully(FOREIGN), id="key-shaped-encoded"),
]
UsageArgs = Callable[[str], list[str]]
USAGE_SHAPES = [
    pytest.param(lambda typed: ["sandbox", "get", SID, typed], id="extra-argument"),
    pytest.param(lambda typed: [typed], id="unknown-command"),
    pytest.param(lambda typed: ["sandbox", "list", f"--{typed}"], id="unknown-option"),
    pytest.param(lambda typed: ["sandbox", typed], id="unknown-subcommand"),
]


@pytest.mark.parametrize("typed", TYPED_VALUES)
@pytest.mark.parametrize("build", USAGE_SHAPES)
def test_a_key_typed_by_mistake_is_masked_in_the_text_usage_error(
    typed: str, build: UsageArgs
) -> None:
    logged_in(SHORT_KEY)

    result = invoke(build(typed))

    shown = flat(result.stderr)
    assert result.exit_code == 2
    assert typed not in shown
    assert typed not in result.output
    assert MASK in shown


@pytest.mark.parametrize("typed", TYPED_VALUES)
@pytest.mark.parametrize("build", USAGE_SHAPES)
def test_the_json_usage_error_masks_the_same_values(typed: str, build: UsageArgs) -> None:
    logged_in(SHORT_KEY)

    result = invoke(build(typed), as_json=True)

    assert result.exit_code == 2
    assert typed not in result.stdout
    assert MASK in json.loads(result.stdout)["error"]["message"]


def test_a_usage_error_without_secrets_is_not_changed() -> None:
    result = invoke(["sandbox", "get", SID, "extra"])

    assert result.exit_code == 2
    assert "extra" in flat(result.stderr)
    assert MASK not in result.stderr


def test_the_json_placement_hint_survives_the_sanitiser() -> None:
    result = invoke(["sandbox", "list", "--json"])

    assert result.exit_code == 2
    assert "belongs before the command" in flat(result.stderr)


# 4) the decoded-copy masking in the label, env and expiry echoes --------------------------------

ENCODED_FORMS = [
    pytest.param(percent_encode_fully(KEY), id="encoded"),
    pytest.param(percent_encode_fully(KEY).lower(), id="encoded-lower"),
    pytest.param(percent_encode_fully(KEY, alphanumerics=True), id="all-bytes"),
    pytest.param("sf%5Ftest_key%5Fdo_not_print", id="mixed"),
]


@pytest.mark.parametrize("option", ["--label", "--env"])
@pytest.mark.parametrize("encoded", ENCODED_FORMS)
def test_a_percent_encoded_key_in_a_pair_echo_is_masked(option: str, encoded: str) -> None:
    logged_in(KEY)

    result = invoke(["sandbox", "create", "demo", option, encoded])

    shown = flat(result.stderr)
    assert result.exit_code == 2
    assert encoded not in shown
    assert KEY not in shown
    assert f"invalid {option[2:]} '{MASK}'" in shown


@pytest.mark.parametrize("option", ["--label", "--env"])
def test_a_percent_encoded_stored_key_is_masked_without_an_environment_key(option: str) -> None:
    logged_in(SHORT_KEY)
    encoded = percent_encode_fully(SHORT_KEY)

    result = invoke(["sandbox", "create", "demo", option, encoded], as_json=True)

    assert result.exit_code == 2
    assert encoded not in result.stdout
    assert SHORT_KEY not in result.stdout


def test_a_key_shaped_token_written_with_escapes_is_masked_anywhere() -> None:
    plain_escaped = percent_encode_fully(FOREIGN)
    all_escaped = "%73%66%5F" + "61" * 10

    shown = sanitise_text(f"saw {plain_escaped} and {all_escaped}")

    assert shown == f"saw {MASK} and {MASK}"


# 5) exit codes and the remote exit passthrough are unchanged -------------------------------------


def test_exec_passes_the_remote_exit_code_and_streams_through(api: Any) -> None:
    with_sandbox(api)
    api.post(EXEC_URL).respond(200, json=exec_body(3))

    result = invoke(["exec", SID, "sh", "-c", "exit 3"])

    assert result.exit_code == 3
    assert result.stdout == "out\n"
    assert result.stderr == "err\n"


def test_exec_json_keeps_the_remote_exit_code(api: Any) -> None:
    with_sandbox(api)
    api.post(EXEC_URL).respond(200, json=exec_body(7))

    result = invoke(["exec", SID, "false"], as_json=True)

    assert result.exit_code == 7
    assert json.loads(result.stdout)["exit_code"] == 7


def test_exec_timeout_still_exits_124(api: Any) -> None:
    with_sandbox(api)
    api.post(EXEC_URL).respond(200, json=exec_body(0, timed_out=True))

    result = invoke(["exec", SID, "sleep", "9"])

    assert result.exit_code == TIMED_OUT_EXIT
    assert "timed out" in result.stderr


def test_a_platform_error_still_exits_125_with_one_error_line(api: Any) -> None:
    with_sandbox(api)
    api.post(EXEC_URL).respond(404, json=error_body("NOT_FOUND", "no such sandbox"))

    result = invoke(["exec", SID, "true"])

    assert result.exit_code == PLATFORM_ERROR_EXIT
    assert result.stderr == "error: NOT_FOUND: no such sandbox\n"


def test_a_plain_cli_error_still_exits_1_with_its_text() -> None:
    # No profile and no environment key (autouse fixture): the local "not logged in" error.
    result = invoke(["sandbox", "list"])

    assert result.exit_code == 1
    assert result.stderr == f"error: {config.NOT_LOGGED_IN_MESSAGE}\n"
    assert "SANDFORT_API_KEY_FILE" in result.stderr


def test_a_usage_error_still_exits_2() -> None:
    assert invoke(["sandbox", "create"]).exit_code == 2
    assert invoke(["sandbox", "create", "demo", "--wait-timeout", "5"]).exit_code == 2
