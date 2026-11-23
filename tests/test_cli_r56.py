"""CLI round 56: usability findings from the persona runs.

1. ``key create --help`` lists the known scope names (mirrored from the server's scope enum).
2. ``--wait-timeout`` refuses non-ASCII digits and surrounding whitespace with the same hints
   as the whole-number options.
3. A not-running 409 with ``details.stop_cause`` adds ``stopped because: <cause>`` to the start
   hint; ``sandbox list`` and ``sandbox get`` help name the REASON column and ``stop_cause``.
4. A damaged profile api key is worded ``api_key in <profile> <problem>`` (no ``Invalid value
   for`` frame); every profile-key error ends with ``run 'sandfort login'``.
5. A name made only of terminal escape sequences is blank: exit 2 before any request.
6. Label keys that collide after sanitising are named alike in the tables and in ``--json``.
7. A repeated ``KEY=VALUE`` key is a usage error naming the key.
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
from sandfort_cli.keys import KNOWN_SCOPES  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.number_parsing import INVISIBLE_HINT_PREFIX, SIGN_HINT  # noqa: E402
from sandfort_cli.output import is_blank, start_hint  # noqa: E402
from sandfort_cli.sandboxes import PLAIN_DIGITS_HINT, SURROUNDING_SPACES_HINT  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOX_URL = f"/v1/sandboxes/{SID}"
USAGE = 2
PLATFORM_ERROR = 125
EMPTY = "must not be empty"
NOT_RUNNING = "toolbox operations require a started sandbox"
RUNNER = CliRunner()
BOTH_MODES = pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
NOT_FOUND = {
    "success": False,
    "data": None,
    "error": {"code": "NOT_FOUND", "message": "gone", "details": {}, "request_id": "req_1"},
    "meta": None,
}
CONTROL_ENV = "\x01env"
HIDDEN_ENV = "​env"
ESCAPE_ONLY_NAMES = {
    "csi-reset": "\x1b[0m",
    "osc-title-bel": "\x1b]0;t\x07",
    "osc-title-st": "\x1b]0;t\x1b\\",
    "apc": "\x1b_payload\x1b\\",
    "sos": "\x1bXpayload\x1b\\",
    "csi-cut-off": "\x1b[1;3",
    "several": "\x1b[1m\x1b]0;t\x07 \x1b",
}


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def flat(text: str) -> str:
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


def reported(result: Any, as_json: bool) -> str:
    return flat(result.stdout if as_json else result.stderr)


def envelope(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data, "error": None, "meta": None}


def sandbox_json(labels: dict[str, str], **extra: Any) -> dict[str, Any]:
    return {
        "id": SID,
        "name": "demo",
        "state": "started",
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
        "labels": labels,
        **extra,
    }


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    # Wide enough that the text usage box shows the whole tmp profile path unwrapped.
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("TERMINAL_WIDTH", "400")
    config.save_profile(BASE, KEY)


@pytest.fixture
def router() -> Iterator[Any]:
    """A respx router; a request no route of the test matches fails the call."""
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


@pytest.fixture
def any_request(router: Any) -> Any:
    """A catch-all route answering NOT_FOUND, for counting requests that must not be sent."""
    return router.route().mock(return_value=httpx.Response(404, json=NOT_FOUND))


def assert_usage(result: Any, as_json: bool, expected: str) -> None:
    assert result.exit_code == USAGE, result.output
    assert "Traceback" not in result.output
    if as_json:
        payload = json.loads(result.stdout)  # exactly one document
        assert payload["error"]["code"] == "USAGE_ERROR"
        assert expected in flat(str(payload["error"]["message"]))
    else:
        assert expected in flat(result.stderr)


# 1. scope names in key create --help ----------------------------------------------------------


def test_key_create_help_lists_every_known_scope() -> None:
    result = invoke(["key", "create", "--help"])

    assert result.exit_code == 0, result.output
    shown = "".join(flat(result.stdout).split())
    for scope in KNOWN_SCOPES:
        assert scope in shown


def test_the_cli_scope_list_mirrors_the_server_enum() -> None:
    org = pytest.importorskip("sandfort.domain.org")

    assert KNOWN_SCOPES == tuple(scope.value for scope in org.Scope)


# 2. --wait-timeout hints ----------------------------------------------------------------------


@BOTH_MODES
@pytest.mark.parametrize("command", [["start", SID], ["create", "demo"]], ids=["start", "create"])
@pytest.mark.parametrize(
    ("value", "hint"),
    [
        ("５", PLAIN_DIGITS_HINT),  # fullwidth 5
        ("٥.5", PLAIN_DIGITS_HINT),  # Arabic-Indic 5
        ("+5", SIGN_HINT),  # round 57: the sign has its own hint
        ("5​", INVISIBLE_HINT_PREFIX + "U+200B"),  # round 57: the character is named
        (" 5 ", SURROUNDING_SPACES_HINT),
    ],
    ids=["fullwidth", "arabic-indic", "plus", "zero-width", "spaces"],
)
def test_a_misleading_wait_timeout_is_refused_with_the_hint(
    any_request: Any, as_json: bool, command: list[str], value: str, hint: str
) -> None:
    result = invoke(["sandbox", *command, "--wait", f"--wait-timeout={value}"], as_json=as_json)

    assert_usage(result, as_json, "must be a finite number greater than 0")
    assert hint.removeprefix("; ") in reported(result, as_json)
    assert any_request.call_count == 0


def test_the_hint_also_follows_the_requires_wait_message(any_request: Any) -> None:
    result = invoke(["sandbox", "start", SID, "--wait-timeout", "５"])

    assert_usage(result, False, "requires --wait, and must be a finite number greater than 0")
    assert PLAIN_DIGITS_HINT.removeprefix("; ") in flat(result.stderr)


def test_a_plain_out_of_range_value_gets_no_digit_hint(any_request: Any) -> None:
    result = invoke(["sandbox", "start", SID, "--wait", "--wait-timeout", "0"])

    assert_usage(result, False, "must be a finite number greater than 0")
    assert "ASCII" not in result.stderr and "whitespace" not in result.stderr


@pytest.mark.parametrize("value", ["2.5", "0.3", ".5", "1e1", "7"])
def test_plain_decimal_wait_timeouts_are_accepted(router: Any, value: str) -> None:
    started = sandbox_json({}, state="started")
    router.post(f"{SANDBOX_URL}/start").respond(200, json=envelope(started))
    router.get(SANDBOX_URL).respond(200, json=envelope(started))

    result = invoke(["sandbox", "start", SID, "--wait", "--wait-timeout", value])

    assert result.exit_code == 0, result.output


# 3. stop_cause in the start hint and in the help ----------------------------------------------


def conflict(details: Any) -> httpx.Response:
    body = {
        "success": False,
        "data": None,
        "error": {
            "code": "CONFLICT",
            "message": NOT_RUNNING,
            "details": details,
            "request_id": "req_9",
        },
        "meta": None,
    }
    return httpx.Response(409, json=body)


@BOTH_MODES
def test_exec_on_a_stopped_sandbox_says_why_it_stopped(router: Any, as_json: bool) -> None:
    router.route().mock(return_value=conflict({"state": "stopped", "stop_cause": "auto_stop"}))

    result = invoke(["exec", SID, "--", "echo", "hi"], as_json=as_json)

    assert result.exit_code == PLATFORM_ERROR, result.output
    expected = f"start it with: sandfort sandbox start {SID}; stopped because: auto_stop"
    if as_json:
        assert json.loads(result.stdout)["error"]["hint"] == expected
    else:
        assert expected in result.stderr


@pytest.mark.parametrize(
    "details",
    [{"state": "stopped"}, {"stop_cause": None}, {"stop_cause": 7}, {"stop_cause": ""}, None],
    ids=["absent", "null", "number", "empty", "no-details"],
)
def test_without_a_usable_stop_cause_the_hint_is_unchanged(router: Any, details: Any) -> None:
    router.route().mock(return_value=conflict(details))

    result = invoke(["exec", SID, "--", "echo", "hi"])

    assert result.exit_code == PLATFORM_ERROR, result.output
    assert f"start it with: sandfort sandbox start {SID}" in result.stderr
    assert "stopped because" not in result.stderr


def test_a_hostile_stop_cause_is_sanitised(router: Any) -> None:
    router.route().mock(return_value=conflict({"stop_cause": f"\x1b]52;c;x\x07oom {KEY}"}))

    result = invoke(["exec", SID, "--", "echo", "hi"])

    assert "stopped because: oom" in result.stderr
    assert "\x1b" not in result.stderr and KEY not in result.stderr


def test_start_hint_keeps_its_plain_form_without_a_cause() -> None:
    assert start_hint("demo") == "start it with: sandfort sandbox start demo"
    assert start_hint("demo", "requested").endswith("; stopped because: requested")


@pytest.mark.parametrize("command", ["list", "get"])
def test_list_and_get_help_name_the_reason_column_and_stop_cause(command: str) -> None:
    result = invoke(["sandbox", command, "--help"])

    assert result.exit_code == 0, result.output
    shown = flat(result.stdout)
    assert "REASON" in shown and "stop_cause" in shown


# 4. profile api key wording -------------------------------------------------------------------


def write_profile(body: dict[str, Any]) -> None:
    config.profile_path().write_text(json.dumps(body), encoding="utf-8")


@BOTH_MODES
@pytest.mark.parametrize(
    ("stored", "problem"),
    [
        (12, config.NOT_A_STRING_KEY_MESSAGE),
        ("", config.EMPTY_KEY_MESSAGE),
        ("   ", config.MALFORMED_KEY_MESSAGE + config.LOGIN_TAIL),
        ("sf_a b", config.MALFORMED_KEY_MESSAGE + config.LOGIN_TAIL),
    ],
    ids=["number", "empty", "whitespace", "inner-space"],
)
def test_a_damaged_profile_key_names_the_profile_then_the_problem(
    any_request: Any, as_json: bool, stored: Any, problem: str
) -> None:
    write_profile({"base_url": BASE, "api_key": stored})

    result = invoke(["sandbox", "list"], as_json=as_json)

    assert_usage(result, as_json, f"api_key in {config.profile_path()} {problem}")
    assert "Invalid value for" not in reported(result, as_json)
    assert any_request.call_count == 0


def test_a_malformed_non_blank_key_ends_with_the_login_tail(any_request: Any) -> None:
    write_profile({"base_url": BASE, "api_key": "sf_a\x07b"})

    result = invoke(["sandbox", "list"])

    assert_usage(
        result,
        False,
        f"api_key in {config.profile_path()} {config.MALFORMED_KEY_MESSAGE}{config.LOGIN_TAIL}",
    )
    assert any_request.call_count == 0


def test_a_too_long_profile_key_ends_with_the_login_tail(any_request: Any) -> None:
    write_profile({"base_url": BASE, "api_key": "sf_" + "k" * config.MAX_API_KEY_CHARS})

    result = invoke(["sandbox", "list"])

    assert_usage(
        result,
        False,
        f"api_key in {config.profile_path()} {config.TOO_LONG_KEY_MESSAGE}{config.LOGIN_TAIL}",
    )
    assert any_request.call_count == 0


def test_an_environment_key_keeps_its_option_style_error(
    any_request: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(config.API_KEY_ENV, "sf_a b")

    result = invoke(["sandbox", "list"])

    assert_usage(result, False, f"{config.API_KEY_ENV}: {config.MALFORMED_KEY_MESSAGE}")


# 5. escape-sequence-only names are blank ------------------------------------------------------


@pytest.mark.parametrize("name", list(ESCAPE_ONLY_NAMES.values()), ids=list(ESCAPE_ONLY_NAMES))
def test_is_blank_ignores_escape_sequences(name: str) -> None:
    assert is_blank(name)


VISIBLE_AROUND_SEQUENCES = ["\x1b[0mdemo", "\x1bdemo", "\x1b]0;t\x07x", "a\x1b[0m", "x\x9bx"]


@pytest.mark.parametrize("name", VISIBLE_AROUND_SEQUENCES)
def test_visible_text_around_sequences_is_not_blank(name: str) -> None:
    assert not is_blank(name)


def test_c1_csi_with_a_final_byte_is_blank() -> None:
    assert is_blank("\x9bx")
    assert is_blank("\x1b[x")


@BOTH_MODES
@pytest.mark.parametrize("name", list(ESCAPE_ONLY_NAMES.values()), ids=list(ESCAPE_ONLY_NAMES))
def test_sandbox_get_of_an_escape_only_name_is_a_usage_error(
    any_request: Any, as_json: bool, name: str
) -> None:
    result = invoke(["sandbox", "get", name], as_json=as_json)

    assert_usage(result, as_json, EMPTY)
    assert any_request.call_count == 0
    assert "no sandbox named" not in result.output


def test_an_escape_only_label_key_is_refused(any_request: Any) -> None:
    result = invoke(["sandbox", "list", "--label", "\x1b[0m=x"])

    assert_usage(result, False, "label key is blank or invisible")
    assert any_request.call_count == 0


# 6. cleaned label keys in the table views -----------------------------------------------------


def label_pairs_shown(stdout: str) -> list[str]:
    return re.findall(r"env(?:#\d+)?=\w+", stdout)


def test_sandbox_get_labels_rows_use_the_json_key_names(router: Any) -> None:
    labels = {CONTROL_ENV: "evil", "env": "prod", HIDDEN_ENV: "other"}
    router.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json(labels)))

    result = invoke(["sandbox", "get", SID])

    assert result.exit_code == 0, result.output
    assert sorted(label_pairs_shown(result.stdout)) == ["env#2=evil", "env#3=other", "env=prod"]


def test_sandbox_list_labels_cell_uses_the_json_key_names(router: Any) -> None:
    labels = {CONTROL_ENV: "a", "env": "b"}
    router.get("/v1/sandboxes").respond(200, json=envelope([sandbox_json(labels)]))

    result = invoke(["sandbox", "list"])

    assert result.exit_code == 0, result.output
    assert "env#2=a,env=b" in result.stdout


def test_the_table_and_json_name_the_keys_alike(router: Any) -> None:
    labels = {"env": "prod", CONTROL_ENV: "evil"}
    router.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json(labels)))

    as_json = json.loads(invoke(["sandbox", "get", SID], as_json=True).stdout)["labels"]
    table = invoke(["sandbox", "get", SID]).stdout

    assert sorted(label_pairs_shown(table)) == sorted(f"{k}={v}" for k, v in as_json.items())


# 7. a repeated KEY=VALUE key is a usage error -------------------------------------------------


@BOTH_MODES
@pytest.mark.parametrize(
    "args",
    [
        ["sandbox", "create", "demo", "-l", "team=a", "-l", "team=b"],
        ["sandbox", "list", "--label", "team=a", "--label", " team =b"],
        ["key", "create", "ci", "-s", "org:read", "-l", "team=a", "-l", "team=a"],
    ],
    ids=["create", "list-stripped", "key-create-same-value"],
)
def test_a_repeated_label_key_is_a_usage_error(
    any_request: Any, as_json: bool, args: list[str]
) -> None:
    result = invoke(args, as_json=as_json)

    assert_usage(result, as_json, "label key 'team' is given more than once")
    assert "--label" in reported(result, as_json)
    assert any_request.call_count == 0


def test_distinct_label_keys_still_reach_the_server(router: Any) -> None:
    route = router.get("/v1/sandboxes").respond(200, json=envelope([]))

    result = invoke(["sandbox", "list", "-l", "team=a", "-l", "env=b"])

    assert result.exit_code == 0, result.output
    assert route.call_count == 1
