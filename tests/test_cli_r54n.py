"""CLI round 54, batch n: blank-argument residue and option handling.

1. A name made only of control characters (C0, DEL, ESC, C1, the single-byte CSI) is blank.
2. A blank option value (``key create --scope``, ``sandbox create --snapshot``/``--egress``,
   ``sandbox list --state``, ``exec --cwd``, ``cmd start --session``, ``snapshot build --name``,
   ``snapshot export --output``) is the shared usage error naming the option; a label or env key
   made only of invisible characters is refused, a blank label or env value stays legal.
3. A blank or malformed ``--mount`` is a usage error (exit 2) with the shared wording.
4. An exec option written after the sandbox name is refused instead of run as the command.
5. The whole-number error adds a plain-digits hint for invisible characters, non-ASCII digits
   and a plus sign.

Each item is checked in text and json mode, with a valid control case that reaches the server.
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

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.number_parsing import (  # noqa: E402
    CONTROL_HINT_PREFIX,
    INVISIBLE_HINT_PREFIX,
    PLAIN_DIGITS_HINT,
    SIGN_HINT,
    SURROUNDING_SPACES_HINT,
)
from sandfort_cli.output import is_blank  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOX_URL = f"/v1/sandboxes/{SID}"
EXEC_URL = f"{SANDBOX_URL}/toolbox/process/execute"
USAGE = 2
EMPTY = "must not be empty"
DIGITS_HINT = PLAIN_DIGITS_HINT
ZWSP_HINT = f"{INVISIBLE_HINT_PREFIX}U+200B"
ESC_HINT = f"{CONTROL_HINT_PREFIX}U+001B"
RUNNER = CliRunner()
BOTH_MODES = pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
NOT_FOUND = {
    "success": False,
    "data": None,
    "error": {"code": "NOT_FOUND", "message": "gone", "details": {}, "request_id": "req_1"},
    "meta": None,
}
ZWSP = "​"
CONTROL_NAMES = {
    "c0": "\x01\x02",
    "nul": "\x00",
    "del": "\x7f",
    "esc": "\x1b",
    "c1": "\x90\x9f",
    "csi-8bit": "\x9b",
    "mixed-invisible": f"\x1b {ZWSP}\x7f",
}


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def flat(text: str) -> str:
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


def envelope(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data, "error": None, "meta": None}


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    config.save_profile(BASE, KEY)


@pytest.fixture
def router() -> Iterator[Any]:
    """Every request is answered with a NOT_FOUND envelope and counted."""
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        mock.route().mock(return_value=httpx.Response(404, json=NOT_FOUND))
        yield mock


def assert_usage_error(result: Any, router: Any, expected: str, as_json: bool) -> None:
    """Exit 2, no request, ``expected`` in the one json document or in the text usage frame."""
    assert result.exit_code == USAGE, result.output
    assert router.calls.call_count == 0
    assert "Traceback" not in result.output
    if as_json:
        payload = json.loads(result.stdout)  # exactly one document
        assert list(payload) == ["error"]
        assert result.stderr.strip() == ""
        error = payload["error"]
        assert error["code"] == "USAGE_ERROR" and error["source"] == "client"
        assert expected in flat(str(error["message"]))
    else:
        assert result.stdout.strip() == ""
        assert expected in flat(result.stderr)


def assert_reached_server(result: Any, router: Any) -> None:
    assert result.exit_code != USAGE, result.output
    assert router.calls.call_count >= 1
    assert EMPTY not in result.output


def last_body(router: Any) -> dict[str, Any]:
    body: dict[str, Any] = json.loads(router.calls.last.request.content)
    return body


# 1. a name made only of control characters is blank ------------------------------------------


@BOTH_MODES
@pytest.mark.parametrize("name", list(CONTROL_NAMES.values()), ids=list(CONTROL_NAMES))
def test_a_control_only_name_is_blank(router: Any, as_json: bool, name: str) -> None:
    result = invoke(["sandbox", "get", name], as_json=as_json)

    assert_usage_error(result, router, f"Invalid value for <sandbox>: {EMPTY}", as_json)


@BOTH_MODES
def test_a_control_only_snapshot_name_is_blank(router: Any, as_json: bool) -> None:
    result = invoke(["snapshot", "create", "sbx_1", "\x1b\x9b"], as_json=as_json)

    assert_usage_error(result, router, f"Invalid value for <name>: {EMPTY}", as_json)


@BOTH_MODES
def test_controls_mixed_with_visible_text_are_not_blank(router: Any, as_json: bool) -> None:
    result = invoke(["sandbox", "get", "\x1bdemo"], as_json=as_json)

    assert_reached_server(result, router)


def test_is_blank_needs_every_character_to_show_nothing() -> None:
    assert is_blank("")
    assert is_blank("\x00\x1f\x7f\x80\x9b\x9f \t" + ZWSP)
    assert not is_blank("a\x1b")
    assert not is_blank("x\x9bx")


# 2. blank option values -----------------------------------------------------------------------

OptionCase = tuple[Callable[[str], list[str]], str]
OPTION_CASES: dict[str, OptionCase] = {
    "key-create-scope": (lambda b: ["key", "create", "ci", "--scope", b], "--scope"),
    "key-create-second-scope": (
        lambda b: ["key", "create", "ci", "-s", "sandboxes:read", "-s", b],
        "--scope",
    ),
    "sandbox-create-snapshot": (
        lambda b: ["sandbox", "create", "demo", "--snapshot", b],
        "--snapshot",
    ),
    "sandbox-create-egress": (lambda b: ["sandbox", "create", "demo", "--egress", b], "--egress"),
    "sandbox-list-state": (lambda b: ["sandbox", "list", "--state", b], "--state"),
    "exec-cwd": (lambda b: ["exec", "--cwd", b, "sbx_1", "ls"], "--cwd"),
    "cmd-start-session": (
        lambda b: ["cmd", "start", "--session", b, "sbx_1", "--", "ls"],
        "--session",
    ),
    "snapshot-build-name": (lambda b: ["snapshot", "build", "spec.json", "--name", b], "--name"),
    "snapshot-export-output": (lambda b: ["snapshot", "export", "snap_1", "-o", b], "--output"),
}
BLANK_VALUES = pytest.mark.parametrize(
    "blank", ["", "   ", ZWSP, "\x1b"], ids=["empty", "spaces", "invisible", "control"]
)


@BOTH_MODES
@BLANK_VALUES
@pytest.mark.parametrize("case", list(OPTION_CASES))
def test_a_blank_option_value_is_a_local_usage_error(
    router: Any, as_json: bool, blank: str, case: str
) -> None:
    build, option = OPTION_CASES[case]

    result = invoke(build(blank), as_json=as_json)

    assert_usage_error(result, router, f"Invalid value for {option}: {EMPTY}", as_json)


OPTION_CONTROLS: dict[str, list[str]] = {
    "key-create-scope": ["key", "create", "ci", "--scope", "sandboxes:read"],
    "sandbox-create-snapshot": ["sandbox", "create", "demo", "--snapshot", "python:3.12"],
    "sandbox-create-egress": ["sandbox", "create", "demo", "--egress", "pypi.org"],
    "sandbox-list-state": ["sandbox", "list", "--state", "started"],
    "exec-cwd": ["exec", "--cwd", "/w", "sbx_1", "ls"],
    "cmd-start-session": ["cmd", "start", "--session", "ses_1", "sbx_1", "--", "ls"],
    "snapshot-build-name": ["snapshot", "build", "spec.json", "--name", "base"],
    "snapshot-export-output": ["snapshot", "export", "snap_1", "-o", "out.tar"],
}


@BOTH_MODES
@pytest.mark.parametrize("args", list(OPTION_CONTROLS.values()), ids=list(OPTION_CONTROLS))
def test_a_valid_option_value_still_reaches_the_server(
    router: Any, as_json: bool, args: list[str], tmp_path: Path
) -> None:
    (tmp_path / "spec.json").write_text("{}", encoding="utf-8")

    result = invoke(args, as_json=as_json)

    assert_reached_server(result, router)


@BOTH_MODES
@pytest.mark.parametrize("kind", ["label", "env"])
@pytest.mark.parametrize("key", [ZWSP, f"{ZWSP}‍", "\x1b"], ids=["zwsp", "joiner", "esc"])
def test_an_invisible_pair_key_is_refused(router: Any, as_json: bool, kind: str, key: str) -> None:
    result = invoke(["sandbox", "create", "demo", f"--{kind}", f"{key}=v"], as_json=as_json)

    assert_usage_error(result, router, f"Invalid value for --{kind}: invalid {kind}", as_json)


@BOTH_MODES
def test_a_blank_pair_value_stays_legal(router: Any, as_json: bool) -> None:
    args = ["sandbox", "create", "demo", "--label", "team=", "--env", "EMPTY= "]

    result = invoke(args, as_json=as_json)

    assert_reached_server(result, router)
    body = last_body(router)
    assert body["labels"] == {"team": ""}
    assert body["env"] == {"EMPTY": " "}


# 3. --mount -----------------------------------------------------------------------------------


@BOTH_MODES
@pytest.mark.parametrize("blank", ["", "   ", ZWSP], ids=["empty", "spaces", "invisible"])
def test_a_blank_mount_is_the_shared_usage_error(router: Any, as_json: bool, blank: str) -> None:
    result = invoke(["sandbox", "create", "demo", "--mount", blank], as_json=as_json)

    assert_usage_error(result, router, f"Invalid value for --mount: {EMPTY}", as_json)


@BOTH_MODES
@pytest.mark.parametrize("value", ["nocolon", f"{ZWSP}:/data", "vol_1:", ":/data", "vol_1:\x1b"])
def test_a_malformed_mount_is_a_usage_error(router: Any, as_json: bool, value: str) -> None:
    result = invoke(["sandbox", "create", "demo", "-m", value], as_json=as_json)

    expected = "Invalid value for --mount: invalid mount"
    assert_usage_error(result, router, expected, as_json)
    assert "; expected VOLUME:PATH[:ro|rw]" in flat(result.output)


@BOTH_MODES
def test_a_valid_mount_still_reaches_the_server(router: Any, as_json: bool) -> None:
    result = invoke(["sandbox", "create", "demo", "--mount", "vol_1:/data"], as_json=as_json)

    assert_reached_server(result, router)
    assert last_body(router)["volumes"] == [{"volume_id": "vol_1", "mount_path": "/data"}]


# 4. exec options after the sandbox name -------------------------------------------------------

MISPLACED = {
    "short-timeout": ["-t", "5", "ls"],
    "long-timeout": ["--timeout", "5", "ls"],
    "timeout-equals": ["--timeout=5", "ls"],
    "short-attached": ["-t5", "ls"],
    "cwd": ["--cwd", "/w", "ls"],
    "stdin": ["-i", "cat"],
    "long-stdin": ["--stdin", "cat"],
}


@BOTH_MODES
@pytest.mark.parametrize("rest", list(MISPLACED.values()), ids=list(MISPLACED))
def test_an_exec_option_after_the_sandbox_is_refused(
    router: Any, as_json: bool, rest: list[str]
) -> None:
    result = invoke(["exec", SID, *rest], as_json=as_json)

    assert_usage_error(result, router, "exec options go before it", as_json)
    assert "came after the sandbox name" in flat(result.output)
    assert "command not found" not in result.output


@pytest.fixture
def exec_api() -> Iterator[Any]:
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        sandbox = {
            "id": SID,
            "name": "demo",
            "state": "started",
            "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
            "network": {"block_all": False},
        }
        mock.get(SANDBOX_URL).respond(200, json=envelope(sandbox))
        result = {
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
            "truncated": False,
            "duration_ms": 1,
        }
        mock.post(EXEC_URL).respond(200, json=envelope(result))
        yield mock


@BOTH_MODES
@pytest.mark.parametrize(
    ("rest", "argv"),
    [
        (["--", "-t", "5"], ["-t", "5"]),
        (["-x"], ["-x"]),
        (["ls", "-t"], ["ls", "-t"]),
        (["-tool", "x"], ["-tool", "x"]),
    ],
    ids=["after-double-dash", "not-an-exec-option", "option-of-the-command", "dash-program"],
)
def test_a_dash_command_word_that_is_not_misplaced_still_runs(
    exec_api: Any, as_json: bool, rest: list[str], argv: list[str]
) -> None:
    result = invoke(["exec", SID, *rest], as_json=as_json)

    assert result.exit_code == 0, result.output
    assert last_body(exec_api)["argv"] == argv


@BOTH_MODES
def test_exec_options_before_the_sandbox_still_work(exec_api: Any, as_json: bool) -> None:
    result = invoke(["exec", "-t", "5", "--cwd", "/w", SID, "ls"], as_json=as_json)

    assert result.exit_code == 0, result.output
    body = last_body(exec_api)
    assert (body["argv"], body["cwd"], body["timeout_s"]) == (["ls"], "/w", 5)


# 5. the whole-number hint ---------------------------------------------------------------------

HINTED = {
    "plus": ("+5", (SIGN_HINT,)),
    "fullwidth": ("５", (PLAIN_DIGITS_HINT,)),
    "arabic-indic": ("٣", (PLAIN_DIGITS_HINT,)),
    "zero-width": (f"5{ZWSP}", (ZWSP_HINT,)),
    "control": ("\x1b5", (ESC_HINT,)),
    "plus-and-spaces": (" +5 ", (SURROUNDING_SPACES_HINT, SIGN_HINT)),
}


TIMEOUT_RANGE = "must be a whole number from 1 to 3600"


@BOTH_MODES
@pytest.mark.parametrize("value, hints", list(HINTED.values()), ids=list(HINTED))
def test_a_number_that_looks_plain_gets_its_hint(
    router: Any, as_json: bool, value: str, hints: tuple[str, ...]
) -> None:
    result = invoke(["exec", "-t", value, SID, "ls"], as_json=as_json)

    assert_usage_error(result, router, TIMEOUT_RANGE, as_json)
    for hint in hints:
        assert hint in flat(result.output)


@BOTH_MODES
def test_the_sign_hint_also_applies_to_an_unbounded_option(router: Any, as_json: bool) -> None:
    result = invoke(["sandbox", "create", "demo", "--cpu-millicores", "+750"], as_json=as_json)

    assert_usage_error(result, router, "must be a whole number", as_json)
    assert SIGN_HINT in flat(result.output)


@BOTH_MODES
def test_both_hints_when_both_apply(router: Any, as_json: bool) -> None:
    result = invoke(["exec", "-t", " +5 ", SID, "ls"], as_json=as_json)

    assert_usage_error(result, router, "surrounding whitespace is not allowed", as_json)
    assert SIGN_HINT in flat(result.output)


@BOTH_MODES
@pytest.mark.parametrize("value", ["abc", " 5 ", "-5", "1.5", "0", "9999"])
def test_other_refused_numbers_get_no_digits_hint(router: Any, as_json: bool, value: str) -> None:
    result = invoke(["exec", "-t", value, SID, "ls"], as_json=as_json)

    assert_usage_error(result, router, TIMEOUT_RANGE, as_json)
    assert DIGITS_HINT not in flat(result.output)


@BOTH_MODES
def test_a_plain_number_still_reaches_the_server(exec_api: Any, as_json: bool) -> None:
    result = invoke(["exec", "-t", "30", SID, "ls"], as_json=as_json)

    assert result.exit_code == 0, result.output
    assert last_body(exec_api)["timeout_s"] == 30
