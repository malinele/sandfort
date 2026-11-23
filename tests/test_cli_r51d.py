"""CLI round 51, batch 4: usage leftovers.

* Every positional argument of cp, shell, snapshot, volume and members has an explicit
  ``<...>`` metavar; no usage line has a curly brace; the two arguments that take an id or a
  name (``snapshot create``, ``shell``) use the neutral ``<sandbox>``.
* The remaining parser-native integer options (cmd-start ``--timeout``, preview ``--ttl``, the
  sandbox-create integers) give the unified ``must be a whole number ...`` wording.
* An empty id or email positional is a usage error (exit 2) before anything is sent.
* A partial ``sandbox rm`` failure under ``--json`` is ONE document: the error plus the refs
  that were processed.
* A server validation ``errors`` list is shown as ``location: message`` pairs in text; json
  keeps the structured list.
* A cut collection in ``details`` stays pure; a sibling number says how many entries were
  dropped.
* The fragment mask leaves a closing parenthesis alone; a lone negative number as the preview
  port gets the unified port wording.
"""

import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.output import (  # noqa: E402
    BEYOND_CAP_SUFFIX,
    describe_error,
    error_payload,
    hoist_negative_numbers,
    relay_value,
    validation_summary,
)
from sandfort_cli.sanitise import (  # noqa: E402
    ELLIPSIS,
    MAX_RELAYED_ENTRIES,
    sanitise_text,
)
from sandfort_sdk import ApiError  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
OTHER_SID = "sbx_01HYYYYYYYYYYYYYYYYYYYYYYY"
SANDBOXES_URL = "/v1/sandboxes"
RUNNER = CliRunner()
BOX_CHARS = str.maketrans(dict.fromkeys("│╭╮╰╯─┃┏┓┗┛━", " "))
ESC = "\x1b"

# (command words, the positional metavars its usage line must show, in order)
POSITIONALS: list[tuple[list[str], str]] = [
    (["cp"], "<source> <destination>"),
    (["shell"], "<sandbox>"),
    (["snapshot", "register"], "<image>"),
    (["snapshot", "create"], "<sandbox> <name>"),
    (["snapshot", "get"], "<snapshot-id>"),
    (["snapshot", "rm"], "<snapshot-id>"),
    (["snapshot", "export"], "<snapshot-id>"),
    (["snapshot", "build"], "<spec-file>"),
    (["volume", "create"], "<name>"),
    (["volume", "get"], "<volume-id>"),
    (["volume", "rm"], "<volume-id>"),
    (["members", "add"], "<email> <display-name>"),
    (["members", "set-role"], "<user-id>"),
    (["members", "remove"], "<user-id>"),
]
NO_POSITIONALS = [
    ["snapshot", "list"],
    ["volume", "list"],
    ["members", "list"],
]


def envelope(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data, "error": None, "meta": None}


def error_envelope(
    code: str, message: str, details: dict[str, Any] | None = None
) -> dict[str, Any]:
    error = {"code": code, "message": message, "details": details or {}, "request_id": "req_1"}
    return {"success": False, "data": None, "error": error, "meta": None}


def sandbox_json(sandbox_id: str = SID, state: str = "started") -> dict[str, Any]:
    return {
        "id": sandbox_id,
        "name": "demo",
        "state": state,
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
    }


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def flat(text: str) -> str:
    """``text`` on one line without the help/error box characters."""
    return " ".join(text.translate(BOX_CHARS).split())


def usage_line(args: list[str]) -> str:
    """The ``Usage:`` block of ``args --help`` (up to the first blank line) on one line."""
    result = invoke([*args, "--help"])
    assert result.exit_code == 0, result.output
    lines = [line.strip() for line in result.stdout.splitlines()]
    start = next(index for index, line in enumerate(lines) if line.startswith("Usage:"))
    block: list[str] = []
    for line in lines[start:]:
        if not line:
            break
        block.append(line)
    return " ".join(block)


@pytest.fixture(autouse=True)
def profile_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, KEY)


@pytest.fixture
def api() -> Iterator[Any]:
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        yield router


# --- 1) angle-bracket metavars -------------------------------------------------------------


@pytest.mark.parametrize(("words", "expected"), POSITIONALS, ids=lambda value: str(value))
def test_every_positional_has_an_explicit_angle_metavar(words: list[str], expected: str) -> None:
    usage = usage_line(words)

    assert "{" not in usage and "}" not in usage, usage
    assert expected in usage, usage


@pytest.mark.parametrize("words", NO_POSITIONALS, ids=" ".join)
def test_commands_without_positionals_have_no_braces_either(words: list[str]) -> None:
    assert "{" not in usage_line(words)


def test_the_name_taking_arguments_use_the_neutral_sandbox_metavar() -> None:
    for words in (["snapshot", "create"], ["shell"]):
        usage = usage_line(words)
        assert "<sandbox>" in usage
        assert "ID" not in usage.replace("OPTIONS", "")


def test_a_missing_argument_names_the_metavar_in_the_usage_frame() -> None:
    result = invoke(["volume", "get"])

    assert result.exit_code == 2
    assert "<volume-id>" in flat(result.output)
    assert "{" not in flat(result.output).split("Try", 1)[0]


# --- 2) unified integer wording ------------------------------------------------------------

CREATE = ["sandbox", "create", "demo"]
BAD_INTEGERS: list[tuple[list[str], str, str]] = [
    ([*CREATE, "--auto-stop", "abc"], "--auto-stop", "must be a whole number, got 'abc'"),
    ([*CREATE, "--auto-delete", "1.5"], "--auto-delete", "must be a whole number, got '1.5'"),
    ([*CREATE, "--cpu-millicores", "x"], "--cpu-millicores", "must be a whole number, got 'x'"),
    ([*CREATE, "--memory-mib", ""], "--memory-mib", "must be a whole number, got ''"),
    ([*CREATE, "--disk-gib", "2g"], "--disk-gib", "must be a whole number, got '2g'"),
    (
        ["cmd", "start", SID, "--timeout", "abc", "--", "true"],
        "--timeout",
        "must be a whole number from 1 to 3600, got 'abc'",
    ),
    (
        ["cmd", "start", SID, "-t", "0", "--", "true"],
        "--timeout",
        "must be a whole number from 1 to 3600, got '0'",
    ),
    (
        ["cmd", "start", SID, "--timeout", "3601", "--", "true"],
        "--timeout",
        "must be a whole number from 1 to 3600, got '3601'",
    ),
    (
        ["preview", SID, "8080", "--ttl", "59"],
        "--ttl",
        "must be a whole number from 60 to 604800, got '59'",
    ),
    (
        ["preview", SID, "8080", "--ttl", "abc"],
        "--ttl",
        "must be a whole number from 60 to 604800, got 'abc'",
    ),
    (
        ["preview", SID, "8080", "--ttl", "-5"],
        "--ttl",
        "must be a whole number from 60 to 604800, got '-5'",
    ),
]


@pytest.mark.parametrize(
    ("args", "hint", "wording"), BAD_INTEGERS, ids=lambda value: str(value)[:40]
)
def test_a_bad_integer_gets_the_unified_wording_and_sends_nothing(
    api: Any, args: list[str], hint: str, wording: str
) -> None:
    result = invoke(args)

    assert result.exit_code == 2, result.output
    text = flat(result.output)
    assert f"Invalid value for {hint}" in text and wording in text
    assert list(api.calls) == []


def test_the_unified_wording_also_holds_under_json(api: Any) -> None:
    result = invoke([*CREATE, "--auto-stop", "abc"], as_json=True)

    assert result.exit_code == 2
    document = json.loads(result.stdout)
    assert "must be a whole number, got 'abc'" in json.dumps(document)
    assert list(api.calls) == []


def test_valid_create_integers_are_unchanged_including_zero_and_negative(api: Any) -> None:
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json()))

    result = invoke(
        [
            *CREATE,
            "--auto-stop",
            "0",
            "--auto-delete",
            "-1",
            "--cpu-millicores",
            "500",
            "--memory-mib",
            "256",
            "--disk-gib",
            "2",
        ]
    )

    assert result.exit_code == 0, result.output
    body = json.loads(route.calls.last.request.content)
    assert body["auto_stop_minutes"] == 0 and body["auto_delete_minutes"] == -1
    assert body["resources"] == {"cpu_millicores": 500, "memory_mib": 256, "disk_gib": 2}


def test_the_integer_options_show_an_integer_metavar_in_the_help() -> None:
    text = flat(invoke(["sandbox", "create", "--help"]).stdout)

    assert "--auto-stop INTEGER" in text and "--disk-gib INTEGER" in text
    assert "--timeout" in flat(invoke(["cmd", "start", "--help"]).stdout)


# --- 3) empty ids and emails ---------------------------------------------------------------

EMPTY_CASES: list[list[str]] = [
    ["volume", "get", ""],
    ["volume", "rm", ""],
    ["snapshot", "get", ""],
    ["snapshot", "rm", ""],
    ["members", "set-role", "", "--role", "admin"],
    ["members", "remove", ""],
    ["members", "add", "", "Ada", "--role", "admin"],
]


@pytest.mark.parametrize("args", EMPTY_CASES, ids=" ".join)
def test_an_empty_id_is_a_usage_error_and_nothing_is_sent(api: Any, args: list[str]) -> None:
    result = invoke(args)

    assert result.exit_code == 2, result.output
    assert "must not be empty" in flat(result.output)
    assert list(api.calls) == []


def test_an_empty_members_remove_no_longer_reports_success(api: Any) -> None:
    api.delete("/v1/org/members/").respond(204)

    result = invoke(["members", "remove", ""])

    assert result.exit_code == 2
    assert "removed" not in result.output
    assert list(api.calls) == []


def test_an_empty_id_is_one_json_usage_object_under_json(api: Any) -> None:
    result = invoke(["volume", "get", ""], as_json=True)

    assert result.exit_code == 2
    assert "must not be empty" in json.dumps(json.loads(result.stdout))
    assert list(api.calls) == []


# --- 4) partial rm failure is one json document --------------------------------------------


def route_delete_ok(api: Any, sandbox_id: str) -> None:
    api.delete(f"{SANDBOXES_URL}/{sandbox_id}").respond(
        200, json=envelope(sandbox_json(sandbox_id, "destroying"))
    )


def test_a_partial_rm_failure_is_one_json_document(api: Any) -> None:
    route_delete_ok(api, SID)
    api.delete(f"{SANDBOXES_URL}/{OTHER_SID}").respond(
        404, json=error_envelope("NOT_FOUND", "no such sandbox")
    )

    result = invoke(["sandbox", "rm", SID, OTHER_SID], as_json=True)

    assert result.exit_code == 1
    document = json.loads(result.stdout)  # the whole stdout is ONE document
    assert document["error"]["code"] == "NOT_FOUND"
    assert [item["id"] for item in document["processed"]] == [SID]


def test_a_name_that_matches_nothing_joins_the_same_document(api: Any) -> None:
    route_delete_ok(api, SID)
    api.get(SANDBOXES_URL).respond(200, json=envelope([]))

    result = invoke(["sandbox", "rm", SID, "ghost"], as_json=True)

    assert result.exit_code == 1
    document = json.loads(result.stdout)
    assert document["error"]["code"] == "NOT_FOUND"
    assert [item["id"] for item in document["processed"]] == [SID]


def test_a_first_ref_failure_has_no_processed_list(api: Any) -> None:
    api.delete(f"{SANDBOXES_URL}/{SID}").respond(
        404, json=error_envelope("NOT_FOUND", "no such sandbox")
    )

    result = invoke(["sandbox", "rm", SID, OTHER_SID], as_json=True)

    document = json.loads(result.stdout)
    assert result.exit_code == 1 and "processed" not in document and "error" in document


def test_a_complete_rm_keeps_its_success_shape(api: Any) -> None:
    route_delete_ok(api, SID)

    single = json.loads(invoke(["sandbox", "rm", SID], as_json=True).stdout)

    assert single["id"] == SID


# --- 5) validation errors read as location: message ----------------------------------------


def validation_details(count: int) -> dict[str, Any]:
    errors = [
        {"loc": ["body", f"field{index}"], "msg": f"problem {index}", "type": "value_error"}
        for index in range(count)
    ]
    return {"errors": errors}


def route_validation_failure(api: Any) -> None:
    envelope_422 = error_envelope(
        "VALIDATION_ERROR", "request validation failed", validation_details(2)
    )
    api.post(SANDBOXES_URL).respond(422, json=envelope_422)


def test_a_validation_answer_is_readable_pairs_in_text(api: Any) -> None:
    route_validation_failure(api)

    result = invoke(["sandbox", "create", "demo"])

    assert result.exit_code == 1
    assert "body.field0: problem 0; body.field1: problem 1" in result.stderr
    assert '"loc"' not in result.stderr and "'loc'" not in result.stderr


def test_a_validation_answer_keeps_the_structured_list_under_json(api: Any) -> None:
    route_validation_failure(api)

    result = invoke(["sandbox", "create", "demo"], as_json=True)

    errors = json.loads(result.stdout)["error"]["details"]["errors"]
    assert errors[0] == {"loc": ["body", "field0"], "msg": "problem 0", "type": "value_error"}


def test_a_long_validation_list_is_capped_with_a_count() -> None:
    summary = validation_summary(validation_details(9)["errors"], "")

    assert summary is not None
    assert summary.count("; ") == 5  # five pairs, then the count note
    assert summary.endswith("and 4 more") and "field5" not in summary


def test_the_validation_summary_is_sanitised() -> None:
    errors = [{"loc": ["body", f"x{ESC}]0;pwned\x07"], "msg": f"bad {KEY} value{ESC}[31m"}]

    summary = validation_summary(errors, KEY)

    assert summary is not None
    assert ESC not in summary and KEY not in summary and "\x07" not in summary


def test_entries_without_a_message_fall_back_to_the_plain_detail() -> None:
    error = ApiError("bad", code="VALIDATION_ERROR", details={"errors": [{"loc": ["a"]}]})

    assert validation_summary([{"loc": ["a"]}], "") is None
    assert "errors=" in describe_error(error) and "loc" in describe_error(error)


# --- 6) the truncation marker is out of the data -------------------------------------------


def test_a_cut_list_in_details_stays_pure_with_a_sibling_count() -> None:
    details = {"items": list(range(MAX_RELAYED_ENTRIES + 20)), "name": "x"}

    cleaned = error_payload(ApiError("boom", code="E", details=details))["error"]["details"]

    assert cleaned["items"] == list(range(MAX_RELAYED_ENTRIES))
    assert cleaned[f"items{BEYOND_CAP_SUFFIX}"] == 20
    assert cleaned["name"] == "x"


def test_a_cut_details_mapping_has_no_marker_entry_and_a_sibling_count() -> None:
    details = {f"k{index:03d}": index for index in range(MAX_RELAYED_ENTRIES + 10)}

    error = error_payload(ApiError("boom", code="E", details=details))["error"]

    assert len(error["details"]) == MAX_RELAYED_ENTRIES
    assert ELLIPSIS not in error["details"]
    assert error[f"details{BEYOND_CAP_SUFFIX}"] == 10


def test_a_cut_nested_mapping_reports_its_count_next_to_it() -> None:
    inner = {f"k{index:03d}": index for index in range(MAX_RELAYED_ENTRIES + 3)}

    cleaned, omitted = relay_value({"inner": inner}, "")

    assert omitted == 0 and len(cleaned["inner"]) == MAX_RELAYED_ENTRIES
    assert cleaned[f"inner{BEYOND_CAP_SUFFIX}"] == 3


def test_collections_at_the_cap_get_no_count() -> None:
    full = {"items": list(range(MAX_RELAYED_ENTRIES))}

    assert relay_value(full, "") == (full, 0)


def test_the_text_line_says_how_many_were_dropped_without_a_marker_entry() -> None:
    details = {f"k{index:03d}": index for index in range(MAX_RELAYED_ENTRIES + 5)}

    text = describe_error(ApiError("boom", code="E", details=details))

    assert text.endswith("and 5 more)") and f"{ELLIPSIS}=" not in text
    assert f"k{MAX_RELAYED_ENTRIES + 4:03d}" not in text


def test_a_cut_list_in_the_text_line_is_a_pure_sibling_pair() -> None:
    details = {"items": list(range(MAX_RELAYED_ENTRIES + 2))}

    text = describe_error(ApiError("boom", code="E", details=details))

    assert "and 2 more" in text and f"items{BEYOND_CAP_SUFFIX}" not in text


# --- 7) small fixes ------------------------------------------------------------------------


def test_the_fragment_mask_keeps_the_closing_parenthesis() -> None:
    shown = sanitise_text("unexpected extra argument (http://host/path#secret)", api_key=KEY)

    assert shown.endswith("#***)") and "secret" not in shown


def test_the_fragment_mask_still_masks_everything_else() -> None:
    assert "frag" not in sanitise_text("see http://h/p#frag now", api_key=KEY)
    assert "frag" not in sanitise_text("see http://h/p#frag, then", api_key=KEY)
    assert "#123" in sanitise_text("issue #123 is open", api_key=KEY)


def test_the_parenthesis_survives_in_the_typer_extra_argument_echo(api: Any) -> None:
    result = invoke(["volume", "list", "http://h/p#frag"])

    assert result.exit_code == 2
    text = flat(result.output)
    assert "http://h/p#***)" in text and "frag" not in text


def test_the_cmd_start_help_has_no_hand_written_usage_line() -> None:
    text = flat(invoke(["cmd", "start", "--help"]).stdout)

    assert text.count("Usage:") == 1
    assert "SANDBOX [--session ID]" not in text


def test_a_lone_negative_port_gets_the_unified_port_wording(api: Any) -> None:
    result = invoke(["preview", SID, "-5"])

    assert result.exit_code == 2
    text = flat(result.output)
    assert "Invalid value for <port>" in text
    assert "must be a whole number from 1024 to 65535, got '-5'" in text
    assert "No such option" not in text
    assert list(api.calls) == []


def test_a_negative_port_is_the_same_usage_error_under_json(api: Any) -> None:
    result = invoke(["preview", SID, "-5"], as_json=True)

    assert result.exit_code == 2
    message = json.dumps(json.loads(result.stdout))
    assert "must be a whole number from 1024 to 65535, got '-5'" in message


def test_a_real_unknown_option_is_still_an_unknown_option(api: Any) -> None:
    result = invoke(["preview", SID, "80", "--bogus"])

    assert result.exit_code == 2
    assert "No such option" in flat(result.output)


def test_negative_numbers_are_hoisted_only_when_they_are_positional() -> None:
    value_options = frozenset({"--ttl"})

    assert hoist_negative_numbers(["sbx", "-5"], value_options) == ["sbx", "--", "-5"]
    assert hoist_negative_numbers(["sbx", "-5", "--ttl", "90"], value_options) == [
        "sbx",
        "--ttl",
        "90",
        "--",
        "-5",
    ]
    assert hoist_negative_numbers(["sbx", "80", "--ttl", "-5"], value_options) == [
        "sbx",
        "80",
        "--ttl",
        "-5",
    ]
    assert hoist_negative_numbers(["sbx", "--", "-5"], value_options) == ["sbx", "--", "-5"]
    assert hoist_negative_numbers(["sbx", "80"], value_options) == ["sbx", "80"]
