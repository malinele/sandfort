"""CLI round 52, batch g: error-message findings from four testers.

1. A validation answer prints its ``location: message`` pairs once in text mode (the server's
   copy of the first pair and its ``(and N more)`` are dropped from the head).
2. A cut collection in ``details`` says ``and N more`` in text instead of its raw
   ``<key>_beyond_cap`` sibling; the json document keeps the sibling exactly as before.
3. ``cp`` download: a destination below a regular file says "is not a directory"; a remote
   directory without ``-r`` suggests ``-r``, not an SDK method name.
4. ``preview`` refuses a port below the server's minimum (1024) locally.
5. The shared whole-number parser accepts plain ASCII digits only (and the minus sign).
6. ``login`` refuses a key the CLI would later refuse as malformed, before saving anything.
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

import pytest  # noqa: E402
import respx  # noqa: E402
import typer  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.cmd_cmd import MAX_PORT, MIN_PREVIEW_PORT  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.output import describe_error, error_payload  # noqa: E402
from sandfort_cli.sandboxes import parse_whole_number  # noqa: E402
from sandfort_cli.sanitise import MAX_RELAYED_ENTRIES  # noqa: E402
from sandfort_sdk import ApiError  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SID = "sbx_1"
USAGE = 2
PLATFORM_ERROR = 125
RUNNER = CliRunner()
BOTH_MODES = pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
SANDBOX_URL = f"/v1/sandboxes/{SID}"
DOWNLOAD_ROUTE = r".*/fs/download$"
VALIDATION_BASE = "request validation failed"
STARTED = {"id": SID, "name": "demo", "state": "started"}


def invoke(args: list[str], *, as_json: bool = False, stdin: str | None = None) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args, input=stdin)


def flat(text: str) -> str:
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


def ok(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data, "error": None, "meta": None}


def failure(code: str, message: str, details: Any) -> dict[str, Any]:
    error = {"code": code, "message": message, "details": details, "request_id": "req_1"}
    return {"success": False, "data": None, "error": error, "meta": None}


def issues(count: int) -> list[dict[str, Any]]:
    return [
        {"loc": ["body", f"field{index}"], "msg": f"problem {index}", "type": "value_error"}
        for index in range(count)
    ]


def server_message(errors: list[dict[str, Any]]) -> str:
    """The message the server builds (``src/sandfort/api/errors.py::_validation_message``)."""
    first = errors[0]
    message = f"{VALIDATION_BASE}: {'.'.join(first['loc'])}: {first['msg']}"
    if len(errors) > 1:
        message += f" (and {len(errors) - 1} more)"
    return message


def preview_reply(port: int) -> dict[str, Any]:
    return ok(
        {
            "url": f"https://{port}-sbx-1.preview.test/",
            "token": "t",
            "port": port,
            "expires_at": "2026-11-10T12:00:00+00:00",
        }
    )


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, KEY)


@pytest.fixture
def api() -> Iterator[Any]:
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


def route_create_failure(api: Any, envelope: dict[str, Any], status: int = 422) -> None:
    api.post("/v1/sandboxes").respond(status, json=envelope)


def validation_envelope(count: int) -> dict[str, Any]:
    errors = issues(count)
    return failure("VALIDATION_ERROR", server_message(errors), {"errors": errors})


# --- 1) validation pairs are printed once ------------------------------------------------------


def test_a_validation_answer_prints_each_pair_once(api: Any) -> None:
    route_create_failure(api, validation_envelope(3))

    result = invoke(["sandbox", "create", "demo"])

    assert result.exit_code == 1
    line = flat(result.stderr)
    assert line == (
        "error: VALIDATION_ERROR: request validation failed: body.field0: problem 0; "
        "body.field1: problem 1; body.field2: problem 2 (request id req_1)"
    )
    assert line.count("body.field0: problem 0") == 1
    assert "errors=[" not in line and "(and 2 more)" not in line


def test_a_long_validation_list_has_one_count_that_matches(api: Any) -> None:
    route_create_failure(api, validation_envelope(8))

    line = flat(invoke(["sandbox", "create", "demo"]).stderr)

    assert line.count("body.field0: problem 0") == 1
    assert "body.field4: problem 4; and 3 more" in line
    assert "field5" not in line and "and 7 more" not in line
    assert line.count("more") == 1


def test_other_details_next_to_the_validation_list_stay_in_parentheses() -> None:
    errors = issues(1)
    details = {"errors": errors, "hint": "x"}
    exc = ApiError(server_message(errors), code="VALIDATION_ERROR", details=details)

    text = describe_error(exc)

    assert text == "VALIDATION_ERROR: request validation failed: body.field0: problem 0 (hint=x)"


def test_a_message_that_does_not_repeat_the_pair_is_kept_whole() -> None:
    issue = {"loc": ["query", "foo"], "msg": "Extra inputs are not permitted"}
    message = "unknown query parameter `foo`; accepted: a"
    exc = ApiError(message, code="VALIDATION_ERROR", details={"errors": [issue]})

    text = describe_error(exc)

    assert text == f"VALIDATION_ERROR: {message}: query.foo: Extra inputs are not permitted"


def test_the_cursor_answer_names_its_location_once() -> None:
    issue = {"type": "value_error", "loc": ["query", "cursor"], "msg": "invalid cursor"}
    message = "invalid cursor: query.cursor"
    exc = ApiError(message, code="VALIDATION_ERROR", details={"errors": [issue]})

    assert describe_error(exc) == "VALIDATION_ERROR: invalid cursor: query.cursor: invalid cursor"


def test_the_json_validation_document_is_unchanged(api: Any) -> None:
    envelope = validation_envelope(8)
    route_create_failure(api, envelope)

    result = invoke(["sandbox", "create", "demo"], as_json=True)

    assert result.exit_code == 1
    assert json.loads(result.stdout) == {"error": envelope["error"]}


# --- 2) a cut collection says "and N more" in text ----------------------------------------------

CUT_NAMES = [f"n{index:03d}" for index in range(MAX_RELAYED_ENTRIES + 10)]


def test_a_cut_list_in_details_reads_and_n_more_in_text(api: Any) -> None:
    route_create_failure(api, failure("CONFLICT", "refused", {"names": CUT_NAMES}), status=409)

    line = flat(invoke(["sandbox", "create", "demo"]).stderr)

    assert "names_beyond_cap" not in line
    assert f'"n{MAX_RELAYED_ENTRIES - 1:03d}"; and 10 more]' in line
    assert f"n{MAX_RELAYED_ENTRIES:03d}" not in line


def test_a_cut_list_keeps_its_json_sibling_exactly(api: Any) -> None:
    details = {"names": CUT_NAMES, "reason": "x"}
    route_create_failure(api, failure("CONFLICT", "refused", details), status=409)

    document = json.loads(invoke(["sandbox", "create", "demo"], as_json=True).stdout)

    assert document == {
        "error": {
            "code": "CONFLICT",
            "message": "refused",
            "details": {
                "names": CUT_NAMES[:MAX_RELAYED_ENTRIES],
                "names_beyond_cap": 10,
                "reason": "x",
            },
            "request_id": "req_1",
        }
    }


def test_a_cut_mapping_and_the_cut_details_both_read_and_n_more() -> None:
    inner = {f"k{index:03d}": index for index in range(MAX_RELAYED_ENTRIES + 3)}
    details: dict[str, Any] = {"inner": inner}
    details.update({f"z{index:03d}": index for index in range(MAX_RELAYED_ENTRIES + 1)})
    exc = ApiError("boom", code="E", details=details)

    text = describe_error(exc)
    payload = error_payload(exc)["error"]

    last = MAX_RELAYED_ENTRIES - 1
    assert "_beyond_cap" not in text
    assert f'"k{last:03d}":{last}; and 3 more}}' in text
    assert text.endswith("; and 2 more)")
    assert payload["details"]["inner_beyond_cap"] == 3
    assert payload["details_beyond_cap"] == 2


def test_an_uncut_collection_has_no_note() -> None:
    text = describe_error(ApiError("boom", code="E", details={"names": ["a", "b"]}))

    assert text == 'E: boom (names=["a","b"])'


# --- 3) cp download messages --------------------------------------------------------------------


def report(result: Any, as_json: bool) -> str:
    if as_json:
        return str(json.loads(result.stdout)["error"]["message"])
    return flat(result.stderr)


@BOTH_MODES
@pytest.mark.parametrize("below", [("out.txt",), ("sub", "out.txt")], ids=["parent", "ancestor"])
def test_a_destination_below_a_regular_file_is_not_a_directory(
    api: Any, tmp_path: Path, as_json: bool, below: tuple[str, ...]
) -> None:
    blocker = tmp_path / "file.txt"
    blocker.write_text("x")
    target = blocker.joinpath(*below)

    result = invoke(["cp", f"{SID}:/w/a.txt", str(target)], as_json=as_json)

    assert result.exit_code == USAGE
    message = report(result, as_json)
    assert f"destination {blocker} is not a directory" in message
    assert "does not exist" not in message
    assert api.calls.call_count == 0
    if as_json:
        assert json.loads(result.stdout)["error"]["source"] == "client"


def test_a_missing_destination_directory_still_does_not_exist(api: Any, tmp_path: Path) -> None:
    result = invoke(["cp", f"{SID}:/w/a.txt", str(tmp_path / "missing" / "out.txt")])

    assert result.exit_code == USAGE
    assert "does not exist" in flat(result.stderr)


@BOTH_MODES
def test_a_remote_directory_without_r_suggests_the_flag(
    api: Any, tmp_path: Path, as_json: bool
) -> None:
    api.get(SANDBOX_URL).respond(200, json=ok(STARTED))
    api.get(path__regex=DOWNLOAD_ROUTE).respond(
        200, content=b"tar bytes", headers={"content-type": "application/x-tar"}
    )
    landing = tmp_path / "land"
    landing.mkdir()

    result = invoke(["cp", f"{SID}:/w/dir", str(landing / "out")], as_json=as_json)

    assert result.exit_code == PLATFORM_ERROR
    message = report(result, as_json)
    assert "/w/dir is a directory; use -r for directories" in message
    assert "download_dir" not in message and "download_file" not in message
    assert list(landing.iterdir()) == []  # no target and no .part file


# --- 4) preview port range matches the server ---------------------------------------------------


def test_the_server_spec_range_is_the_client_range() -> None:
    spec = json.loads((ROOT / "openapi" / "sandfort.v1.json").read_text())
    port = spec["components"]["schemas"]["MintPreviewTokenRequest"]["properties"]["port"]

    assert (MIN_PREVIEW_PORT, MAX_PORT) == (int(port["minimum"]), int(port["maximum"]))


@BOTH_MODES
@pytest.mark.parametrize("raw", ["1", "80", "1023"])
def test_a_low_preview_port_is_a_local_usage_error(api: Any, as_json: bool, raw: str) -> None:
    result = invoke(["preview", SID, raw], as_json=as_json)

    assert result.exit_code == USAGE
    expected = f"must be a whole number from 1024 to 65535, got '{raw}'"
    if as_json:
        error = json.loads(result.stdout)["error"]
        assert error["code"] == "USAGE_ERROR" and error["source"] == "client"
        assert f"Invalid value for <port>: {expected}" in flat(error["message"])
    else:
        assert f"Invalid value for <port>: {expected}" in flat(result.output)
    assert api.calls.call_count == 0


def test_the_minimum_preview_port_is_sent(api: Any) -> None:
    api.get(SANDBOX_URL).respond(200, json=ok(STARTED))
    minted = api.post(f"{SANDBOX_URL}/preview-tokens").respond(201, json=preview_reply(1024))

    result = invoke(["preview", SID, "1024"])

    assert result.exit_code == 0, result.output
    assert json.loads(minted.calls.last.request.content)["port"] == 1024


# --- 5) the whole-number parser takes plain ASCII digits only -----------------------------------

ODD_NUMBERS = ["+5", " 5", "5 ", "1_000", "٣", "５", "5\n", "--5", "- 5"]
KEY_CREATE = ["key", "create", "k", "--scope", "sandboxes:read", "--label", "t=a"]
NUMBER_COMMANDS = {
    "exec-timeout": lambda raw: ["exec", "--timeout", raw, SID, "--", "true"],
    "cmd-start-timeout": lambda raw: ["cmd", "start", SID, "--timeout", raw, "--", "true"],
    "preview-port": lambda raw: ["preview", SID, "--", raw],
    "preview-ttl": lambda raw: ["preview", SID, "3000", "--ttl", raw],
    "create-cpu": lambda raw: ["sandbox", "create", "demo", "--cpu-millicores", raw],
    "create-auto-stop": lambda raw: ["sandbox", "create", "demo", "--auto-stop", raw],
    "key-max-sandboxes": lambda raw: [*KEY_CREATE, "--max-sandboxes", raw],
}


@pytest.mark.parametrize("raw", ODD_NUMBERS, ids=repr)
@pytest.mark.parametrize("command", sorted(NUMBER_COMMANDS))
def test_odd_number_forms_are_usage_errors_everywhere(api: Any, command: str, raw: str) -> None:
    result = invoke(NUMBER_COMMANDS[command](raw))

    assert result.exit_code == USAGE, result.output
    assert "must be a whole number" in flat(result.output)
    assert api.calls.call_count == 0


@pytest.mark.parametrize("raw", ["+5", " 5", "1_000", "٣", "５", "5 "], ids=repr)
def test_the_parser_refuses_what_int_would_take(raw: str) -> None:
    int(raw)  # python itself takes it

    with pytest.raises(typer.BadParameter) as caught:
        parse_whole_number(raw, "--x", low=None)

    assert "must be a whole number" in str(caught.value)


def test_the_parser_keeps_its_sign_rules() -> None:
    assert parse_whole_number("-5", "--x", low=None) == -5
    assert parse_whole_number("0", "--x", low=None) == 0
    assert parse_whole_number("007", "--x") == 7
    with pytest.raises(typer.BadParameter, match="greater than 0, got '-5'"):
        parse_whole_number("-5", "--x")


def test_plain_numbers_still_reach_the_server(api: Any) -> None:
    api.get(SANDBOX_URL).respond(200, json=ok(STARTED))
    minted = api.post(f"{SANDBOX_URL}/preview-tokens").respond(201, json=preview_reply(3000))

    result = invoke(["preview", SID, "3000", "--ttl", "600"])

    assert result.exit_code == 0, result.output
    assert json.loads(minted.calls.last.request.content) == {"port": 3000, "ttl_seconds": 600}


# --- 6) login refuses a malformed key before saving ---------------------------------------------

BAD_KEYS = ["sf_a b", "sf_a\tb", "sf_\x01x", "sf_\x7fx", "sf_éx", "sf_​x"]
LOGIN_MODES = {
    "default": [],
    "no-verify": ["--no-verify"],
    "verify-key": ["--verify-key"],
    "require-verified": ["--require-verified"],
}
MALFORMED_LINE = f"Invalid value for --api-key: {config.MALFORMED_KEY_MESSAGE}"
# r64: a key that came from stdin or the environment names that source, in a full sentence.
STDIN_MALFORMED_LINE = (
    f"Invalid value for stdin: the api key read from stdin {config.MALFORMED_KEY_MESSAGE}"
)
ENV_MALFORMED_LINE = (
    f"Invalid value for {config.API_KEY_ENV}: the api key in {config.API_KEY_ENV} "
    f"{config.MALFORMED_KEY_MESSAGE}"
)


@pytest.fixture
def fresh_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    directory = tmp_path / "fresh"
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(directory))
    return directory


def assert_refused_key(
    result: Any, fresh_config: Path, api: Any, as_json: bool, line: str = MALFORMED_LINE
) -> None:
    assert result.exit_code == USAGE, result.output
    if as_json:
        error = json.loads(result.stdout)["error"]
        assert error["code"] == "USAGE_ERROR" and error["source"] == "client"
        assert line in flat(error["message"])
    else:
        assert line in flat(result.output)
    assert api.calls.call_count == 0
    assert not (fresh_config / config.PROFILE_FILENAME).exists()


@BOTH_MODES
@pytest.mark.parametrize("mode", sorted(LOGIN_MODES))
@pytest.mark.parametrize("bad_key", BAD_KEYS, ids=repr)
def test_login_refuses_a_malformed_key_and_saves_nothing(
    api: Any, fresh_config: Path, as_json: bool, mode: str, bad_key: str
) -> None:
    args = ["login", "--base-url", BASE, "--api-key", bad_key, *LOGIN_MODES[mode]]

    result = invoke(args, as_json=as_json)

    assert_refused_key(result, fresh_config, api, as_json)
    assert bad_key not in result.output


@pytest.mark.parametrize("mode", sorted(LOGIN_MODES))
def test_a_prompted_malformed_key_is_refused_too(api: Any, fresh_config: Path, mode: str) -> None:
    result = invoke(["login", *LOGIN_MODES[mode]], stdin=f"{BASE}\nsf_a b\n")

    assert_refused_key(result, fresh_config, api, as_json=False, line=STDIN_MALFORMED_LINE)


def test_a_malformed_key_from_the_environment_is_refused(
    api: Any, fresh_config: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(config.API_KEY_ENV, "sf_a b")

    result = invoke(["login", "--base-url", BASE, "--no-verify"])

    assert_refused_key(result, fresh_config, api, as_json=False, line=ENV_MALFORMED_LINE)


def test_the_next_command_uses_the_same_wording(api: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(config.API_KEY_ENV, "sf_a b")

    result = invoke(["sandbox", "list"])

    assert result.exit_code == USAGE
    assert config.MALFORMED_KEY_MESSAGE in flat(result.output)


def test_a_well_formed_key_still_logs_in(api: Any, fresh_config: Path) -> None:
    result = invoke(["login", "--base-url", BASE, "--api-key", KEY, "--no-verify"])

    assert result.exit_code == 0, result.output
    assert (fresh_config / config.PROFILE_FILENAME).exists()
