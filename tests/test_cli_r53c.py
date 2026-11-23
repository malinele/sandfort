"""CLI round 53, batch c: login prompt decoding, key length cap, invisible names, whole-number
echo and the validation message cap.

1. A hidden api key prompt fed bytes that are not valid UTF-8 is the usage error of every other
   malformed key (exit 2, nothing saved, key never echoed), not a traceback.
2. A configured key longer than ``MAX_API_KEY_CHARS`` is a "too long" usage error wherever the
   key check runs: ``login`` (flag and prompt, every mode), the environment and the profile.
3. A name made only of invisible format characters is blank, like an empty one.
4. A whole number typed with surrounding whitespace says so instead of echoing a plain number.
5. A validation message that lists allowed values fits whole in the text line; json is unchanged.
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
from sandfort_cli.sanitise import MAX_RELAYED_CHARS  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SECRET_PART = "sf_secret_part"
USAGE = 2
RUNNER = CliRunner()
BOTH_MODES = pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
TRACEBACK_MARKERS = ("Traceback", 'File "', "UnicodeDecodeError", "codec can't decode")
TOO_LONG = "is too long"
NOT_FOUND = {
    "success": False,
    "data": None,
    "error": {"code": "NOT_FOUND", "message": "gone", "details": {}, "request_id": "req_1"},
    "meta": None,
}
KEY_CREATE = ["key", "create", "ci", "--scope", "sandboxes:read"]


def invoke(args: list[str], *, as_json: bool = False, data: bytes | None = None) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args, input=data)


def flat(text: str) -> str:
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


def reported(result: Any, as_json: bool) -> str:
    """The error text of a failed run, flattened, from the stream that carries it."""
    return flat(result.stdout if as_json else result.stderr)


def assert_clean(result: Any) -> None:
    for stream in (result.stdout, result.stderr):
        assert not any(marker in stream for marker in TRACEBACK_MARKERS), stream
    assert result.exception is None or isinstance(result.exception, SystemExit)


def assert_usage_json(result: Any) -> None:
    payload = json.loads(result.stdout)  # exactly one document
    assert list(payload) == ["error"]
    error = payload["error"]
    assert error["code"] == "USAGE_ERROR" and error["source"] == "client"


@pytest.fixture(autouse=True)
def config_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)


@pytest.fixture
def logged_in() -> None:
    config.save_profile(BASE, KEY)


@pytest.fixture
def router() -> Iterator[Any]:
    """Every request is answered with a NOT_FOUND envelope and counted."""
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        mock.route().mock(return_value=httpx.Response(404, json=NOT_FOUND))
        yield mock


# 1) the hidden key prompt on stdin that is not UTF-8 -------------------------------------------


def test_a_key_prompt_fed_invalid_utf8_is_the_malformed_key_usage_error(router: Any) -> None:
    result = invoke(["login", "--base-url", BASE, "--no-verify"], data=b"sf_secret_part\xff\xfe\n")

    assert_clean(result)
    assert result.exit_code == USAGE
    assert router.calls.call_count == 0
    assert not config.profile_path().exists()
    assert SECRET_PART not in result.stdout + result.stderr
    shown = reported(result, as_json=False)
    assert "Invalid value for stdin" in shown  # r64: the source is named, not --api-key
    assert f"the api key read from stdin {config.MALFORMED_KEY_MESSAGE}" in shown


# 2) the key length cap -------------------------------------------------------------------------


def long_key(length: int) -> str:
    return "sf_" + "a" * (length - 3)


@BOTH_MODES
@pytest.mark.parametrize("no_verify", [False, True], ids=["verify", "no-verify"])
def test_login_refuses_a_key_over_the_cap(router: Any, as_json: bool, no_verify: bool) -> None:
    key = long_key(config.MAX_API_KEY_CHARS + 1)
    args = ["login", "--base-url", BASE, "--api-key", key]

    result = invoke(args + (["--no-verify"] if no_verify else []), as_json=as_json)

    assert_clean(result)
    assert result.exit_code == USAGE
    assert router.calls.call_count == 0
    assert not config.profile_path().exists()
    assert key not in result.stdout + result.stderr
    shown = reported(result, as_json)
    assert "Invalid value for --api-key" in shown and TOO_LONG in shown
    if as_json:
        assert_usage_json(result)


def test_login_refuses_a_prompted_key_over_the_cap(router: Any) -> None:
    key = long_key(config.MAX_API_KEY_CHARS + 1)

    result = invoke(["login", "--base-url", BASE, "--no-verify"], data=f"{key}\n".encode())

    assert result.exit_code == USAGE
    assert not config.profile_path().exists()
    assert key not in result.stdout + result.stderr
    assert TOO_LONG in reported(result, as_json=False)


def test_a_key_at_the_cap_is_still_saved() -> None:
    key = long_key(config.MAX_API_KEY_CHARS)

    result = invoke(["login", "--base-url", BASE, "--api-key", key, "--no-verify"])

    assert result.exit_code == 0, result.output
    assert config.load_profile()["api_key"] == key


@BOTH_MODES
def test_a_too_long_key_in_the_environment_is_a_usage_error(
    router: Any, monkeypatch: pytest.MonkeyPatch, as_json: bool
) -> None:
    key = long_key(1_000_000)
    monkeypatch.setenv(config.BASE_URL_ENV, BASE)
    monkeypatch.setenv(config.API_KEY_ENV, key)

    result = invoke(["sandbox", "list"], as_json=as_json)

    assert_clean(result)
    assert result.exit_code == USAGE
    assert router.calls.call_count == 0
    assert key not in result.stdout + result.stderr
    shown = reported(result, as_json)
    assert config.API_KEY_ENV in shown and TOO_LONG in shown
    if as_json:
        assert_usage_json(result)


@BOTH_MODES
def test_a_too_long_key_in_the_profile_is_a_usage_error(router: Any, as_json: bool) -> None:
    key = long_key(config.MAX_API_KEY_CHARS + 1)
    config.save_profile(BASE, key)  # the profile writer does not check; the later commands do

    result = invoke(["sandbox", "list"], as_json=as_json)

    assert_clean(result)
    assert result.exit_code == USAGE
    assert router.calls.call_count == 0
    assert key not in result.stdout + result.stderr
    shown = reported(result, as_json)
    assert "api_key in" in shown and TOO_LONG in shown
    if as_json:
        assert_usage_json(result)


# 3) names made only of invisible characters ----------------------------------------------------

INVISIBLE_NAMES = {
    "zero-width-space": "​",
    "joiners": "‌‍",
    "bidi-marks": "‎‏‮",
    "word-joiner-and-spaces": " ⁠ ​ ",
    "byte-order-mark": "﻿",
    "soft-hyphen": "­",
}


@BOTH_MODES
@pytest.mark.parametrize("name", list(INVISIBLE_NAMES.values()), ids=list(INVISIBLE_NAMES))
def test_a_name_of_invisible_characters_is_blank(
    router: Any, logged_in: None, as_json: bool, name: str
) -> None:
    result = invoke(["sandbox", "get", name], as_json=as_json)

    assert_clean(result)
    assert result.exit_code == USAGE
    assert router.calls.call_count == 0
    assert "Invalid value for <sandbox>: must not be empty" in reported(result, as_json)
    if as_json:
        assert_usage_json(result)


def test_a_key_name_of_invisible_characters_is_blank_too(router: Any, logged_in: None) -> None:
    result = invoke(["key", "create", "​‍", "--scope", "sandboxes:read"])

    assert result.exit_code == USAGE
    assert router.calls.call_count == 0
    assert "Invalid value for <name>: must not be empty" in reported(result, as_json=False)


def test_a_name_with_a_visible_character_still_reaches_the_server(
    router: Any, logged_in: None
) -> None:
    result = invoke(["sandbox", "get", "a​"])

    assert result.exit_code != USAGE
    assert router.calls.call_count > 0


# 4) the whole-number echo ----------------------------------------------------------------------


@BOTH_MODES
@pytest.mark.parametrize(
    "typed", [" 5 ", "5 ", " 5", "\t5"], ids=["both", "after", "before", "tab"]
)
def test_a_whole_number_with_surrounding_whitespace_says_so(
    router: Any, logged_in: None, as_json: bool, typed: str
) -> None:
    result = invoke([*KEY_CREATE, "--max-sandboxes", typed], as_json=as_json)

    assert_clean(result)
    assert result.exit_code == USAGE
    assert router.calls.call_count == 0
    shown = reported(result, as_json)
    assert "must be a whole number greater than 0, got '5'" in shown
    assert "surrounding whitespace is not allowed" in shown
    if as_json:
        assert_usage_json(result)


def test_a_whole_number_without_spaces_gets_no_whitespace_note(
    router: Any, logged_in: None
) -> None:
    result = invoke([*KEY_CREATE, "--max-sandboxes", "x"])

    assert result.exit_code == USAGE
    shown = reported(result, as_json=False)
    assert "got 'x'" in shown
    assert "surrounding whitespace" not in shown


# 5) the validation message cap -----------------------------------------------------------------

REAL_SCOPES = [
    "org:read",
    "sandboxes:read",
    "sandboxes:write",
    "toolbox:use",
    "snapshots:read",
    "snapshots:write",
    "volumes:read",
    "volumes:write",
    "api_keys:admin",
    "webhooks:write",
    "usage:read",
    "audit:read",
]
LONG_LIST = [f"scope_{number:02d}:read" for number in range(30)]


def allowed_values_message(values: list[str]) -> str:
    quoted = [f"'{value}'" for value in values]
    return f"Input should be {', '.join(quoted[:-1])} or {quoted[-1]}"


def validation_reply(values: list[str]) -> httpx.Response:
    what = allowed_values_message(values)
    where = ["body", "scopes", "0"]
    body = {
        "success": False,
        "data": None,
        "error": {
            "code": "VALIDATION_ERROR",
            "message": f"request validation failed: {'.'.join(where)}: {what}",
            "details": {"errors": [{"loc": where, "msg": what, "type": "enum"}]},
            "request_id": "req_2",
        },
        "meta": None,
    }
    return httpx.Response(422, json=body)


@pytest.fixture
def validation_router(logged_in: None) -> Iterator[Any]:
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


@pytest.mark.parametrize("values", [REAL_SCOPES, LONG_LIST], ids=["documented", "thirty"])
def test_the_text_line_lists_every_allowed_value(validation_router: Any, values: list[str]) -> None:
    validation_router.route().mock(return_value=validation_reply(values))

    result = invoke(KEY_CREATE)

    assert_clean(result)
    assert result.exit_code == 1
    shown = flat(result.stderr)
    assert f"'{values[0]}'" in shown
    assert f"or '{values[-1]}'" in shown  # the list is not cut before its end
    assert "…" not in shown


def test_the_json_error_is_cut_as_before(validation_router: Any) -> None:
    validation_router.route().mock(return_value=validation_reply(LONG_LIST))

    result = invoke(KEY_CREATE, as_json=True)

    assert result.exit_code == 1
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert len(error["message"]) <= MAX_RELAYED_CHARS
    assert f"or '{LONG_LIST[-1]}'" not in error["message"]
    entry = error["details"]["errors"][0]
    assert len(entry["msg"]) <= MAX_RELAYED_CHARS
