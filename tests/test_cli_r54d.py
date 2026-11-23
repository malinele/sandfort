"""CLI round 54, batch d: a profile api key of the wrong json type is a damaged profile.

A profile whose ``api_key`` is a number, null, a list, an object, a boolean or the empty
string is the unified usage error (exit 2, one ``USAGE_ERROR`` document under ``--json``)
naming the profile path, without printing the value. A missing profile, or a profile without
the key field, stays "not logged in". A string key still goes through the malformed-key check.
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
USAGE = 2
RUNNER = CliRunner()
BOTH_MODES = pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
TRACEBACK_MARKERS = ("Traceback", 'File "', "TypeError", "AttributeError")
NOT_LOGGED_IN = "not logged in"
NOT_A_STRING = "is not a string"
EMPTY = "is empty"
NOT_FOUND = {
    "success": False,
    "data": None,
    "error": {"code": "NOT_FOUND", "message": "gone", "details": {}, "request_id": "req_1"},
    "meta": None,
}
# Each value carries a marker that must never reach the output.
MARKER = "9137046528"
WRONG_TYPES: dict[str, Any] = {
    "integer": int(MARKER),
    "float": float(MARKER + ".5"),
    "null": None,
    "list": [f"sf_{MARKER}"],
    "empty-list": [],
    "object": {"key": f"sf_{MARKER}"},
    "true": True,
    "false": False,
}


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def flat(text: str) -> str:
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


def reported(result: Any, as_json: bool) -> str:
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


def write_profile(body: dict[str, Any]) -> None:
    path = config.profile_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body), encoding="utf-8")


@pytest.fixture(autouse=True)
def config_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    # Wide enough that the text error box shows the whole tmp profile path unwrapped.
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("TERMINAL_WIDTH", "400")


@pytest.fixture
def router() -> Iterator[Any]:
    """Every request is answered with a NOT_FOUND envelope and counted."""
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        mock.route().mock(return_value=httpx.Response(404, json=NOT_FOUND))
        yield mock


def assert_damaged_key(result: Any, as_json: bool, router: Any, says: str) -> None:
    assert_clean(result)
    assert result.exit_code == USAGE
    assert router.calls.call_count == 0
    assert MARKER not in result.stdout + result.stderr
    shown = reported(result, as_json)
    assert says in shown
    assert f"api_key in {config.profile_path()}" in shown
    assert NOT_LOGGED_IN not in shown
    if as_json:
        assert_usage_json(result)


def assert_not_logged_in(result: Any, as_json: bool, router: Any) -> None:
    assert_clean(result)
    assert result.exit_code not in (0, USAGE)
    assert router.calls.call_count == 0
    shown = reported(result, as_json)
    assert NOT_LOGGED_IN in shown
    assert NOT_A_STRING not in shown and EMPTY not in shown
    if as_json:
        payload = json.loads(result.stdout)  # exactly one document
        assert list(payload) == ["error"]
        assert payload["error"]["code"] != "USAGE_ERROR"


# 1) wrong json types and the empty string --------------------------------------------------------


@BOTH_MODES
@pytest.mark.parametrize("value", list(WRONG_TYPES.values()), ids=list(WRONG_TYPES))
def test_a_key_of_the_wrong_type_is_a_usage_error(router: Any, as_json: bool, value: Any) -> None:
    write_profile({"base_url": BASE, "api_key": value})

    result = invoke(["sandbox", "list"], as_json=as_json)

    assert_damaged_key(result, as_json, router, NOT_A_STRING)


@BOTH_MODES
def test_an_empty_key_is_a_usage_error(router: Any, as_json: bool) -> None:
    write_profile({"base_url": BASE, "api_key": ""})

    result = invoke(["sandbox", "list"], as_json=as_json)

    assert_damaged_key(result, as_json, router, EMPTY)
    assert NOT_A_STRING not in reported(result, as_json)


@BOTH_MODES
def test_a_damaged_key_without_a_base_url_is_still_a_usage_error(
    router: Any, as_json: bool
) -> None:
    write_profile({"api_key": int(MARKER)})

    result = invoke(["sandbox", "list"], as_json=as_json)

    assert_damaged_key(result, as_json, router, NOT_A_STRING)


def test_the_environment_key_overrides_a_damaged_profile_key(
    router: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_profile({"base_url": BASE, "api_key": None})
    monkeypatch.setenv(config.API_KEY_ENV, KEY)

    result = invoke(["sandbox", "list"])

    assert_clean(result)
    assert result.exit_code != USAGE
    assert router.calls.call_count > 0


# 2) not logged in stays not logged in ------------------------------------------------------------


@BOTH_MODES
def test_a_profile_without_the_key_field_is_not_logged_in(router: Any, as_json: bool) -> None:
    write_profile({"base_url": BASE})

    result = invoke(["sandbox", "list"], as_json=as_json)

    assert_not_logged_in(result, as_json, router)


@BOTH_MODES
def test_a_missing_profile_is_not_logged_in(router: Any, as_json: bool) -> None:
    assert not config.profile_path().exists()

    result = invoke(["sandbox", "list"], as_json=as_json)

    assert_not_logged_in(result, as_json, router)


# 3) a string key keeps the malformed-key check ---------------------------------------------------


@BOTH_MODES
@pytest.mark.parametrize(
    "key", [f"sf_{MARKER} inner", "   ", f"sf_{MARKER}\x07"], ids=["space", "blank", "control"]
)
def test_a_string_key_still_goes_through_the_malformed_check(
    router: Any, as_json: bool, key: str
) -> None:
    write_profile({"base_url": BASE, "api_key": key})

    result = invoke(["sandbox", "list"], as_json=as_json)

    assert_damaged_key(result, as_json, router, config.MALFORMED_KEY_MESSAGE)


def test_a_valid_string_key_reaches_the_server(router: Any) -> None:
    write_profile({"base_url": BASE, "api_key": KEY})

    result = invoke(["sandbox", "list"])

    assert_clean(result)
    assert result.exit_code != USAGE
    assert router.calls.call_count > 0
    assert KEY not in result.stdout + result.stderr
