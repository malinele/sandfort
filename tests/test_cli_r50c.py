"""CLI round 50, batch 3: finishing the configured-url path.

A control character anywhere in a configured url (userinfo included) is the unified usage
error, userinfo is dropped before the client is built (requests stay Bearer-authenticated),
the sandbox-create name pre-check cannot leak a traceback when the server is down, and a
profile whose base-url field is not a usable string is a malformed profile.
"""

import json
import logging
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
SANDBOXES_URL = "/v1/sandboxes"
RUNNER = CliRunner()
BOTH_MODES = pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
SOURCES = ("env", "profile")
TRACEBACK_MARKERS = ("Traceback", "InvalidURL", "httpx.", 'File "')
CONTROL_CHARS = {"vertical-tab": "\x0b", "escape": "\x1b"}
BAD_BASE_URL_FIELDS = {
    "number": 42,
    "null": None,
    "list": ["http://sandfort.test"],
    "empty-string": "",
}
EMPTY_LIST = {"success": True, "data": [], "error": None, "meta": None}


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def flat(text: str) -> str:
    """Text without the box-drawing frame, whitespace collapsed."""
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
        yield mock


def write_profile(profile: Path, fields: dict[str, Any]) -> None:
    profile.parent.mkdir(parents=True, exist_ok=True)
    profile.write_text(json.dumps(fields), encoding="utf-8")


def configure(monkeypatch: pytest.MonkeyPatch, profile: Path, source: str, url: str) -> None:
    """Supply ``url`` (and the key) through the environment or a written profile file."""
    if source == "env":
        monkeypatch.setenv(config.BASE_URL_ENV, url)
        monkeypatch.setenv(config.API_KEY_ENV, KEY)
        return
    write_profile(profile, {"base_url": url, "api_key": KEY})


def assert_no_traceback(result: Any) -> None:
    for stream in (result.stdout, result.stderr):
        assert not any(marker in stream for marker in TRACEBACK_MARKERS)


@BOTH_MODES
@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("char", list(CONTROL_CHARS))
def test_a_control_character_in_the_userinfo_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch,
    profile_dir: Path,
    router: Any,
    as_json: bool,
    source: str,
    char: str,
) -> None:
    url = f"http://al{CONTROL_CHARS[char]}ice:hunter2@sandfort.test"
    configure(monkeypatch, profile_dir, source, url)

    result = invoke(["sandbox", "list"], as_json=as_json)

    assert result.exit_code == 2
    assert router.calls.call_count == 0
    assert_no_traceback(result)
    assert "hunter2" not in result.stdout + result.stderr
    report = result.stdout if as_json else result.stderr
    assert "is not a valid url" in flat(report)
    if as_json:
        error = json.loads(result.stdout)["error"]
        assert error["code"] == "USAGE_ERROR" and error["source"] == "client"
        assert result.stderr.strip() == ""
    else:
        assert result.stdout.strip() == ""


@BOTH_MODES
@pytest.mark.parametrize("source", SOURCES)
def test_configured_userinfo_is_dropped_and_the_bearer_key_is_kept(
    monkeypatch: pytest.MonkeyPatch,
    profile_dir: Path,
    router: Any,
    as_json: bool,
    source: str,
) -> None:
    route = router.get(SANDBOXES_URL).respond(200, json=EMPTY_LIST)
    configure(monkeypatch, profile_dir, source, "http://alice:hunter2@sandfort.test")

    result = invoke(["sandbox", "list"], as_json=as_json)

    assert result.exit_code == 0, result.output
    assert route.call_count == 1
    headers = route.calls.last.request.headers
    assert headers["authorization"] == f"Bearer {KEY}"
    assert "hunter2" not in result.stdout + result.stderr
    if as_json:
        assert json.loads(result.stdout) == []
        assert result.stderr.strip() == ""
    else:
        assert "userinfo was removed from the configured base url" in flat(result.stderr)


@BOTH_MODES
def test_create_with_wait_against_an_unreachable_server_is_a_clean_connect_error(
    monkeypatch: pytest.MonkeyPatch,
    profile_dir: Path,
    router: Any,
    caplog: pytest.LogCaptureFixture,
    as_json: bool,
) -> None:
    router.route().mock(side_effect=httpx.ConnectError("connection refused"))
    configure(monkeypatch, profile_dir, "env", BASE)

    with caplog.at_level(logging.WARNING):
        result = invoke(["sandbox", "create", "box", "--wait"], as_json=as_json)

    assert result.exit_code == 1
    assert_no_traceback(result)
    assert "cannot check the name" not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
    if as_json:
        error = json.loads(result.stdout)["error"]
        assert "connection refused" in error["message"]
        assert result.stderr.strip() == ""
    else:
        assert result.stdout.strip() == ""
        assert flat(result.stderr).startswith("error:")
        assert "connection refused" in result.stderr


@BOTH_MODES
@pytest.mark.parametrize("case", list(BAD_BASE_URL_FIELDS))
def test_an_unusable_base_url_field_is_a_malformed_profile(
    profile_dir: Path, router: Any, as_json: bool, case: str
) -> None:
    write_profile(profile_dir, {"base_url": BAD_BASE_URL_FIELDS[case], "api_key": KEY})

    result = invoke(["sandbox", "list"], as_json=as_json)

    assert result.exit_code == 1
    assert router.calls.call_count == 0
    assert_no_traceback(result)
    report = result.stdout if as_json else result.stderr
    assert "is malformed; run 'sandfort login' again" in flat(report)
    assert "not logged in" not in flat(report)
    assert KEY not in result.stdout + result.stderr
