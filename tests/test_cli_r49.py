"""CLI round 49: a bad base url from the environment or the profile is a usage error.

The structural url validation of ``login`` also runs where settings are resolved, so a bad
configured url gives the unified ``is not a valid url`` usage error (exit 2, one json usage
object under ``--json``, no traceback) before any client is built.
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
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SANDBOXES_URL = "/v1/sandboxes"
RUNNER = CliRunner()
BOTH_MODES = pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
TRACEBACK_MARKERS = ("Traceback", "InvalidURL", "httpx.", 'File "')
BAD_URLS = {
    "non-numeric-port": ("http://sandfort.test:abc", "invalid port"),
    "port-out-of-range": ("http://sandfort.test:70000", "port out of range"),
    "unsupported-scheme": ("ftp://sandfort.test", "unsupported scheme"),
    "no-host": ("http://", "no host"),
}
SOURCES = ("env", "profile")


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


def configure(monkeypatch: pytest.MonkeyPatch, profile: Path, source: str, url: str) -> None:
    """Supply ``url`` (and the key) through the environment or a written profile file."""
    if source == "env":
        monkeypatch.setenv(config.BASE_URL_ENV, url)
        monkeypatch.setenv(config.API_KEY_ENV, KEY)
        return
    profile.parent.mkdir(parents=True, exist_ok=True)
    profile.write_text(json.dumps({"base_url": url, "api_key": KEY}), encoding="utf-8")


@pytest.fixture
def router() -> Iterator[Any]:
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


@BOTH_MODES
@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("case", list(BAD_URLS))
def test_a_bad_configured_url_is_a_usage_error_without_a_traceback(
    monkeypatch: pytest.MonkeyPatch,
    profile_dir: Path,
    router: Any,
    as_json: bool,
    source: str,
    case: str,
) -> None:
    url, reason = BAD_URLS[case]
    configure(monkeypatch, profile_dir, source, url)

    result = invoke(["sandbox", "list"], as_json=as_json)

    assert result.exit_code == 2
    assert router.calls.call_count == 0
    for stream in (result.stdout, result.stderr):
        assert not any(marker in stream for marker in TRACEBACK_MARKERS)
    assert KEY not in result.stdout + result.stderr
    report = result.stdout if as_json else result.stderr
    assert "is not a valid url" in flat(report) and reason in flat(report)
    if as_json:
        error = json.loads(result.stdout)["error"]
        assert error["code"] == "USAGE_ERROR" and error["source"] == "client"
        assert result.stderr.strip() == ""
    else:
        assert result.stdout.strip() == ""


@BOTH_MODES
@pytest.mark.parametrize("source", SOURCES)
def test_a_valid_configured_url_still_reaches_the_transport(
    monkeypatch: pytest.MonkeyPatch,
    profile_dir: Path,
    router: Any,
    as_json: bool,
    source: str,
) -> None:
    route = router.get(SANDBOXES_URL).respond(
        200, json={"success": True, "data": [], "error": None, "meta": None}
    )
    configure(monkeypatch, profile_dir, source, BASE)

    result = invoke(["sandbox", "list"], as_json=as_json)

    assert result.exit_code == 0, result.output
    assert route.call_count == 1
