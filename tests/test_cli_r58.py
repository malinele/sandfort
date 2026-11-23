"""CLI round 58: ``sandbox list`` single-value options, stop-cause hints, flowing help text.

A repeated ``--state``, ``--order`` or ``--stop-cause`` is a usage error (exit 2, before any
request) naming the option. A stop cause refused only for whitespace or letter case says so.
"""

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
EMPTY_LIST = {"success": True, "data": [], "error": None, "meta": None}
SHORT_WORD_CHARS = 5


def invoke(args: list[str]) -> Any:
    return RUNNER.invoke(create_app(None), args)


def flat(text: str) -> str:
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("TERMINAL_WIDTH", "400")
    config.save_profile(BASE, KEY)


@pytest.fixture
def listing() -> Iterator[Any]:
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock.get("/v1/sandboxes").mock(return_value=httpx.Response(200, json=EMPTY_LIST))


@pytest.mark.parametrize(
    ("args", "option"),
    [
        (["--stop-cause", "unknown", "--stop-cause", "requested"], "--stop-cause"),
        (["--state", "stopped", "--state", "started"], "--state"),
        (["--order", "asc", "--order", "desc"], "--order"),
        (["--order", "asc", "--order", "asc"], "--order"),
    ],
)
def test_a_repeated_single_value_option_is_a_usage_error(
    listing: Any, args: list[str], option: str
) -> None:
    result = invoke(["sandbox", "list", *args])

    assert result.exit_code == USAGE, result.output
    shown = flat(result.stderr)
    assert option in shown
    assert "more than once" in shown
    assert listing.call_count == 0


def test_single_values_are_still_sent(listing: Any) -> None:
    args = ["--state", "stopped", "--order", "asc", "--stop-cause", "oom_killed"]
    result = invoke(["sandbox", "list", *args])

    assert result.exit_code == 0, result.output
    params = listing.calls.last.request.url.params
    assert params["state"] == "stopped"
    assert params["order"] == "asc"
    assert params["stop_cause"] == "oom_killed"


def test_a_repeated_label_with_different_keys_is_still_allowed(listing: Any) -> None:
    result = invoke(["sandbox", "list", "--label", "a=1", "--label", "b=2"])

    assert result.exit_code == 0, result.output
    assert listing.call_count == 1


@pytest.mark.parametrize("value", ["requested ", " requested", "\tauto_stop"])
def test_a_stop_cause_with_surrounding_whitespace_says_so(listing: Any, value: str) -> None:
    result = invoke(["sandbox", "list", f"--stop-cause={value}"])

    assert result.exit_code == USAGE, result.output
    shown = flat(result.stderr)
    assert "surrounding whitespace is not allowed" in shown
    assert "expected one of" in shown
    assert "values are lowercase" not in shown
    assert listing.call_count == 0


@pytest.mark.parametrize("value", ["AUTO_STOP", "Requested", "OOM_KILLED"])
def test_an_uppercase_stop_cause_says_values_are_lowercase(listing: Any, value: str) -> None:
    result = invoke(["sandbox", "list", f"--stop-cause={value}"])

    assert result.exit_code == USAGE, result.output
    shown = flat(result.stderr)
    assert "values are lowercase" in shown
    assert "surrounding whitespace" not in shown
    assert listing.call_count == 0


@pytest.mark.parametrize("value", ["crashed", "auto-stop", "CRASHED"])
def test_a_stop_cause_without_a_cheap_fix_gets_no_hint(listing: Any, value: str) -> None:
    result = invoke(["sandbox", "list", f"--stop-cause={value}"])

    assert result.exit_code == USAGE, result.output
    shown = flat(result.stderr)
    assert "unknown stop cause" in shown
    assert "values are lowercase" not in shown
    assert "surrounding whitespace" not in shown


@pytest.mark.parametrize("columns", ["60", "80", "100"])
def test_list_help_has_no_line_with_a_single_short_word(
    monkeypatch: pytest.MonkeyPatch, columns: str
) -> None:
    monkeypatch.setenv("COLUMNS", columns)
    monkeypatch.setenv("TERMINAL_WIDTH", columns)
    result = invoke(["sandbox", "list", "--help"])

    assert result.exit_code == 0, result.output
    for line in result.stdout.splitlines():
        words = line.split()
        assert not (len(words) == 1 and len(words[0]) <= SHORT_WORD_CHARS), line
