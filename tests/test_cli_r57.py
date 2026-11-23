"""CLI round 57: ``sandbox list --stop-cause`` (validated locally, passed to the SDK).

A blank or unknown value is a usage error (exit 2) naming the accepted values, before any
request. The list help mentions the option.
"""

import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any, get_args

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config, sandboxes  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import StopCause  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
USAGE = 2
RUNNER = CliRunner()
CAUSES = ["requested", "auto_stop", "container_exited", "oom_killed", "unknown"]
EMPTY_LIST = {"success": True, "data": [], "error": None, "meta": None}


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
    """The list route, answering an empty page; yields the route to inspect its calls."""
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock.get("/v1/sandboxes").mock(return_value=httpx.Response(200, json=EMPTY_LIST))


@pytest.mark.parametrize("cause", CAUSES)
def test_each_known_stop_cause_is_sent_as_the_query_parameter(listing: Any, cause: str) -> None:
    result = invoke(["sandbox", "list", "--stop-cause", cause])

    assert result.exit_code == 0, result.output
    assert listing.call_count == 1
    assert listing.calls.last.request.url.params["stop_cause"] == cause


def test_without_the_option_no_stop_cause_is_sent(listing: Any) -> None:
    result = invoke(["sandbox", "list"])

    assert result.exit_code == 0, result.output
    assert "stop_cause" not in listing.calls.last.request.url.params


@pytest.mark.parametrize("value", ["", "   ", "\t"], ids=["empty", "spaces", "tab"])
def test_a_blank_stop_cause_is_a_usage_error_naming_the_values(listing: Any, value: str) -> None:
    result = invoke(["sandbox", "list", f"--stop-cause={value}"])

    assert result.exit_code == USAGE, result.output
    shown = flat(result.stderr)
    assert "must not be empty" in shown
    assert ", ".join(CAUSES) in shown
    assert listing.call_count == 0


@pytest.mark.parametrize("value", ["crashed", "AUTO_STOP", " requested", "auto-stop"])
def test_an_unknown_stop_cause_is_a_usage_error_naming_values(listing: Any, value: str) -> None:
    result = invoke(["sandbox", "list", f"--stop-cause={value}"])

    assert result.exit_code == USAGE, result.output
    assert "Traceback" not in result.output
    shown = flat(result.stderr)
    assert "unknown stop cause" in shown
    assert ", ".join(CAUSES) in shown
    assert listing.call_count == 0


def test_accepted_causes_equal_the_sdk_stop_cause_literal_values() -> None:
    assert sandboxes.STOP_CAUSES == get_args(StopCause)
    assert sandboxes.STOP_CAUSES == tuple(CAUSES)


def test_list_help_gives_the_option_a_short_metavar(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLUMNS", "100")
    monkeypatch.setenv("TERMINAL_WIDTH", "100")
    result = invoke(["sandbox", "list", "--help"])

    assert result.exit_code == 0, result.output
    shown = flat(result.stdout)
    assert sandboxes.STOP_CAUSE_METAVAR == "CAUSE"
    assert "--stop-cause CAUSE" in shown
    assert "<requested" not in shown


def test_list_help_names_all_five_values_in_a_100_column_render(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("COLUMNS", "100")
    monkeypatch.setenv("TERMINAL_WIDTH", "100")
    result = invoke(["sandbox", "list", "--help"])

    assert result.exit_code == 0, result.output
    shown = flat(result.stdout)
    for cause in CAUSES:
        assert cause in shown


def test_list_help_mentions_the_option_and_the_values() -> None:
    result = invoke(["sandbox", "list", "--help"])

    assert result.exit_code == 0, result.output
    shown = flat(result.stdout)
    assert "--stop-cause" in shown
    assert ", ".join(CAUSES) in shown
    assert "REASON" in shown and "stop_cause" in shown
