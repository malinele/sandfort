"""CLI r30 follow-up: `sandbox list` shows user text literally. Label values and the error reason
are data, never Rich markup, and control characters never reach the terminal."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.output import ELLIPSIS, TABLE_CELL_MAX, truncate_cell  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOXES_URL = "/v1/sandboxes"
ESC = "\x1b"

RUNNER = CliRunner()


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def sandbox_json(state="started", **extra):
    return {"id": SID, "name": "demo", "state": state, **extra}


def list_output(api, **extra):
    api.get(SANDBOXES_URL).respond(200, json=envelope([sandbox_json(**extra)]))
    return RUNNER.invoke(create_app(), ["sandbox", "list"])


@pytest.fixture(autouse=True)
def profile_env(monkeypatch, tmp_path):
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, KEY)


@pytest.fixture
def api():
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        yield router


def test_label_value_that_looks_like_a_closing_tag_is_shown_literally(api):
    result = list_output(api, labels={"k": "[/x]"})

    assert result.exit_code == 0, result.output
    assert "k=[/x]" in result.output


def test_label_value_that_looks_like_an_opening_tag_is_shown_literally(api):
    result = list_output(api, labels={"k": "[bold]x"})

    assert result.exit_code == 0, result.output
    assert "k=[bold]x" in result.output


def test_error_reason_markup_is_shown_literally(api):
    result = list_output(api, state="error", error_reason="bad [red]thing[/red]")

    assert result.exit_code == 0, result.output
    assert "bad [red]thing[/red]" in result.output


def test_error_reason_escape_sequence_loses_its_esc_byte(api):
    result = list_output(api, state="error", error_reason=f"boom {ESC}[31mred{ESC}[0m end")

    assert result.exit_code == 0, result.output
    assert ESC not in result.output
    assert "boom red end" in result.output


def test_table_headers_and_ids_are_unchanged(api):
    result = list_output(api, labels={"env": "ci"})

    assert result.exit_code == 0, result.output
    for header in ("ID", "NAME", "STATE", "LABELS", "REASON"):
        assert header in result.output
    assert SID in result.output
    assert "env=ci" in result.output


def test_long_cell_is_still_cut_with_an_ellipsis(api):
    result = list_output(api, state="error", error_reason="x" * (TABLE_CELL_MAX + 20))

    assert result.exit_code == 0, result.output
    assert "x" * (TABLE_CELL_MAX - len(ELLIPSIS)) + ELLIPSIS in result.output
    assert "x" * TABLE_CELL_MAX not in result.output


def test_truncate_cell_drops_c0_and_c1_controls_before_cutting():
    dirty = f"a{ESC}b\x00c\x7fd\x80e\x9bf"

    assert truncate_cell(dirty) == "acde"
    padded = ESC * 40 + "y" * TABLE_CELL_MAX
    # The last ESC and the first "y" form one two-byte escape sequence, removed whole; the
    # escape padding never counts toward the cell budget, so nothing is cut.
    assert truncate_cell(padded) == "y" * (TABLE_CELL_MAX - 1)


def test_truncate_cell_keeps_collapsing_whitespace_to_single_spaces():
    assert truncate_cell("a\n\tb   c") == "a b c"


def get_output(api, args=("sandbox", "get", SID), **extra):
    api.get(f"{SANDBOXES_URL}/{SID}").respond(200, json=envelope(sandbox_json(**extra)))
    return RUNNER.invoke(create_app(), list(args))


def test_get_error_reason_loses_control_characters_and_keeps_markup_literal(api):
    reason = f"boom {ESC}[31mred{ESC}[0m \x9b end [/x]"

    result = get_output(api, state="error", error_reason=reason)

    assert result.exit_code == 0, result.output
    assert ESC not in result.output
    assert "\x9b" not in result.output
    assert "boom red nd [/x]" in result.output


def test_get_name_loses_control_characters(api):
    result = get_output(api, name=f"de{ESC}[2Jmo\x07")

    assert result.exit_code == 0, result.output
    assert ESC not in result.output
    assert "\x07" not in result.output
    assert "[2J" not in result.output
    assert "demo" in result.output


def test_get_error_reason_is_not_cut_like_a_table_cell(api):
    result = get_output(api, state="error", error_reason="x" * (TABLE_CELL_MAX + 20))

    assert result.exit_code == 0, result.output
    assert "x" * (TABLE_CELL_MAX + 20) in result.output


def test_get_json_keeps_the_raw_error_reason(api):
    reason = f"boom {ESC}[31m [/x]"

    result = get_output(
        api, args=("--json", "sandbox", "get", SID), state="error", error_reason=reason
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["error_reason"] == "boom [/x]"
