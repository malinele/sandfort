"""CLI round 58b: message nits from the persona runs.

1. The cp summary says ``1 byte`` and ``N bytes``.
2. A control character (category Cc) in a number is named as a control character; a format or
   other default-ignorable character keeps the invisible wording.
3. The malformed profile-key message says "no whitespace inside or around it".
4. With stdout not a terminal and COLUMNS unset, tables are not cut (headers included); a
   terminal, or a set COLUMNS, keeps Rich's width.
"""

import json
import os
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
from rich.console import Console  # noqa: E402
from sandfort_cli import config, cp_cmd, number_parsing, output  # noqa: E402
from sandfort_cli.cp_dir import CopyStats  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOX_URL = f"/v1/sandboxes/{SID}"
USAGE = 2
RUNNER = CliRunner()
BOTH_MODES = pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
NOT_FOUND = {
    "success": False,
    "data": None,
    "error": {"code": "NOT_FOUND", "message": "gone", "details": {}, "request_id": "req_1"},
    "meta": None,
}
ZWSP = "​"
WORD_JOINER = "⁠"
CONTROL_TEXT = "contains a control character"
INVISIBLE_TEXT = "contains an invisible character"
AROUND_TEXT = "printable ASCII with no whitespace inside or around it"
ANSI_SGR_RE = re.compile(r"\x1b\[[0-9;]*m")
# Longer than the 80-column fallback and the old 200-column pipe width.
LONG_CELL = "x" * 300
NARROW_COLUMNS = 40
# Slack for borders and padding when checking that a table is sized to its content.
BORDER_SLACK = 50
COLOR_ENV_VARS = ("FORCE_COLOR", "TTY_COMPATIBLE", "TTY_INTERACTIVE")
TABLE_HEADERS = ("ISOLATION", "STATE", "LABELS")
TABLE_ROW = ("gvisor", "destroying", LONG_CELL)


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def flat(text: str) -> str:
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", ANSI_SGR_RE.sub("", text)).split())


def reported(result: Any, as_json: bool) -> str:
    if as_json:
        return flat(str(json.loads(result.stdout)["error"]["message"]))
    return flat(result.stderr)


def envelope(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data, "error": None, "meta": None}


def sandbox_json(name: str) -> dict[str, Any]:
    return {
        "id": SID,
        "name": name,
        "state": "destroying",
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
        "labels": {},
    }


def fake_copy_of(size: int, files: int) -> Any:
    def fake_copy(source: str, destination: str, *, recursive: bool = False) -> CopyStats:
        return CopyStats(bytes=size, files=files)

    return fake_copy


def printed_lines(text: str) -> list[str]:
    return [ANSI_SGR_RE.sub("", line) for line in text.splitlines()]


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("TERMINAL_WIDTH", "400")
    config.save_profile(BASE, KEY)


@pytest.fixture
def router() -> Iterator[Any]:
    """A respx router; a request no route of the test matches fails the call."""
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


@pytest.fixture
def any_request(router: Any) -> Any:
    """A catch-all route answering NOT_FOUND, for counting requests that must not be sent."""
    return router.route().mock(return_value=httpx.Response(404, json=NOT_FOUND))


@pytest.fixture
def piped_without_columns(monkeypatch: pytest.MonkeyPatch) -> None:
    """stdout is not a tty (capsys / CliRunner) and COLUMNS is unset."""
    monkeypatch.delenv("COLUMNS", raising=False)
    for name in COLOR_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


# 1. cp summary: byte / bytes ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("size", "files", "summary"),
    [
        (1, 1, "copied 1 byte (1 file):"),
        (0, 0, "copied 0 bytes (0 files):"),
        (2, 1, "copied 2 bytes (1 file):"),
        (1, 3, "copied 1 byte (3 files):"),
    ],
    ids=["one-byte", "zero", "two-bytes", "one-byte-many-files"],
)
def test_cp_summary_uses_byte_for_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, size: int, files: int, summary: str
) -> None:
    local = tmp_path / "a.txt"
    local.write_text("x", encoding="utf-8")
    monkeypatch.setattr(cp_cmd, "_copy", fake_copy_of(size, files))

    result = invoke(["cp", str(local), f"{SID}:/x"])

    assert result.exit_code == 0, result.output
    assert summary in flat(result.stdout)


def test_cp_json_payload_keeps_the_byte_count(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    local = tmp_path / "a.txt"
    local.write_text("x", encoding="utf-8")
    monkeypatch.setattr(cp_cmd, "_copy", fake_copy_of(1, 1))

    result = invoke(["cp", str(local), f"{SID}:/x"], as_json=True)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert (payload["bytes"], payload["files"]) == (1, 1)


# 2. control vs invisible character hints ------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("5\x01", number_parsing.CONTROL_HINT_PREFIX + "U+0001"),
        ("\x1b5", number_parsing.CONTROL_HINT_PREFIX + "U+001B"),
        ("5\x7f", number_parsing.CONTROL_HINT_PREFIX + "U+007F"),
        ("5\x9b", number_parsing.CONTROL_HINT_PREFIX + "U+009B"),
        ("5" + ZWSP, number_parsing.INVISIBLE_HINT_PREFIX + "U+200B"),
        (WORD_JOINER + "5", number_parsing.INVISIBLE_HINT_PREFIX + "U+2060"),
        ("\x01+5", number_parsing.SIGN_HINT + number_parsing.CONTROL_HINT_PREFIX + "U+0001"),
    ],
    ids=["c0", "escape", "delete", "c1", "zero-width", "word-joiner", "control-then-plus"],
)
def test_a_control_character_is_named_as_control(raw: str, expected: str) -> None:
    assert number_parsing.whole_number_hints(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("5" + ZWSP + "\x01", number_parsing.INVISIBLE_HINT_PREFIX + "U+200B"),
        ("5\x01" + ZWSP, number_parsing.CONTROL_HINT_PREFIX + "U+0001"),
    ],
    ids=["invisible-first", "control-first"],
)
def test_the_first_hidden_character_decides_the_wording(raw: str, expected: str) -> None:
    assert number_parsing.whole_number_hints(raw) == expected


@BOTH_MODES
def test_wait_timeout_control_character_says_control(any_request: Any, as_json: bool) -> None:
    args = ["sandbox", "start", SID, "--wait", "--wait-timeout=5\x01"]

    result = invoke(args, as_json=as_json)

    assert result.exit_code == USAGE, result.output
    shown = reported(result, as_json)
    assert f"{CONTROL_TEXT} U+0001" in shown
    assert INVISIBLE_TEXT not in shown
    assert any_request.call_count == 0


@BOTH_MODES
def test_wait_timeout_zero_width_still_says_invisible(any_request: Any, as_json: bool) -> None:
    args = ["sandbox", "start", SID, "--wait", f"--wait-timeout=5{ZWSP}"]

    result = invoke(args, as_json=as_json)

    assert result.exit_code == USAGE, result.output
    shown = reported(result, as_json)
    assert f"{INVISIBLE_TEXT} U+200B" in shown
    assert CONTROL_TEXT not in shown
    assert any_request.call_count == 0


# 3. malformed profile-key wording -------------------------------------------------------------


def test_the_malformed_key_message_covers_surrounding_whitespace() -> None:
    assert AROUND_TEXT in config.MALFORMED_KEY_MESSAGE


@BOTH_MODES
@pytest.mark.parametrize("stored", [f" {KEY}", f"{KEY}\n"], ids=["leading", "trailing"])
def test_a_profile_key_with_surrounding_whitespace_says_around_it(
    any_request: Any, as_json: bool, stored: str
) -> None:
    body = {"base_url": BASE, "api_key": stored}
    config.profile_path().write_text(json.dumps(body), encoding="utf-8")

    result = invoke(["sandbox", "list"], as_json=as_json)

    assert result.exit_code == USAGE, result.output
    assert AROUND_TEXT in reported(result, as_json)
    assert KEY not in result.output
    assert any_request.call_count == 0


# 4. table width when piped --------------------------------------------------------------------


@pytest.mark.usefixtures("piped_without_columns")
def test_a_piped_table_without_columns_is_not_cut(capsys: pytest.CaptureFixture[str]) -> None:
    output.print_table("Sandboxes", TABLE_HEADERS, [TABLE_ROW])

    lines = printed_lines(capsys.readouterr().out)

    text = "\n".join(lines)
    for whole in ("ISOLATION", "destroying", LONG_CELL):
        assert whole in text
    # Sized to the content: nothing is padded out to the unbounded width.
    assert max(len(line) for line in lines) < len(LONG_CELL) + BORDER_SLACK


@pytest.mark.usefixtures("piped_without_columns")
def test_a_piped_table_ignores_force_color_for_the_width(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("FORCE_COLOR", "1")

    output.print_table("Sandboxes", TABLE_HEADERS, [TABLE_ROW])

    text = "\n".join(printed_lines(capsys.readouterr().out))
    for whole in ("ISOLATION", "destroying", LONG_CELL):
        assert whole in text


def test_a_set_columns_still_bounds_a_piped_table(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("COLUMNS", str(NARROW_COLUMNS))

    output.print_table("Sandboxes", TABLE_HEADERS, [TABLE_ROW])

    lines = printed_lines(capsys.readouterr().out)
    assert max(len(line) for line in lines) <= NARROW_COLUMNS


@pytest.mark.usefixtures("piped_without_columns")
def test_a_terminal_keeps_its_own_width(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(output, "writes_to_terminal", lambda console: True)
    monkeypatch.delenv("TERM", raising=False)  # TERM=dumb would force 80 columns
    narrow = os.terminal_size((NARROW_COLUMNS, 24))
    monkeypatch.setattr(os, "get_terminal_size", lambda *args: narrow)

    output.print_table("Sandboxes", TABLE_HEADERS, [TABLE_ROW])

    lines = printed_lines(capsys.readouterr().out)
    assert max(len(line) for line in lines) <= NARROW_COLUMNS
    assert LONG_CELL not in "\n".join(lines)


class ClosedStream:
    """A stream whose ``isatty`` raises, like a closed file."""

    def write(self, text: str) -> int:
        return len(text)

    def flush(self) -> None:
        return None

    def isatty(self) -> bool:
        raise ValueError("I/O operation on closed file")


def test_writes_to_terminal_is_false_for_a_closed_or_plain_stream(tmp_path: Path) -> None:
    assert output.writes_to_terminal(Console(file=ClosedStream())) is False
    with (tmp_path / "out.txt").open("w", encoding="utf-8") as handle:
        assert output.writes_to_terminal(Console(file=handle)) is False


@pytest.mark.usefixtures("piped_without_columns")
def test_sandbox_get_piped_shows_a_long_name_whole(router: Any) -> None:
    router.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json(LONG_CELL)))

    result = invoke(["sandbox", "get", SID])

    assert result.exit_code == 0, result.output
    shown = flat(result.stdout)
    for whole in ("FIELD", "VALUE", "destroying", LONG_CELL):
        assert whole in shown
