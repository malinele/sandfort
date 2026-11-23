"""CLI round 57b: message nits from the persona runs.

1. A plus sign gets "a sign is not accepted"; an invisible character is named by code point.
2. A name made only of escape sequences says the sequences were removed.
3. A profile api key with surrounding whitespace is refused as malformed, never sent.
4. An undecodable byte (a lone surrogate) in a number option gets its own hint.
5. A label key made only of invisible characters is shown as ``(invisible)``.
6. The cp summary says ``1 file`` and ``N files``.
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
import typer  # noqa: E402
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
LONE_SURROGATE = "\udcff"
SIGN_TEXT = "a sign is not accepted; write the number without it"
DIGITS_TEXT = "only plain ASCII digits are accepted"
UNDECODABLE_TEXT = "contains an undecodable byte"
AFTER_SEQUENCES = "must not be empty (after removing terminal control sequences)"


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def flat(text: str) -> str:
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


def reported(result: Any, as_json: bool) -> str:
    if as_json:
        return flat(str(json.loads(result.stdout)["error"]["message"]))
    return flat(result.stderr)


def envelope(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data, "error": None, "meta": None}


def sandbox_json(labels: dict[str, str]) -> dict[str, Any]:
    return {
        "id": SID,
        "name": "demo",
        "state": "started",
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
        "labels": labels,
    }


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    # Wide enough that the text usage box shows the whole tmp profile path unwrapped.
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


# 1. sign and invisible-character hints --------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("+5", number_parsing.SIGN_HINT),
        ("5" + ZWSP, number_parsing.INVISIBLE_HINT_PREFIX + "U+200B"),
        ("\x1b5", number_parsing.CONTROL_HINT_PREFIX + "U+001B"),  # round 58: control wording
        ("５", number_parsing.PLAIN_DIGITS_HINT),
        (" +5 ", number_parsing.SURROUNDING_SPACES_HINT + number_parsing.SIGN_HINT),
        ("1000", ""),
        ("1+1", number_parsing.PLAIN_DIGITS_HINT),
        ("1e+5", number_parsing.PLAIN_DIGITS_HINT),
        ("+1+1", number_parsing.SIGN_HINT + number_parsing.PLAIN_DIGITS_HINT),
        ("\x1b+5", number_parsing.SIGN_HINT + number_parsing.CONTROL_HINT_PREFIX + "U+001B"),
        (ZWSP + "+5", number_parsing.SIGN_HINT + number_parsing.INVISIBLE_HINT_PREFIX + "U+200B"),
        ("＋5", number_parsing.SIGN_HINT),
        ("＋+5", number_parsing.SIGN_HINT + number_parsing.PLAIN_DIGITS_HINT),
        (
            " " + ZWSP + "+5",
            number_parsing.SURROUNDING_SPACES_HINT
            + number_parsing.SIGN_HINT
            + number_parsing.INVISIBLE_HINT_PREFIX
            + "U+200B",
        ),
    ],
    ids=[
        "plus",
        "zero-width",
        "control",
        "fullwidth",
        "plus-and-spaces",
        "plain",
        "inner-plus",
        "exponent-plus",
        "leading-and-inner-plus",
        "escape-then-plus",
        "zero-width-then-plus",
        "fullwidth-plus",
        "fullwidth-and-ascii-plus",
        "spaces-zero-width-plus",
    ],
)
def test_each_misleading_character_gets_its_own_hint(raw: str, expected: str) -> None:
    assert number_parsing.whole_number_hints(raw) == expected


def test_a_plus_sign_no_longer_says_ascii_digits() -> None:
    hints = number_parsing.whole_number_hints("+5")

    assert DIGITS_TEXT not in hints
    assert SIGN_TEXT in hints


def test_only_the_first_invisible_character_is_named() -> None:
    hints = number_parsing.whole_number_hints("5" + ZWSP + "⁠")

    assert hints == number_parsing.INVISIBLE_HINT_PREFIX + "U+200B"


@BOTH_MODES
def test_wait_timeout_plus_sign_gets_the_sign_hint(any_request: Any, as_json: bool) -> None:
    args = ["sandbox", "start", SID, "--wait", "--wait-timeout", "+5"]

    result = invoke(args, as_json=as_json)

    assert result.exit_code == USAGE, result.output
    shown = reported(result, as_json)
    assert SIGN_TEXT in shown
    assert DIGITS_TEXT not in shown
    assert any_request.call_count == 0


@BOTH_MODES
def test_wait_timeout_zero_width_names_the_character(any_request: Any, as_json: bool) -> None:
    args = ["sandbox", "start", SID, "--wait", f"--wait-timeout=5{ZWSP}"]

    result = invoke(args, as_json=as_json)

    assert result.exit_code == USAGE, result.output
    assert "contains an invisible character U+200B" in reported(result, as_json)
    assert any_request.call_count == 0


# 2. escape-only names -------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["\x1b[0m", "\x1b]0;t\x07", "\x01", " \x1b[1m "])
def test_an_escape_only_name_says_the_sequences_were_removed(name: str) -> None:
    with pytest.raises(typer.BadParameter) as caught:
        output.reject_empty_name(name)

    assert caught.value.message == AFTER_SEQUENCES


@pytest.mark.parametrize("name", ["", "   ", ZWSP], ids=["empty", "spaces", "zero-width"])
def test_a_plainly_empty_name_keeps_the_short_message(name: str) -> None:
    with pytest.raises(typer.BadParameter) as caught:
        output.reject_empty_name(name)

    assert caught.value.message == output.EMPTY_MESSAGE


@BOTH_MODES
def test_sandbox_get_of_an_escape_only_name_says_so(any_request: Any, as_json: bool) -> None:
    result = invoke(["sandbox", "get", "\x1b[0m"], as_json=as_json)

    assert result.exit_code == USAGE, result.output
    assert AFTER_SEQUENCES in reported(result, as_json)
    assert any_request.call_count == 0


# 3. profile key with surrounding whitespace ---------------------------------------------------


def write_profile(api_key: str) -> None:
    body = {"base_url": BASE, "api_key": api_key}
    config.profile_path().write_text(json.dumps(body), encoding="utf-8")


@BOTH_MODES
@pytest.mark.parametrize(
    "stored", [f" {KEY}", f"{KEY} ", f"\t{KEY}\n"], ids=["leading", "trailing", "both"]
)
def test_a_profile_key_with_surrounding_whitespace_is_malformed(
    any_request: Any, as_json: bool, stored: str
) -> None:
    write_profile(stored)

    result = invoke(["sandbox", "list"], as_json=as_json)

    assert result.exit_code == USAGE, result.output
    problem = config.MALFORMED_KEY_MESSAGE + config.LOGIN_TAIL
    assert f"api_key in {config.profile_path()} {problem}" in reported(result, as_json)
    assert KEY not in result.output
    assert any_request.call_count == 0


def test_a_whitespace_only_profile_key_keeps_the_same_message(any_request: Any) -> None:
    write_profile("   ")

    result = invoke(["sandbox", "list"])

    assert result.exit_code == USAGE, result.output
    assert config.MALFORMED_KEY_MESSAGE + config.LOGIN_TAIL in flat(result.stderr)
    assert any_request.call_count == 0


def test_a_clean_profile_key_passes_the_check() -> None:
    config.check_profile_key(KEY)


# 4. undecodable byte in a number option -------------------------------------------------------


def test_a_lone_surrogate_gets_the_undecodable_hint() -> None:
    hints = number_parsing.whole_number_hints("512" + LONE_SURROGATE)

    assert hints == number_parsing.UNDECODABLE_HINT
    assert number_parsing.misleads_as_digits(LONE_SURROGATE)


@BOTH_MODES
def test_a_number_option_with_an_undecodable_byte_says_so(any_request: Any, as_json: bool) -> None:
    args = ["sandbox", "create", "demo", f"--memory-mib=512{LONE_SURROGATE}"]

    result = invoke(args, as_json=as_json)

    assert result.exit_code == USAGE, result.output
    assert UNDECODABLE_TEXT in reported(result, as_json)
    assert any_request.call_count == 0


# 5. invisible-only label keys -----------------------------------------------------------------


def test_an_invisible_only_key_is_named_invisible() -> None:
    names = output.clean_key_names([ZWSP, "env"], KEY)

    assert names == [output.INVISIBLE_KEY_NAME, "env"]


def test_colliding_invisible_keys_are_numbered() -> None:
    names = output.clean_key_names([ZWSP, ZWSP + ZWSP, "\x01"], KEY)

    assert names == ["(invisible)", "(invisible)#2", "(invisible)#3"]


def test_a_genuine_key_named_invisible_keeps_its_name() -> None:
    names = output.clean_key_names([ZWSP, "(invisible)"], KEY)

    assert names == ["(invisible)#2", "(invisible)"]


def test_an_empty_key_is_left_as_it_is() -> None:
    assert output.clean_key_names([""], KEY) == [""]


def test_sandbox_get_shows_an_invisible_key_as_invisible(router: Any) -> None:
    labels = {ZWSP: "a", ZWSP + ZWSP: "b"}
    router.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json(labels)))

    result = invoke(["sandbox", "get", SID])

    assert result.exit_code == 0, result.output
    assert "(invisible)=a" in result.stdout
    assert "(invisible)#2=b" in result.stdout


def test_json_names_an_invisible_key_alike(router: Any) -> None:
    router.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json({ZWSP: "a"})))

    result = invoke(["sandbox", "get", SID], as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["labels"] == {"(invisible)": "a"}


# 6. cp summary wording ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("files", "word"),
    [(1, "(1 file)"), (0, "(0 files)"), (3, "(3 files)")],
    ids=["one", "zero", "many"],
)
def test_cp_summary_uses_file_for_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, files: int, word: str
) -> None:
    local = tmp_path / "a.txt"
    local.write_text("x", encoding="utf-8")

    def fake_copy(source: str, destination: str, *, recursive: bool = False) -> CopyStats:
        return CopyStats(bytes=1, files=files)

    monkeypatch.setattr(cp_cmd, "_copy", fake_copy)

    result = invoke(["cp", str(local), f"{SID}:/x"])

    assert result.exit_code == 0, result.output
    assert f"copied 1 byte {word}:" in flat(result.stdout)  # round 58: "byte" for one
