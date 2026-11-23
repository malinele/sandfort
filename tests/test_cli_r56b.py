"""CLI round 56 review fixes.

1. The number helpers live in ``number_parsing.py`` and the escape patterns in ``escapes.py``;
   the old import paths (``sandboxes``, ``output``) keep working.
2. An underscore in a number option gets the "digit separators are not accepted" hint.
3. The shared ``KEY=VALUE`` parser refuses a key given twice, compared after stripping.
4. A label is sanitised as the joined ``key=value``, so a secret spanning the ``=`` is masked.
"""

import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import typer  # noqa: E402
from sandfort_cli import config, escapes, number_parsing, output, sandboxes  # noqa: E402

KEY = "sf_test_key_do_not_print"
CONTROL_ENV = "\x01env"


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)


# 1. the new modules ---------------------------------------------------------------------------


def test_the_number_parsing_module_backs_the_old_sandboxes_names() -> None:
    assert sandboxes.PLAIN_DIGITS_HINT is number_parsing.PLAIN_DIGITS_HINT
    assert sandboxes.SURROUNDING_SPACES_HINT is number_parsing.SURROUNDING_SPACES_HINT
    assert sandboxes.parse_plain_decimal is number_parsing.parse_plain_decimal
    assert sandboxes.whole_number_hints is number_parsing.whole_number_hints
    assert number_parsing.parse_plain_decimal("-1.5e1") == -15.0
    assert math.isnan(number_parsing.parse_plain_decimal("+1"))


def test_the_escapes_module_backs_the_old_output_names() -> None:
    assert output.without_escape_sequences is escapes.without_escape_sequences
    assert output.DANGEROUS_SEQUENCE_RE is escapes.DANGEROUS_SEQUENCE_RE
    assert output.CSI_SEQUENCE_RE is escapes.CSI_SEQUENCE_RE
    text = "\x1b[0mA\x1b]0;t\x07B\x1b_apc\x1b\\C\x1bXsos\x1b\\"
    assert escapes.without_escape_sequences(text) == "ABC"
    assert escapes.without_escape_sequences("\x1b") == "\x1b"  # a lone ESC stays


# 2. the underscore hint -----------------------------------------------------------------------


def test_an_underscore_gets_the_digit_separator_hint() -> None:
    assert number_parsing.whole_number_hints("1_000") == number_parsing.UNDERSCORE_HINT
    assert number_parsing.whole_number_hints("+5") == number_parsing.SIGN_HINT
    assert number_parsing.whole_number_hints("５") == number_parsing.PLAIN_DIGITS_HINT
    assert number_parsing.whole_number_hints("1000") == ""


def test_a_whole_number_option_with_an_underscore_names_the_reason() -> None:
    with pytest.raises(typer.BadParameter) as excinfo:
        sandboxes.parse_whole_number("1_000", "--auto-stop")

    assert "digit separators are not accepted" in str(excinfo.value)


def test_a_wait_timeout_with_an_underscore_names_the_reason() -> None:
    with pytest.raises(typer.BadParameter) as excinfo:
        sandboxes.parse_wait_timeout(True, "1_0")

    assert "must be a finite number greater than 0" in str(excinfo.value)
    assert "digit separators are not accepted" in str(excinfo.value)


# 3. duplicate KEY=VALUE keys ------------------------------------------------------------------


def test_a_repeated_pair_key_is_a_usage_error() -> None:
    with pytest.raises(typer.BadParameter) as excinfo:
        sandboxes.parse_pairs(["A=1", " A =2"], "env")

    assert "env key 'A' is given more than once" in str(excinfo.value)
    assert excinfo.value.param_hint == "--env"


def test_distinct_pair_keys_are_kept() -> None:
    assert sandboxes.parse_pairs(["a=1", "b=", " c =x=y"], "label") == {
        "a": "1",
        "b": "",
        "c": "x=y",
    }


# 4. joined label sanitising -------------------------------------------------------------------


def test_a_secret_spanning_the_equals_sign_is_masked() -> None:
    pairs = output.label_pairs({"https://user:pa": "ss@host.test/x"}, KEY)

    assert len(pairs) == 1
    assert "user:pa" not in pairs[0]
    assert "ss@host" not in pairs[0]


def test_plain_labels_keep_their_json_key_names() -> None:
    pairs = output.label_pairs({CONTROL_ENV: "a", "env": "b", "team": "x=y"}, KEY)

    assert pairs == ["env#2=a", "env=b", "team=x=y"]


def test_the_caller_key_in_a_label_value_is_masked() -> None:
    (pair,) = output.label_pairs({"token": KEY}, KEY)

    assert pair.startswith("token=")
    assert KEY not in pair
