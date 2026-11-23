"""CLI round 57: short escape sequences (ESC plus intermediates and a final byte, and the C1
CSI with parameters) count as blank, as the sanitiser already treats them."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli import escapes  # noqa: E402
from sandfort_cli.output import is_blank  # noqa: E402

ESC = "\x1b"

SHORT_SEQUENCES = {
    "reset": f"{ESC}c",
    "charset-g0": f"{ESC}(B",
    "keypad": f"{ESC}=",
    "save-cursor": f"{ESC}7",
    "reverse-index": f"{ESC}M",
    "charset-g1": f"{ESC})0",
    "two-intermediates": f"{ESC}(!B",
    "locking-shift": f"{ESC}~",
    "string-terminator": f"{ESC}\\",
    "c1-csi-sgr-reset": "\x9b0m",
    "c1-csi-sgr-colour": "\x9b31m",
    "c1-csi-erase": "\x9b2J",
    "cut-off-intermediate": f"{ESC}!",
    "cut-off-two-intermediates": f"{ESC}(!",
    "c1-csi-params-no-final": "\x9b31",
    "c1-csi-letter-final": "\x9bx",
    "c1-csi-cursor-up": "\x9bA",
    "csi-params-no-final": f"{ESC}[31",
    "two-in-a-row": f"{ESC}c{ESC}M",
    "mixed-with-csi": f"{ESC}c{ESC}[0m\x9b2J",
}


@pytest.mark.parametrize("name", list(SHORT_SEQUENCES.values()), ids=list(SHORT_SEQUENCES))
def test_a_short_escape_sequence_alone_is_blank(name: str) -> None:
    assert is_blank(name)
    assert escapes.without_escape_sequences(name) == ""


@pytest.mark.parametrize(
    "name",
    [
        "E",
        "ESC",
        "ESCc",
        "c",
        f"{ESC}cdemo",
        f"demo{ESC}c",
        f"{ESC}(Bdemo",
        "\x9b31mdemo",
        "demo\x9b2J",
        f"{ESC}!demo",
        "\x9b31demo",
        "\x9bxdemo",
    ],
)
def test_look_alikes_and_text_after_a_sequence_stay_visible(name: str) -> None:
    assert not is_blank(name)


def test_a_lone_escape_is_kept_by_the_stripper() -> None:
    assert escapes.without_escape_sequences(ESC) == ESC


def test_a_cut_off_sequence_is_removed_like_the_sanitiser_does() -> None:
    assert escapes.without_escape_sequences(f"a{ESC}!") == "a"
    assert escapes.without_escape_sequences("a\x9b31") == "a"
    assert escapes.without_escape_sequences("a\x9bxb") == "ab"


def test_the_text_around_short_sequences_is_kept() -> None:
    assert escapes.without_escape_sequences(f"a{ESC}cb\x9b0mc{ESC}(Bd") == "abcd"


@pytest.mark.parametrize(
    "text",
    [
        f"{ESC}\x9b[[",
        f"{ESC}\x9b0m[",
        f"{ESC}\x9d0;t\x07[",
    ],
    ids=["c1-csi-bracket", "c1-csi-sgr", "c1-osc"],
)
def test_removing_a_sequence_does_not_join_its_neighbours_into_one(text: str) -> None:
    # One substitution: the ESC before a removed C1 sequence and the "[" after it stay apart.
    assert escapes.without_escape_sequences(text) == f"{ESC}["
    assert not is_blank(text)


@pytest.mark.parametrize(
    "text",
    [
        f"{ESC}​[",
        "\x9b​m",
        f"{ESC}[3​1m",
        f"{ESC}⁠c",
        f"{ESC}\x01(B",
        f"{ESC}[­0m",
    ],
    ids=["esc-zwsp-bracket", "c1-zwsp-final", "zwsp-in-params", "word-joiner", "control", "shy"],
)
def test_an_invisible_or_control_character_inside_a_sequence_does_not_hide_it(text: str) -> None:
    assert is_blank(text)
    assert escapes.without_escape_sequences(text) == ""


def test_invisible_characters_outside_a_sequence_leave_the_text_unchanged() -> None:
    assert escapes.without_escape_sequences("a​b") == "a​b"
    assert escapes.without_escape_sequences("​") == "​"
    assert is_blank("​")
    assert not is_blank("a​")


def test_the_longer_forms_are_not_cut_by_the_short_pattern() -> None:
    text = f"{ESC}]0;title\x07A{ESC}_apc{ESC}\\B{ESC}[1;2HC"
    assert escapes.without_escape_sequences(text) == "ABC"
