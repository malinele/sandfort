"""CLI round 54, batch o: the pre-strip key mask runs before the credentials mask.

1. A terminal sequence whose body holds a question mark or a hash, placed inside the caller's own
   key, no longer splits the key: the key mask runs first in the pre-strip pass, so the query and
   fragment masks cannot swallow the word from the marker and leave the key prefix behind.
2. Sweep: every sequence family at every position of a key that is not key-shaped and of a key
   of real length that is key-shaped leaves no piece of the key in the output.
3. Decision: an unterminated string-introducer sequence (APC, OSC, DCS, PM, SOS) swallows the
   rest of the text in the display view, which is the terminal's own semantics.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli.sanitise import MASK, sanitise_text  # noqa: E402

ESC = "\x1b"
# Not key-shaped (the dots are outside the key alphabet): only the own-key lookup can mask it.
OWN_KEY = "sf_test.key.do.not.print"
# A real key: ``sf_<env>_<8 lowercase or digits>_<43 url-safe characters>`` (60 in all).
REAL_KEY = "sf_live_ab12cd34_" + "Qw3rTy9UiOpAsDfGhJkLzXcVbNm-_0123456789abcd"
REAL_KEY_LENGTH = 60
FIRST_TWELVE = 12
LEAK_WINDOW = 6
HYPERLINK = ESC + "]8;;https://h.test/p?a=b#frag" + ESC + "\\"

SEQUENCES = {
    "csi-sgr": ESC + "[31m",
    "csi-private": ESC + "[?25h",
    "csi-space": ESC + "[ q",
    "c1-csi": "\x9b31m",
    "osc-bel": ESC + "]0;title\x07",
    "osc-esc-st": ESC + "]0;title" + ESC + "\\",
    "osc-c1-st": ESC + "]0;title\x9c",
    "c1-osc-bel": "\x9d0;title\x07",
    "c1-osc-st": "\x9d0;title\x9c",
    "osc8-link": ESC + "]8;;http://x.test/p?q#f\x07",
    "osc8-hyperlink": HYPERLINK,
    "osc-question": ESC + "]0;a?b\x07",
    "osc-hash": ESC + "]0;a#b\x07",
    "dcs": ESC + "Pq data" + ESC + "\\",
    "dcs-markers": ESC + "Pq?#" + ESC + "\\",
    "c1-dcs": "\x90q data\x9c",
    "sos": ESC + "X note " + ESC + "\\",
    "c1-sos": "\x98 note \x9c",
    "pm": ESC + "^ note " + ESC + "\\",
    "c1-pm": "\x9e note \x9c",
    "apc": ESC + "_ note " + ESC + "\\",
    "apc-markers": ESC + "_a?#" + ESC + "\\",
    "c1-apc": "\x9f note \x9c",
    "esc-short": ESC + "c",
    "esc-charset": ESC + "(B",
}
# String sequences without a terminator: they swallow what follows them.
UNTERMINATED = {
    "osc": ESC + "]0;title",
    "osc-markers": ESC + "]0;a?b#c",
    "c1-osc": "\x9d0;title",
    "dcs": ESC + "Pq data",
    "c1-dcs": "\x90q data",
    "sos": ESC + "X note",
    "c1-sos": "\x98 note",
    "pm": ESC + "^ note",
    "c1-pm": "\x9e note",
    "apc": ESC + "_ note",
    "apc-markers": ESC + "_a?#",
    "c1-apc": "\x9f note",
}
EVERY_FAMILY = {**SEQUENCES, **{f"open-{name}": body for name, body in UNTERMINATED.items()}}
FAMILY_IDS = list(EVERY_FAMILY)


def leaks(result: str, secret: str) -> list[str]:
    """The pieces of ``secret`` of six characters that are visible in ``result``."""
    size = LEAK_WINDOW
    pieces = (secret[at : at + size] for at in range(len(secret) - size + 1))
    return [piece for piece in pieces if piece in result]


# 1) the exact failing case ---------------------------------------------------------------------


def test_a_hyperlink_sequence_inside_a_non_key_shaped_own_key_masks_the_whole_key() -> None:
    cut = FIRST_TWELVE
    text = f"bad {OWN_KEY[:cut]}{HYPERLINK}{OWN_KEY[cut:]} now"

    result = sanitise_text(text, api_key=OWN_KEY)

    assert OWN_KEY[:cut] not in result and not leaks(result, OWN_KEY)
    assert MASK in result and result.startswith("bad ")


# 2) the sweep ----------------------------------------------------------------------------------


def sweep_failures(key: str, sequence: str) -> list[str]:
    failures: list[str] = []
    for at in range(len(key) + 1):
        text = f"x {key[:at]}{sequence}{key[at:]} y"
        found = leaks(sanitise_text(text, api_key=key), key)
        if found:
            failures.append(f"position {at}: {found[0]!r}")
    return failures


@pytest.mark.parametrize("sequence", list(EVERY_FAMILY.values()), ids=FAMILY_IDS)
def test_no_piece_of_a_non_key_shaped_own_key_survives_a_sequence_at_any_position(
    sequence: str,
) -> None:
    assert not sweep_failures(OWN_KEY, sequence)


@pytest.mark.parametrize("sequence", list(EVERY_FAMILY.values()), ids=FAMILY_IDS)
def test_no_piece_of_a_real_length_key_survives_a_sequence_at_any_position(
    sequence: str,
) -> None:
    assert len(REAL_KEY) == REAL_KEY_LENGTH
    assert not sweep_failures(REAL_KEY, sequence)


# 3) the decision on an unterminated string sequence ---------------------------------------------


@pytest.mark.parametrize("sequence", list(UNTERMINATED.values()), ids=list(UNTERMINATED))
def test_an_unterminated_string_sequence_swallows_the_rest_of_the_text_in_display(
    sequence: str,
) -> None:
    # The terminal's own semantics and the safe choice: what follows such an introducer is never
    # shown, whatever it holds; the text before it is kept.
    result = sanitise_text(f"before {sequence} tail after")

    assert result == "before"
