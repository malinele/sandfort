"""Plain-decimal parsing and the hints after a refused number option."""

import math
import re
import unicodedata

from sandfort_cli.output import is_blank_char

SURROUNDING_SPACES_HINT = "; surrounding whitespace is not allowed"
PLAIN_DIGITS_HINT = "; only plain ASCII digits are accepted"
UNDERSCORE_HINT = "; digit separators are not accepted"
SIGN_HINT = "; a sign is not accepted; write the number without it"
# Followed by the code point (``U+200B``): the echo drops the character, so it is named. A
# control character (category Cc: C0, DEL, C1) gets the control wording; a format or other
# default-ignorable character keeps the invisible one.
INVISIBLE_HINT_PREFIX = "; contains an invisible character "
CONTROL_HINT_PREFIX = "; contains a control character "
CONTROL_CATEGORY = "Cc"
# A raw byte the shell could not decode arrives as a lone surrogate, which the echo drops.
UNDECODABLE_HINT = "; contains an undecodable byte"
SURROGATE_FIRST = 0xD800
SURROGATE_LAST = 0xDFFF
PLUS_SIGN = "+"
FULLWIDTH_PLUS_SIGN = "\uff0b"
PLUS_SIGNS = (PLUS_SIGN, FULLWIDTH_PLUS_SIGN)
UNDERSCORE = "_"

# A decimal number as a user types it: plain ASCII digits with an optional leading minus (a plus
# sign is refused), fraction and exponent. ``float()`` also takes non-ASCII digits, surrounding
# whitespace and underscores; those are refused like they are for the whole-number options.
PLAIN_DECIMAL_RE = re.compile(r"-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][-+]?[0-9]+)?")


def parse_plain_decimal(raw: str) -> float:
    """``raw`` as a float when it is a :data:`PLAIN_DECIMAL_RE` number, else ``nan``."""
    if not PLAIN_DECIMAL_RE.fullmatch(raw):
        return math.nan
    try:
        return float(raw)
    except ValueError:  # pragma: no cover - the pattern only admits float() syntax
        return math.nan


def is_lone_surrogate(char: str) -> bool:
    """True for a lone surrogate: how Python keeps an undecodable byte of a command line."""
    return SURROGATE_FIRST <= ord(char) <= SURROGATE_LAST


def is_hidden_char(char: str) -> bool:
    """An invisible or control character that is not whitespace (the echo drops it)."""
    return not char.isspace() and not is_lone_surrogate(char) and is_blank_char(char)


def misleads_as_digits(char: str) -> bool:
    """A character the echo hides or makes look like a plain number part: an invisible or
    control character (not whitespace), a non-ASCII digit or a plus sign."""
    if char in PLUS_SIGNS or (char.isdigit() and not char.isascii()):
        return True
    return is_hidden_char(char) or is_lone_surrogate(char)


def code_point(char: str) -> str:
    """``U+200B`` style name of one character (at least four hex digits)."""
    return f"U+{ord(char):04X}"


def character_hints(raw: str) -> str:
    """The notes on characters that make ``raw`` look like a plain number when echoed: a
    leading plus sign, a non-ASCII digit, an undecodable byte and the first invisible character.
    The sign is looked for once invisible characters are removed (``ESC +5``, ``ZWSP +5``) and
    the fullwidth plus counts as one. A plus sign elsewhere (``1+1``, ``1e+5``) is not a sign:
    the plain-digits note applies."""
    visible = "".join(char for char in raw if not is_hidden_char(char)).strip()
    has_sign = visible.startswith(PLUS_SIGNS)
    hints = SIGN_HINT if has_sign else ""
    rest = visible[1:] if has_sign else visible
    inner_plus = any(char in PLUS_SIGNS for char in rest)
    if inner_plus or any(char.isdigit() and not char.isascii() for char in raw):
        hints += PLAIN_DIGITS_HINT
    if any(is_lone_surrogate(char) for char in raw):
        hints += UNDECODABLE_HINT
    hidden = next((char for char in raw if is_hidden_char(char)), None)
    if hidden is not None:
        hints += hidden_hint_prefix(hidden) + code_point(hidden)
    return hints


def hidden_hint_prefix(char: str) -> str:
    """The hint wording for a hidden character: control (Cc) or invisible (anything else)."""
    if unicodedata.category(char) == CONTROL_CATEGORY:
        return CONTROL_HINT_PREFIX
    return INVISIBLE_HINT_PREFIX


def whole_number_hints(raw: str) -> str:
    """The notes after a refused number: the echo flattens whitespace and drops invisible
    characters and undecodable bytes, so a value that would look like a plain number says why
    it is not one (each misleading kind of character gets its own note); an underscore
    (``1_000``, which ``int()`` takes) gets its own note too."""
    hints = SURROUNDING_SPACES_HINT if raw != raw.strip() else ""
    hints += character_hints(raw)
    if UNDERSCORE in raw:
        hints += UNDERSCORE_HINT
    return hints
