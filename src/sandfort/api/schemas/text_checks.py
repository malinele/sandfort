"""Checks that refuse request text which would show up blank or garbled in a listing."""

import unicodedata
from collections.abc import Iterable, Mapping

from pydantic_core import PydanticCustomError

from sandfort.services.volumes import RESERVED_LABEL_PREFIX, is_reserved_label

# Sandbox label bounds (round 58), published as ``maxProperties`` and ``maxLength``.
MAX_LABELS = 32
MAX_LABEL_KEY_LENGTH = 63
MAX_LABEL_VALUE_LENGTH = 256
LABEL_ERROR_TYPE = "value_error"  # the type a label refusal has always carried
RESERVED_LABEL_CODE = "RESERVED_LABEL"  # ``ctx.code`` of the reserved-label refusal (round 59)
CONTROL_CATEGORY = "Cc"  # C0 and C1 controls and DEL: ESC, BEL, NUL, tab, newline, ...
# Invisible format characters: zero-width space and joiners, bidi controls, tag characters.
FORMAT_CATEGORY = "Cf"
# Letters and symbols that render as nothing (round 56): Hangul fillers, the braille blank,
# the combining grapheme joiner and the variation selectors. They count as blank only when
# they are the whole text; next to a visible character they stay accepted.
BLANK_LOOKING_CHARACTERS = frozenset(
    {
        0x115F,  # HANGUL CHOSEONG FILLER
        0x1160,  # HANGUL JUNGSEONG FILLER
        0x3164,  # HANGUL FILLER
        0x2800,  # BRAILLE PATTERN BLANK
        0x034F,  # COMBINING GRAPHEME JOINER
        0xFFA0,  # HALFWIDTH HANGUL FILLER
        0x17B4,  # KHMER VOWEL INHERENT AQ
        0x17B5,  # KHMER VOWEL INHERENT AA
        *range(0x180B, 0x180E),  # MONGOLIAN FREE VARIATION SELECTOR ONE to THREE
        0x180F,  # MONGOLIAN FREE VARIATION SELECTOR FOUR
        *range(0xFE00, 0xFE10),  # VARIATION SELECTOR-1 to -16
        *range(0xE0100, 0xE01F0),  # VARIATION SELECTOR-17 to -256 (supplement)
    }
)
# Published wording (guide, changelog); unchanged by the blank-looking letters extension.
BLANK_TEXT_MESSAGE = (
    "must contain a visible character, not only whitespace and invisible format characters"
)


def _blank(char: str) -> bool:
    """Whitespace (``str.isspace()``), an invisible format character or a blank-looking letter."""
    return (
        char.isspace()
        or unicodedata.category(char) == FORMAT_CATEGORY
        or ord(char) in BLANK_LOOKING_CHARACTERS
    )


def invisible_text_problem(text: str) -> str | None:
    """Why ``text`` would show up blank or garbled in a listing; ``None`` when it would not.

    Text with any control character (round 53), or made only of whitespace (every character
    for which ``str.isspace()`` is true: space, no-break space, em space, ideographic space,
    ...; round 56), invisible format characters and blank-looking letters and symbols (Hangul
    fillers U+115F, U+1160, U+3164 and U+FFA0, braille blank U+2800, combining grapheme joiner
    U+034F, Khmer inherent vowels U+17B4 and U+17B5, Mongolian free variation selectors U+180B
    to U+180D and U+180F, variation selectors U+FE00 to U+FE0F and U+E0100 to U+E01EF; round
    56), is refused. Whitespace between visible
    characters, a joiner or variation selector between visible characters (an emoji sequence)
    and any non-ASCII script stay accepted.
    """
    if any(unicodedata.category(char) == CONTROL_CATEGORY for char in text):
        return "must not contain control characters"
    if all(_blank(char) for char in text):
        return BLANK_TEXT_MESSAGE
    return None


def plain_error(message: str) -> PydanticCustomError:
    """A ``value_error`` whose published message is ``message`` itself (rounds 58, 59).

    A plain ``ValueError`` is published as ``"Value error, " + message``; this keeps the type
    and the location and drops that prefix. It is still a ``ValueError``, so a caller outside
    a validator can catch it as one. Without a context the message is not formatted, so
    braces in the text are shown as they are.
    """
    return PydanticCustomError(LABEL_ERROR_TYPE, message)


def label_error(message: str) -> PydanticCustomError:
    """``plain_error`` for a label refusal, which reads ``label names ...`` (round 58)."""
    return plain_error(message)


def check_visible_text(text: str) -> str:
    """``text`` unchanged; a 422 naming the field (no pydantic prefix) when it is not visible."""
    if (problem := invisible_text_problem(text)) is not None:
        raise plain_error(problem)
    return text


def check_label_keys(labels: Mapping[str, str] | None) -> None:
    """Refuse a label key ``invisible_text_problem`` names; values are not checked here."""
    for name in labels or {}:
        if (problem := invisible_text_problem(name)) is not None:
            raise label_error(f"label names {problem}: {name!r}")


def check_label_bounds(labels: Mapping[str, str] | None, max_labels: int = MAX_LABELS) -> None:
    """Refuse too many labels, a key past 63 characters or a value past 256 characters.

    The bounds the sandbox labels publish (round 58), for a label map that is not typed with
    them. A long key is not echoed; a long value is reported under its (escaped) key.
    """
    found = labels or {}
    if len(found) > max_labels:
        raise label_error(f"at most {max_labels} labels are allowed")
    for name, value in found.items():
        if len(name) > MAX_LABEL_KEY_LENGTH:
            raise label_error(f"label names must be at most {MAX_LABEL_KEY_LENGTH} characters")
        if len(value) > MAX_LABEL_VALUE_LENGTH:
            raise label_error(
                f"the value of label {ascii(name)} must be at most "
                f"{MAX_LABEL_VALUE_LENGTH} characters"
            )


def reserved_label_error(names: Iterable[str]) -> PydanticCustomError:
    """The one refusal of reserved label names (round 59), whichever schema raises it.

    Message ``label names starting with sandfort. are reserved: a, b`` (names sorted); the
    context carries ``code`` ``RESERVED_LABEL`` and the sorted ``names`` list.
    """
    ordered = sorted(names)
    message = f"label names starting with {RESERVED_LABEL_PREFIX} are reserved: " + ", ".join(
        ordered
    )
    return PydanticCustomError(
        LABEL_ERROR_TYPE, message, {"code": RESERVED_LABEL_CODE, "names": ordered}
    )


def check_reserved_labels(labels: Mapping[str, str] | None) -> None:
    """Refuse every label name starting with the platform's reserved prefix."""
    reserved = [name for name in labels or {} if is_reserved_label(name)]
    if reserved:
        raise reserved_label_error(reserved)


# --- the one content rule for stored strings (round 63) --------------------------------------
# Label keys and values, env keys and values, egress hosts, working directories and key names
# share ``content_problem``; mount paths add their look-alike list on top of it. A refusal
# names the field and the code point (``U+XXXX``) and never echoes a raw control character.
TAB = "\t"
BIDI_CONTROLS = frozenset({0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)})
# Marks that change how the character before them draws; at the start they draw nothing.
VARIATION_SELECTORS = frozenset(
    {0x180B, 0x180C, 0x180D, 0x180F, *range(0xFE00, 0xFE10), *range(0xE0100, 0xE01F0)}
)
FORMAT_CLASS = "an invisible format character"
SEPARATOR_CATEGORIES = frozenset({"Zl", "Zp"})  # line and paragraph separator
NONCHARACTER_LOW_BITS = 0xFFFE  # U+xxFFFE and U+xxFFFF are noncharacters in every plane
FIRST_NONCHARACTER, LAST_NONCHARACTER = 0xFDD0, 0xFDEF
# Zero width joiner and non-joiner: part of emoji sequences and of Indic and Persian words.
JOINERS = frozenset({0x200C, 0x200D})


def _is_noncharacter(code: int) -> bool:
    return (
        FIRST_NONCHARACTER <= code <= LAST_NONCHARACTER
        or (code & NONCHARACTER_LOW_BITS) == NONCHARACTER_LOW_BITS
    )


def _non_ascii_space(char: str) -> bool:
    return char != " " and unicodedata.category(char) == "Zs"


def _class_of(char: str, *, allow_tab: bool) -> str | None:
    """The refused class ``char`` belongs to, or ``None`` when it is fine."""
    code = ord(char)
    category = unicodedata.category(char)
    if char == TAB and allow_tab:
        return None
    if category == CONTROL_CATEGORY:
        return "a control character"
    if code in BIDI_CONTROLS:
        return "a bidi control character"
    if category == FORMAT_CATEGORY:
        return FORMAT_CLASS
    if category in SEPARATOR_CATEGORIES:
        return "a line or paragraph separator"
    if category == "Co":
        return "a private-use character"
    if category == "Cs" or _is_noncharacter(code):
        return "a noncharacter"
    return None


def _visible_neighbour(char: str) -> bool:
    """A letter, mark or symbol: not whitespace, a separator, nor any refused character."""
    return (
        not char.isspace()
        and not unicodedata.category(char).startswith("Z")
        and _class_of(char, allow_tab=False) is None
    )


def _joins_visible_characters(text: str, index: int) -> bool:
    """Whether the joiner at ``index`` sits between two visible characters of ``text``."""
    if index == 0 or index == len(text) - 1:
        return False
    return _visible_neighbour(text[index - 1]) and _visible_neighbour(text[index + 1])


def content_violation(
    text: str,
    *,
    allow_tab: bool = False,
    ascii_spaces_only: bool = False,
    no_whitespace: bool = False,
    allow_joiners: bool = False,
) -> tuple[str, str] | None:
    """``(class, "U+XXXX")`` of the first refused character of ``text``, else ``None``.

    Refused: C0 and C1 controls and DEL (a tab only when ``allow_tab``; a newline never), bidi
    controls and isolates, zero-width and other invisible format characters (category Cf),
    line and paragraph separators, private-use code points, noncharacters and surrogates, and a
    variation selector as the first character. ``ascii_spaces_only`` also refuses every space
    but U+0020 (no-break and the typographic spaces); ``no_whitespace`` refuses any whitespace.
    ``allow_joiners`` (label and env values) accepts U+200D and U+200C between two visible
    characters (emoji sequences, Indic and Persian words); at either end, next to whitespace,
    doubled or next to another format character they are refused as before.
    """
    if text and ord(text[0]) in VARIATION_SELECTORS:
        return "a variation selector at the start", f"U+{ord(text[0]):04X}"
    for index, char in enumerate(text):
        if allow_joiners and ord(char) in JOINERS and _joins_visible_characters(text, index):
            continue
        found = _class_of(char, allow_tab=allow_tab)
        if found is None and no_whitespace and char.isspace():
            found = "whitespace"
        if found is None and ascii_spaces_only and _non_ascii_space(char):
            found = "a non-ASCII space"
        if found is not None:
            return found, f"U+{ord(char):04X}"
    return None


def content_problem(text: str, **rules: bool) -> str | None:
    """``contains <class> (U+XXXX)`` for the first refused character of ``text``, else ``None``.

    The rules are those of ``content_violation``.
    """
    if (found := content_violation(text, **rules)) is None:
        return None
    return f"contains {found[0]} ({found[1]})"


def check_content(text: str, field: str, **rules: bool) -> str:
    """``text`` unchanged; a 422 ``<field> contains ... (U+XXXX)`` when ``content_problem``."""
    if (problem := content_problem(text, **rules)) is not None:
        raise plain_error(f"{field} {problem}")
    return text


def label_key_problem(name: str) -> str | None:
    """Why ``name`` is no label key (content rule, blank text, any whitespace), or ``None``."""
    if (problem := content_problem(name)) is not None:
        return problem
    if (problem := invisible_text_problem(name)) is not None:
        return problem
    return content_problem(name, no_whitespace=True)


def check_label_content(labels: Mapping[str, str] | None) -> None:
    """Refuse a label key ``label_key_problem`` names and a value ``content_problem`` names.

    A key that was already refused before (a control character, nothing visible) keeps its
    published ``label names ...`` wording; the newly refused characters name their code point.
    """
    for name, value in (labels or {}).items():
        if (old := invisible_text_problem(name)) is not None:
            raise label_error(f"label names {old}: {name!r}")
        if (problem := label_key_problem(name)) is not None:
            raise label_error(f"label key {problem}: {ascii(name)}")
        problem = content_problem(value, ascii_spaces_only=True, allow_joiners=True)
        if problem is not None:
            raise label_error(f"label value {problem}: label {ascii(name)}")


def check_env(env: Mapping[str, str]) -> None:
    """Refuse an env key or value ``content_problem`` names; only values may hold a tab."""
    for name, value in env.items():
        if (problem := content_problem(name)) is not None:
            raise plain_error(f"env key {problem}: {ascii(name)}")
        if (problem := content_problem(value, allow_tab=True, allow_joiners=True)) is not None:
            raise plain_error(f"env value {problem}: variable {ascii(name)}")


def check_cwd(value: str | None) -> str | None:
    """``value`` unchanged; a 422 naming ``cwd`` and the code point when it holds a bad one."""
    return None if value is None else check_content(value, "cwd")


def check_egress_hosts(entries: list[str] | None) -> list[str] | None:
    """``entries`` unchanged; a 422 for a host with a refused character or any whitespace."""
    for entry in entries or []:
        if (problem := content_problem(entry, no_whitespace=True)) is not None:
            raise plain_error(f"egress_allowlist entry {problem}: {ascii(entry)}")
    return entries
