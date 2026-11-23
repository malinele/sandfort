"""CLI round 51, batch 2: the sanitiser stage recipes from the two security personas.

* The tail drops at the cut run on the MATCHING view (invisibles ignored), so a mark or joiner
  between the two slashes of a scheme-relative credential does not defeat them.
* Userinfo, query and fragment are masked again between the terminal strip and the flattening
  pass: a terminal sequence inside the userinfo plus a whitespace-class character in the
  password, and string-introducer sequences that swallow the ``@``, no longer leak. A plain
  space inside an escape sequence is part of it; a string sequence that never ends counts as a
  cut.
* The matching-view invisible class is the Default_Ignorable_Code_Point property (the unassigned
  ranges around U+FFF0 and the plane-14 gaps included).
* The display strip keeps the format characters that draw something (Arabic prefixed signs and
  end-of-ayah, the Syriac abbreviation mark, the Kaithi marks) and well-formed emoji tag
  sequences (a tagged flag).
* The query mask needs a url-ish context before the question mark.
* The tail drop is bounded: a long spaceless script text with a colon keeps a prefix.
* The caller's key is masked on a repeatedly percent-decoded copy (the double-encoded form).
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli.sanitise import (  # noqa: E402
    ELLIPSIS,
    MASK,
    MAX_RAW_CHARS,
    MAX_TAIL_TOKEN_CHARS,
    drop_partial_url,
    is_hidden_in_display,
    is_invisible,
    redact_url,
    sanitise_text,
    strip_invisible,
)

KEY = "sf_test_key_do_not_print"
# Twenty characters: split in two, neither half reaches the eight-character leak threshold on
# its own, so each half is also asserted explicitly.
LONG_PW = "Zx9Qm4Lv7Tn2Bk8Rw5Hd"
FRAGMENT = 8
ESC = "\x1b"
URL_PREFIX = "https:"
URL_REST = f"//admin:{LONG_PW}@host.test:8443/v1/items"
FOREIGN = "sf_" + "abcdefghijklmnop"


def leaks(result: str, secret: str) -> list[str]:
    """The pieces of ``secret`` of eight or more characters that are visible in ``result``."""
    pieces = {secret[i : i + FRAGMENT] for i in range(len(secret) - FRAGMENT + 1)}
    return [piece for piece in pieces if piece in result]


def padded_to_cut(body: str) -> str:
    """``body`` after plain-word padding so that the raw cut lands at the end of ``body``,
    followed by more text."""
    padding = ("w " * MAX_RAW_CHARS)[: MAX_RAW_CHARS - len(body) - len("failed ")]
    if not padding.endswith(" "):
        padding = padding[:-1] + " "
    return "failed " + padding + body + "z" * 50


def encode_levels(text: str, levels: int, *, lower: bool = False) -> str:
    """Every byte of ``text`` percent-encoded, ``levels`` times over (the hex digits and the
    percent signs of the previous level are encoded too)."""
    template = "%{:02x}" if lower else "%{:02X}"
    for _ in range(levels):
        text = "".join(template.format(byte) for byte in text.encode())
    return text


def double_encoded(text: str) -> str:
    """``text`` percent-encoded once, then only the percent signs encoded again: ``%2573``."""
    return "".join(f"%25{byte:02X}" for byte in text.encode())


def tag_letters(letters: str) -> str:
    """``letters`` written as Unicode tag characters."""
    return "".join(chr(0xE0000 + ord(char)) for char in letters)


# 1) the tail drops run on the matching view ----------------------------------------------------

MARKS = ["́", "‍", "‌", "️", "͏", "⃝", "\U000e0001"]
MARK_IDS = ["acute", "zwj", "zwnj", "vs16", "cgj", "enclosing", "tag-begin"]


@pytest.mark.parametrize("mark", MARKS, ids=MARK_IDS)
def test_a_mark_between_the_slashes_does_not_defeat_the_drop_at_the_cut(mark: str) -> None:
    for tail in (f"/{mark}/admin", f"/{mark}/admin:{LONG_PW[:10]}"):
        result = sanitise_text(padded_to_cut(tail))

        assert "admin" not in result and LONG_PW[:6] not in result


@pytest.mark.parametrize("mark", MARKS, ids=MARK_IDS)
def test_a_mark_between_the_slashes_of_a_scheme_is_looked_through_at_the_cut(mark: str) -> None:
    tail = f"https:/{mark}/admin:{LONG_PW[:10]}"

    result = sanitise_text(padded_to_cut(tail))

    assert "admin" not in result and LONG_PW[:6] not in result


def test_the_drop_finds_a_bare_double_slash_token_through_a_mark() -> None:
    assert drop_partial_url("failed at /́/admin") == "failed at "


def test_the_drop_keeps_a_complete_authority_through_a_mark() -> None:
    text = "failed at /́/host.test/a/b"

    assert drop_partial_url(text) == text


def test_the_drop_cuts_a_credential_pair_in_the_last_segment_through_a_mark() -> None:
    text = "failed at /́/host.test/a/user:pa"

    assert drop_partial_url(text) == "failed at /́/host.test/a/"


# 2) userinfo, query and fragment between the strip and the flattening --------------------------

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
    "dcs": ESC + "Pq data" + ESC + "\\",
    "c1-dcs": "\x90q data\x9c",
    "sos": ESC + "X note " + ESC + "\\",
    "c1-sos": "\x98 note \x9c",
    "pm": ESC + "^ note " + ESC + "\\",
    "c1-pm": "\x9e note \x9c",
    "apc": ESC + "_ note " + ESC + "\\",
    "c1-apc": "\x9f note \x9c",
    "esc-short": ESC + "c",
    "esc-charset": ESC + "(B",
}
# String sequences without a terminator: they swallow what follows them.
UNTERMINATED = {
    "osc": ESC + "]0;title",
    "c1-osc": "\x9d0;title",
    "dcs": ESC + "Pq data",
    "c1-dcs": "\x90q data",
    "sos": ESC + "X note",
    "c1-sos": "\x98 note",
    "pm": ESC + "^ note",
    "c1-pm": "\x9e note",
    "apc": ESC + "_ note",
    "c1-apc": "\x9f note",
}
INTRODUCERS = {
    "c1-dcs": ("\x90", "\x9c"),
    "c1-sos": ("\x98", "\x9c"),
    "c1-osc": ("\x9d", "\x9c"),
    "c1-pm": ("\x9e", "\x9c"),
    "c1-apc": ("\x9f", "\x9c"),
    "esc-dcs": (ESC + "P", ESC + "\\"),
    "esc-sos": (ESC + "X", ESC + "\\"),
    "esc-osc": (ESC + "]", ESC + "\\"),
    "esc-pm": (ESC + "^", ESC + "\\"),
    "esc-apc": (ESC + "_", ESC + "\\"),
}
WHITESPACE = [
    "\t",
    "\n",
    "\x0b",
    "\x0c",
    "\x1c",
    "\x85",
    " ",
    " ",
    " ",
    "　",
]
SEQUENCE_IDS = list(SEQUENCES)
UNTERMINATED_IDS = list(UNTERMINATED)
INTRODUCER_IDS = list(INTRODUCERS)


def assert_password_gone(result: str) -> None:
    assert LONG_PW[:10] not in result and LONG_PW[10:] not in result
    assert not leaks(result, LONG_PW) and "admin" not in result


@pytest.mark.parametrize("sequence", list(SEQUENCES.values()), ids=SEQUENCE_IDS)
@pytest.mark.parametrize("space", WHITESPACE, ids=[f"U+{ord(c):04X}" for c in WHITESPACE])
def test_a_terminal_sequence_in_the_userinfo_and_a_whitespace_character_in_the_password(
    sequence: str, space: str
) -> None:
    password = f"{LONG_PW[:10]}{sequence}{LONG_PW[10:15]}{space}{LONG_PW[15:]}"

    result = sanitise_text(f"see https://admin:{password}@host.test:8443/x ok")

    assert_password_gone(result)
    assert result.endswith("host.test:8443/x ok")


@pytest.mark.parametrize("introducer", list(INTRODUCERS.values()), ids=INTRODUCER_IDS)
def test_an_unterminated_string_introducer_does_not_swallow_the_marker(
    introducer: tuple[str, str],
) -> None:
    opener, _ = introducer

    result = sanitise_text(f"see https://admin:{LONG_PW}{opener} @host.test:8443/x ok")

    assert_password_gone(result)
    assert result.startswith("see ")


@pytest.mark.parametrize("introducer", list(INTRODUCERS.values()), ids=INTRODUCER_IDS)
def test_a_terminated_string_sequence_with_a_space_does_not_split_the_userinfo(
    introducer: tuple[str, str],
) -> None:
    opener, closer = introducer

    result = sanitise_text(f"see https://admin:{LONG_PW}{opener} {closer}@host.test:8443/x ok")

    assert_password_gone(result)
    assert result.endswith("host.test:8443/x ok")


@pytest.mark.parametrize("sequence", list(UNTERMINATED.values()), ids=UNTERMINATED_IDS)
def test_an_unterminated_string_sequence_inside_the_key_leaves_no_key_prefix(
    sequence: str,
) -> None:
    result = sanitise_text(f"x {KEY[:12]}{sequence}{KEY[12:]} y", api_key=KEY)

    assert not leaks(result, KEY) and "sf_test" not in result


@pytest.mark.parametrize("sequence", list(UNTERMINATED.values()), ids=UNTERMINATED_IDS)
def test_an_unterminated_string_sequence_inside_the_password_leaves_no_prefix(
    sequence: str,
) -> None:
    url = f"https://admin:{LONG_PW[:10]}{sequence}{LONG_PW[10:]}@host.test:8443/x"

    result = sanitise_text(f"see {url} ok")

    assert_password_gone(result)


def test_query_and_fragment_are_masked_after_sequences_inside_them_are_stripped() -> None:
    text = f"see http://h.test/p?k=abc{ESC}[ qdef#frag{ESC}[31mxyz ok"

    assert sanitise_text(text) == f"see http://h.test/p?k={MASK}#{MASK} ok"


# 3) the Default_Ignorable_Code_Point property ----------------------------------------------------

# Unicode 16 DerivedCoreProperties.txt, Default_Ignorable_Code_Point (assigned and unassigned).
DICP_RANGES = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)
DICP = [chr(code) for low, high in DICP_RANGES for code in range(low, high + 1)]
# What the display keeps: joiners, the Mongolian free variation selectors, variation selectors.
KEPT_IN_DISPLAY_RANGES = (
    (0x180B, 0x180D),
    (0x180F, 0x180F),
    (0x200C, 0x200D),
    (0xFE00, 0xFE0F),
    (0xE0100, 0xE01EF),
)
KEPT_IN_DISPLAY = {code for low, high in KEPT_IN_DISPLAY_RANGES for code in range(low, high + 1)}
CHUNK = 256
DICP_CHUNKS = [DICP[i : i + CHUNK] for i in range(0, len(DICP), CHUNK)]
# The cut variants are slow (a 2000-character text); the long plane-14 filler blocks, which all
# take the same path, are sampled with this stride. Everything else runs in full.
PLANE_14_FILLER_STRIDE = 37
PLANE_14_FILLER_BLOCKS = ((0xE0000, 0xE00FF), (0xE01F0, 0xE0FFF))
UNASSIGNED_SAMPLES = [0x2065, 0xFFF0, 0xFFF8, 0xE0002, 0xE0080, 0xE00FF, 0xE01F0, 0xE0FFF]


def runs_cut_variant(char: str) -> bool:
    code = ord(char)
    for low, high in PLANE_14_FILLER_BLOCKS:
        if low <= code <= high:
            return (code - low) % PLANE_14_FILLER_STRIDE == 0 or code == high
    return True


def uncut_texts(insert: str) -> list[tuple[str, str]]:
    """(text, secret) pairs with ``insert`` at the sampled sensitive positions."""
    url = URL_PREFIX + URL_REST
    middle = len(URL_PREFIX) + URL_REST.index(LONG_PW) + len(LONG_PW) // 2
    half = len(KEY) // 2
    return [
        (f"x {URL_PREFIX}{insert}{URL_REST} y", LONG_PW),
        (f"x {insert}{URL_REST} y", LONG_PW),
        (f"x {insert}{KEY} y", KEY),
        (f"x {url[:middle]}{insert}{url[middle:]} y", LONG_PW),
        (f"x {KEY[:3]}{insert}{KEY[3:]} y", KEY),
        (f"x {KEY[:half]}{insert}{KEY[half:]} y", KEY),
        (f"x {KEY[:-2]}{insert}{KEY[-2:]} y", KEY),
    ]


def cut_texts(insert: str) -> list[tuple[str, str]]:
    """(text, secret) pairs where the raw cut lands right after the inserted-into secret."""
    url = URL_PREFIX + URL_REST
    middle = len(URL_PREFIX) + URL_REST.index(LONG_PW) + len(LONG_PW) // 2
    half = len(KEY) // 2
    key_cut = KEY[:half] + insert + KEY[half : len(KEY) - 4]
    url_cut = url[:middle] + insert + url[middle : middle + 4]
    return [(padded_to_cut(key_cut), KEY), (padded_to_cut(url_cut), LONG_PW)]


def leak_failures(insert: str, *, cut: bool) -> list[str]:
    failures: list[str] = []
    texts = uncut_texts(insert) + (cut_texts(insert) if cut else [])
    for text, secret in texts:
        found = leaks(sanitise_text(text, api_key=KEY), secret)
        if found:
            failures.append(f"{insert.encode('unicode_escape')!r} {text[-40:]!r} -> {found[0]!r}")
    return failures


def test_every_default_ignorable_code_point_is_in_the_matching_view() -> None:
    assert len(DICP) > 4000
    assert all(is_invisible(char) for char in DICP)


@pytest.mark.parametrize("code", UNASSIGNED_SAMPLES)
def test_the_unassigned_ranges_are_looked_through_and_stripped_from_display(code: int) -> None:
    char = chr(code)

    assert is_invisible(char) and is_hidden_in_display(char)
    assert strip_invisible(f"a{char}b") == "ab"
    assert sanitise_text(f"bad {char.join(KEY)} now", api_key=KEY) == f"bad {MASK} now"
    assert sanitise_text(f"bad {char.join(FOREIGN)} now") == f"bad {MASK} now"


def test_the_display_keeps_only_joiners_and_selectors_of_the_ignorable_set() -> None:
    for char in DICP:
        if ord(char) in KEPT_IN_DISPLAY:
            assert not is_hidden_in_display(char), hex(ord(char))
            assert strip_invisible(f"a{char}b") == f"a{char}b", hex(ord(char))
        else:
            assert is_hidden_in_display(char), hex(ord(char))
            assert strip_invisible(f"a{char}b") == "ab", hex(ord(char))


@pytest.mark.parametrize("chunk", DICP_CHUNKS, ids=[f"U+{ord(c[0]):04X}" for c in DICP_CHUNKS])
def test_no_secret_fragment_survives_any_default_ignorable_code_point(chunk: list[str]) -> None:
    failures: list[str] = []
    for char in chunk:
        failures.extend(leak_failures(char, cut=runs_cut_variant(char)))

    assert not failures, failures[:10]


@pytest.mark.parametrize("sequence", list(SEQUENCES.values()), ids=SEQUENCE_IDS)
def test_no_secret_fragment_survives_a_terminal_sequence_at_a_sensitive_position(
    sequence: str,
) -> None:
    assert not leak_failures(sequence, cut=True)


@pytest.mark.parametrize("sequence", list(UNTERMINATED.values()), ids=UNTERMINATED_IDS)
def test_no_secret_fragment_survives_an_unterminated_sequence_at_a_sensitive_position(
    sequence: str,
) -> None:
    assert not leak_failures(sequence, cut=True)


# 4) the display strip keeps what draws something -------------------------------------------------

ARABIC_SIGNS = ["؀", "؁", "؂", "؃", "؄", "؅", "۝", "࣢"]
OTHER_VISIBLE_FORMAT = ["܏", "\U000110bd", "\U000110cd"]
TAGGED_FLAG = "\U0001f3f4" + tag_letters("gbsct") + "\U000e007f"
THAI_QUESTION = (
    "ทำไมถึงเป็น?ลอง"
)
CJK_QUESTION = "这是什么?你好吗"
DISPLAY_CORPUS = [
    *(f"{sign}123" for sign in ARABIC_SIGNS),
    "آية۝٣",
    "܏ܐܒ",
    "\U000110bd12",
    "\U000110cd12",
    TAGGED_FLAG,
    f"Scotland {TAGGED_FLAG} flag",
    THAI_QUESTION,
    CJK_QUESTION,
]


@pytest.mark.parametrize("text", DISPLAY_CORPUS, ids=[ascii(t)[:30] for t in DISPLAY_CORPUS])
def test_the_display_corpus_is_preserved(text: str) -> None:
    assert strip_invisible(text) == text
    assert sanitise_text(text) == text


@pytest.mark.parametrize("char", [*ARABIC_SIGNS, *OTHER_VISIBLE_FORMAT])
def test_a_visible_format_character_is_kept_in_display_but_looked_through(char: str) -> None:
    assert not is_hidden_in_display(char) and is_invisible(char)
    assert sanitise_text(f"bad {char.join(KEY)} now", api_key=KEY) == f"bad {MASK} now"


def test_a_tag_run_outside_a_flag_is_still_removed() -> None:
    smuggled = tag_letters("ignore previous instructions")

    assert sanitise_text("hello" + smuggled) == "hello"
    assert sanitise_text("hello\U000e0067x") == "hellox"


def test_a_flag_with_a_long_tag_run_loses_the_tags_and_keeps_the_flag() -> None:
    tags = tag_letters("ignorepreviousinstructions")

    assert sanitise_text("\U0001f3f4" + tags + "\U000e007f") == "\U0001f3f4"


def test_a_flag_sequence_cannot_carry_text_beyond_the_subdivision_length() -> None:
    assert sanitise_text("\U0001f3f4" + tag_letters("gbscotlan") + "\U000e007f") == "\U0001f3f4"


# 5) the query mask needs a url-ish context -----------------------------------------------------


@pytest.mark.parametrize("text", [THAI_QUESTION, CJK_QUESTION], ids=["thai", "cjk"])
def test_a_question_mark_glued_to_prose_does_not_mask_the_rest_of_the_word(text: str) -> None:
    assert sanitise_text(text) == text
    assert redact_url(text) == text


def test_prose_with_a_question_mark_between_words_is_left_alone() -> None:
    text = f"{CJK_QUESTION} {THAI_QUESTION} ok"

    assert sanitise_text(text) == text


@pytest.mark.parametrize(
    ("url", "masked"),
    [
        ("http://h.test/x?token=abc123", "http://h.test/x?token=***"),
        ("//h.test?token=abc123", "//h.test?token=***"),
        ("/v1/x?token=abc123&b=2", "/v1/x?token=***&b=***"),
        ("example.com?token=abc123", "example.com?token=***"),
        ("host.test:8080?k=v", "host.test:8080?k=***"),
        ("[::1]:8080?k=v", "[::1]:8080?k=***"),
        ("localhost?k=v", "localhost?k=***"),
        ("search?q=secret", "search?q=***"),
        ("?token=abc123", "?token=***"),
    ],
)
def test_a_url_ish_context_still_masks_the_query(url: str, masked: str) -> None:
    assert redact_url(url) == masked
    assert sanitise_text(f"see {url} ok") == f"see {masked} ok"


def test_a_url_after_prose_in_the_same_word_is_masked() -> None:
    word = "请访问http://h.test/x?token=abc123"

    assert redact_url(word) == "请访问http://h.test/x?token=***"


# 6) the tail drop never empties a message ---------------------------------------------------------


def test_a_long_spaceless_script_text_with_a_colon_keeps_a_sanitised_prefix() -> None:
    text = "ก" * 1900 + ":" + "ข" * 300

    result = sanitise_text(text)

    assert result == "ก" * 299 + ELLIPSIS


def test_the_drop_removes_at_most_the_bounded_tail_of_a_spaceless_token() -> None:
    text = "ก" * 1900 + ":x" + "ข" * 98

    assert len(drop_partial_url(text)) == len(text) - MAX_TAIL_TOKEN_CHARS


def test_a_colon_far_from_the_cut_leaves_the_spaceless_text_whole() -> None:
    text = "ก:" + "ข" * 2100

    assert sanitise_text(text) == "ก:" + "ข" * 297 + ELLIPSIS


def test_a_short_partial_credential_token_is_still_dropped_whole() -> None:
    assert drop_partial_url("failed at admin:Zx9Qm4Lv7T") == "failed at "


# 7) the key on a repeatedly percent-decoded copy -------------------------------------------------


@pytest.mark.parametrize("levels", [2, 3, 4])
@pytest.mark.parametrize("lower", [False, True], ids=["upper", "lower"])
def test_a_repeatedly_encoded_key_is_masked(levels: int, lower: bool) -> None:
    encoded = encode_levels(KEY, levels, lower=lower)

    result = sanitise_text(f"bad {encoded} now", api_key=KEY)

    assert result == f"bad {MASK} now"


def test_a_double_encoded_key_is_masked() -> None:
    assert sanitise_text(f"bad {double_encoded(KEY)} now", api_key=KEY) == f"bad {MASK} now"


def test_a_key_with_only_its_underscores_double_encoded_is_masked() -> None:
    mixed = KEY.replace("_", "%255F")

    assert sanitise_text(f"bad {mixed} now", api_key=KEY) == f"bad {MASK} now"


def test_a_repeatedly_encoded_key_shaped_token_is_masked_without_a_caller_key() -> None:
    assert sanitise_text(f"bad {double_encoded(FOREIGN)} now") == f"bad {MASK} now"
    assert sanitise_text(f"bad {encode_levels(FOREIGN, 3)} now") == f"bad {MASK} now"


def test_a_double_encoded_key_cut_in_the_middle_of_an_escape_is_dropped() -> None:
    result = sanitise_text(padded_to_cut(double_encoded(KEY)[:62]), api_key=KEY)

    assert "%25" not in result and "%73" not in result


def test_text_that_only_looks_encoded_is_left_as_it_is() -> None:
    assert sanitise_text("ratio 100%25 done, 50%2 left") == "ratio 100%25 done, 50%2 left"


def test_a_plain_key_is_still_masked() -> None:
    assert sanitise_text(f"bad {KEY} now", api_key=KEY) == f"bad {MASK} now"
