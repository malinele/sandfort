"""CLI round 60 (persona noor): host separators from more scripts, sentence ends, closing quotes.

* A host glued to a character of the Unicode categories Po, Pd, Ps, Pe, Pi, Pf or Zs (the Arabic
  comma, question mark and semicolon, the devanagari danda and double danda, the wave dash, the
  katakana middle dot, the ideographic space) or to the fullwidth tilde keeps its query or
  fragment masked. The dot and the hyphen inside a host and the apostrophe inside a word are not
  separators.
* A masked query or fragment ends at the first non-ASCII character of category Po, so a Japanese
  sentence without spaces keeps its text after the secret. A Unicode space (Zs) inside a value
  does not end it (the r54b rule: a hostile server could split a secret with one).
* A masked fragment or query stops before a closing quote or bracket (Pe, Pf) and before an ASCII
  quote, so the closing character survives.
"""

import sys
import time
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli.sanitise import mask_fragments, mask_queries, sanitise_text  # noqa: E402

# Realistic secret lengths: a 36-character token, a 43-character ``sf_`` key and 64 hex digits.
TOKEN = "tok_9fK2mQx7LpR4vB8nZc3Wd5YhA1sE6uJt"
API_KEY = "sf_Qm3xV9tLr2KcYb7NpWd4HgZs8EaUf6JiXo1"
HEX_SECRET = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
SECRETS = [TOKEN, API_KEY, HEX_SECRET]
HOST = "host.example"
PERFORMANCE_CHARS = 200_000
TIME_LIMIT_SECONDS = 2.0

SEPARATORS = {
    "arabic comma": "،",
    "arabic question mark": "؟",
    "arabic semicolon": "؛",
    "devanagari danda": "।",
    "devanagari double danda": "॥",
    "wave dash": "〜",
    "fullwidth tilde": "～",
    "katakana middle dot": "・",
    "ideographic space": "　",
}
EXTRA_CATEGORY_SEPARATORS = {
    "en dash": "–",
    "left double quotation mark": "“",
    "right double quotation mark": "”",
    "left corner bracket": "「",
    "fullwidth right parenthesis": "）",
    "left guillemet": "«",
    "no-break space": " ",
    "thin space": " ",
    "armenian full stop": "։",
    "hebrew punctuation maqaf": "־",
}
ALL_SEPARATORS = {**SEPARATORS, **EXTRA_CATEGORY_SEPARATORS}
SENTENCE_ENDS = {
    "ideographic full stop": "。",
    "ideographic comma": "、",
    "arabic comma": "،",
    "devanagari danda": "।",
    "katakana middle dot": "・",
    "fullwidth exclamation mark": "！",
}
CLOSERS = {
    "ascii double quote": '"',
    "ascii single quote": "'",
    "right double quotation mark": "”",
    "right single quotation mark": "’",
    "right corner bracket": "」",
    "fullwidth right parenthesis": "）",
    "right guillemet": "»",
    "right white corner bracket": "』",
    "right black lenticular bracket": "】",
}
# A closer glued to letters on both sides is an apostrophe inside a word, not a closing quote.
APOSTROPHE_CLOSERS = ("ascii single quote", "right single quotation mark")
TAIL = "続きの文章です"

Stage = Callable[[str], str]


# --- 1. host separators from more scripts ---------------------------------------------------


@pytest.mark.parametrize("secret", SECRETS)
@pytest.mark.parametrize("name", list(ALL_SEPARATORS))
def test_query_after_a_separator_of_any_script_is_masked(name: str, secret: str) -> None:
    mark = ALL_SEPARATORS[name]

    masked = mask_queries(f"x{mark}{HOST}?token={secret}", across_breaks=True)

    assert secret not in masked
    assert masked == f"x{mark}{HOST}?token=***"


@pytest.mark.parametrize("secret", SECRETS)
@pytest.mark.parametrize("name", list(ALL_SEPARATORS))
def test_fragment_after_a_separator_of_any_script_is_masked(name: str, secret: str) -> None:
    mark = ALL_SEPARATORS[name]

    masked = mask_fragments(f"x{mark}{HOST}#{secret}", across_breaks=True)

    assert secret not in masked
    assert masked == f"x{mark}{HOST}#***"


@pytest.mark.parametrize("name", list(SEPARATORS))
def test_separator_glued_to_an_arabic_or_japanese_word_masks_the_host(name: str) -> None:
    mark = SEPARATORS[name]

    assert mask_queries(f"مرحبا{mark}{HOST}?k={TOKEN}") == f"مرحبا{mark}{HOST}?k=***"
    assert mask_fragments(f"こんにちは{mark}{HOST}#{TOKEN}") == f"こんにちは{mark}{HOST}#***"


@pytest.mark.parametrize("name", list(SEPARATORS))
def test_separator_before_a_host_with_a_port_keeps_the_tail_masked(name: str) -> None:
    mark = SEPARATORS[name]

    masked_fragment = mask_fragments(f"x{mark}host:8443#{TOKEN}", across_breaks=True)
    masked_query = mask_queries(f"x{mark}host:8443?t={TOKEN}", across_breaks=True)

    assert masked_fragment == f"x{mark}host:8443#***"
    assert masked_query == f"x{mark}host:8443?t=***"


@pytest.mark.parametrize("name", list(SEPARATORS))
def test_the_separator_itself_stays_visible_in_sanitise_text(name: str) -> None:
    mark = SEPARATORS[name]

    shown = sanitise_text(f"failed{mark}{HOST}?token={TOKEN}")

    assert TOKEN not in shown
    # The flattening turns the ideographic space into a plain space; the others stay as written.
    separator = " " if mark == "　" else mark
    assert shown == f"failed{separator}{HOST}?token=***"


def test_dot_and_hyphen_inside_a_host_are_not_separators() -> None:
    assert mask_queries(f"a.b.example?token={TOKEN}") == "a.b.example?token=***"
    assert mask_fragments(f"a-b.example#{TOKEN}") == "a-b.example#***"


@pytest.mark.parametrize("apostrophe", ["'", "’"])
def test_apostrophe_inside_a_word_is_not_a_separator(apostrophe: str) -> None:
    text = f"don{apostrophe}t.example?token={TOKEN}"

    assert mask_queries(text) == f"don{apostrophe}t.example?token=***"


@pytest.mark.parametrize("mark", ["、", "，", "،", "؟", "।"])
def test_a_bare_word_after_a_sentence_break_stays_prose(mark: str) -> None:
    text = f"你好{mark}再见?x=1"

    assert mask_queries(text) == text
    assert mask_fragments(f"你好{mark}再见#frag") == f"你好{mark}再见#frag"


# --- 2. the end of the sentence -------------------------------------------------------------


@pytest.mark.parametrize("secret", SECRETS)
@pytest.mark.parametrize("name", list(SENTENCE_ENDS))
def test_masked_query_ends_at_the_sentence_end(name: str, secret: str) -> None:
    mark = SENTENCE_ENDS[name]

    masked = mask_queries(f"{HOST}?token={secret}{mark}{TAIL}", across_breaks=True)

    assert masked == f"{HOST}?token=***{mark}{TAIL}"


@pytest.mark.parametrize("secret", SECRETS)
@pytest.mark.parametrize("name", list(SENTENCE_ENDS))
def test_masked_fragment_ends_at_the_sentence_end(name: str, secret: str) -> None:
    mark = SENTENCE_ENDS[name]

    masked = mask_fragments(f"{HOST}#{secret}{mark}{TAIL}", across_breaks=True)

    assert masked == f"{HOST}#***{mark}{TAIL}"


def test_japanese_sentence_without_spaces_keeps_its_text_after_the_token() -> None:
    text = f"接続に失敗しました {HOST}?token={TOKEN}。もう一度お試しください"

    shown = sanitise_text(text)

    assert TOKEN not in shown
    assert shown == f"接続に失敗しました {HOST}?token=***。もう一度お試しください"


def test_two_fragments_in_one_sentence_are_both_masked() -> None:
    text = f"a.example#{TOKEN}。b.example#{API_KEY}。{TAIL}"

    masked = mask_fragments(text)

    assert TOKEN not in masked
    assert API_KEY not in masked
    assert masked == f"a.example#***。b.example#***。{TAIL}"


def test_two_queries_in_one_sentence_are_both_masked() -> None:
    text = f"a.example?k={TOKEN}、b.example?k={API_KEY}、{TAIL}"

    assert mask_queries(text) == f"a.example?k=***、b.example?k=***、{TAIL}"


def test_a_secret_with_ascii_punctuation_is_masked_whole() -> None:
    secret = "ab.cd-ef_gh/ij%3Dkl:mn"

    assert mask_queries(f"{HOST}?token={secret}。{TAIL}") == f"{HOST}?token=***。{TAIL}"
    assert mask_fragments(f"{HOST}#{secret}。{TAIL}") == f"{HOST}#***。{TAIL}"


@pytest.mark.parametrize("gap", ["　", " ", " "])
def test_a_unicode_space_inside_a_value_does_not_end_it(gap: str) -> None:
    # A hostile server could split a secret with a space that is flattened later (r54b).
    query = mask_queries(f"{HOST}?token=ab{gap}cd", across_breaks=True)
    fragment = mask_fragments(f"{HOST}#ab{gap}cd", across_breaks=True)

    assert query == f"{HOST}?token=***"
    assert fragment == f"{HOST}#***"


def test_a_numeric_anchor_before_the_sentence_end_stays() -> None:
    text = f"refs/heads/feature#12。{TAIL}"

    assert mask_fragments(text) == text


# --- 3. the closing character survives ------------------------------------------------------


@pytest.mark.parametrize("secret", SECRETS)
@pytest.mark.parametrize("name", list(CLOSERS))
def test_closing_quote_survives_a_fragment_mask(name: str, secret: str) -> None:
    closer = CLOSERS[name]
    opener = closer if closer in "\"'" else "("

    masked = mask_fragments(f"{opener}{HOST}#{secret}{closer}")

    assert masked == f"{opener}{HOST}#***{closer}"


@pytest.mark.parametrize("secret", SECRETS)
@pytest.mark.parametrize("name", list(CLOSERS))
def test_closing_quote_survives_a_query_mask(name: str, secret: str) -> None:
    closer = CLOSERS[name]
    opener = closer if closer in "\"'" else "("

    masked = mask_queries(f"{opener}{HOST}?token={secret}{closer}")

    assert masked == f"{opener}{HOST}?token=***{closer}"


@pytest.mark.parametrize("name", [n for n in CLOSERS if n not in APOSTROPHE_CLOSERS])
def test_text_after_the_closing_quote_stays(name: str) -> None:
    closer = CLOSERS[name]

    masked = mask_fragments(f"({HOST}#{TOKEN}{closer}{TAIL}")

    assert masked == f"({HOST}#***{closer}{TAIL}"


@pytest.mark.parametrize("apostrophe", ["'", "’"])
def test_apostrophe_between_letters_inside_a_value_does_not_end_it(apostrophe: str) -> None:
    masked = mask_fragments(f"{HOST}#ab{apostrophe}cd{TOKEN}")

    assert masked == f"{HOST}#***"
    assert mask_queries(f"{HOST}?k=ab{apostrophe}cd{TOKEN}") == f"{HOST}?k=***"


def test_quoted_egress_error_keeps_its_closing_quote() -> None:
    text = f'egress denied for "{HOST}#{TOKEN}"'

    assert sanitise_text(text) == 'egress denied for "host.example#***"'


@pytest.mark.parametrize("opener,closer", [("“", "”"), ("「", "」"), ("«", "»")])
def test_quoted_host_with_a_fragment_keeps_the_pair_of_quotes(opener: str, closer: str) -> None:
    masked = mask_fragments(f"{opener}{HOST}#{TOKEN}{closer}")

    assert masked == f"{opener}{HOST}#***{closer}"


# --- Latin regressions: ASCII separators and ASCII text are unchanged -----------------------


@pytest.mark.parametrize("mark", [",", ";", "=", ":", "|", "@", "~", "*", "`", ">", "[", "("])
def test_ascii_separators_before_a_host_still_work(mark: str) -> None:
    assert mask_queries(f"see {mark}{HOST}?token={TOKEN}") == f"see {mark}{HOST}?token=***"
    assert mask_fragments(f"see {mark}{HOST}#{TOKEN}") == f"see {mark}{HOST}#***"


@pytest.mark.parametrize(
    "text,expected",
    [
        (f"https://h.test/p?token={TOKEN}", "https://h.test/p?token=***"),
        (f"https://h.test/p?a={TOKEN}&b={API_KEY}", "https://h.test/p?a=***&b=***"),
        (f"https://h.test/p#{TOKEN}", "https://h.test/p#***"),
        (f"(https://h.test/p#{TOKEN})", "(https://h.test/p#***)"),
        (f"[https://h.test/p#{TOKEN}]", "[https://h.test/p#***]"),
        ("https://h.test/p?token=a.b/c%3Dxyz", "https://h.test/p?token=***"),
        ("what?x=1", "what?x=***"),
        ("plain words, no url", "plain words, no url"),
        ("refs/heads/feature#12", "refs/heads/feature#12"),
        ("don't stop? ok", "don't stop? ok"),
    ],
)
def test_latin_text_is_unchanged(text: str, expected: str) -> None:
    assert mask_fragments(mask_queries(text)) == expected


def test_ascii_spaces_still_end_a_value() -> None:
    masked = mask_queries(f"{HOST}?token={TOKEN} and more text", across_breaks=True)

    assert masked == f"{HOST}?token=*** and more text"


# --- idempotence per stage ------------------------------------------------------------------

IDEMPOTENT_TEXTS = [
    f"x،{HOST}?token={TOKEN}#{API_KEY}",
    f"x।{HOST}#{TOKEN}。{TAIL}",
    f"{HOST}?token={TOKEN}。{HOST}#{API_KEY}、{TAIL}",
    f'"{HOST}#{TOKEN}"',
    f"「{HOST}?k={HEX_SECRET}」{TAIL}",
    f"a　{HOST}#{TOKEN}　b",
    f"x～{HOST}:8443?t={TOKEN}",
    "ref=abc#frag",
]


@pytest.mark.parametrize("text", IDEMPOTENT_TEXTS)
def test_mask_queries_is_idempotent(text: str) -> None:
    for across_breaks in (False, True):
        once = mask_queries(text, across_breaks=across_breaks)
        assert mask_queries(once, across_breaks=across_breaks) == once


@pytest.mark.parametrize("text", IDEMPOTENT_TEXTS)
def test_mask_fragments_is_idempotent(text: str) -> None:
    for across_breaks in (False, True):
        once = mask_fragments(text, across_breaks=across_breaks)
        assert mask_fragments(once, across_breaks=across_breaks) == once


@pytest.mark.parametrize("text", IDEMPOTENT_TEXTS)
def test_sanitise_text_is_idempotent(text: str) -> None:
    once = sanitise_text(text)

    for secret in SECRETS:
        assert secret not in once
    assert sanitise_text(once) == once


# --- performance guard: 200k characters in under two seconds --------------------------------


def _elapsed(stage: Stage, text: str) -> float:
    assert len(text) >= PERFORMANCE_CHARS
    started = time.perf_counter()
    stage(text)
    return time.perf_counter() - started


@pytest.mark.parametrize("stage", [mask_queries, mask_fragments, sanitise_text])
@pytest.mark.parametrize(
    "unit",
    [
        "،host.example#x?a=b。",
        "।h.e:80#x?a=b",
        "・h.e?a=b”",
        "x　h.e#y　",
        '"h.e#y"',
    ],
)
def test_many_markers_and_separators_in_one_word_stay_linear(stage: Stage, unit: str) -> None:
    text = unit * (PERFORMANCE_CHARS // len(unit) + 1)

    assert _elapsed(stage, text) < TIME_LIMIT_SECONDS


@pytest.mark.parametrize("stage", [mask_queries, mask_fragments])
def test_a_long_run_of_separators_before_one_marker_stays_linear(stage: Stage) -> None:
    text = "،" * PERFORMANCE_CHARS + "host.example#x?a=b"

    assert _elapsed(stage, text) < TIME_LIMIT_SECONDS


@pytest.mark.parametrize("stage", [mask_queries, mask_fragments])
def test_a_long_value_without_a_sentence_end_stays_linear(stage: Stage) -> None:
    text = f"{HOST}?a=b#" + "日本語" * (PERFORMANCE_CHARS // 3 + 1)

    assert _elapsed(stage, text) < TIME_LIMIT_SECONDS


@pytest.mark.parametrize("stage", [mask_queries, mask_fragments])
def test_many_words_with_sentence_ends_stay_linear(stage: Stage) -> None:
    unit = f"{HOST}?a={TOKEN}#{TOKEN}。 "
    text = unit * (PERFORMANCE_CHARS // len(unit) + 1)

    assert _elapsed(stage, text) < TIME_LIMIT_SECONDS


# --- ines: bracketed IPv6 hosts and the remaining punctuation -------------------------------

IPV6_LITERALS = ["[::1]", "[2001:db8::7]", "[fe80::1%eth0]", "[::ffff:192.0.2.1]", "[ABCD:ef01::2]"]
IPV6_PREFIXES = ["key=", "url=", "，", "、", "；", "。", "x،", "|", "->", "ref:", "「", ""]
# Sentence breaks among the siblings: a bare word after one of them stays prose.
SIBLING_BREAKS = {
    "halfwidth ideographic comma": "､",
    "vertical ideographic full stop": "︒",
    "small full stop": "﹒",
    "vertical ellipsis": "︙",
    "double exclamation mark": "‼",
    "double question mark": "⁇",
    "question exclamation mark": "⁈",
    "exclamation question mark": "⁉",
    "arabic full stop": "۔",
    "arabic semicolon": "؛",
}
# Every sibling ines listed (Po, Ps, Pe, Pi and Pf marks): all separate a host from the text before.
SIBLING_MARKS = {
    **SIBLING_BREAKS,
    "vertical two dot leader": "︰",
    "dashed overline": "﹉",
    "wavy overline": "﹌",
    "white lenticular left": "〖",
    "white lenticular right": "〗",
    "white tortoise shell left": "〘",
    "white tortoise shell right": "〙",
    "white square left": "〚",
    "white square right": "〛",
    "double angle left": "《",
    "double angle right": "》",
    "angle left": "〈",
    "angle right": "〉",
    "tortoise shell left": "〔",
    "tortoise shell right": "〕",
    "small tortoise shell left": "﹝",
    "small tortoise shell right": "﹞",
    "inverted question mark": "¿",
    "inverted exclamation mark": "¡",
    "arabic percent sign": "٪",
    "arabic decimal separator": "٫",
    "arabic thousands separator": "٬",
    "devanagari abbreviation sign": "॰",
    "single guillemet left": "‹",
    "single guillemet right": "›",
}


@pytest.mark.parametrize("secret", [TOKEN, API_KEY])
@pytest.mark.parametrize("literal", IPV6_LITERALS)
@pytest.mark.parametrize("prefix", IPV6_PREFIXES)
def test_bracketed_ipv6_host_with_port_and_fragment_is_masked(
    prefix: str, literal: str, secret: str
) -> None:
    masked = mask_fragments(f"{prefix}{literal}:8080#{secret}")

    assert masked == f"{prefix}{literal}:8080#***"


@pytest.mark.parametrize("prefix", IPV6_PREFIXES)
@pytest.mark.parametrize("literal", IPV6_LITERALS)
def test_bracketed_ipv6_host_with_port_and_query_is_masked(prefix: str, literal: str) -> None:
    masked = mask_queries(f"{prefix}{literal}:8080?token={HEX_SECRET}", across_breaks=True)

    assert masked == f"{prefix}{literal}:8080?token=***"


@pytest.mark.parametrize("literal", IPV6_LITERALS)
@pytest.mark.parametrize("prefix", IPV6_PREFIXES)
def test_bracketed_ipv6_host_without_a_port_is_masked(prefix: str, literal: str) -> None:
    assert mask_fragments(f"{prefix}{literal}#{TOKEN}") == f"{prefix}{literal}#***"
    assert mask_queries(f"失敗{prefix}{literal}?k={TOKEN}") == f"失敗{prefix}{literal}?k=***"


def test_ipv6_loopback_with_cjk_comma_leaks_nothing_in_sanitise_text() -> None:
    shown = sanitise_text(f"接続失敗、[::1]:8080#{API_KEY}")

    assert API_KEY not in shown
    assert shown == "接続失敗、[::1]:8080#***"


def test_ipv6_with_port_then_query_and_fragment_masks_both() -> None:
    shown = sanitise_text(f"key=[::1]:8080?a={TOKEN}#{API_KEY}")

    assert TOKEN not in shown
    assert API_KEY not in shown
    assert shown == "key=[::1]:8080?a=***#***"


def test_ipv6_literal_keeps_the_tail_text_after_a_sentence_end() -> None:
    masked = mask_fragments(f"，[::1]:8080#{TOKEN}。{TAIL}")

    assert masked == f"，[::1]:8080#***。{TAIL}"


@pytest.mark.parametrize("opener,closer", [("(", ")"), ("[", "]"), ("「", "」"), ("“", "”")])
def test_ipv6_host_inside_a_pair_keeps_its_closer(opener: str, closer: str) -> None:
    masked = mask_fragments(f"{opener}[::1]:8080#{TOKEN}{closer}")

    assert masked == f"{opener}[::1]:8080#***{closer}"


@pytest.mark.parametrize("text", ["arr[1:2]#note", "x=a[1:2]#note", "k=[1, 2, 3]#note"])
def test_brackets_that_are_not_an_ipv6_host_stay_readable(text: str) -> None:
    assert mask_fragments(text) == text


@pytest.mark.parametrize(
    "text",
    [
        "a[1:2:3]#note",
        "x=a[1:2:3]#note",
        "m[0:1:2]#note",
        "grid[1:2:3:4]#note",
        "(a[1:2:3]#note)",
    ],
)
def test_hex_only_subscripts_with_short_groups_stay_readable(text: str) -> None:
    assert mask_fragments(text) == text


@pytest.mark.parametrize(
    "literal",
    ["[a:b:c]", "[1:2:300]", "[2001:db8:0:0:0:0:0:1]", "[1::2]", "[::]", "[1:2:1.2.3.4]"],
)
def test_groups_with_a_letter_or_three_digits_or_a_double_colon_are_hosts(literal: str) -> None:
    assert mask_fragments(f"a{literal}#{TOKEN}") == f"a{literal}#***"
    assert mask_fragments(f"{literal}:80#{TOKEN}") == f"{literal}:80#***"


def test_a_subscript_does_not_hide_a_real_host_next_to_it() -> None:
    masked = mask_fragments(f"a[1:2:3] [::1]:8080#{TOKEN}")

    assert masked == "a[1:2:3] [::1]:8080#***"


@pytest.mark.parametrize("name", list(SIBLING_MARKS))
@pytest.mark.parametrize("secret", [TOKEN, API_KEY])
def test_sibling_punctuation_is_a_separator_before_a_host(name: str, secret: str) -> None:
    mark = SIBLING_MARKS[name]

    queried = mask_queries(f"x{mark}{HOST}?token={secret}", across_breaks=True)
    fragment = mask_fragments(f"x{mark}{HOST}#{secret}", across_breaks=True)
    ported = mask_fragments(f"x{mark}host:8443#{secret}", across_breaks=True)
    bracketed = mask_fragments(f"x{mark}[::1]:8443#{secret}", across_breaks=True)

    assert queried == f"x{mark}{HOST}?token=***"
    assert fragment == f"x{mark}{HOST}#***"
    assert ported == f"x{mark}host:8443#***"
    assert bracketed == f"x{mark}[::1]:8443#***"


@pytest.mark.parametrize("name", list(SIBLING_MARKS))
def test_sibling_punctuation_stays_visible_after_sanitise_text(name: str) -> None:
    mark = SIBLING_MARKS[name]

    shown = sanitise_text(f"failed{mark}{HOST}#{TOKEN}")

    assert TOKEN not in shown
    assert shown == f"failed{mark}{HOST}#***"


@pytest.mark.parametrize("name", list(SIBLING_MARKS))
def test_sibling_punctuation_between_two_hosts_masks_both(name: str) -> None:
    mark = SIBLING_MARKS[name]

    masked = mask_fragments(f"a.example#{TOKEN}{mark}b.example#{API_KEY}")

    assert TOKEN not in masked
    assert API_KEY not in masked


@pytest.mark.parametrize("name", list(SIBLING_BREAKS))
def test_a_bare_word_after_a_sibling_sentence_break_stays_prose(name: str) -> None:
    mark = SIBLING_BREAKS[name]
    text = f"你好{mark}再见?x=1"

    assert mask_queries(text) == text
    assert mask_fragments(f"你好{mark}再见#frag") == f"你好{mark}再见#frag"


@pytest.mark.parametrize("text", [f"x،[::1]:8080#{TOKEN}", f"key=[::1]:80?a={TOKEN}#{API_KEY}"])
def test_ipv6_stages_are_idempotent(text: str) -> None:
    for across_breaks in (False, True):
        queries = mask_queries(text, across_breaks=across_breaks)
        fragments = mask_fragments(text, across_breaks=across_breaks)
        assert mask_queries(queries, across_breaks=across_breaks) == queries
        assert mask_fragments(fragments, across_breaks=across_breaks) == fragments
    once = sanitise_text(text)
    assert sanitise_text(once) == once


@pytest.mark.parametrize("stage", [mask_queries, mask_fragments, sanitise_text])
@pytest.mark.parametrize(
    "unit",
    ["key=[::1]:8080#x?a=b、", "[fe80::1%eth0]:80#y。", "،[::1]#x", "[[[[a:a:a:", "[:::::::::::"],
)
def test_many_ipv6_literals_in_one_word_stay_linear(stage: Stage, unit: str) -> None:
    text = unit * (PERFORMANCE_CHARS // len(unit) + 1)

    assert _elapsed(stage, text) < TIME_LIMIT_SECONDS


@pytest.mark.parametrize("stage", [mask_queries, mask_fragments])
def test_a_long_unclosed_bracket_run_before_a_marker_stays_linear(stage: Stage) -> None:
    text = "[" + "a:" * (PERFORMANCE_CHARS // 2) + "#x?a=b"

    assert _elapsed(stage, text) < TIME_LIMIT_SECONDS


# --- 5. whitespace after a numeric anchor vs. the sentence end (r56b and r60 reconciled) -------
# tests/test_cli_sanitise_r56b.py: a secret fragment that continues after whitespace is masked.
# This module: the Japanese sentence end still ends a masked run and keeps the text after it.


@pytest.mark.parametrize("space", ["\n", "\t", "\r", "\xa0"])
def test_a_secret_fragment_after_whitespace_is_masked_across_breaks(space: str) -> None:
    text = f"refs/heads/feature#12{space}https://{HOST}/p#{TOKEN}"

    masked = mask_fragments(text, across_breaks=True)

    assert TOKEN not in masked
    assert masked == f"refs/heads/feature#12{space}https://{HOST}/p#***"


@pytest.mark.parametrize("space", ["\n", "\t", "\r", "\xa0"])
def test_plain_words_after_whitespace_stay_visible(space: str) -> None:
    text = f"refs/heads/feature#12{space}see the docs{space}refs/heads/main"

    assert mask_fragments(text, across_breaks=True) == text


@pytest.mark.parametrize("space", ["\n", "\t", "\r", "\xa0"])
def test_a_secret_query_after_a_numeric_anchor_and_whitespace_is_masked(space: str) -> None:
    text = f"refs/heads/feature#12{space}{HOST}?token={TOKEN}"

    masked = mask_queries(mask_fragments(text, across_breaks=True), across_breaks=True)

    assert TOKEN not in masked
    assert masked == f"refs/heads/feature#12{space}{HOST}?token=***"


def test_the_sentence_end_still_ends_the_run_after_a_numeric_anchor_and_whitespace() -> None:
    text = f"refs/heads/feature#12\n{HOST}#{TOKEN}。{TAIL}"

    masked = mask_fragments(text, across_breaks=True)

    assert masked == f"refs/heads/feature#12\n{HOST}#***。{TAIL}"
