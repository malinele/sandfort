"""CLI round 50, batch 2: ordering and character-class gaps inside the text sanitiser.

* An escape byte in front of a scheme-relative credential token or the api key no longer erases
  the marker or the key's first character before the mask runs.
* Two views of an invisible character: the MATCHING view (format and mark categories plus the
  listed fillers and selectors) is used to find a hidden key or userinfo; the DISPLAY strip
  removes only the format category and the explicit filler list, so combining marks, joiners
  and variation selectors stay in printed text (see ``tests/test_cli_r50f.py``).
* The complete-authority exemption of the cut reaches only up to the last slash.
* A property test over every control, format, nonspacing and enclosing mark code point: no
  secret fragment survives, and the display strip never removes a mark that is not a filler.
"""

import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli.sanitise import (  # noqa: E402
    DISPLAY_FILLERS,
    EXTRA_INVISIBLE,
    MASK,
    MAX_RAW_CHARS,
    drop_partial_url,
    is_hidden_in_display,
    is_invisible,
    sanitise_text,
    strip_invisible,
)

KEY = "sf_test_key_do_not_print"
PASSWORD = "S3cr3tPassw0rd"
FRAGMENT = 8
ESC = "\x1b"
CSI = "\x9b"

# Fillers that are stripped from displayed text (and looked through when matching a secret).
STRIPPED_FILLERS = [
    "­",  # soft hyphen
    "͏",  # combining grapheme joiner
    "؜",  # Arabic letter mark
    "᠎",  # Mongolian vowel separator
    "ᅟ",  # Hangul choseong filler
    "ᅠ",  # Hangul jungseong filler
    "ㅤ",  # Hangul filler
    "ﾠ",  # halfwidth Hangul filler
    "⠀",  # braille blank
    "​",  # zero width space
    "‮",  # right-to-left override
    "￹",  # interlinear annotation anchor
    "￺",  # interlinear annotation separator
    "￻",  # interlinear annotation terminator
]
# Characters that real text needs: kept in displayed text, but still looked through when
# matching a secret (a key interleaved with them is masked).
KEPT_SELECTORS = [
    "᠋",  # Mongolian free variation selector one
    "‌",  # zero width non-joiner
    "‍",  # zero width joiner
    "️",  # variation selector 16
    "\U000e0100",  # variation selector supplement
    "\U000e01ef",
]
FILLERS = [*STRIPPED_FILLERS, *KEPT_SELECTORS]
CATEGORIES = {"Cc", "Cf", "Mn", "Me"}
# Sorted and de-duplicated, split into chunks so a failure names a small range.
PROPERTY_CODE_POINTS = sorted(
    {
        char
        for char in (chr(code) for code in range(0x110000))
        if unicodedata.category(char) in CATEGORIES
    }
    | set(FILLERS)
)
CHUNK = 400
CHUNKS = [PROPERTY_CODE_POINTS[i : i + CHUNK] for i in range(0, len(PROPERTY_CODE_POINTS), CHUNK)]


def leaks(result: str, secret: str) -> list[str]:
    """The pieces of ``secret`` of eight or more characters that are visible in ``result``."""
    pieces = {secret[i : i + FRAGMENT] for i in range(len(secret) - FRAGMENT + 1)}
    return [piece for piece in pieces if piece in result]


# 1) the escape-byte marker erase -----------------------------------------------------------


@pytest.mark.parametrize(
    "lead", [ESC, CSI, ESC + "[", ESC + "]"], ids=["esc", "c1", "esc-[", "esc-]"]
)
def test_an_escape_byte_in_front_of_a_scheme_relative_token_does_not_hide_it(lead: str) -> None:
    result = sanitise_text(f"failed at {lead}//admin:{PASSWORD}@host.test:8443/x tail")

    assert not leaks(result, PASSWORD) and "admin" not in result


@pytest.mark.parametrize("lead", [ESC, CSI, ESC + "["], ids=["esc", "c1", "esc-["])
def test_an_escape_byte_in_front_of_the_api_key_does_not_eat_its_first_character(
    lead: str,
) -> None:
    result = sanitise_text(f"bad {lead}{KEY} now", api_key=KEY)

    assert not leaks(result, KEY) and "key_do_not" not in result
    assert result.startswith("bad")


def test_an_escape_byte_inside_the_key_is_looked_through() -> None:
    # ESC then ``_`` opens an APC string that never ends: it swallows the rest of the text in
    # the display view (the terminal's own semantics), so only the mask is shown. The key must
    # still be masked whole.
    result = sanitise_text(f"bad sf_test{ESC}_key_do_not_print now", api_key=KEY)

    assert result == f"bad {MASK}"
    assert "key_do_not" not in result and "sf_test" not in result


@pytest.mark.parametrize("lead", [ESC, CSI], ids=["esc", "c1"])
def test_the_tail_drop_checks_the_text_before_the_terminal_strip(lead: str) -> None:
    for tail in (f"{lead}{KEY[:14]}", f"{lead}//admin:{PASSWORD[:10]}"):
        padding = "x " * ((MAX_RAW_CHARS - len(tail) - len("denied ")) // 2)
        text = f"denied {padding}{tail}" + "y" * 100
        assert len(text) > MAX_RAW_CHARS

        result = sanitise_text(text, api_key=KEY)

        assert "sf_t" not in result and "key_do" not in result
        assert "admin" not in result and "S3cr3t" not in result


# 2) one definition of invisible ------------------------------------------------------------


@pytest.mark.parametrize("char", STRIPPED_FILLERS)
def test_a_listed_filler_is_invisible_and_stripped_from_display(char: str) -> None:
    assert is_invisible(char) and is_hidden_in_display(char)
    assert strip_invisible(f"a{char}b") == "ab"


@pytest.mark.parametrize("char", KEPT_SELECTORS)
def test_a_joiner_or_selector_is_looked_through_but_kept_in_display(char: str) -> None:
    assert is_invisible(char) and not is_hidden_in_display(char)
    assert strip_invisible(f"a{char}b") == f"a{char}b"


def test_the_matching_view_covers_every_format_and_mark_category_code_point() -> None:
    for code in range(0x110000):
        char = chr(code)
        if unicodedata.category(char) in {"Cf", "Mn", "Me"}:
            assert is_invisible(char), hex(code)
    assert all(is_invisible(chr(code)) for code in EXTRA_INVISIBLE)


def test_the_display_strip_removes_only_format_characters_and_listed_fillers() -> None:
    for code in range(0x110000):
        char = chr(code)
        category = unicodedata.category(char)
        if is_hidden_in_display(char):
            assert category == "Cf" or code in DISPLAY_FILLERS, hex(code)
        elif category in {"Mn", "Me"}:
            assert code not in DISPLAY_FILLERS, hex(code)
    # every nonspacing and enclosing mark outside the filler list survives the display strip
    marks = [
        chr(code)
        for code in range(0x110000)
        if unicodedata.category(chr(code)) in {"Mn", "Me"} and code not in DISPLAY_FILLERS
    ]
    assert len(marks) > 1000
    assert all(strip_invisible(f"a{mark}") == f"a{mark}" for mark in marks)


@pytest.mark.parametrize("char", FILLERS)
def test_a_whole_key_joined_with_a_filler_is_masked(char: str) -> None:
    result = sanitise_text(f"bad {char.join(KEY)} now", api_key=KEY)

    assert result == f"bad {MASK} now"


@pytest.mark.parametrize("char", FILLERS)
def test_a_key_shaped_server_token_joined_with_a_filler_is_masked(char: str) -> None:
    token = "sf_" + "abcdefghijklmnop"

    result = sanitise_text(f"bad {char.join(token)} now")

    assert result == f"bad {MASK} now"


# 3) the exemption reaches only to the last slash ----------------------------------------------


def test_a_credential_pair_in_the_last_path_segment_is_dropped_across_the_cut() -> None:
    text = "failed at http://host.test/a/b/user:pa"

    assert drop_partial_url(text) == "failed at http://host.test/a/b/"


def test_a_credential_pair_in_a_query_after_the_authority_is_dropped_across_the_cut() -> None:
    assert drop_partial_url("failed at http://host.test?x=user:pa") == "failed at http://host.test"


def test_a_long_path_without_a_colon_is_still_kept_whole() -> None:
    text = "failed at http://host.test/" + "p/" * 30 + "end"

    assert drop_partial_url(text) == text


def test_a_credential_pair_inside_a_url_path_is_masked_when_whole() -> None:
    result = sanitise_text(f"see http://host.test/a/user:{PASSWORD}@inner.test:80/x ok")

    assert not leaks(result, PASSWORD) and "ok" in result


# 4) the property test ------------------------------------------------------------------------

URL_PREFIX = "https:"
URL_REST = f"//admin:{PASSWORD}@host.test:8443/v1/items"


def padded_to_cut(body: str) -> str:
    """``body`` after plain-word padding so that the raw cut lands at the end of ``body``,
    followed by more text."""
    padding = ("w " * MAX_RAW_CHARS)[: MAX_RAW_CHARS - len(body) - len("failed ")]
    if not padding.endswith(" "):
        padding = padding[:-1] + " "
    return "failed " + padding + body + "z" * 50


def sensitive_texts(char: str) -> list[tuple[str, str]]:
    """(text, secret) pairs with ``char`` at the sampled sensitive positions."""
    url = URL_PREFIX + URL_REST
    middle = len(URL_PREFIX) + URL_REST.index(PASSWORD) + len(PASSWORD) // 2
    half = len(KEY) // 2
    key_cut = KEY[:half] + char + KEY[half : len(KEY) - 4]
    url_cut = url[:middle] + char + url[middle : middle + 4]
    return [
        # before the marker
        (f"x {URL_PREFIX}{char}{URL_REST} y", PASSWORD),
        (f"x {char}{URL_REST} y", PASSWORD),
        (f"x {char}{KEY} y", KEY),
        # inside the password / interleaved in the key
        (f"x {url[:middle]}{char}{url[middle:]} y", PASSWORD),
        (f"x {KEY[:3]}{char}{KEY[3:]} y", KEY),
        (f"x {KEY[:half]}{char}{KEY[half:]} y", KEY),
        (f"x {KEY[:-2]}{char}{KEY[-2:]} y", KEY),
        # straddling the cut
        (padded_to_cut(key_cut), KEY),
        (padded_to_cut(url_cut), PASSWORD),
    ]


@pytest.mark.parametrize(
    "chunk", CHUNKS, ids=[f"{c[0].encode('unicode_escape').decode()}" for c in CHUNKS]
)
def test_no_secret_fragment_survives_any_hidden_code_point_at_a_sensitive_position(
    chunk: list[str],
) -> None:
    failures: list[str] = []
    for char in chunk:
        for text, secret in sensitive_texts(char):
            found = leaks(sanitise_text(text, api_key=KEY), secret)
            if found:
                failures.append(f"U+{ord(char):04X} {text[-40:]!r} -> {found[0]!r}")
    assert not failures, failures[:10]


def test_the_property_covers_the_expected_code_point_classes() -> None:
    assert len(PROPERTY_CODE_POINTS) > 2000
    for char in (ESC, CSI, "\x00", "\n", "​", "́", "⃝", *FILLERS):
        assert char in PROPERTY_CODE_POINTS
