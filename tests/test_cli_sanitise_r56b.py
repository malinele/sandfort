"""CLI round 56 (review fixes): the host part, whitespace after an anchor, trailing punctuation
and the scheme rule of the numeric-fragment exemption in :mod:`sandfort_cli.sanitise_stages`.
"""

import sys
import time
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli.sanitise_stages import mask_fragments, mask_queries  # noqa: E402

MASKED_QUERY = "?token=***"


# 1. combining marks in the host part
@pytest.mark.parametrize(
    "host",
    [
        unicodedata.normalize("NFD", "café"),
        "हिन्दी",
    ],
)
def test_query_after_a_word_with_combining_marks_is_masked(host: str) -> None:
    assert mask_queries(f"{host}?token=SECRET") == f"{host}{MASKED_QUERY}"


# 2. whitespace after a numeric anchor
@pytest.mark.parametrize("space", ["\n", "\t", "\r", "\xa0"])
def test_text_after_whitespace_is_judged_on_its_own(space: str) -> None:
    text = f"refs/heads/feature#12{space}refs/heads/main"
    assert mask_fragments(text, across_breaks=True) == text
    assert mask_fragments(text) == text


@pytest.mark.parametrize("space", ["\n", "\t", "\r", "\xa0"])
def test_a_later_secret_fragment_after_whitespace_is_still_masked(space: str) -> None:
    text = f"refs/heads/feature#12{space}https://host.test/p#secret"
    expected = f"refs/heads/feature#12{space}https://host.test/p#***"
    assert mask_fragments(text, across_breaks=True) == expected


# 3. trailing punctuation
@pytest.mark.parametrize(
    "text",
    ["a/b#12,", "a/b#12.", "a/b#12;", "a/b#12:", "a/b#12!", "a/b#12?", '"a/b#12"', "'a/b#12'"],
)
def test_trailing_punctuation_keeps_the_numeric_exemption(text: str) -> None:
    assert mask_fragments(text) == text
    assert mask_fragments(text, across_breaks=True) == text


def test_punctuation_inside_the_fragment_is_not_numeric() -> None:
    assert mask_fragments("a/b#12,secret") == "a/b#***"


# 4. the scheme rule
def test_all_digit_fragment_on_a_url_with_a_scheme_is_masked() -> None:
    assert mask_fragments("https://host.test/verify#123456") == "https://host.test/verify#***"


@pytest.mark.parametrize(
    "text",
    ["page.html#42", "refs/heads/feature#12", "page.html#123456", "https://host.test/docs#7"],
)
def test_short_or_scheme_less_numeric_fragment_stays(text: str) -> None:
    assert mask_fragments(text) == text


def test_scheme_in_another_token_does_not_count() -> None:
    text = "https://host.test/x\npage.html#123456"
    assert mask_fragments(text, across_breaks=True) == text


# 5. linear cost
def test_many_numeric_anchors_in_one_text_are_linear() -> None:
    text = "a/b#1\n" * 4000
    for across_breaks in (False, True):
        start = time.perf_counter()
        result = mask_fragments(text, across_breaks=across_breaks)
        assert time.perf_counter() - start < 0.3
        assert result == text
