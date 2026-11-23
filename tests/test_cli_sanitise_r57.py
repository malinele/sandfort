"""CLI round 57, security findings for the sanitiser.

* A host run before ``?`` may hold the IDNA dot variants and non-ASCII punctuation or symbols.
* The whitespace rule also covers the part after the ``@`` of a bare credential and the gap
  between the slashes of a scheme-relative one.
* A numeric or other fragment is not eaten together with a closing bracket, quote or CJK mark.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli.sanitise import mask_fragments, mask_queries, sanitise_text  # noqa: E402

SECRET = "SECRET"
SEPARATORS = {
    "ideographic full stop": "。",
    "fullwidth full stop": "．",
    "halfwidth ideographic full stop": "｡",
    "one dot leader": "․",
    "two dot leader": "‥",
    "en dash": "–",
    "middle dot": "·",
    "katakana middle dot": "・",
    "emoji": "\U0001f600",
}


# 1. unicode punctuation or symbols between host letters
@pytest.mark.parametrize("separator", SEPARATORS.values(), ids=SEPARATORS.keys())
def test_query_after_a_host_with_a_unicode_separator_is_masked(separator: str) -> None:
    text = f"see host{separator}example?token={SECRET} ok"
    expected = f"see host{separator}example?token=*** ok"
    assert sanitise_text(text) == expected
    assert mask_queries(text) == expected


@pytest.mark.parametrize("separator", SEPARATORS.values(), ids=SEPARATORS.keys())
def test_query_value_never_survives_a_unicode_separator(separator: str) -> None:
    assert SECRET not in sanitise_text(f"host{separator}example?token={SECRET}")


def test_the_literal_issue_example_is_masked() -> None:
    text = "see host。example?token=SECRET ok"
    assert sanitise_text(text) == "see host。example?token=*** ok"


@pytest.mark.parametrize(
    "text",
    [
        "really?",
        "really? yes",
        "日本語、はい?x=1",
        "こんにちは！?x=1",
        "café…?x=1",
        "¿qué?x=1",
        "「はい」?x=1",
        "——?x=1",
        "\U0001f600?x=1",
        "café!?x=1",
    ],
)
def test_prose_look_alikes_stay_readable(text: str) -> None:
    assert sanitise_text(text) == text
    assert mask_queries(text) == text


@pytest.mark.parametrize("dot", ["。", "．", "｡", "․", "‥"])
def test_idna_dot_variants_give_a_host_context_for_a_fragment(dot: str) -> None:
    # Only the dot-as-"." reading gives this context; the symbol rule is not used for fragments.
    text = f"see host{dot}example#secret ok"
    assert sanitise_text(text) == f"see host{dot}example#*** ok"


def test_ascii_word_with_a_query_is_masked_as_before() -> None:
    assert sanitise_text("what?x=1") == "what?x=***"


# 2. whitespace after the ``@`` of a bare credential
@pytest.mark.parametrize("gap", ["\t", "\r", " ", " ", "　", "\x0b", "\x0c"])
@pytest.mark.parametrize(
    "tail", ["host.internal:8443/x", "host.internal/x", "[::1]:8443/x", "db:5432/x"]
)
def test_whitespace_after_the_at_sign_does_not_hide_the_password(gap: str, tail: str) -> None:
    shown = sanitise_text(f"admin:HunterPW@{gap}{tail}")
    assert "HunterPW" not in shown
    assert tail in shown


def test_the_literal_tab_example_is_masked() -> None:
    shown = sanitise_text("admin:HunterPW@\thost.internal:8443/x")
    assert "HunterPW" not in shown
    assert "admin" not in shown


def test_empty_user_with_whitespace_after_the_at_sign_is_masked() -> None:
    assert "HunterPW" not in sanitise_text(":HunterPW@\thost.internal:8443/x")


@pytest.mark.parametrize("gap", ["\t", " ", " ", "　"])
def test_whitespace_between_the_slashes_does_not_hide_the_password(gap: str) -> None:
    shown = sanitise_text(f"/{gap}/HunterPW@evil.example/x")
    assert "HunterPW" not in shown
    assert "evil.example/x" in shown


def test_plain_space_and_lf_remain_the_documented_trade_off() -> None:
    assert sanitise_text("admin:pw@ x") == "admin:pw@ x"
    assert sanitise_text("ratio 3:2@ 4") == "ratio 3:2@ 4"


def test_unrelated_text_after_the_at_sign_stays() -> None:
    assert sanitise_text("write to me:you@\tsoon") == "write to me:you@ soon"


# 3. closers after a fragment
CLOSERS = {
    "bracket": "]",
    "brace": "}",
    "angle": ">",
    "pipe": "|",
    "ellipsis": "…",
    "curly double": "”",
    "curly single": "’",
    "cjk bracket": "】",
    "cjk corner": "」",
    "cjk full stop": "。",
    "cjk comma": "、",
    "fullwidth paren": "）",
    "parenthesis": ")",
}


@pytest.mark.parametrize("closer", CLOSERS.values(), ids=CLOSERS.keys())
def test_numeric_fragment_before_a_closer_stays_whole(closer: str) -> None:
    text = f"[refs/heads/feature#12{closer}"
    assert sanitise_text(text) == text
    assert mask_fragments(text) == text


@pytest.mark.parametrize("closer", CLOSERS.values(), ids=CLOSERS.keys())
def test_secret_fragment_is_masked_and_the_closer_is_kept(closer: str) -> None:
    text = f"[https://host.test/p#secret{closer}"
    expected = f"[https://host.test/p#***{closer}"
    assert sanitise_text(text) == expected
    assert mask_fragments(text) == expected


def test_the_literal_bracket_example_is_not_eaten() -> None:
    assert sanitise_text("[refs/heads/feature#12]") == "[refs/heads/feature#12]"


def test_long_numeric_fragment_before_a_bracket_is_masked() -> None:
    assert sanitise_text("[refs/heads/feature#1234567]") == "[refs/heads/feature#***]"
