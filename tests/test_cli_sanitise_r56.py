"""CLI round 56: sanitiser findings from the persona fuzz.

* A query after a non-ASCII word (``café?token=...``, ``日本語?x=1``) is masked like the ASCII
  ``what?x=1``: any run of letters (any script), digits, ``-``, ``_`` and ``.`` is a host part.
* A fragment of only ASCII digits, up to six of them (``refs/heads/feature#12``), is never masked;
  a longer or non-numeric fragment still is. With ``://`` before the anchor in the same token
  only up to three digits stay, so a verify link with a six-digit code is masked (a scheme-less
  or scheme-relative token keeps six digits, a conscious trade-off).
* A bare credential with an empty user (``:secret@host:8443``) is masked, also with an ESC X (SOS)
  sequence inside it, and a Unicode White_Space character other than the plain space and LF inside
  a bare credential does not end it. The plain-space trade-off stays (a space ends it).
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli.sanitise import mask_fragments, mask_queries, sanitise_text  # noqa: E402

# Unicode White_Space characters other than the plain space and LF.
BREAK_CHARS = [
    "\t",
    "\x0b",
    "\x0c",
    "\r",
    "\x85",
    "\xa0",
    " ",
    " ",
    " ",
    " ",
    " ",
    " ",
    " ",
    "　",
]
# An SOS sequence (ESC X ... ESC backslash) whose body holds a slash.
SOS = "\x1bXa/b\x1b\\"


def show(text: str) -> str:
    return sanitise_text(text)


MASKED_QUERIES = [
    ("café?token=SECRET", "café?token=***"),
    ("日本語?x=1", "日本語?x=***"),
    ("what?x=1", "what?x=***"),
    ("naïve_name-2.v?k=v&j=w", "naïve_name-2.v?k=***&j=***"),
    ("see: café?token=SECRET now", "see: café?token=*** now"),
]


# 1. a query after a word of any script
@pytest.mark.parametrize(("text", "expected"), MASKED_QUERIES)
def test_query_after_a_word_of_any_script_is_masked(text: str, expected: str) -> None:
    assert show(text) == expected
    assert mask_queries(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "日本語?はい",
        "本当ですか?",
        "café?",
        "café?はい=1",
        "café!?x=1",
        "日本語、はい?x=1",
        "what is this?",
    ],
)
def test_prose_with_a_question_mark_stays_readable(text: str) -> None:
    assert show(text) == text
    assert mask_queries(text) == text


# 2. a numeric fragment
@pytest.mark.parametrize(
    "text",
    [
        "refs/heads/feature#12",
        "(see refs/heads/feature#12)",
        "page.html#123456",
        "https://host.test/docs#7",
        "issue #123",
        "see issue #123 is open",
        "C#",
        "C# and F#",
    ],
)
def test_short_numeric_fragment_is_not_masked(text: str) -> None:
    assert show(text) == text
    assert mask_fragments(text) == text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("refs/heads/feature#1234567", "refs/heads/feature#***"),
        ("page.html#1234567", "page.html#***"),
        ("refs/heads/feature#v12", "refs/heads/feature#***"),
        ("refs/heads/feature#12a", "refs/heads/feature#***"),
        ("refs/heads/feature#1_2", "refs/heads/feature#***"),
        ("refs/heads/feature#١٢", "refs/heads/feature#***"),
        ("https://host.test/p#secret", "https://host.test/p#***"),
        ("(see refs/heads/feature#abc)", "(see refs/heads/feature#***)"),
    ],
)
def test_long_or_non_numeric_fragment_is_still_masked(text: str, expected: str) -> None:
    assert show(text) == expected
    assert mask_fragments(text) == expected


def test_query_is_masked_while_a_numeric_fragment_after_it_stays() -> None:
    assert show("https://host.test/p?a=1#12") == "https://host.test/p?a=***#12"


# 3a. a bare credential with an empty user
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (":secret@host:8443", "host:8443"),
        (":secret@host:8443/path", "host:8443/path"),
        (":secret@host/path", "host/path"),
        ("login to :secret@[::1]:8443 now", "login to [::1]:8443 now"),
        ("user:secret@host:8443", "host:8443"),
    ],
)
def test_bare_credential_with_empty_user_is_masked(text: str, expected: str) -> None:
    shown = show(text)
    assert "secret" not in shown
    assert shown == expected


@pytest.mark.parametrize(
    "text",
    [
        ":name@example.com",
        "note:name@example.com",
        "contact :name@example.com please",
        ":8443",
        "ratio :3@2",
    ],
)
def test_colon_and_at_without_a_host_port_or_path_stay_readable(text: str) -> None:
    assert show(text) == text


# 3b. an ESC X (SOS) sequence inside a credential
@pytest.mark.parametrize(
    "text",
    [
        f"https://user:hun{SOS}ter2@host/x",
        f"user:hun{SOS}ter2@host:8443",
        f":hun{SOS}ter2@host:8443",
        f"//user:hun{SOS}ter2@host/x",
        "https://user:hun\x1bXa b\x1b\\ter2@host/x",
        "https://user:hun\x9801 02\x9cter2@host/x",
    ],
)
def test_sos_sequence_inside_a_credential_does_not_let_it_survive(text: str) -> None:
    shown = show(text)
    for leaked in ("hun", "ter2", "a/b", "\x1b", "\x98"):
        assert leaked not in shown
    assert "host" in shown


def test_unterminated_sos_inside_a_credential_leaks_nothing() -> None:
    shown = show("https://user:hun\x1bXa/b ter2@host/x")
    assert "hun" not in shown
    assert "ter2" not in shown
    assert "\x1b" not in shown


# 3c. whitespace inside a bare credential
@pytest.mark.parametrize("space", BREAK_CHARS)
@pytest.mark.parametrize("user", ["user", ""])
def test_unicode_space_inside_a_bare_credential_keeps_it_whole(user: str, space: str) -> None:
    assert show(f"{user}:hunter{space}two@host:8443") == "host:8443"


@pytest.mark.parametrize("space", BREAK_CHARS)
def test_unicode_whitespace_in_the_password_before_a_path_host_is_masked(space: str) -> None:
    assert show(f"user:hunter{space}two@host/x") == "host/x"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("user:hunter two@host:8443", "user:hunter two@host:8443"),
        (":hunter two@host:8443", ":hunter two@host:8443"),
        ("user:hunter\ntwo@host:8443", "user:hunter two@host:8443"),
        ("label:\xa0name@example.com", "label: name@example.com"),
        ("label: name@example.com", "label: name@example.com"),
    ],
)
def test_plain_space_and_lf_still_end_a_bare_credential(text: str, expected: str) -> None:
    assert show(text) == expected


# idempotence of the new cases
FIXED_CASES = [
    "refs/heads/feature#12",
    "refs/heads/feature#1234567",
    "refs/heads/feature#v12",
    "https://host.test/p?a=1#12",
    "issue #123",
    "C#",
    ":secret@host:8443",
    ":secret@host/path",
    f":hun{SOS}ter2@host:8443",
    f"https://user:hun{SOS}ter2@host/x",
    "https://user:hun\x1bXa/b ter2@host/x",
    ":name@example.com",
    "user:hunter two@host:8443",
    "user:hunter\ntwo@host:8443",
]
NEW_CASES = [
    *(text for text, _ in MASKED_QUERIES),
    *FIXED_CASES,
    *(f"user:hunter{space}two@host:8443" for space in BREAK_CHARS),
    *(f":hunter{space}two@host:8443" for space in BREAK_CHARS),
]


@pytest.mark.parametrize("text", NEW_CASES)
def test_new_cases_are_idempotent(text: str) -> None:
    once = show(text)
    assert show(once) == once
