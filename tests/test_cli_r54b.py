"""CLI round 54, batch b: sanitiser stage-ordering gaps from two security testers.

1. A key of real length (60 characters) with one hidden character anywhere inside is masked
   whole: the tolerant own-key and shape passes run before the plain shape pass (and on the
   view the display will show), and the key mask runs again between the strip and the flatten.
2. An escape sequence that eats the query question mark, the colon of the scheme separator or
   the fragment marker cannot unmask the query value or the fragment (masked before the strip).
3. A terminal sequence whose body holds an at sign plus a hash or question mark, inside a
   password with whitespace, cannot turn its body into text that leaks the rest of the password.
4. The query context is tested on the matching view; non-ASCII host labels are hosts.
5. Whitespace other than the plain space inside a query or fragment value does not end it.
6. A scheme-less host followed by a fragment is masked like a scheme-less query.
7. Property checks: every stage is idempotent, no escape byte, C1 control or lone surrogate
   survives the pipeline, and ordinary non-ASCII text is shown unchanged.
"""

import random
import sys
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli.sanitise import (  # noqa: E402
    MASK,
    flatten_text,
    key_forms,
    mask_credentials,
    mask_fragments,
    mask_key,
    mask_queries,
    mask_raw_userinfo,
    redact_url,
    sanitise_text,
    scrub_local,
    strip_invisible,
    strip_terminal,
)

# A real key: ``sf_<env>_<8 lowercase or digits>_<43 url-safe characters>`` (60 in all).
KEY = "sf_live_ab12cd34_" + "Qw3rTy9UiOpAsDfGhJkLzXcVbNm-_0123456789abcd"
FOREIGN = "sf_test_zz98yx76_" + "Mn8bV7cX6zL5kJ4hG3fD2sA1pO0iU9yT8rE7wQ6-_ab"
REAL_KEY_LENGTH = 60
HIDDEN = {
    "zero-width-space": "\u200b",
    "soft-hyphen": "\u00ad",
    "nul": "\x00",
    "vertical-tab": "\x0b",
    "bare-escape": "\x1b",
    "csi": "\x1b[0m",
    "osc": "\x1b]0;t\x07",
    "osc-c1": "\x9d0;t\x9c",
    "combining-mark": "\u0301",
    "joiner": "\u200d",
    "bidi-mark": "\u200f",
    "bidi-override": "\u202e",
    "tag": "\U000e0041",
    "lone-surrogate": "\ud800",
}
# Whitespace controls are looked through only for the caller's own (exact) key: a key-shaped
# token from someone else followed by a line break and a word is ordinary text.
FOREIGN_HIDDEN = {name: char for name, char in HIDDEN.items() if not char.isspace()}
ESC = "\x1b"
C1 = frozenset(chr(code) for code in range(0x80, 0xA0))


def windows(secret: str, size: int = 6) -> list[str]:
    return [secret[at : at + size] for at in range(len(secret) - size + 1)]


def leaks(result: str, secret: str) -> list[str]:
    return [piece for piece in windows(secret) if piece in result]


# ESC before one of these opens a string sequence (DCS, SOS, PM, APC) that never ends here: it
# swallows the rest of the text, so only the mask before it is shown.
STRING_OPENING_LETTERS = "PX^_"


def expected_after(secret: str, hidden: str, position: int) -> str:
    if hidden == ESC and secret[position] in STRING_OPENING_LETTERS:
        return f"denied {MASK}"
    return f"denied {MASK} today"


def test_the_test_keys_have_the_real_length() -> None:
    assert len(KEY) == REAL_KEY_LENGTH and len(FOREIGN) == REAL_KEY_LENGTH


# 1) one hidden character anywhere inside a real-length key -------------------------------------


@pytest.mark.parametrize("hidden", list(HIDDEN.values()), ids=list(HIDDEN))
def test_the_own_key_with_a_hidden_character_at_any_position_is_masked_whole(hidden: str) -> None:
    for position in range(1, len(KEY)):
        text = f"denied {KEY[:position]}{hidden}{KEY[position:]} today"

        result = sanitise_text(text, api_key=KEY)

        assert result == expected_after(KEY, hidden, position), (position, result)


@pytest.mark.parametrize("hidden", list(FOREIGN_HIDDEN.values()), ids=list(FOREIGN_HIDDEN))
def test_a_key_shaped_token_with_a_hidden_character_at_any_position_is_masked_whole(
    hidden: str,
) -> None:
    for position in range(1, len(FOREIGN)):
        text = f"denied {FOREIGN[:position]}{hidden}{FOREIGN[position:]} today"

        result = sanitise_text(text, api_key=KEY)

        assert result == expected_after(FOREIGN, hidden, position), (position, result)


@pytest.mark.parametrize("hidden", list(HIDDEN.values()), ids=list(HIDDEN))
def test_the_own_key_with_a_hidden_character_is_masked_in_local_text(hidden: str) -> None:
    for position in range(1, len(KEY)):
        text = f"bad {KEY[:position]}{hidden}{KEY[position:]} value"

        result = scrub_local(text, KEY)

        assert not leaks(result, KEY), (position, result)


def test_the_key_mask_alone_masks_the_whole_key_through_a_hidden_character() -> None:
    forms = key_forms(KEY)
    for position in range(19, 49):
        text = f"x {KEY[:position]}\u200b{KEY[position:]} y"

        assert mask_key(text, forms, KEY) == f"x {MASK} y", position
        assert mask_key(text, [], "") == f"x {MASK} y", position


# 2) an escape sequence that eats a marker ------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "see http://host.test/p\x1b?token=secretvalue1 end",
        "see http://host.test/p\x1b[?token=secretvalue1 end",
        "see host.test\x1b?token=secretvalue1 end",
        "see http\x1b://host.test?token=secretvalue1 end",
        "see http\x1b://host.test/p#secretvalue1 end",
        "see http://host.test/p\x1b#secretvalue1 end",
        "see http\x1b]x\x07://host.test/p#secretvalue1 end",
    ],
    ids=[
        "esc-question",
        "csi-question",
        "host-esc-question",
        "esc-colon-query",
        "esc-colon-fragment",
        "esc-hash",
        "osc-before-colon",
    ],
)
def test_a_sequence_eating_a_marker_leaves_no_query_or_fragment_value(text: str) -> None:
    result = sanitise_text(text)

    assert "secretvalue1" not in result and not leaks(result, "secretvalue1")
    assert result.startswith("see ") and result.endswith(" end")
    assert ESC not in result


# 3) a sequence body with an at sign inside a password ------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "see http://user:pa\tss\x1b]x@y# \x07secondhalfpw@host.test/p end",
        "see http://user:pa\tss\x1b]x@y? \x07secondhalfpw@host.test/p end",
        "see http://user:pa\nss\x1b]x@y#z \x07secondhalfpw@host.test/p end",
        "see http://user:pa\u00a0ss\x9dx@y?z \x9csecondhalfpw@host.test/p end",
        "see //user:pa\tss\x1b]x@y# \x1b\\secondhalfpw@host.test/p end",
        "see http://user:pa\tss\x1bPx@y# \x1b\\secondhalfpw@host.test/p end",
    ],
    ids=["osc-hash", "osc-question", "newline", "c1-nbsp", "scheme-relative", "dcs"],
)
def test_a_sequence_with_an_at_sign_inside_a_password_leaks_nothing(text: str) -> None:
    result = sanitise_text(text)

    assert "secondhalf" not in result and "user" not in result and "pa" not in result
    assert "host.test/p" in result and result.endswith(" end")


# 4) the query context on the matching view, internationalised hosts ----------------------------


@pytest.mark.parametrize(
    ("text", "shown"),
    [
        ("see host.test\u200d?token=secretvalue1 end", "?token=***"),
        ("see host.te\u0301st?token=secretvalue1 end", "?token=***"),
        ("see search\u200d?q=secretvalue1 end", "?q=***"),
        ("see bücher.example?token=secretvalue1 end", "bücher.example?token=***"),
        ("see пример.рф?token=secretvalue1 end", "пример.рф?token=***"),
        ("see 例子.测试:8080?token=secretvalue1 end", "例子.测试:8080?token=***"),
        ("see bücher.example/p?token=secretvalue1 end", "bücher.example/p?token=***"),
    ],
    ids=["joiner", "accent", "joiner-key", "umlaut", "cyrillic", "cjk-port", "idn-path"],
)
def test_the_query_context_is_found_through_marks_and_on_idn_hosts(text: str, shown: str) -> None:
    result = sanitise_text(text)

    assert "secretvalue1" not in result
    assert shown in result and result.endswith(" end")
    assert mask_queries(text) == mask_queries(mask_queries(text))
    assert "secretvalue1" not in redact_url(text)


@pytest.mark.parametrize(
    "text",
    ["ทำไมถึงเป็น?ลอง", "这是什么?你好吗", "Ça va? Très bien", "क्या आप ठीक हैं?"],
    ids=["thai", "cjk", "french", "hindi"],
)
def test_a_question_mark_in_prose_is_still_not_a_query(text: str) -> None:
    assert sanitise_text(text) == text


# 5) whitespace inside a query or fragment value ------------------------------------------------


@pytest.mark.parametrize(
    "gap", ["\t", "\n", "\r\n", "\x0b", "\x0c", "\x85", "\u00a0", "\u2028", "\u3000"]
)
@pytest.mark.parametrize(
    "template",
    [
        "see http://host.test/p?token=secret{gap}tailvalue end",
        "see host.test?token=secret{gap}tailvalue end",
        "see http://host.test/p#secret{gap}tailvalue end",
        "see host.test#secret{gap}tailvalue end",
    ],
    ids=["query", "schemeless-query", "fragment", "schemeless-fragment"],
)
def test_whitespace_inside_a_query_or_fragment_value_does_not_end_it(
    template: str, gap: str
) -> None:
    result = sanitise_text(template.format(gap=gap))

    assert "tailvalue" not in result and "secret" not in result
    assert result.startswith("see ") and result.endswith(" end")


def test_a_plain_space_still_ends_a_query_value() -> None:
    assert sanitise_text("see http://host.test/p?token=abc def") == (
        "see http://host.test/p?token=*** def"
    )


# 6) a fragment after a scheme-less host --------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "masked"),
    [
        ("host.test#secretfrag1", "host.test#***"),
        ("host.test:8080#secretfrag1", "host.test:8080#***"),
        ("localhost#secretfrag1", "localhost#***"),
        ("[::1]:8080#secretfrag1", "[::1]:8080#***"),
        ("/v1/x#secretfrag1", "/v1/x#***"),
        ("search?q=1#secretfrag1", "search?q=***#***"),
        ("bücher.example#secretfrag1", "bücher.example#***"),
        ("(host.test#secretfrag1)", "(host.test#***)"),
        ("http://host.test/p#secretfrag1", "http://host.test/p#***"),
    ],
)
def test_a_fragment_is_masked_like_a_query(url: str, masked: str) -> None:
    assert sanitise_text(f"see {url} end") == f"see {masked} end"
    assert redact_url(url) == masked


@pytest.mark.parametrize(
    "text", ["issue #123 is open", "C# and F# and C#/F#", "ทำไม#ลอง", "word#tag here"]
)
def test_a_hash_without_a_url_context_is_left_alone(text: str) -> None:
    assert sanitise_text(text) == text


# 7) properties -----------------------------------------------------------------------------------

PIECES = [
    "http://", "//", "u", ":", "@", "?", "#", "=", "&", "/", " ", "\t", "\n", "\x0b", "\x85",
    "\u00a0", "\x1b", "\x1b[", "\x1b]", "\x1bP", "\x07", "\x1b\\", "\x9b", "\x9c", "\x9d",
    "\u200b", "\u200d", "\u0301", "\u00ad", "\ud800", "\udfff", "\U000e0041", "sf_", KEY[:12],
    KEY[12:40], KEY[40:], "a" * 16, "%5F", "%41", "host.test", "bücher.example", ":8080", ")",
    "x", "0;t", "[::1]", "token", "pw",
]  # fmt: skip
SEED = 54
CORPUS_SIZE = 400
MAX_PIECES = 24


def hostile_corpus() -> list[str]:
    rng = random.Random(SEED)
    generated = [
        "".join(rng.choice(PIECES) for _ in range(rng.randint(1, MAX_PIECES)))
        for _ in range(CORPUS_SIZE)
    ]
    findings = [
        f"{KEY[:position]}{hidden}{KEY[position:]}"
        for hidden in HIDDEN.values()
        for position in (5, 19, 30, 48)
    ]
    fixed = [
        "see http://user:pa\tss\x1b]x@y# \x07secondhalfpw@host.test/p end",
        "see http://host.test/p\x1b?token=secretvalue1 end",
        "see http\x1b://host.test/p#secretvalue1 end",
        "\x1b]0;" + KEY,
        "\x9b31m\x9d8;;http://u:p@h/\x9c",
        "\ud800\udc00 lone halves",
    ]
    return generated + findings + fixed


CORPUS = hostile_corpus()
FORMS = key_forms(KEY)


def keep_text(text: str) -> str:
    return text


STAGES: dict[str, Callable[[str], str]] = {
    "strip-invisible": strip_invisible,
    "strip-terminal": lambda text: strip_terminal(text, keep_text),
    "flatten": flatten_text,
    "userinfo": mask_raw_userinfo,
    "queries": mask_queries,
    "fragments": mask_fragments,
    "credentials": mask_credentials,
    "key": lambda text: mask_key(text, FORMS, KEY),
    "key-shape": lambda text: mask_key(text, [], ""),
    "redact-url": redact_url,
    "pipeline": lambda text: sanitise_text(text, api_key=KEY, limit=10_000),
}


@pytest.mark.parametrize("stage", list(STAGES.values()), ids=list(STAGES))
def test_every_stage_is_idempotent(stage: Callable[[str], str]) -> None:
    for text in CORPUS:
        once = stage(text)

        assert stage(once) == once, repr(text)


def test_no_escape_c1_control_or_lone_surrogate_survives_the_pipeline() -> None:
    for text in CORPUS:
        for result in (sanitise_text(text, api_key=KEY), scrub_local(text, KEY)):
            assert ESC not in result, repr(text)
            assert not C1.intersection(result), repr(text)
            assert not any(0xD800 <= ord(char) <= 0xDFFF for char in result), repr(text)
            result.encode("utf-8")


ENGLAND_FLAG = "\U0001f3f4\U000e0067\U000e0062\U000e0065\U000e006e\U000e0067\U000e007f"
ORDINARY = [
    "ภาษาไทยง่ายนิดเดียว ไม่ยาก",
    "नमस्ते दुनिया, क्या हाल है?",
    "Cafe\u0301 re\u0301sume\u0301 and Ça va? Très bien",
    "family \U0001f468\u200d\U0001f469\u200d\U0001f467\u200d\U0001f466 rainbow "
    "\U0001f3f3\ufe0f\u200d\U0001f308",
    "\u0600\u0661\u0662\u0663 \u06dd\u0661 \u0890\u0661",
    "שָׁלוֹם and مَرْحَبًا",
    f"go {ENGLAND_FLAG} team",
    "版本 1.2 已发布，请访问文档。",
]


@pytest.mark.parametrize("text", ORDINARY)
def test_ordinary_non_ascii_text_is_shown_unchanged(text: str) -> None:
    assert sanitise_text(text, api_key=KEY) == text
    assert scrub_local(text, KEY) == text
