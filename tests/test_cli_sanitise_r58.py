"""CLI round 58 (security): hosts after a separator, CJK punctuation, credential masker cost.

* A non-ASCII host is judged as the run after the last opener or separator, so
  ``see ref=bücher.example?token=SECRET`` masks the query value like the ASCII form does.
* CJK and fullwidth colon, brackets and quotes glued to a host work like their ASCII forms.
* ``mask_credentials`` cuts its input to the raw cap, so repeated ``u:p@<TAB>`` is not quadratic.
"""

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli.sanitise import MAX_RAW_CHARS, mask_credentials, mask_queries  # noqa: E402
from sandfort_cli.sanitise_hosts import scan_boundaries  # noqa: E402

HOSTS = ["café", "bücher.example", "пример.рф", "例子.测试", "example.com"]
SEPARATORS = [
    "ref=",
    "url=",
    "next=",
    "x=",
    "a&b=",
    "k:",
    "k,",
    "k;",
    "[",
    "|",
    "->",
    "=>",
    "@",
    "~",
    "*",
    "`",
]
CREDENTIAL_BYTES = 32_000
CREDENTIAL_LIMIT_SECONDS = 0.5


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("separator", SEPARATORS)
def test_host_after_a_separator_keeps_the_query_masked(separator: str, host: str) -> None:
    masked = mask_queries(f"see {separator}{host}?token=SECRET")

    assert "SECRET" not in masked
    assert masked.endswith("?token=***")


@pytest.mark.parametrize(
    "text",
    [
        "链接：example.com?token=S",
        "URL：example.com?token=S",
        "「例子.测试?token=S」",
        "（例子.测试?token=S）",
        "【例子.测试?token=S】",
        "“host。example?token=S",
        "”host.example?token=S",
        "«host。example?token=S",
        "»host.example?token=S",
        "‘host.example?token=S",
        "’host.example?token=S",
    ],
)
def test_cjk_punctuation_before_a_host_keeps_the_query_masked(text: str) -> None:
    masked = mask_queries(text)

    assert "=S" not in masked
    assert "token=***" in masked


@pytest.mark.parametrize(
    "text",
    [
        "see ref=café?go",
        "k:bücher?go",
        "see ref=what?",
        "a=b?c",
        "你好，再见?token=S",
        "你好！再见?token=S",
        "他说：你好?",
        "「例子」?",
        "ref=例子?token",
    ],
)
def test_prose_and_plain_words_stay_readable(text: str) -> None:
    assert mask_queries(text) == text


def test_ascii_hosts_with_a_port_still_mask() -> None:
    assert mask_queries("see example.com:8080?token=S") == "see example.com:8080?token=***"
    assert mask_queries("[::1]:80?token=S") == "[::1]:80?token=***"


def test_boundaries_are_found_once_in_increasing_order() -> None:
    bounds = scan_boundaries("a=(b:c")

    assert bounds.openers == [2]
    assert bounds.boundaries == [1, 2, 4]


def test_credential_masker_is_linear_on_repeated_userinfo_with_tabs() -> None:
    text = "u:p@\t" * (CREDENTIAL_BYTES // 5)

    started = time.perf_counter()
    mask_credentials(text)
    elapsed = time.perf_counter() - started

    assert elapsed < CREDENTIAL_LIMIT_SECONDS


def test_credential_masker_cuts_its_input_to_the_raw_cap() -> None:
    text = "x" * (MAX_RAW_CHARS + 50)

    assert mask_credentials(text) == "x" * MAX_RAW_CHARS


def test_credential_masker_masks_userinfo_in_a_short_text() -> None:
    masked = mask_credentials("see https://user:SECRET@host.example/x")

    assert "SECRET" not in masked
