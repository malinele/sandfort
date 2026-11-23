"""CLI round 59 (security, MINOR-3): two remaining host gaps in the query and fragment stages.

* CJK sentence punctuation (ideographic comma and full stop, fullwidth comma, semicolon,
  exclamation and question marks, the horizontal ellipsis, the fullwidth colon variants) glued
  to a dotted host or a host with a port is a separator, like an ASCII comma.
* ``host:port`` followed by a fragment or query tail is recognised after any host separator or
  a pipe (``ref=host:443#frag``, ``k:host:443#frag``): the port colon is not read as the
  separator, the tail is masked and the key, the separator and the host stay visible.
* A key=value pair whose value is not host-like stays readable.
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

TOKEN = "tok_9fK2mQx7LpR4vB8nZc3Wd5YhA1sE6uJt"
SENTENCE_MARKS = [
    "、",  # ideographic comma
    "。",  # ideographic full stop
    "，",  # fullwidth comma
    "；",  # fullwidth semicolon
    "！",  # fullwidth exclamation mark
    "？",  # fullwidth question mark
    "…",  # horizontal ellipsis
    "⋯",  # midline horizontal ellipsis
    "：",  # fullwidth colon
    "︓",  # presentation form for vertical colon
    "﹕",  # small colon
    "︐",  # presentation form for vertical comma
    "﹐",  # small comma
    "﹔",  # small semicolon
    "﹗",  # small exclamation mark
    "﹖",  # small question mark
]
PORT_SEPARATORS = ["ref=", "url=", "k:", "|", ",", ";", "[", "@", "->", "=>", "a&b=", "：", "「"]
HOSTS_WITH_PORT = ["host:443", "host.example:8443", "10.0.0.5:80", "例子.测试:9000"]
PERFORMANCE_CHARS = 200_000
TIME_LIMIT_SECONDS = 2.0

Stage = Callable[[str], str]


@pytest.mark.parametrize("prefix", ["", "你好", "see "])
@pytest.mark.parametrize("mark", SENTENCE_MARKS)
def test_sentence_punctuation_before_a_host_keeps_the_query_masked(mark: str, prefix: str) -> None:
    masked = mask_queries(f"{prefix}{mark}host.example?token={TOKEN}")

    assert TOKEN not in masked
    assert masked.endswith(f"{mark}host.example?token=***")


@pytest.mark.parametrize("prefix", ["", "你好", "see "])
@pytest.mark.parametrize("mark", SENTENCE_MARKS)
def test_sentence_punctuation_before_a_host_keeps_the_fragment_masked(
    mark: str, prefix: str
) -> None:
    masked = mask_fragments(f"{prefix}{mark}host.example#{TOKEN}")

    assert TOKEN not in masked
    assert masked.endswith(f"{mark}host.example#***")


@pytest.mark.parametrize("mark", SENTENCE_MARKS)
def test_sentence_punctuation_before_a_host_with_a_port_is_masked(mark: str) -> None:
    masked = sanitise_text(f"失败{mark}host:8443#{TOKEN}")

    assert TOKEN not in masked
    assert masked.endswith(f"{mark}host:8443#***")


@pytest.mark.parametrize("separator", PORT_SEPARATORS)
@pytest.mark.parametrize("host", HOSTS_WITH_PORT)
def test_host_with_a_port_and_a_fragment_is_masked_and_the_key_stays(
    separator: str, host: str
) -> None:
    masked = mask_fragments(f"see {separator}{host}#{TOKEN}")

    assert TOKEN not in masked
    assert masked == f"see {separator}{host}#***"


@pytest.mark.parametrize("separator", PORT_SEPARATORS)
@pytest.mark.parametrize("host", HOSTS_WITH_PORT)
def test_host_with_a_port_and_a_query_is_masked_and_the_key_stays(
    separator: str, host: str
) -> None:
    masked = mask_queries(f"see {separator}{host}?token={TOKEN}")

    assert TOKEN not in masked
    assert masked == f"see {separator}{host}?token=***"


@pytest.mark.parametrize(
    "text",
    [
        "ref=host:443#frag",
        "url=host:8443#x",
        "k:host:443#frag",
        "|host:443#frag",
    ],
)
def test_the_four_listed_forms_mask_the_fragment(text: str) -> None:
    head, _, _ = text.partition("#")

    assert mask_fragments(text) == f"{head}#***"


@pytest.mark.parametrize(
    "text",
    [
        "ref=abc#frag",
        "url=value#x",
        "k:value#frag",
        "|label#frag",
        "key=abc?go",
        "k:host:abc#frag",
        "ref=host:#frag",
        "ref=host:123456789#frag",
        "label=build#7",
        "k=v",
        "note: ref=abc",
    ],
)
def test_a_value_that_is_not_host_like_stays_readable(text: str) -> None:
    assert mask_fragments(text) == text
    assert mask_queries(text) == text


@pytest.mark.parametrize(
    "text",
    [
        "你好，再见?token=S",
        "你好！再见?token=S",
        "他说：你好?",
        "「例子」?",
        "ref=例子?token",
        "你好、再见#frag",
        "好的…再见",
    ],
)
def test_prose_around_the_new_separators_stays_readable(text: str) -> None:
    assert mask_queries(text) == text
    assert mask_fragments(text) == text


@pytest.mark.parametrize("stage", [mask_queries, mask_fragments])
@pytest.mark.parametrize(
    "text",
    [
        f"你好，host.example?token={TOKEN}#{TOKEN}",
        f"ref=host:443#{TOKEN}",
        f"k:host:443?token={TOKEN}#{TOKEN}",
        f"|host:443#{TOKEN}",
        f"链接。host.example:8443?a={TOKEN}#{TOKEN}",
        "ref=abc#frag",
    ],
)
def test_each_stage_is_idempotent(stage: Stage, text: str) -> None:
    once = stage(text)

    assert stage(once) == once


def test_sanitise_text_is_idempotent_on_the_new_shapes() -> None:
    text = f"失败，host.example:443#{TOKEN} ref=host:8443?token={TOKEN}#{TOKEN}"

    once = sanitise_text(text)

    assert TOKEN not in once
    assert sanitise_text(once) == once


def _elapsed(stage: Stage, text: str) -> float:
    started = time.perf_counter()
    stage(text)
    return time.perf_counter() - started


@pytest.mark.parametrize("stage", [mask_queries, mask_fragments])
def test_many_markers_in_one_word_stay_linear(stage: Stage) -> None:
    unit = "，h.e:80#x?a=b"
    text = unit * (PERFORMANCE_CHARS // len(unit))

    assert _elapsed(stage, text) < TIME_LIMIT_SECONDS


@pytest.mark.parametrize("stage", [mask_queries, mask_fragments])
def test_many_words_stay_linear(stage: Stage) -> None:
    unit = "ref=host:443#x?a=b "
    text = unit * (PERFORMANCE_CHARS // len(unit))

    assert _elapsed(stage, text) < TIME_LIMIT_SECONDS


@pytest.mark.parametrize("stage", [mask_queries, mask_fragments])
def test_a_long_run_of_separators_before_one_marker_stays_linear(stage: Stage) -> None:
    text = ":" * PERFORMANCE_CHARS + "1#x?a=b"

    assert _elapsed(stage, text) < TIME_LIMIT_SECONDS
