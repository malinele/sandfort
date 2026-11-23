"""CLI round 57 review (c): IDNA dots in an ASCII head and many markers in one word.

* A head of ASCII and IDNA dots counts as ASCII again, so ``ref=foo。?token=...`` is masked.
* The ``/`` position and the first non-ASCII position are found once per word, so many markers
  in one word cost linear time.
"""

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli.sanitise import mask_queries  # noqa: E402
from sandfort_cli.sanitise_hosts import scan_word  # noqa: E402

REPEATS = 50_000
TIME_LIMIT_SECONDS = 2.0
GROWTH_FACTOR = 4
GROWTH_SLACK_SECONDS = 0.5
WORD_JOINER = "⁠"


@pytest.mark.parametrize(
    "text",
    [
        "ref=foo。?token=SECRET",
        "a,b。?token=SECRET",
        "k=v｡?token=SECRET",
        "(a=b‥?token=SECRET",
    ],
)
def test_idna_dot_in_an_ascii_head_keeps_the_query_masked(text: str) -> None:
    masked = mask_queries(text)

    assert "SECRET" not in masked
    assert masked.endswith("?token=***")


def test_idna_dot_and_joiner_before_a_hash_still_mask_the_query() -> None:
    text = f"。{WORD_JOINER}#?a=b.x"

    masked = mask_queries(text)

    assert "b.x" not in masked
    assert masked.endswith("?a=***")


def test_scan_word_treats_idna_dots_as_narrow() -> None:
    assert scan_word("ref=foo。?x") == (-1, 10)
    assert scan_word("a/b。ü") == (1, 4)


def _elapsed(text: str) -> float:
    started = time.perf_counter()
    mask_queries(text)
    return time.perf_counter() - started


@pytest.mark.parametrize("unit", ["a?", "ü?"])
def test_many_markers_in_one_word_cost_linear_time(unit: str) -> None:
    single = _elapsed(unit * REPEATS)
    double = _elapsed(unit * (2 * REPEATS))

    assert single < TIME_LIMIT_SECONDS
    assert double < GROWTH_FACTOR * single + GROWTH_SLACK_SECONDS
