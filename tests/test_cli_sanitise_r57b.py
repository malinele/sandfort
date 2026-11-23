"""CLI round 57 review: the url-ish lookback costs time bounded by the host length.

* A long single word of ``a#`` or ``?`` passes through the public maskers in linear time.
* The host helpers live in :mod:`sandfort_cli.sanitise_hosts` and are re-exported unchanged.
"""

import sys
import time
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli import sanitise, sanitise_hosts  # noqa: E402
from sandfort_cli.sanitise import mask_fragments, mask_queries  # noqa: E402

LONG_WORD_CHARS = 50_000
TIME_LIMIT_SECONDS = 0.5
NI_HAO_ZAI_JIAN = "你好。再见"
KONNICHIWA_SEKAI = "こんにちは、世界"


@pytest.mark.parametrize("masker", [mask_fragments, mask_queries])
@pytest.mark.parametrize("unit", ["a#", "?"])
def test_long_single_word_is_masked_in_bounded_time(
    masker: Callable[[str], str], unit: str
) -> None:
    text = unit * (LONG_WORD_CHARS // len(unit))

    started = time.perf_counter()
    masker(text)
    elapsed = time.perf_counter() - started

    assert elapsed < TIME_LIMIT_SECONDS


def test_long_head_still_gives_a_host_context_from_its_tail() -> None:
    text = "x" * 5_000 + " " + "a" * 400 + "host.test?token=SECRET"

    assert "SECRET" not in mask_queries(text)


def test_slash_far_before_the_marker_still_counts() -> None:
    # The sentence breaks are neither ASCII nor a host run, so only the "/" can give the context.
    head = "a/" + "、" * 1_000

    assert mask_queries(head + "?token=SECRET") == head + "?token=***"


def test_idna_dot_in_the_tail_gives_a_host_context() -> None:
    assert mask_queries("host。example?token=SECRET") == "host。example?token=***"
    assert mask_fragments("host。example#SECRET") == "host。example#***"


def test_cjk_full_stop_with_a_letter_masks_the_query_value() -> None:
    assert mask_queries(f"{NI_HAO_ZAI_JIAN}?q=1") == f"{NI_HAO_ZAI_JIAN}?q=***"


def test_sentence_break_before_a_question_mark_does_not_make_a_host() -> None:
    assert mask_queries(f"{KONNICHIWA_SEKAI}?x=1") == f"{KONNICHIWA_SEKAI}?x=1"


def test_host_helpers_live_in_the_hosts_module_and_are_reexported() -> None:
    for name in ("HOST_OPENERS", "MAX_HOST_CHARS", "QUERY_SHAPED_RE", "URLISH_HOST_RE"):
        assert getattr(sanitise, name) is getattr(sanitise_hosts, name)
    assert sanitise_hosts.MAX_HOST_CHARS == 253
