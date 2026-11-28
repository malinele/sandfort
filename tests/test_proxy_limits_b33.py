"""Round 101 (B33): the preview concurrency counters, their settings and the file sizes."""

from pathlib import Path

import pytest

from sandfort.config import Settings
from sandfort.proxy.limits import PROXY_CAP, SANDBOX_CAP, PreviewBusy, PreviewLimits

ROOT = Path(__file__).resolve().parents[1]
SANDBOX_BUSY = "this preview has too many open requests, retry shortly"
PROXY_BUSY = "the preview proxy has too many open requests, retry shortly"


def test_slots_count_per_sandbox_and_in_total() -> None:
    limits = PreviewLimits(2, 3)

    first = limits.acquire("sbx_a")
    limits.acquire("sbx_a")
    limits.acquire("sbx_b")

    assert (limits.active("sbx_a"), limits.active("sbx_b"), limits.active()) == (2, 1, 3)
    assert limits.tracked_sandboxes() == 2
    first.release()
    first.release()  # a second release frees nothing
    assert (limits.active("sbx_a"), limits.active()) == (1, 2)


def test_sandbox_cap_is_checked_before_the_total() -> None:
    limits = PreviewLimits(1, 1)
    limits.acquire("sbx_a")

    with pytest.raises(PreviewBusy) as same:
        limits.acquire("sbx_a")
    with pytest.raises(PreviewBusy) as other:
        limits.acquire("sbx_b")

    assert (same.value.cap, same.value.message) == (SANDBOX_CAP, SANDBOX_BUSY)
    assert (other.value.cap, other.value.message) == (PROXY_CAP, PROXY_BUSY)
    assert (same.value.status, same.value.code) == (503, "CAPACITY")
    assert same.value.headers == ((b"retry-after", b"1"),)
    assert limits.active() == 1


def test_zero_is_no_cap_and_a_negative_cap_is_refused() -> None:
    limits = PreviewLimits(0, 0)

    slots = [limits.acquire("sbx_a") for _ in range(1000)]

    assert limits.active() == 1000
    for slot in slots:
        slot.release()
    assert (limits.active(), limits.tracked_sandboxes()) == (0, 0)
    with pytest.raises(ValueError):
        PreviewLimits(-1, 0)
    with pytest.raises(ValueError):
        PreviewLimits(0, -1)


def test_with_block_frees_the_slot_on_an_exception() -> None:
    limits = PreviewLimits(1, 0)

    with pytest.raises(RuntimeError), limits.acquire("sbx_a"):
        raise RuntimeError("boom")

    assert limits.active("sbx_a") == 0
    assert limits.acquire("sbx_a")


def test_caps_default_to_768_and_4096_and_load_from_the_environment() -> None:
    defaults = Settings()
    loaded = Settings.from_env(
        {
            "SANDFORT_PREVIEW_MAX_CONCURRENT_PER_SANDBOX": "0",
            "SANDFORT_PREVIEW_MAX_CONCURRENT": "7",
        }
    )

    limits = PreviewLimits.from_settings(loaded)

    assert defaults.preview_max_concurrent_per_sandbox == 768
    assert defaults.preview_max_concurrent == 4096
    assert (loaded.preview_max_concurrent_per_sandbox, loaded.preview_max_concurrent) == (0, 7)
    assert (limits.per_sandbox, limits.total) == (0, 7)
    with pytest.raises(ValueError, match="PREVIEW_MAX_CONCURRENT_PER_SANDBOX"):
        Settings.from_env({"SANDFORT_PREVIEW_MAX_CONCURRENT_PER_SANDBOX": "-1"})


def test_limit_files_stay_small() -> None:
    paths = [
        ROOT / "src" / "sandfort" / "proxy" / "limits.py",
        ROOT / "src" / "sandfort" / "proxy" / "app.py",
        Path(__file__),
        Path(__file__).with_name("test_proxy_caps_b33.py"),
    ]
    for path in paths:
        lines = path.read_text().splitlines()
        assert len(lines) < 400, path
        assert all(len(line) <= 100 for line in lines), path
