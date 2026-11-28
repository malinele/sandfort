"""Round 103: the preview cap defaults, the upstream keep-alive pool and the operations text."""

from dataclasses import replace
from pathlib import Path

from sandfort.config import Settings
from sandfort.domain.sandbox import Sandbox
from sandfort.drivers.fake import FakeDriver
from sandfort.proxy.app import MAX_KEEPALIVE, PreviewProxy
from sandfort.proxy.tokens import InMemoryPreviewTokenStore

ROOT = Path(__file__).resolve().parents[1]
CAP_ROW = "| `SANDFORT_PREVIEW_MAX_CONCURRENT_PER_SANDBOX`, `SANDFORT_PREVIEW_MAX_CONCURRENT` |"
CAPS_BULLET = "- **The preview caps count work in flight, not connections or time.**"
LOAD_TEST_BULLET = "- **The preview cap defaults come from a load test.**"
MEASURED_HEADING = "### Measured facts that exist"
THREE_BROWSER_PEAK = 576  # the highest per-sandbox in-flight count of the 2026-11-28 load test
FIVE_SANDBOXES = 5


def operations_text() -> str:
    return (ROOT / "docs" / "operations.md").read_text(encoding="utf-8")


def test_the_defaults_hold_three_browsers_on_one_preview() -> None:
    settings = Settings()

    assert settings.preview_max_concurrent_per_sandbox == 768
    assert settings.preview_max_concurrent == 4096
    assert settings.preview_max_concurrent_per_sandbox > THREE_BROWSER_PEAK
    assert settings.preview_max_concurrent >= FIVE_SANDBOXES * 768


async def no_sandbox(sandbox_id: str) -> Sandbox | None:
    return None


async def keepalive_pool(settings: Settings) -> int:
    """``max_keepalive_connections`` of the upstream client the proxy builds for itself."""
    proxy = PreviewProxy(settings, InMemoryPreviewTokenStore(), no_sandbox, FakeDriver())
    try:
        pool = proxy._client._transport._pool  # httpx 0.28 keeps the httpcore pool here
        return int(pool._max_keepalive_connections)
    finally:
        await proxy.aclose()


async def test_the_keep_alive_pool_follows_the_per_sandbox_cap() -> None:
    settings = replace(Settings(), preview_max_concurrent_per_sandbox=123)

    assert await keepalive_pool(settings) == 123


async def test_the_default_keep_alive_pool_covers_one_sandbox_burst() -> None:
    assert await keepalive_pool(Settings()) == 768


async def test_no_per_sandbox_cap_falls_back_to_the_named_default() -> None:
    settings = replace(Settings(), preview_max_concurrent_per_sandbox=0)

    assert MAX_KEEPALIVE == 768
    assert await keepalive_pool(settings) == MAX_KEEPALIVE


def test_the_operations_row_states_the_defaults_in_force() -> None:
    settings = Settings()
    rows = [line for line in operations_text().splitlines() if line.startswith(CAP_ROW)]

    assert len(rows) == 1
    defaults = rows[0].strip("|").split("|")[1].strip()
    assert defaults == (
        f"{settings.preview_max_concurrent_per_sandbox}, {settings.preview_max_concurrent}"
    )


def test_operations_explains_the_defaults_and_the_descriptor_budget() -> None:
    text = operations_text()
    caps = text.split(CAPS_BULLET, 1)[1].split(MEASURED_HEADING, 1)[0]
    assert LOAD_TEST_BULLET in caps
    load_test = caps.split(LOAD_TEST_BULLET, 1)[1]
    flat = " ".join(load_test.split())

    assert "16384" in flat
    assert "/proc/<pid>/limits" in flat
    assert "`MAX_KEEPALIVE`" in flat
    assert "2026-11-28" in flat
