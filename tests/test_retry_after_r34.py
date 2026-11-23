"""Round 34: the SDK honours Retry-After on 503; the per-org terminal cap advertises 30 s."""

import sys
from pathlib import Path

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
from sandfort_sdk._requests import RETRY_AFTER_CAP_S  # noqa: E402

from sandfort.errors import CapacityExceeded  # noqa: E402
from sandfort.toolbox.pty import TERMINAL_CAP_RETRY_AFTER_S, PtyRegistry  # noqa: E402
from test_sdk_retries import SID, Script, failed, ok, sync_client  # noqa: E402

ORG = "org_1"


def capacity(retry_after: str | None) -> httpx.Response:
    headers = None if retry_after is None else {"Retry-After": retry_after}
    return failed(503, "CAPACITY", headers)


def test_503_with_retry_after_waits_at_least_that_long_then_succeeds() -> None:
    script = Script(capacity("3"), ok())
    client, sleeps = sync_client(script)

    assert client.get(SID).id == SID

    assert len(sleeps) == 1
    assert sleeps[0] >= 3.0


def test_503_without_retry_after_keeps_the_jittered_backoff() -> None:
    script = Script(capacity(None), capacity(None), ok())
    client, sleeps = sync_client(script)

    client.get(SID)

    assert sleeps == [0.5, 1.0]


def test_503_retry_after_is_capped_at_the_429_cap() -> None:
    script = Script(capacity("999"), ok())
    client, sleeps = sync_client(script)

    client.get(SID)

    assert sleeps == [RETRY_AFTER_CAP_S] == [30.0]


def test_503_retry_after_shorter_than_the_backoff_keeps_the_backoff() -> None:
    script = Script(capacity("0"), capacity("0"), ok())
    client, sleeps = sync_client(script)

    client.get(SID)

    assert sleeps == [0.5, 1.0]


def test_terminal_cap_error_advertises_30_seconds_and_says_when_a_slot_frees() -> None:
    registry = PtyRegistry(max_per_org=1)
    registry.reserve(ORG, "pty_1")

    with pytest.raises(CapacityExceeded) as caught:
        registry.reserve(ORG, "pty_2")

    assert caught.value.retry_after_s == 30 == TERMINAL_CAP_RETRY_AFTER_S
    assert "a slot frees when a terminal closes" in str(caught.value)
