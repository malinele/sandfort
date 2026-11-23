"""SDK r54: typed stop causes and ``stop_cause`` / ``stopped_at`` on the sandbox handle."""

import asyncio
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import get_args

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import pytest  # noqa: E402
import sandfort_sdk  # noqa: E402
from sandfort_sdk import (  # noqa: E402
    SANDBOX_STOP_CAUSE_AUTO_STOP,
    SANDBOX_STOP_CAUSE_CONTAINER_EXITED,
    SANDBOX_STOP_CAUSE_OOM_KILLED,
    SANDBOX_STOP_CAUSE_REQUESTED,
    SANDBOX_STOP_CAUSE_UNKNOWN,
    AsyncSandbox,
    Sandbox,
    SandboxInfo,
    StopCause,
    is_known_stop_cause,
)
from sandfort_sdk._transport import AsyncTransport, SyncTransport  # noqa: E402
from sandfort_sdk.stop_causes import KNOWN_STOP_CAUSES  # noqa: E402

from sandfort.domain import sandbox as server_domain  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
TIMEOUT_S = 30.0
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
STOPPED_AT = "2026-11-10T12:00:00Z"
STOPPED_AT_VALUE = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)

CONSTANTS = (
    SANDBOX_STOP_CAUSE_REQUESTED,
    SANDBOX_STOP_CAUSE_AUTO_STOP,
    SANDBOX_STOP_CAUSE_CONTAINER_EXITED,
    SANDBOX_STOP_CAUSE_OOM_KILLED,
    SANDBOX_STOP_CAUSE_UNKNOWN,
)


def info(stop_cause: str | None, stopped_at: str | None = None) -> SandboxInfo:
    return SandboxInfo.from_payload(
        {
            "id": SID,
            "name": "demo",
            "state": "stopped" if stop_cause else "started",
            "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
            "network": {"block_all": False},
            "stop_cause": stop_cause,
            "stopped_at": stopped_at,
        }
    )


def test_literal_equals_the_server_stop_causes() -> None:
    assert get_args(StopCause) == server_domain.STOP_CAUSES
    assert frozenset(get_args(StopCause)) == KNOWN_STOP_CAUSES


def test_constants_equal_the_literal_args() -> None:
    assert CONSTANTS == get_args(StopCause)
    assert len(set(CONSTANTS)) == len(CONSTANTS)


def test_every_constant_is_exported_and_none_starts_with_stop() -> None:
    for cause in CONSTANTS:
        name = f"SANDBOX_STOP_CAUSE_{cause.upper()}"
        assert name in sandfort_sdk.__all__
        assert getattr(sandfort_sdk, name) == cause
    assert {"StopCause", "is_known_stop_cause"} <= set(sandfort_sdk.__all__)
    # The round-30 test collects every export named STOP_* as an exec stop reason.
    new_exports = {n for n in sandfort_sdk.__all__ if "CAUSE" in n.upper()}
    assert new_exports
    assert not any(n.startswith("STOP_") for n in new_exports)


@pytest.mark.parametrize("value", sorted(KNOWN_STOP_CAUSES))
def test_type_guard_accepts_known_causes(value: str) -> None:
    raw: str | None = value
    assert is_known_stop_cause(raw)
    narrowed: StopCause = raw  # accepted by mypy only after the TypeGuard
    assert narrowed == value


@pytest.mark.parametrize("value", [None, "", "Requested", "auto-stop", "future_cause"])
def test_type_guard_rejects_unknown_values(value: str | None) -> None:
    assert not is_known_stop_cause(value)


def test_unknown_value_stays_a_string() -> None:
    parsed = info("future_cause")
    assert parsed.stop_cause == "future_cause"
    assert isinstance(parsed.stop_cause, str)
    assert not is_known_stop_cause(parsed.stop_cause)


@pytest.mark.parametrize("cause", [None, SANDBOX_STOP_CAUSE_AUTO_STOP, "future_cause"])
def test_sync_handle_exposes_both_properties(cause: str | None) -> None:
    transport = SyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    try:
        handle = Sandbox(info(cause, STOPPED_AT if cause else None), transport)
        assert handle.stop_cause == handle.info.stop_cause == cause
        assert handle.stopped_at == handle.info.stopped_at
        assert handle.stopped_at == (STOPPED_AT_VALUE if cause else None)
        with pytest.raises(AttributeError):
            handle.stop_cause = "requested"  # type: ignore[misc]
        with pytest.raises(AttributeError):
            handle.stopped_at = None  # type: ignore[misc]
    finally:
        transport.close()


def test_async_handle_exposes_both_properties() -> None:
    transport = AsyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    try:
        handle = AsyncSandbox(info(SANDBOX_STOP_CAUSE_OOM_KILLED, STOPPED_AT), transport)
        assert handle.stop_cause == SANDBOX_STOP_CAUSE_OOM_KILLED
        assert handle.stopped_at == STOPPED_AT_VALUE
    finally:
        asyncio.run(transport.aclose())
