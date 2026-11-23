"""Per-organisation byte and count budgets of the in-memory command log store (L7)."""

import asyncio
import inspect
from collections.abc import AsyncIterator
from typing import Any, cast

import pytest

from sandfort.drivers.base import (
    ExecEvent,
    ExecRequest,
    ExecResult,
    ExitEvent,
    OutputChunk,
    SandboxDriver,
)
from sandfort.toolbox import command_logs
from sandfort.toolbox.command_logs import CommandLogStore
from sandfort.toolbox.sessions import SessionRuntime, SessionService


class _StreamDriver:
    """Streams a fixed payload for every command; the cwd read fails (best effort)."""

    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    async def exec_stream(self, ref: str, request: ExecRequest) -> AsyncIterator[ExecEvent]:
        yield OutputChunk("stdout", self.payload)
        yield ExitEvent(exit_code=0)

    async def exec(self, ref: str, request: ExecRequest) -> ExecResult:
        raise RuntimeError("no cwd in this fake")


def _no_uow() -> Any:
    raise RuntimeError("no database in this test")


def _service(runtime: SessionRuntime, driver: _StreamDriver) -> SessionService:
    return SessionService(
        uow_factory=_no_uow,
        driver=cast(SandboxDriver, driver),
        recorder=cast(Any, None),
        clock=cast(Any, None),
        runtime=runtime,
    )


async def _pump(
    service: SessionService, runtime: SessionRuntime, org_id: str, command_id: str
) -> None:
    request = ExecRequest(argv=["sh", "-c", "true"], timeout_s=5.0, max_output_bytes=100)
    service._start_pump(org_id, "sbx_1", "ref", "ses1", command_id, request)
    await runtime.tasks[command_id]


def test_create_requires_an_org_id() -> None:
    parameter = inspect.signature(CommandLogStore.create).parameters["org_id"]

    assert parameter.default is inspect.Parameter.empty


def test_flood_through_session_runtime_keeps_other_orgs_logs() -> None:
    async def scenario() -> None:
        runtime = SessionRuntime()
        runtime.logs = CommandLogStore(max_bytes=10)
        driver = _StreamDriver(b"12345678")
        service = _service(runtime, driver)
        await _pump(service, runtime, "org_b", "quiet")
        driver.payload = b"abcdefgh"
        for index in range(5):
            await _pump(service, runtime, "org_a", f"flood{index}")

        quiet = runtime.logs.get("quiet")
        assert quiet is not None
        assert quiet.finished is True
        assert quiet.truncated is False
        assert quiet.read(0).chunks[0].data == b"12345678"
        assert runtime.logs.get("flood0") is None
        assert runtime.logs.get("flood4") is not None

    asyncio.run(scenario())


def test_org_bucket_is_freed_with_its_last_log() -> None:
    store = CommandLogStore(max_retained=1)
    store.create("a1", "org_a").finish("exited", 0)
    store.create("b1", "org_b").finish("exited", 0)
    assert store.org_count() == 2

    store.create("a1", "org_b")

    assert store.get("a1") is not None
    assert store.org_count() == 1


def test_dropped_log_no_longer_charges_its_org() -> None:
    store = CommandLogStore(max_bytes=10)
    stale = store.create("cmd", "org_a")
    store.create("cmd", "org_b")
    stale.append("stdout", b"123456789")
    fresh = store.create("other", "org_a")
    fresh.append("stdout", b"1234")
    fresh.append("stderr", b"56789")

    assert store.org_count() == 2
    assert fresh.truncated is False


def test_flooding_org_does_not_evict_other_orgs_logs() -> None:
    store = CommandLogStore(max_bytes=10)
    quiet = store.create("quiet", "org_b")
    quiet.append("stdout", b"12345678")
    quiet.finish("exited", 0)

    for index in range(5):
        flood = store.create(f"flood{index}", "org_a")
        flood.append("stdout", b"abcdefgh")
        flood.finish("exited", 0)

    assert store.get("quiet") is quiet
    assert quiet.read(0).chunks[0].data == b"12345678"
    assert quiet.truncated is False
    assert store.get("flood0") is None
    assert store.get("flood4") is not None


def test_flooding_running_log_only_loses_its_own_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(command_logs, "COALESCE_MAX_BYTES", 4)
    store = CommandLogStore(max_bytes=10)
    quiet = store.create("quiet", "org_b")
    quiet.append("stdout", b"12345678")
    flood = store.create("flood", "org_a")
    for _ in range(20):
        flood.append("stdout", b"abcd")

    assert quiet.truncated is False
    assert quiet.retained_bytes == 8
    assert quiet.read(0).chunks[0].data == b"12345678"
    assert flood.retained_bytes <= 10


def test_same_total_budget_applies_independently_per_org() -> None:
    store = CommandLogStore(max_bytes=10)
    first = store.create("a1", "org_a")
    first.append("stdout", b"123456")
    first.finish("exited", 0)
    other = store.create("b1", "org_b")
    other.append("stdout", b"123456")
    other.finish("exited", 0)

    assert store.get("a1") is first
    assert store.get("b1") is other


def test_budget_still_evicts_oldest_finished_log_inside_one_org() -> None:
    store = CommandLogStore(max_bytes=10)
    old = store.create("old", "org_a")
    old.append("stdout", b"123456")
    old.finish("exited", 0)
    running = store.create("running", "org_a")
    running.append("stdout", b"abcdef")

    assert store.get("old") is None
    assert store.get("running") is running


def test_log_count_cap_is_per_org() -> None:
    store = CommandLogStore(max_retained=2)
    for index in range(2):
        store.create(f"b{index}", "org_b").finish("exited", 0)
    for index in range(4):
        store.create(f"a{index}", "org_a").finish("exited", 0)

    assert store.get("b0") is not None
    assert store.get("b1") is not None
    assert store.get("a0") is None
    assert store.get("a3") is not None


def test_global_ceiling_squeezes_only_the_writing_org() -> None:
    store = CommandLogStore(max_bytes=100, max_total_bytes=20)
    quiet = store.create("quiet", "org_b")
    quiet.append("stdout", b"x" * 12)
    quiet.finish("exited", 0)
    for index in range(4):
        flood = store.create(f"flood{index}", "org_a")
        flood.append("stdout", b"y" * 12)
        flood.finish("exited", 0)

    assert store.get("quiet") is quiet
    assert quiet.retained_bytes == 12


def test_recreating_a_command_id_replaces_its_owner() -> None:
    store = CommandLogStore(max_bytes=10)
    store.create("cmd", "org_a").append("stdout", b"123")
    replacement = store.create("cmd", "org_b")

    assert store.get("cmd") is replacement
