"""Exec liveness: the rate-limited container check and its use by ``exec_stream`` (fakes only)."""

import time
from typing import Any

import pytest

from sandfort.drivers.base import ExecEvent, ExecRequest, ExitEvent, OutputChunk
from sandfort.drivers.docker import exec as exec_module
from sandfort.drivers.docker import exec_liveness
from sandfort.drivers.docker.demux import STDERR
from sandfort.drivers.docker.exec import (
    SANDBOX_DIED_EXIT_CODE,
    SANDBOX_DIED_MESSAGE,
    TIMED_OUT_EXIT_CODE,
    exec_stream,
    has_own_network_stack,
    timeout_message,
)
from sandfort.drivers.docker.exec_liveness import LIVENESS_CHECK_INTERVAL_S, ContainerLiveness

PROMPT_S = 5.0


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


class StateApi:
    """Inspect answers from a list of ``Running`` values (the last one repeats)."""

    def __init__(self, runtime: str, running: list[bool], error: Exception | None = None) -> None:
        self.runtime = runtime
        self.running = running
        self.error = error
        self.inspected = 0

    def inspect_container(self, ref: str) -> dict[str, Any]:
        self.inspected += 1
        if self.error is not None:
            raise self.error
        index = min(self.inspected, len(self.running)) - 1
        return {"HostConfig": {"Runtime": self.runtime}, "State": {"Running": self.running[index]}}


class FakeClient:
    def __init__(self, api: Any) -> None:
        self.api = api


def make_checker(api: Any, clock: FakeClock) -> ContainerLiveness:
    return ContainerLiveness(FakeClient(api), "ref", has_own_network_stack, clock)


def test_the_check_interval_is_two_seconds() -> None:
    assert LIVENESS_CHECK_INTERVAL_S == 2.0


async def test_a_runc_container_is_inspected_once_and_never_again() -> None:
    clock = FakeClock()
    api = StateApi("runc", [False])
    checker = make_checker(api, clock)

    answers = []
    for _ in range(5):
        clock.now += LIVENESS_CHECK_INTERVAL_S
        answers.append(await checker.is_running())

    assert answers == [True] * 5
    assert api.inspected == 1


async def test_nothing_is_inspected_before_the_first_interval_has_passed() -> None:
    clock = FakeClock()
    api = StateApi("kata", [False])
    checker = make_checker(api, clock)

    clock.now += LIVENESS_CHECK_INTERVAL_S - 0.1

    assert await checker.is_running() is True
    assert api.inspected == 0


@pytest.mark.parametrize("runtime", ["kata", "kata-qemu", "runsc"])
async def test_an_own_kernel_container_is_inspected_at_most_once_per_interval(
    runtime: str,
) -> None:
    clock = FakeClock()
    api = StateApi(runtime, [True, True, False])
    checker = make_checker(api, clock)

    clock.now += LIVENESS_CHECK_INTERVAL_S
    assert await checker.is_running() is True
    assert api.inspected == 1

    clock.now += LIVENESS_CHECK_INTERVAL_S - 0.5
    assert await checker.is_running() is True
    assert api.inspected == 1

    clock.now += 0.5
    assert await checker.is_running() is True
    assert api.inspected == 2

    clock.now += LIVENESS_CHECK_INTERVAL_S
    assert await checker.is_running() is False
    assert api.inspected == 3


async def test_inspection_errors_count_as_alive_and_are_retried_next_interval() -> None:
    clock = FakeClock()
    api = StateApi("kata", [False], error=RuntimeError("daemon unreachable"))
    checker = make_checker(api, clock)

    clock.now += LIVENESS_CHECK_INTERVAL_S
    assert await checker.is_running() is True
    clock.now += LIVENESS_CHECK_INTERVAL_S
    assert await checker.is_running() is True

    assert api.inspected == 2


async def test_a_payload_without_a_running_flag_counts_as_alive() -> None:
    clock = FakeClock()

    class OddApi:
        def inspect_container(self, ref: str) -> dict[str, Any]:
            return {"HostConfig": {"Runtime": "kata"}}

    checker = make_checker(OddApi(), clock)
    clock.now += LIVENESS_CHECK_INTERVAL_S

    assert await checker.is_running() is True


# --- exec_stream ----------------------------------------------------------------------


class SilentPump:
    """A pump that never produces data, like a Kata attach stream whose guest is gone."""

    def __init__(self) -> None:
        self.closed = False

    def read(self, wait_s: float) -> bytes | None:
        time.sleep(min(wait_s, 0.01))
        return None

    def close(self) -> None:
        self.closed = True


class Calls:
    def __init__(self) -> None:
        self.kill = 0
        self.wait = 0


@pytest.fixture
def pump(monkeypatch: pytest.MonkeyPatch) -> SilentPump:
    silent = SilentPump()
    monkeypatch.setattr(exec_module, "_create_exec", lambda client, ref, request, pid_file: "e1")
    monkeypatch.setattr(exec_module, "_open_pump", lambda client, ref, exec_id, stdin: silent)
    return silent


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> Calls:
    recorded = Calls()

    def kill(client: Any, ref: str, user: str | None, pid_file: str) -> None:
        recorded.kill += 1

    async def wait(client: Any, ref: str, exec_id: str) -> tuple[int, bool]:
        recorded.wait += 1
        return 0, False

    monkeypatch.setattr(exec_module, "_kill_blocking", kill)
    monkeypatch.setattr(exec_module, "_wait_exit", wait)
    return recorded


async def collect(client: Any, timeout_s: float) -> list[ExecEvent]:
    request = ExecRequest(argv=["x"], timeout_s=timeout_s)
    return [event async for event in exec_stream(client, "ref", request)]


async def test_a_dead_kata_vm_ends_the_exec_promptly_as_a_sandbox_death(
    monkeypatch: pytest.MonkeyPatch, pump: SilentPump, calls: Calls
) -> None:
    monkeypatch.setattr(exec_liveness, "LIVENESS_CHECK_INTERVAL_S", 0.0)
    api = StateApi("kata", [True, False])
    started = time.monotonic()

    events = await collect(FakeClient(api), timeout_s=60)

    assert time.monotonic() - started < PROMPT_S
    assert events[:-1] == [OutputChunk(STDERR, SANDBOX_DIED_MESSAGE)]
    exit_event = events[-1]
    assert isinstance(exit_event, ExitEvent)
    assert exit_event.exit_code == SANDBOX_DIED_EXIT_CODE
    assert exit_event.sandbox_stopped is True
    assert (exit_event.timed_out, exit_event.truncated) == (False, False)
    assert (calls.kill, calls.wait) == (0, 0)
    assert pump.closed is True
    assert api.inspected == 2


async def test_a_runc_exec_that_times_out_still_kills_the_process(
    pump: SilentPump, calls: Calls
) -> None:
    api = StateApi("runc", [False])

    events = await collect(FakeClient(api), timeout_s=0.3)

    exit_event = events[-1]
    assert isinstance(exit_event, ExitEvent)
    assert exit_event.exit_code == TIMED_OUT_EXIT_CODE
    assert (exit_event.timed_out, exit_event.sandbox_stopped) == (True, False)
    assert calls.kill == 1
    assert pump.closed is True
    assert events[:-1] == [OutputChunk(STDERR, timeout_message(0.3))]
