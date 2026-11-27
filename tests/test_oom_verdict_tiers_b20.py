"""Round 97 (B20): the daemon's OOM verdict is read for runc and runsc, not for Kata, per the
2026-11-27 measurement on the beta VM.
"""

from typing import Any

import pytest

from sandfort.drivers.docker import oom

REF = "ab" * 32


class _Api:
    def __init__(self, runtime: str, state: dict[str, Any] | None, *, fail: bool = False) -> None:
        self._runtime = runtime
        self._state = state
        self._fail = fail

    def inspect_container(self, ref: str) -> dict[str, Any]:
        if self._fail:
            raise RuntimeError("down")
        return {"HostConfig": {"Runtime": self._runtime}, "State": self._state or {}}


class _Client:
    def __init__(self, api: _Api) -> None:
        self.api = api


def test_daemon_flags_oom_for_runc_runsc_and_an_empty_runtime() -> None:
    assert oom.daemon_flags_oom("runc") is True
    assert oom.daemon_flags_oom("runsc") is True
    assert oom.daemon_flags_oom("") is True
    assert oom.daemon_flags_oom("kata") is False
    assert oom.daemon_flags_oom("kata-qemu") is False
    assert oom.daemon_flags_oom("kata-clh") is False


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ({"Running": False, "OOMKilled": True, "ExitCode": 137}, True),
        ({"Running": True, "OOMKilled": True, "ExitCode": 137}, False),
        ({"Running": False, "OOMKilled": False, "ExitCode": 137}, False),
        ({"Running": False, "ExitCode": 137}, False),
    ],
)
def test_runsc_reports_the_daemon_oom_verdict(state: dict[str, Any], expected: bool) -> None:
    client = _Client(_Api("runsc", state))

    assert oom.container_oom_killed_blocking(client, REF) is expected


@pytest.mark.parametrize("runtime", ["kata", "kata-qemu"])
def test_kata_never_reports_the_daemon_verdict(runtime: str) -> None:
    client = _Client(_Api(runtime, {"Running": False, "OOMKilled": True, "ExitCode": 137}))

    assert oom.container_oom_killed_blocking(client, REF) is False


def test_an_inspect_failure_is_not_an_oom_kill() -> None:
    client = _Client(_Api("runsc", None, fail=True))

    assert oom.container_oom_killed_blocking(client, REF) is False


def test_the_cgroup_counter_still_ignores_runsc() -> None:
    assert oom.shares_host_kernel("runsc") is False
    assert oom.shares_host_kernel("runc") is True


@pytest.mark.parametrize("runtime", ["runc", "runsc"])
def test_a_stale_flag_with_another_exit_code_is_not_an_oom_kill(runtime: str) -> None:
    # Docker keeps OOMKilled true after a survived OOM, so a later stop exits 143, not 137.
    client = _Client(_Api(runtime, {"Running": False, "OOMKilled": True, "ExitCode": 143}))

    assert oom.container_oom_killed_blocking(client, REF) is False


@pytest.mark.parametrize("runtime", ["runc", "runsc"])
def test_an_oom_death_with_exit_137_is_reported(runtime: str) -> None:
    client = _Client(_Api(runtime, {"Running": False, "OOMKilled": True, "ExitCode": 137}))

    assert oom.container_oom_killed_blocking(client, REF) is True


@pytest.mark.parametrize("exit_code", [None, "137", True, 0])
def test_a_missing_or_non_integer_exit_code_is_not_an_oom_kill(exit_code: object) -> None:
    state: dict[str, Any] = {"Running": False, "OOMKilled": True}
    if exit_code is not None:
        state["ExitCode"] = exit_code
    client = _Client(_Api("runc", state))

    assert oom.container_oom_killed_blocking(client, REF) is False
