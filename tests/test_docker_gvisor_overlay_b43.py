"""Round 100 (B43): a startup warning when the gvisor runtime lacks --overlay2=none."""

import logging
from typing import Any

import pytest

from sandfort.config import Settings
from sandfort.drivers.docker.driver import DockerDriver
from sandfort.drivers.docker.overlay_check import (
    gvisor_overlay_finding,
    overlay2_disabled,
    warn_gvisor_overlay,
)

LOGGER = "sandfort.drivers.docker.overlay_check"
SETTINGS = Settings(isolation_runtimes=(("container", ""), ("gvisor", "runsc")))
RUNSC_PATH = "/usr/local/bin/runsc"
RUNSC_OK = {"path": RUNSC_PATH, "runtimeArgs": ["--overlay2=none", "--file-access=shared"]}
RUNSC_BAD = {"path": RUNSC_PATH, "runtimeArgs": ["--file-access=shared"]}


class _Api:
    def __init__(self, info: Any) -> None:
        self.info_calls = 0
        self._info = info

    def version(self) -> dict[str, str]:
        return {"Version": "27.3.1", "ApiVersion": "1.47"}

    def df(self) -> dict[str, Any]:
        return {}

    def info(self) -> Any:
        self.info_calls += 1
        if isinstance(self._info, Exception):
            raise self._info
        return self._info


class StubClient:
    def __init__(self, info: Any) -> None:
        self.api = _Api(info)


def info_with(runsc: dict[str, Any] | None) -> dict[str, Any]:
    runtimes: dict[str, Any] = {"runc": {"path": "runc"}}
    if runsc is not None:
        runtimes["runsc"] = runsc
    return {
        "Driver": "overlay2",
        "DriverStatus": [["Backing Filesystem", "xfs"]],
        "Runtimes": runtimes,
        "DefaultRuntime": "runc",
    }


def records_of(caplog: pytest.LogCaptureFixture, level: int) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == LOGGER and r.levelno == level]


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["--overlay2=none"], True),
        (["--file-access=shared", "--overlay2=none"], True),
        (["-overlay2=none"], True),
        (["--overlay2", "none"], True),
        (["--overlay2=root:self"], False),
        (["--overlay2", "root:self"], False),
        (["--file-access=shared"], False),
        ([], False),
    ],
)
def test_overlay2_disabled_reads_the_runtime_arguments(args: list[str], expected: bool) -> None:
    assert overlay2_disabled(args) is expected


async def test_the_flag_present_logs_no_warning(caplog: pytest.LogCaptureFixture) -> None:
    client = StubClient(info_with(RUNSC_OK))

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        await warn_gvisor_overlay(client, SETTINGS)

    assert client.api.info_calls == 1
    assert records_of(caplog, logging.WARNING) == []


async def test_the_flag_absent_logs_one_warning(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        await warn_gvisor_overlay(StubClient(info_with(RUNSC_BAD)), SETTINGS)

    [record] = records_of(caplog, logging.WARNING)
    message = record.getMessage()
    assert "--overlay2=none" in message
    assert "'runsc'" in message
    assert "does not refuse startup" in message
    assert "\n" not in message


@pytest.mark.parametrize(
    "runsc",
    [
        {"path": RUNSC_PATH},
        {"path": RUNSC_PATH, "runtimeArgs": None},
        {"path": RUNSC_PATH, "runtimeArgs": ["--overlay2=root:self"]},
        RUNSC_BAD,
    ],
)
def test_the_finding_names_every_form_of_absent(runsc: dict[str, Any]) -> None:
    finding = gvisor_overlay_finding(info_with(runsc), SETTINGS)

    assert finding is not None
    assert "--overlay2=none" in finding


def test_the_finding_is_none_when_the_flag_is_present() -> None:
    assert gvisor_overlay_finding(info_with(RUNSC_OK), SETTINGS) is None


async def test_runsc_not_registered_logs_no_warning(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        await warn_gvisor_overlay(StubClient(info_with(None)), SETTINGS)

    assert records_of(caplog, logging.WARNING) == []


async def test_a_deployment_without_a_gvisor_tier_does_not_read_docker(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = StubClient(info_with(RUNSC_BAD))

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        await warn_gvisor_overlay(client, Settings())

    assert client.api.info_calls == 0
    assert records_of(caplog, logging.WARNING) == []


async def test_an_unreadable_docker_info_logs_a_debug_line_and_no_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = StubClient(RuntimeError("daemon went away"))

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        await warn_gvisor_overlay(client, SETTINGS)

    assert records_of(caplog, logging.WARNING) == []
    [record] = records_of(caplog, logging.DEBUG)
    assert "docker info unreadable" in record.getMessage()


@pytest.mark.parametrize("info", [None, "garbage", []])
async def test_a_non_mapping_docker_info_logs_nothing(
    info: Any, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        await warn_gvisor_overlay(StubClient(info), SETTINGS)

    assert records_of(caplog, logging.WARNING) == []


async def test_isolation_gaps_warns_once_and_adds_no_gap(
    caplog: pytest.LogCaptureFixture,
) -> None:
    driver = DockerDriver(SETTINGS, client=StubClient(info_with(RUNSC_BAD)))

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        gaps = await driver.isolation_gaps()

    assert len(records_of(caplog, logging.WARNING)) == 1
    assert all("--overlay2" not in gap for gap in gaps)


async def test_isolation_gaps_with_the_flag_present_logs_no_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    driver = DockerDriver(SETTINGS, client=StubClient(info_with(RUNSC_OK)))

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        await driver.isolation_gaps()

    assert records_of(caplog, logging.WARNING) == []
