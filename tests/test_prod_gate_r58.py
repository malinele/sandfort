"""Round 58: prod gate for the build runtime (H4) and for drivers without a self-check (L3).

Everything runs on a fake capabilities report; no daemon is involved.
"""

import logging

import pytest

from sandfort.api.app import IsolationUnavailableError, check_isolation
from sandfort.config import Settings
from sandfort.drivers.docker.capabilities import (
    BUILD_RUNTIME_FINDING,
    DockerCapabilities,
    advisory_findings,
    missing_isolation,
)
from sandfort.drivers.fake import FakeDriver

TIERS = (("container", ""), ("gvisor", "runsc"), ("microvm", "kata"))
RUNSC_ONLY = (("container", "runsc"),)


def report_for(default_runtime: str) -> DockerCapabilities:
    return DockerCapabilities(
        "27.0",
        "1.46",
        True,
        storage_driver="overlay2",
        backing_filesystem="xfs",
        disk_quota_supported=True,
        runtimes=("kata", "runc", "runsc"),
        userns_remap=True,
        default_runtime=default_runtime,
    )


def settings_for(
    environment: str = "prod", *, require: bool = True, tiers: tuple[tuple[str, str], ...] = TIERS
) -> Settings:
    return Settings(
        environment=environment,
        isolation_runtimes=tiers,
        require_build_runtime=require,
        egress_acknowledged=True,
    )


def build_gaps(report: DockerCapabilities, settings: Settings) -> list[str]:
    return [gap for gap in missing_isolation(report, settings=settings) if "build runtime" in gap]


class ReportDriver:
    """A driver stand-in whose self-check is the docker one, over a fixed report."""

    def __init__(self, report: DockerCapabilities, settings: Settings) -> None:
        self._report = report
        self._settings = settings

    async def isolation_gaps(self) -> list[str]:
        return missing_isolation(self._report, settings=self._settings)


# --- settings ---------------------------------------------------------------------------


def test_the_env_default_requires_the_build_runtime() -> None:
    settings = Settings.from_env({})

    assert settings.require_build_runtime is True
    assert settings.build_network == ""


def test_the_flag_and_the_build_network_are_read_from_the_environment() -> None:
    settings = Settings.from_env(
        {"SANDFORT_REQUIRE_BUILD_RUNTIME": "false", "SANDFORT_BUILD_NETWORK": " build-net "}
    )

    assert settings.require_build_runtime is False
    assert settings.build_network == "build-net"


def test_a_malformed_build_network_is_rejected() -> None:
    with pytest.raises(ValueError, match="BUILD_NETWORK"):
        Settings.from_env({"SANDFORT_BUILD_NETWORK": "two words"})


# --- item 1: the build runtime ----------------------------------------------------------


async def test_prod_refuses_a_default_runtime_that_is_not_a_strong_tier_runtime() -> None:
    settings = settings_for()
    driver = ReportDriver(report_for("runc"), settings)

    with pytest.raises(IsolationUnavailableError, match="build runtime"):
        await check_isolation(driver, settings)


def test_the_refusal_names_the_default_runtime_and_the_strong_ones() -> None:
    finding = BUILD_RUNTIME_FINDING.format(default="runc", strong=["kata", "runsc"])

    assert build_gaps(report_for("runc"), settings_for()) == [finding]


@pytest.mark.parametrize("default", ["runsc", "kata"])
async def test_prod_allows_a_strong_default_runtime(default: str) -> None:
    settings = settings_for()

    await check_isolation(ReportDriver(report_for(default), settings), settings)


@pytest.mark.parametrize(
    ("default", "tiers"),
    [
        ("runsc", (("container", "runc"), ("gvisor", "runsc-kvm"))),
        ("kata", RUNSC_ONLY),
    ],
)
async def test_prod_allows_a_strong_default_that_is_not_a_configured_tier_runtime(
    default: str, tiers: tuple[tuple[str, str], ...]
) -> None:
    settings = settings_for(tiers=tiers)
    report = report_for(default)

    assert build_gaps(report, settings) == []
    await check_isolation(ReportDriver(report, settings), settings)


async def test_prod_still_refuses_a_weak_default_when_the_tier_maps_another_runtime() -> None:
    settings = settings_for(tiers=(("gvisor", "runsc-kvm"),))
    driver = ReportDriver(report_for("runc"), settings)

    assert len(build_gaps(report_for("runc"), settings)) == 1
    with pytest.raises(IsolationUnavailableError, match="build runtime"):
        await check_isolation(driver, settings)


async def test_prod_allows_any_default_when_no_tier_offers_a_strong_runtime() -> None:
    settings = settings_for(tiers=(("container", ""),))

    await check_isolation(ReportDriver(report_for("runc"), settings), settings)


async def test_the_flag_off_does_not_refuse_in_prod() -> None:
    settings = settings_for(require=False)

    await check_isolation(ReportDriver(report_for("runc"), settings), settings)
    assert build_gaps(report_for("runc"), settings) == []


async def test_dev_only_warns_about_the_default_runtime() -> None:
    settings = settings_for("dev", tiers=RUNSC_ONLY)
    report = report_for("runc")

    assert build_gaps(report, settings) == []
    [finding] = advisory_findings(report, settings)
    assert finding.startswith("default runtime 'runc'")
    await check_isolation(ReportDriver(report, settings), settings)  # does not raise


def test_the_advisory_finding_stays_a_warning_with_the_flag_off() -> None:
    settings = settings_for(require=False, tiers=RUNSC_ONLY)

    [finding] = advisory_findings(report_for("runc"), settings)

    assert finding.startswith("default runtime 'runc'")
    assert build_gaps(report_for("runc"), settings) == []


def test_the_advisory_finding_is_not_repeated_when_the_gate_refuses() -> None:
    settings = settings_for(tiers=RUNSC_ONLY)

    assert advisory_findings(report_for("runc"), settings) == []
    assert len(build_gaps(report_for("runc"), settings)) == 1


# --- item 2: drivers other than docker --------------------------------------------------


async def test_prod_refuses_the_fake_driver() -> None:
    with pytest.raises(IsolationUnavailableError, match="FakeDriver.*requires the docker"):
        await check_isolation(FakeDriver(), settings_for())


async def test_dev_allows_the_fake_driver(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        await check_isolation(FakeDriver(), settings_for("dev"))

    assert caplog.records == []


async def test_prod_refuses_any_object_without_a_self_check() -> None:
    with pytest.raises(IsolationUnavailableError, match="no isolation self-check"):
        await check_isolation(object(), settings_for())
