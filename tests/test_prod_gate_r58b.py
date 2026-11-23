"""Round 58b: root on a runc-class tier (M1), the runc version floor and tier families (L2).

Everything runs on a fake capabilities report or a fake docker client; no daemon is involved.
"""

from typing import Any

import pytest

from sandfort.api.app import IsolationUnavailableError, check_isolation
from sandfort.config import Settings
from sandfort.drivers.docker.capabilities import (
    DockerCapabilities,
    advisory_findings,
    capability_report,
    hardening_findings,
    missing_isolation,
    version_tuple,
)

ROOT_MARK = "root on a shared kernel"
RUNC_MARK = "runc version"
TIERS = (("container", ""), ("gvisor", "runsc"), ("microvm", "kata"))
STRONG_TIERS = (("container", "runsc"), ("gvisor", "runsc"), ("microvm", "kata"))


def report_for(
    *, remap: bool = False, default_runtime: str = "runc", runc_version: str = "1.1.12"
) -> DockerCapabilities:
    return DockerCapabilities(
        "27.3.1",
        "1.47",
        True,
        storage_driver="overlay2",
        backing_filesystem="xfs",
        disk_quota_supported=True,
        runtimes=("kata", "runc", "runsc"),
        userns_remap=remap,
        default_runtime=default_runtime,
        runc_version=runc_version,
    )


def settings_for(
    environment: str = "prod",
    *,
    allow: bool = False,
    tiers: tuple[tuple[str, str], ...] = TIERS,
    min_runc: str = "",
    host_tiers: tuple[str, ...] = ("microvm",),
) -> Settings:
    return Settings(
        environment=environment,
        isolation_runtimes=tiers,
        allow_root_shared_kernel=allow,
        min_runc_version=min_runc,
        userns_host_tiers=host_tiers,
        egress_acknowledged=True,
    )


def marked(findings: list[str], mark: str) -> list[str]:
    return [finding for finding in findings if finding.startswith(mark)]


class ReportDriver:
    """A driver stand-in whose self-check is the docker one, over a fixed report."""

    def __init__(self, report: DockerCapabilities, settings: Settings) -> None:
        self._report = report
        self._settings = settings

    async def isolation_gaps(self) -> list[str]:
        return missing_isolation(self._report, settings=self._settings)


# --- settings ---------------------------------------------------------------------------


def test_the_env_defaults_refuse_root_and_skip_the_version_check() -> None:
    settings = Settings.from_env({})

    assert settings.allow_root_shared_kernel is False
    assert settings.min_runc_version == ""


def test_a_settings_built_directly_does_not_ask_for_the_refusal() -> None:
    assert Settings().allow_root_shared_kernel is True


def test_the_flag_and_the_version_are_read_from_the_environment() -> None:
    settings = Settings.from_env(
        {"SANDFORT_ALLOW_ROOT_SHARED_KERNEL": "true", "SANDFORT_MIN_RUNC_VERSION": " 1.1.12 "}
    )

    assert settings.allow_root_shared_kernel is True
    assert settings.min_runc_version == "1.1.12"


@pytest.mark.parametrize("raw", ["v1.1.12", "1", "1.1.12-rc1", "latest"])
def test_a_malformed_minimum_runc_version_is_rejected(raw: str) -> None:
    with pytest.raises(ValueError, match="MIN_RUNC_VERSION"):
        Settings.from_env({"SANDFORT_MIN_RUNC_VERSION": raw})


# --- item 1: root on a runc-class tier --------------------------------------------------


async def test_prod_refuses_a_tier_on_the_runc_default_without_remapping() -> None:
    settings = settings_for()

    with pytest.raises(IsolationUnavailableError, match=ROOT_MARK):
        await check_isolation(ReportDriver(report_for(), settings), settings)


def test_the_refusal_names_the_tier_and_the_runtime() -> None:
    [finding] = marked(hardening_findings(report_for(), settings_for()), ROOT_MARK)

    assert "['container']" in finding
    assert "['runc']" in finding
    assert "SANDFORT_ALLOW_ROOT_SHARED_KERNEL" in finding


def test_an_explicit_runc_tier_is_refused_too() -> None:
    settings = settings_for(tiers=(("container", "runc"),))
    report = report_for(default_runtime="runsc")

    assert marked(hardening_findings(report, settings), ROOT_MARK)


def test_an_unreported_default_runtime_counts_as_runc() -> None:
    report = report_for(default_runtime="")

    [finding] = marked(hardening_findings(report, settings_for()), ROOT_MARK)

    assert "runtimes ['runc']" in finding


def test_an_empty_runtime_on_a_strong_default_is_not_runc() -> None:
    report = report_for(default_runtime="runsc")

    assert marked(hardening_findings(report, settings_for()), ROOT_MARK) == []


async def test_prod_allows_a_runc_tier_with_remapping_on() -> None:
    settings = settings_for()

    await check_isolation(ReportDriver(report_for(remap=True), settings), settings)


def test_a_runc_tier_opting_out_of_remapping_is_refused_even_with_remapping_on() -> None:
    settings = settings_for(host_tiers=("container", "microvm"))

    assert marked(hardening_findings(report_for(remap=True), settings), ROOT_MARK)


async def test_prod_allows_a_runc_tier_with_the_flag_on() -> None:
    settings = settings_for(allow=True)

    await check_isolation(ReportDriver(report_for(), settings), settings)
    assert marked(advisory_findings(report_for(), settings), ROOT_MARK) == []


async def test_prod_allows_no_runc_tier_without_remapping() -> None:
    settings = settings_for(tiers=STRONG_TIERS)

    await check_isolation(ReportDriver(report_for(), settings), settings)


def test_dev_only_warns_about_root_on_a_runc_tier() -> None:
    settings = settings_for("dev")

    assert marked(hardening_findings(report_for(), settings), ROOT_MARK) == []
    assert len(marked(advisory_findings(report_for(), settings), ROOT_MARK)) == 1


# --- item 1: the runc version floor -----------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "parsed"),
    [("1.1.12", (1, 1, 12)), ("v1.2.0-0-g59923ef", (1, 2, 0)), ("1.2", (1, 2, 0)), ("", None)],
)
def test_version_tuple(raw: str, parsed: tuple[int, int, int] | None) -> None:
    assert version_tuple(raw) == parsed


async def test_prod_refuses_an_older_runc() -> None:
    settings = settings_for(tiers=STRONG_TIERS, min_runc="1.1.12")
    report = report_for(runc_version="v1.1.11-0-gabcdef0")

    with pytest.raises(IsolationUnavailableError, match="older than"):
        await check_isolation(ReportDriver(report, settings), settings)


@pytest.mark.parametrize("found", ["1.1.12", "v1.1.12-0-g51d5e94", "1.2.0"])
def test_an_equal_or_newer_runc_passes(found: str) -> None:
    settings = settings_for(tiers=STRONG_TIERS, min_runc="1.1.12")

    assert marked(hardening_findings(report_for(runc_version=found), settings), RUNC_MARK) == []


def test_an_unreported_runc_version_refuses_in_prod() -> None:
    settings = settings_for(tiers=STRONG_TIERS, min_runc="1.1.12")

    [finding] = marked(hardening_findings(report_for(runc_version=""), settings), RUNC_MARK)
    assert "cannot be verified" in finding


def test_no_minimum_means_no_version_check() -> None:
    settings = settings_for(tiers=STRONG_TIERS)
    report = report_for(runc_version="0.9.0")

    assert marked(hardening_findings(report, settings), RUNC_MARK) == []
    assert marked(advisory_findings(report, settings), RUNC_MARK) == []


def test_dev_only_warns_about_an_older_runc() -> None:
    settings = settings_for("dev", tiers=STRONG_TIERS, min_runc="1.1.12")
    report = report_for(runc_version="1.0.0")

    assert marked(hardening_findings(report, settings), RUNC_MARK) == []
    assert len(marked(advisory_findings(report, settings), RUNC_MARK)) == 1


class _Api:
    def __init__(self, info: dict[str, Any]) -> None:
        self._info = info

    def version(self) -> dict[str, str]:
        return {"Version": "27.3.1", "ApiVersion": "1.47"}

    def df(self) -> dict[str, Any]:
        return {}

    def info(self) -> dict[str, Any]:
        return self._info


class InfoClient:
    def __init__(self, info: dict[str, Any]) -> None:
        self.api = _Api(info)


async def test_the_report_reads_the_runc_version_from_docker_info() -> None:
    info = {"DefaultRuntime": "runc", "RuncCommit": {"ID": "v1.1.12-0-g51d5e94"}}

    report = await capability_report(InfoClient(info))

    assert report.runc_version == "v1.1.12-0-g51d5e94"


async def test_a_missing_runc_commit_reports_no_version() -> None:
    report = await capability_report(InfoClient({"RuncCommit": "garbage"}))

    assert report.runc_version == ""


# --- item 2: tier-to-runtime families ---------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "tier", "runtime"),
    [
        ("gvisor=kata", "gvisor", "kata"),
        ("gvisor=runc", "gvisor", "runc"),
        ("gvisor=", "gvisor", ""),
        ("gvisor=kata-runsc", "gvisor", "kata-runsc"),
        ("microvm=runsc", "microvm", "runsc"),
        ("microvm=", "microvm", ""),
    ],
)
def test_a_tier_on_the_wrong_runtime_family_is_refused(raw: str, tier: str, runtime: str) -> None:
    env = {"SANDFORT_ISOLATION_RUNTIMES": raw, "SANDFORT_DEFAULT_ISOLATION": tier}

    with pytest.raises(ValueError, match=f"tier '{tier}'.*'{runtime}'"):
        Settings.from_env(env)


def test_the_fallback_runtime_of_the_default_tier_is_checked_too() -> None:
    env = {"SANDFORT_CONTAINER_RUNTIME": "runc", "SANDFORT_DEFAULT_ISOLATION": "gvisor"}

    with pytest.raises(ValueError, match="tier 'gvisor'.*'runc'"):
        Settings.from_env(env)


def test_matching_families_and_any_container_runtime_load() -> None:
    raw = "container=runc,gvisor=runsc-debug,microvm=kata-qemu"

    settings = Settings.from_env({"SANDFORT_ISOLATION_RUNTIMES": raw})

    assert settings.isolation_tiers() == {
        "container": "runc",
        "gvisor": "runsc-debug",
        "microvm": "kata-qemu",
    }
