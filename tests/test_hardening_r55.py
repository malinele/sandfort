"""Round 55: cgroup parent, per-tier userns opt-out and the daemon hardening facts (no daemon)."""

import logging
from collections.abc import Sequence
from types import SimpleNamespace
from typing import Any

import pytest

from sandfort.api.app import IsolationUnavailableError, check_isolation
from sandfort.config import DEFAULT_USERNS_HOST_TIERS, Settings
from sandfort.domain.resources import ResourceSpec
from sandfort.drivers.base import SandboxSpec
from sandfort.drivers.docker.capabilities import (
    DEFAULT_RUNTIME_FINDING,
    USERNS_FINDING,
    DockerCapabilities,
    advisory_findings,
    capability_report,
    hardening_findings,
    missing_isolation,
)
from sandfort.drivers.docker.driver import DockerDriver
from sandfort.drivers.docker.hardening import build_host_config, options_from_settings

TIER_MAP = "container=,gvisor=runsc,microvm=kata"
CGROUP_PARENT = "sandfort.slice"


def spec_for(tier: str | None) -> SandboxSpec:
    return SandboxSpec(
        sandbox_id="sbx_1",
        org_id="org_1",
        name="sf-sbx_1",
        image="alpine:3.20",
        resources=ResourceSpec(cpu_millicores=1000, memory_mib=512, disk_gib=2),
        isolation=tier,
    )


def tiered_settings(**env: str) -> Settings:
    return Settings.from_env({"SANDFORT_ISOLATION_RUNTIMES": TIER_MAP, **env})


# --- settings -----------------------------------------------------------------------


def test_settings_defaults_for_the_three_new_values() -> None:
    settings = Settings.from_env({})

    assert settings.cgroup_parent == ""
    assert settings.userns_host_tiers == DEFAULT_USERNS_HOST_TIERS == ("microvm",)
    assert settings.require_userns_remap is False


def test_settings_parse_the_three_new_values() -> None:
    settings = Settings.from_env(
        {
            "SANDFORT_CGROUP_PARENT": f" {CGROUP_PARENT} ",
            "SANDFORT_USERNS_HOST_TIERS": "microvm, gvisor,microvm",
            "SANDFORT_REQUIRE_USERNS_REMAP": "true",
        }
    )

    assert settings.cgroup_parent == CGROUP_PARENT
    assert settings.userns_host_tiers == ("microvm", "gvisor")
    assert settings.require_userns_remap is True


def test_an_empty_tier_list_means_no_tier_opts_out() -> None:
    assert Settings.from_env({"SANDFORT_USERNS_HOST_TIERS": ""}).userns_host_tiers == ()


@pytest.mark.parametrize(
    ("name", "value", "match"),
    [
        ("SANDFORT_USERNS_HOST_TIERS", "microvm,vm", "USERNS_HOST_TIERS.*'vm'"),
        ("SANDFORT_REQUIRE_USERNS_REMAP", "maybe", "REQUIRE_USERNS_REMAP"),
        ("SANDFORT_CGROUP_PARENT", "two words", "CGROUP_PARENT"),
    ],
)
def test_settings_reject_bad_values(name: str, value: str, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        Settings.from_env({name: value})


@pytest.mark.parametrize(
    "value",
    [
        "sandfort.slice",
        "sandfort-tenants.slice",
        "system-sandfort_1.slice",
        "user@1000:a.slice",
        "a.b.slice",
        "system.slice",
        "user-1000.slice",
    ],
)
def test_cgroup_parent_accepts_systemd_slice_names(value: str) -> None:
    assert Settings.from_env({"SANDFORT_CGROUP_PARENT": value}).cgroup_parent == value


@pytest.mark.parametrize(
    "value",
    [
        "sandfort",  # no .slice suffix
        ".slice",  # no unit name
        "/sandfort.slice",  # path separator
        "system.slice/sandfort.slice",
        "../sandfort.slice",  # parent reference
        "a..b.slice",
        "sandfort\n.slice",  # control character
        "sand\tfort.slice",
        "sand\x00fort.slice",
        "sandfort.slice.scope",
        "sand fort.slice",
        "-.slice",  # the root slice
        "-sandfort.slice",  # leading hyphen
        "sandfort-.slice",  # trailing hyphen
        "a--b.slice",  # double hyphen
        ".sandfort.slice",  # leading dot
        "a-.b.slice",  # component starting with a dot
        "sandfort.slice.slice",  # doubled suffix
    ],
)
def test_cgroup_parent_rejects_anything_but_a_slice_name(value: str) -> None:
    with pytest.raises(ValueError, match="CGROUP_PARENT must be a systemd slice name"):
        Settings.from_env({"SANDFORT_CGROUP_PARENT": value})


# --- create kwargs ------------------------------------------------------------------


@pytest.mark.parametrize("cgroup_parent", [None, CGROUP_PARENT])
@pytest.mark.parametrize(
    ("tier", "userns_host"),
    [("container", False), ("gvisor", False), ("microvm", True), (None, False)],
)
def test_create_kwargs_per_tier_with_and_without_the_cgroup_parent(
    tier: str | None, userns_host: bool, cgroup_parent: str | None
) -> None:
    env = {"SANDFORT_CGROUP_PARENT": cgroup_parent} if cgroup_parent else {}
    settings = tiered_settings(**env)

    config = build_host_config(spec_for(tier), settings, options_from_settings(settings))

    assert config.get("userns_mode") == ("host" if userns_host else None)
    assert config.get("cgroup_parent") == cgroup_parent
    assert ("userns_mode" in config) is userns_host
    assert ("cgroup_parent" in config) is (cgroup_parent is not None)


def test_the_userns_opt_out_leaves_every_other_kwarg_untouched() -> None:
    settings = tiered_settings()
    opted_out = build_host_config(spec_for("microvm"), settings, options_from_settings(settings))
    plain = build_host_config(
        spec_for("microvm"),
        settings,
        options_from_settings(tiered_settings(SANDFORT_USERNS_HOST_TIERS="")),
    )

    assert {k: v for k, v in opted_out.items() if k != "userns_mode"} == plain
    assert "userns_mode" not in plain


def test_a_default_tier_in_the_opt_out_list_opts_out_without_a_spec_tier() -> None:
    settings = tiered_settings(SANDFORT_DEFAULT_ISOLATION="microvm")

    config = build_host_config(spec_for(None), settings, options_from_settings(settings))

    assert config["userns_mode"] == "host"
    assert config["runtime"] == "kata"


def test_a_configured_opt_out_list_replaces_the_default() -> None:
    settings = tiered_settings(SANDFORT_USERNS_HOST_TIERS="gvisor")
    options = options_from_settings(settings)

    assert "userns_mode" in build_host_config(spec_for("gvisor"), settings, options)
    assert "userns_mode" not in build_host_config(spec_for("microvm"), settings, options)


# --- capability facts ---------------------------------------------------------------


class InfoClient:
    def __init__(self, info: Any) -> None:
        self.api = SimpleNamespace(
            version=lambda: {"Version": "27.3.1", "ApiVersion": "1.47"},
            df=lambda: {},
            info=lambda: info,
        )


def daemon_info(security: Any = None, **extra: Any) -> dict[str, Any]:
    info: dict[str, Any] = {
        "Driver": "overlay2",
        "DriverStatus": [["Backing Filesystem", "xfs"]],
        "Runtimes": {"runc": {}, "runsc": {}, "kata": {}},
        "DefaultRuntime": "runc",
        "CgroupDriver": "systemd",
        **extra,
    }
    if security is not None:
        info["SecurityOptions"] = security
    return info


async def test_facts_with_the_userns_entry() -> None:
    options = ["name=seccomp,profile=builtin", "name=userns", "name=cgroupns"]

    report = await capability_report(InfoClient(daemon_info(options)))

    assert report.userns_remap is True
    assert report.default_runtime == "runc"
    assert report.cgroup_driver == "systemd"


@pytest.mark.parametrize(
    "security",
    [["name=seccomp,profile=builtin", "name=cgroupns"], [], None, "name=userns"],
)
async def test_facts_without_the_userns_entry(security: Any) -> None:
    report = await capability_report(InfoClient(daemon_info(security)))

    assert report.userns_remap is False


async def test_facts_are_empty_when_the_daemon_reports_nothing() -> None:
    report = await capability_report(InfoClient({}))

    assert (report.userns_remap, report.default_runtime, report.cgroup_driver) == (False, "", "")


# --- gap findings -------------------------------------------------------------------


def report_for(*, remap: bool, default_runtime: str = "runc") -> DockerCapabilities:
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
        cgroup_driver="systemd",
    )


def test_existing_findings_are_unchanged_without_settings() -> None:
    assert missing_isolation(report_for(remap=False)) == []
    assert missing_isolation(report_for(remap=False), egress_acknowledged=False)[0].startswith(
        "host egress enforcement"
    )


def test_dev_reports_missing_remapping_and_tolerates_it() -> None:
    settings = tiered_settings()

    assert hardening_findings(report_for(remap=False), settings) == [USERNS_FINDING]
    assert hardening_findings(report_for(remap=True), settings) == []
    assert missing_isolation(report_for(remap=False), settings=settings) == [USERNS_FINDING]


def test_prod_reports_missing_remapping_only_with_the_require_flag() -> None:
    # Built directly: from_env demands the unrelated prod secrets.
    tiers = (("container", ""), ("gvisor", "runsc"), ("microvm", "kata"))
    relaxed = Settings(environment="prod", isolation_runtimes=tiers)
    strict = Settings(environment="prod", isolation_runtimes=tiers, require_userns_remap=True)

    assert hardening_findings(report_for(remap=False), relaxed) == []
    assert hardening_findings(report_for(remap=False), strict) == [USERNS_FINDING]
    assert hardening_findings(report_for(remap=True), strict) == []


def test_the_default_runtime_must_be_a_configured_sandbox_runtime() -> None:
    explicit = Settings.from_env({"SANDFORT_ISOLATION_RUNTIMES": "container=runsc,microvm=kata"})
    finding = DEFAULT_RUNTIME_FINDING.format(default="runc", configured=["kata", "runsc"])

    assert advisory_findings(report_for(remap=True), explicit) == [finding]
    assert advisory_findings(report_for(remap=True, default_runtime="runsc"), explicit) == []
    assert hardening_findings(report_for(remap=True), explicit) == []  # never refusing
    assert "advisory" in finding


def test_a_tier_on_the_daemon_default_counts_as_a_configured_runtime() -> None:
    assert advisory_findings(report_for(remap=True), tiered_settings()) == []


def test_an_unreported_default_runtime_raises_no_finding() -> None:
    explicit = Settings.from_env({"SANDFORT_ISOLATION_RUNTIMES": "container=runsc"})

    assert advisory_findings(report_for(remap=True, default_runtime=""), explicit) == []


def test_the_default_runtime_finding_is_advisory_in_prod_and_never_refusing() -> None:
    explicit = Settings(environment="prod", isolation_runtimes=(("container", "runsc"),))

    [finding] = advisory_findings(report_for(remap=True), explicit)

    assert finding.startswith("default runtime 'runc'")
    assert missing_isolation(report_for(remap=True), settings=explicit) == []


def test_prod_without_the_flag_keeps_the_remap_finding_out_of_the_refusing_list() -> None:
    relaxed = Settings(environment="prod", isolation_runtimes=PROD_TIERS)
    strict = Settings(environment="prod", isolation_runtimes=PROD_TIERS, require_userns_remap=True)

    assert missing_isolation(report_for(remap=False), settings=relaxed) == []
    assert advisory_findings(report_for(remap=False), relaxed) == [USERNS_FINDING]
    assert advisory_findings(report_for(remap=False), strict) == []
    assert advisory_findings(report_for(remap=True), relaxed) == []


# --- through the driver and the application's startup check ---------------------------

PROD_TIERS = (("container", ""), ("gvisor", "runsc"), ("microvm", "kata"))


class CleanCanary:
    """The egress probe's seam (round 58): every target refused, so only these gates speak."""

    async def prune(self) -> None:
        return None

    async def gateway(self, network: str) -> str:
        return "172.20.0.1"

    async def reachable(self, network: str, image: str, targets: Sequence[str]) -> frozenset[str]:
        return frozenset()
USERNS_ON = ["name=seccomp,profile=builtin", "name=userns"]


def prod_driver(*, remap: bool, require: bool, tiers: Any = PROD_TIERS) -> tuple[Any, Settings]:
    settings = Settings(
        environment="prod",
        isolation_runtimes=tiers,
        require_userns_remap=require,
        egress_acknowledged=True,
    )
    info = daemon_info(USERNS_ON if remap else ["name=seccomp,profile=builtin"])
    return DockerDriver(settings, client=InfoClient(info)), settings


async def test_driver_gaps_include_the_remap_finding_in_prod_with_the_flag() -> None:
    driver, _ = prod_driver(remap=False, require=True)

    assert await driver.isolation_gaps() == [USERNS_FINDING]


async def test_prod_with_the_flag_and_no_remap_refuses_startup() -> None:
    driver, settings = prod_driver(remap=False, require=True)

    with pytest.raises(IsolationUnavailableError, match="user-namespace remapping"):
        await check_isolation(driver, settings, canary=CleanCanary())


async def test_prod_with_remap_on_and_the_microvm_tier_configured_starts() -> None:
    driver, settings = prod_driver(remap=True, require=True)

    assert await driver.isolation_gaps() == []
    await check_isolation(driver, settings, canary=CleanCanary())


async def test_prod_without_the_flag_starts_and_warns_about_the_remap_finding(
    caplog: pytest.LogCaptureFixture,
) -> None:
    driver, settings = prod_driver(remap=False, require=False)

    with caplog.at_level(logging.WARNING, logger="sandfort.drivers.docker.driver"):
        await check_isolation(driver, settings, canary=CleanCanary())

    [record] = [r for r in caplog.records if "user-namespace remapping" in r.getMessage()]
    assert record.levelno == logging.WARNING
    assert "\n" not in record.getMessage()


@pytest.mark.parametrize("environment", ["dev", "prod"])
async def test_the_default_runtime_finding_warns_but_never_refuses(
    environment: str, caplog: pytest.LogCaptureFixture
) -> None:
    settings = Settings(
        environment=environment,
        isolation_runtimes=(("container", "runsc"),),
        egress_acknowledged=True,
    )
    driver = DockerDriver(settings, client=InfoClient(daemon_info(USERNS_ON)))

    with caplog.at_level(logging.WARNING, logger="sandfort.drivers.docker.driver"):
        await check_isolation(driver, settings, canary=CleanCanary())

    assert any("default runtime 'runc'" in r.getMessage() for r in caplog.records)


async def test_an_existing_prod_deployment_without_new_variables_starts_with_one_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # No new environment variable: defaults for the tiers, the flag and the cgroup parent.
    settings = Settings(environment="prod", egress_acknowledged=True)
    driver = DockerDriver(
        settings, client=InfoClient(daemon_info(["name=seccomp,profile=builtin"]))
    )

    with caplog.at_level(logging.WARNING, logger="sandfort.drivers.docker.driver"):
        await check_isolation(driver, settings, canary=CleanCanary())  # does not raise

    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1
    assert "user-namespace remapping" in warnings[0].getMessage()


async def test_the_advisory_warning_is_not_emitted_when_the_finding_refuses(
    caplog: pytest.LogCaptureFixture,
) -> None:
    driver, settings = prod_driver(remap=False, require=True)

    with caplog.at_level(logging.WARNING, logger="sandfort.drivers.docker.driver"):
        with pytest.raises(IsolationUnavailableError, match="user-namespace remapping"):
            await check_isolation(driver, settings, canary=CleanCanary())

    # The finding refuses: it is in the exception, not logged as an advisory warning, and the
    # refusal logs one summary line (a count) rather than repeating the finding.
    assert not [r for r in caplog.records if "user-namespace remapping" in r.getMessage()]
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) <= 1
    assert all("1 finding(s)" in r.getMessage() for r in errors)
