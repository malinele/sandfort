"""WP 5.4 isolation hardening, no daemon needed: create kwargs, capability report, prod guard.

A recording docker-py stand-in captures what reaches ``containers.create``; the capability
report runs over a fake ``client.api``; the startup guard runs the real application lifespan
with the driver's report monkeypatched.
"""

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.fernet import Fernet

from sandfort.api.app import IsolationUnavailableError, check_isolation, create_app
from sandfort.api.deps import DRIVER_ATTR
from sandfort.config import Settings
from sandfort.domain.resources import ResourceSpec
from sandfort.domain.sandbox import EGRESS_RESTRICTED_LABEL, NetworkPolicy, Sandbox
from sandfort.drivers.base import SandboxSpec
from sandfort.drivers.docker.capabilities import (
    DockerCapabilities,
    capability_report,
    disk_quota_supported,
    missing_isolation,
)
from sandfort.drivers.docker.driver import DockerDriver
from sandfort.drivers.docker.hardening import (
    NO_NEW_PRIVILEGES,
    SECCOMP_OPT_PREFIX,
    HardeningOptions,
    build_host_config,
    load_seccomp_profile,
    options_from_settings,
)
from sandfort.drivers.docker.networks import EGRESS_NETWORK_NAME, NETWORK_NAME
from sandfort.services.sandboxes import MountingLifecycle

docker = pytest.importorskip("docker")

ROOT = Path(__file__).resolve().parents[1]
REPO_PROFILE = ROOT / "deploy" / "seccomp.json"
CLONE_NEWUSER = 0x10000000
EPERM = 1
ENOSYS = 38
CREATED_ATTRS: dict[str, Any] = {
    "Id": "abc123",
    "Name": "/sf-sbx_1",
    "Created": "2026-10-31T03:00:00.000000Z",
    "State": {"Status": "created"},
    "Config": {"Image": "alpine:3.20", "Labels": {}},
    "HostConfig": {"NanoCpus": 1_000_000_000, "Memory": 512 * 1024 * 1024},
}
WORKERS_OFF: dict[str, Any] = {
    "job_execution_enabled": False,
    "autostop_enabled": False,
    "reconcile_enabled": False,
    "gc_enabled": False,
    "webhook_dispatcher_enabled": False,
    "metering_enabled": False,
}


def make_spec() -> SandboxSpec:
    # block_all keeps the network helpers out of the recorded calls.
    return SandboxSpec(
        sandbox_id="sbx_1",
        org_id="org_1",
        name="sf-sbx_1",
        image="alpine:3.20",
        resources=ResourceSpec(cpu_millicores=1000, memory_mib=512, disk_gib=2),
        network=NetworkPolicy(block_all=True),
    )


class RecordingClient:
    """Just enough docker-py for ``containers.create``; every create's kwargs are kept."""

    def __init__(self) -> None:
        self.created: list[dict[str, Any]] = []
        self.containers = SimpleNamespace(create=self._create)
        # create reads client.api for image volumes; no inspect_image means none declared
        self.api = SimpleNamespace()

    def _create(self, image: str, **kwargs: Any) -> Any:
        self.created.append(kwargs)
        return SimpleNamespace(attrs=CREATED_ATTRS)


def write_profile(tmp_path: Path, body: str) -> str:
    path = tmp_path / "profile.json"
    path.write_text(body, encoding="utf-8")
    return str(path)


# --- hardening options --------------------------------------------------------------


def test_default_settings_keep_the_previous_create_kwargs_exactly() -> None:
    settings = Settings()
    assert options_from_settings(settings) == HardeningOptions()
    config = build_host_config(make_spec(), settings, options_from_settings(settings))
    assert config == build_host_config(make_spec(), settings)
    assert config["security_opt"] == [NO_NEW_PRIVILEGES]
    assert "runtime" not in config
    assert "storage_opt" not in config


def test_settings_runtime_and_seccomp_reach_the_options(tmp_path: Path) -> None:
    path = write_profile(tmp_path, '{"defaultAction": "SCMP_ACT_ALLOW", "syscalls": []}')
    settings = Settings(container_runtime=" runsc ", seccomp_profile_path=path)
    options = options_from_settings(settings)
    assert options.runtime == "runsc"
    assert options.seccomp_profile == '{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[]}'
    assert options.enforce_disk_quota is False


def test_prod_enforces_the_disk_quota_it_requires() -> None:
    assert options_from_settings(Settings(environment="prod")).enforce_disk_quota is True


async def test_runtime_and_seccomp_reach_the_container_create_call(tmp_path: Path) -> None:
    path = write_profile(tmp_path, '{"defaultAction": "SCMP_ACT_ALLOW"}')
    client = RecordingClient()
    settings = Settings(container_runtime="runsc", seccomp_profile_path=path)
    info = await DockerDriver(settings, client=client).create(make_spec())
    assert info.ref == "abc123"
    [kwargs] = client.created
    assert kwargs["runtime"] == "runsc"
    assert kwargs["security_opt"] == [
        NO_NEW_PRIVILEGES,
        f'{SECCOMP_OPT_PREFIX}{{"defaultAction":"SCMP_ACT_ALLOW"}}',
    ]


async def test_explicit_options_take_precedence_over_settings(tmp_path: Path) -> None:
    path = write_profile(tmp_path, "{}")
    client = RecordingClient()
    settings = Settings(container_runtime="runsc", seccomp_profile_path=path)
    driver = DockerDriver(settings, client=client, options=HardeningOptions(runtime="kata"))
    await driver.create(make_spec())
    [kwargs] = client.created
    assert kwargs["runtime"] == "kata"
    assert kwargs["security_opt"] == [NO_NEW_PRIVILEGES]


@pytest.mark.parametrize(
    ("body", "message"),
    [("{not json", "not valid JSON"), ("[1, 2]", "must be a JSON object")],
)
def test_bad_seccomp_profiles_fail_at_load(tmp_path: Path, body: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        load_seccomp_profile(write_profile(tmp_path, body))


def test_missing_seccomp_profile_fails_when_the_driver_is_built(tmp_path: Path) -> None:
    settings = Settings(seccomp_profile_path=str(tmp_path / "absent.json"))
    with pytest.raises(ValueError, match="unreadable"):
        DockerDriver(settings, client=RecordingClient())


def test_repository_profile_denies_the_high_risk_syscalls() -> None:
    # The profile is moby's default allowlist (deny by default) minus the syscalls sandfort
    # denies outright, plus the argument-conditioned clone denial for new user namespaces.
    profile = json.loads(load_seccomp_profile(str(REPO_PROFILE)))
    assert profile["defaultAction"] == "SCMP_ACT_ERRNO"
    allowed = {
        name
        for rule in profile["syscalls"]
        if rule["action"] == "SCMP_ACT_ALLOW"
        for name in rule.get("names", [])
    }
    high_risk = {
        "kexec_load",
        "kexec_file_load",
        "open_by_handle_at",
        "bpf",
        "userfaultfd",
        "unshare",
        "clone3",
        "mount",
        "setns",
        "pivot_root",
        "init_module",
        "keyctl",
        "io_uring_setup",
        "perf_event_open",
        "reboot",
    }
    assert not (high_risk & allowed)
    assert {"read", "write", "clone", "fork", "execve", "openat"} <= allowed
    mask = {"index": 0, "value": CLONE_NEWUSER, "valueTwo": CLONE_NEWUSER}
    newuser_denials = [
        rule
        for rule in profile["syscalls"]
        if rule["action"] == "SCMP_ACT_ERRNO"
        and "clone" in rule.get("names", [])
        and rule.get("args") == [{**mask, "op": "SCMP_CMP_MASKED_EQ"}]
        and rule.get("errnoRet") == EPERM
    ]
    assert newuser_denials
    clone3_rules = [
        rule
        for rule in profile["syscalls"]
        if rule.get("names") == ["clone3"] and rule["action"] == "SCMP_ACT_ERRNO"
    ]
    assert clone3_rules and clone3_rules[0]["errnoRet"] == ENOSYS


# --- settings -----------------------------------------------------------------------


def test_settings_read_the_isolation_knobs_from_env() -> None:
    settings = Settings.from_env(
        {
            "SANDFORT_ENVIRONMENT": "PROD",
            "SANDFORT_WEBHOOK_SECRET_KEY": Fernet.generate_key().decode(),
            "SANDFORT_CONTAINER_RUNTIME": "runsc",
            "SANDFORT_SECCOMP_PROFILE_PATH": "/etc/sandfort/seccomp.json",
        }
    )
    assert settings.environment == "prod"
    assert settings.container_runtime == "runsc"
    assert settings.seccomp_profile_path == "/etc/sandfort/seccomp.json"


def test_settings_isolation_defaults_and_validation() -> None:
    defaults = Settings.from_env({})
    assert (defaults.environment, defaults.container_runtime) == ("dev", "")
    assert (defaults.seccomp_profile_path, defaults.egress_acknowledged) == ("", False)  # off
    assert Settings.from_env({"SANDFORT_EGRESS_ACKNOWLEDGED": "true"}).egress_acknowledged
    with pytest.raises(ValueError, match="SANDFORT_ENVIRONMENT"):
        Settings.from_env({"SANDFORT_ENVIRONMENT": "staging"})


def test_missing_isolation_reports_unacknowledged_egress_only() -> None:
    report = DockerCapabilities("27.3.1", "1.47", True, disk_quota_supported=True)
    [finding] = missing_isolation(report, egress_acknowledged=False)
    assert "deploy/host-setup.sh" in finding and "SANDFORT_EGRESS_ACKNOWLEDGED" in finding
    assert missing_isolation(report) == []


def test_host_script_blocks_metadata_cgnat_azure_and_ipv6_ranges() -> None:
    script = (ROOT / "deploy" / "host-setup.sh").read_text(encoding="utf-8")
    for needed in ("169.254.0.0/16", "100.64.0.0/10", "168.63.129.16/32", "fe80::/10", "fc00::/7"):
        assert needed in script
    assert "ip6tables" in script


def test_host_script_has_the_egress_proxy_chain_and_variable() -> None:
    script = (ROOT / "deploy" / "host-setup.sh").read_text(encoding="utf-8")
    assert 'PROXY_CHAIN="SANDFORT-EGRESS-PROXY"' in script
    # the endpoint comes from SF_EGRESS_PROXY, the env file variable or the network gateway
    for source in ("SF_EGRESS_PROXY", "SANDFORT_EGRESS_PROXY_ADDRESS", "egress_gateway"):
        assert source in script
    # and a loopback result is refused rather than used silently
    assert "127.*)" in script and "SF_ALLOW_LOOPBACK_PROXY" in script
    assert "loopback and sandboxes cannot reach loopback" in script
    assert '-d "$EGRESS_PROXY" --dport "$EGRESS_PROXY_PORT" \\\n        -j RETURN' in script
    assert '-A "$PROXY_CHAIN" -j REJECT' in script
    assert EGRESS_NETWORK_NAME in script


# --- egress network selection ---------------------------------------------------------


def egress_spec(*, allowlisted: bool, block_all: bool = False) -> SandboxSpec:
    base = make_spec()
    return SandboxSpec(
        sandbox_id=base.sandbox_id,
        org_id=base.org_id,
        name=base.name,
        image=base.image,
        resources=base.resources,
        labels={EGRESS_RESTRICTED_LABEL: "true"} if allowlisted else {},
        network=NetworkPolicy(block_all=block_all),
    )


def test_host_config_picks_the_egress_network_exactly_when_allowlisted() -> None:
    settings = Settings()
    allowlisted = build_host_config(egress_spec(allowlisted=True), settings)
    plain = build_host_config(egress_spec(allowlisted=False), settings)
    assert allowlisted["network_mode"] == EGRESS_NETWORK_NAME
    assert plain["network_mode"] == NETWORK_NAME


class NetworkRecordingClient(RecordingClient):
    """Adds the network lookups/creations ``ensure_network`` performs; none exist yet."""

    def __init__(self) -> None:
        super().__init__()
        self.network_lookups: list[str] = []
        self.network_creations: list[str] = []
        self.networks = SimpleNamespace(list=self._list, create=self._create_network)

    def _list(self, names: list[str]) -> list[Any]:
        self.network_lookups.extend(names)
        return []

    def _create_network(self, name: str, **kwargs: Any) -> None:
        self.network_creations.append(name)


async def test_create_ensures_the_egress_network_only_for_allowlisted_specs() -> None:
    plain_client = NetworkRecordingClient()
    await DockerDriver(Settings(), client=plain_client).create(egress_spec(allowlisted=False))
    assert plain_client.network_creations == [NETWORK_NAME]
    assert EGRESS_NETWORK_NAME not in plain_client.network_lookups

    egress_client = NetworkRecordingClient()
    await DockerDriver(Settings(), client=egress_client).create(egress_spec(allowlisted=True))
    assert egress_client.network_creations == [NETWORK_NAME, EGRESS_NETWORK_NAME]
    assert egress_client.created[0]["network_mode"] == EGRESS_NETWORK_NAME


def test_a_blocked_network_wins_over_the_egress_network() -> None:
    config = build_host_config(egress_spec(allowlisted=True, block_all=True), Settings())
    assert config["network_mode"] == "none"


def test_the_service_spec_marks_every_allowlist_but_not_an_unset_one() -> None:
    now = datetime(2026, 11, 2, tzinfo=UTC)

    def sandbox(allowlist: tuple[str, ...] | None) -> Sandbox:
        return Sandbox(
            id="sbx_1",
            org_id="org_1",
            name="n",
            image_ref="alpine:3.20",
            driver="docker",
            created_at=now,
            updated_at=now,
            egress_allowlist=allowlist,
        )

    assert MountingLifecycle.spec(sandbox(("example.com",))).labels == {
        EGRESS_RESTRICTED_LABEL: "true"
    }
    assert MountingLifecycle.spec(sandbox(())).labels == {EGRESS_RESTRICTED_LABEL: "true"}
    assert MountingLifecycle.spec(sandbox(None)).labels == {}


# --- capability report --------------------------------------------------------------


class InfoClient:
    """A ``client.api`` answering version/df and a configurable ``docker info``."""

    def __init__(self, info: Any = None, *, info_fails: bool = False) -> None:
        self._info = info
        self._info_fails = info_fails
        self.api = SimpleNamespace(
            version=lambda: {"Version": "27.3.1", "ApiVersion": "1.47"},
            df=lambda: {},
            info=self._read_info,
        )

    def _read_info(self) -> Any:
        if self._info_fails:
            raise docker.errors.DockerException("daemon went away")
        return self._info


def docker_info(driver: str, filesystem: str | None, runtimes: tuple[str, ...]) -> Any:
    status = [["Backing Filesystem", filesystem]] if filesystem is not None else []
    return {
        "Driver": driver,
        "DriverStatus": [*status, ["Supports d_type", "true"]],
        "Runtimes": {name: {"path": name} for name in runtimes},
    }


async def test_capability_report_shape() -> None:
    client = InfoClient(docker_info("overlay2", "xfs", ("runsc", "runc")))
    report = await capability_report(client, runtime="runsc")
    assert report == DockerCapabilities(
        daemon_version="27.3.1",
        api_version="1.47",
        disk_usage_available=True,
        storage_driver="overlay2",
        backing_filesystem="xfs",
        disk_quota_supported=True,
        runtimes=("runc", "runsc"),
        configured_runtime="runsc",
    )
    assert report.runtime_available is True
    assert missing_isolation(report) == []


@pytest.mark.parametrize(
    ("driver", "filesystem", "supported"),
    [
        ("overlay2", "xfs", True),
        ("overlay2", "extfs", False),
        ("overlay2", None, False),
        ("btrfs", None, True),
        ("zfs", None, True),
        ("overlayfs", None, False),  # containerd snapshotter: no size option
        ("vfs", None, False),
        ("", None, False),
    ],
)
async def test_disk_quota_detection_is_conservative(
    driver: str, filesystem: str | None, supported: bool
) -> None:
    report = await capability_report(InfoClient(docker_info(driver, filesystem, ("runc",))))
    assert report.disk_quota_supported is supported
    assert disk_quota_supported(driver, filesystem or "") is supported


async def test_unreadable_docker_info_reports_nothing_supported() -> None:
    report = await capability_report(InfoClient(info_fails=True), runtime="runsc")
    assert report.daemon_version == "27.3.1"
    assert report.storage_driver == ""
    assert report.disk_quota_supported is False
    assert report.runtimes == ()
    assert report.runtime_available is False


async def test_configured_runtime_presence_in_the_daemon_runtimes() -> None:
    info = docker_info("overlay2", "xfs", ("runc",))
    assert (await capability_report(InfoClient(info))).runtime_available is True
    missing = await capability_report(InfoClient(info), runtime="runsc")
    assert missing.runtime_available is False
    [finding] = missing_isolation(missing)
    assert "container runtime 'runsc'" in finding
    assert "['runc']" in finding


async def test_driver_report_uses_the_configured_runtime() -> None:
    client = InfoClient(docker_info("overlay2", "extfs", ("runc",)))
    driver = DockerDriver(Settings(container_runtime="kata"), client=client)
    report = await driver.capability_report()
    assert report.configured_runtime == "kata"
    gaps = await driver.isolation_gaps()
    # Advisory findings may be added next to the two original gaps; they stay in the list
    # only when they are refusing, so the two original gaps must be present and ordered first.
    quota_gaps = [gap for gap in gaps if "disk quota support" in gap]
    runtime_gaps = [gap for gap in gaps if "container runtime 'kata'" in gap]
    assert len(quota_gaps) == 1
    assert "'extfs'" in quota_gaps[0]
    assert len(runtime_gaps) == 1
    assert "['runc']" in runtime_gaps[0]
    assert gaps.index(quota_gaps[0]) < gaps.index(runtime_gaps[0])


# --- startup guard ------------------------------------------------------------------


def report_with(*, quota: bool, runtimes: tuple[str, ...] = ("runc",), runtime: str = "") -> Any:
    async def report(self: DockerDriver) -> DockerCapabilities:
        return DockerCapabilities(
            "27.3.1",
            "1.47",
            True,
            storage_driver="overlay2",
            backing_filesystem="xfs" if quota else "extfs",
            disk_quota_supported=quota,
            runtimes=runtimes,
            configured_runtime=runtime,
        )

    return report


def guarded_app(tmp_path: Path, environment: str, *, acknowledged: bool = True) -> Any:
    """A fake-driver app whose state driver is swapped for a docker driver to self-check.

    Host capacity and a valid fernet webhook key are set so the configuration preflight and
    the capacity gate pass and the capability gates speak; the egress probe is off so the
    acknowledgement path is the egress gate under test here (the probe has its own module,
    ``test_egress_probe_r58``).
    """
    pytest.importorskip("aiosqlite")
    settings = Settings(
        driver="fake",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'guard.db'}",
        api_key_pepper="test-pepper",
        environment=environment,
        egress_acknowledged=acknowledged,
        egress_probe=False,
        webhook_secret_key=Fernet.generate_key().decode(),
        host_capacity_cpu_millicores=8000,
        host_capacity_memory_mib=16384,
        **WORKERS_OFF,
    )
    app = create_app(settings)
    setattr(app.state, DRIVER_ATTR, DockerDriver(settings, client=RecordingClient()))
    return app


@pytest.mark.parametrize(
    ("quota", "runtime", "acknowledged", "match"),
    [
        (False, "", True, "disk quota support"),
        (True, "runsc", True, "container runtime 'runsc'"),
        (True, "", False, "host egress enforcement.*deploy/host-setup.sh"),
    ],
)
async def test_prod_refuses_to_start_on_a_missing_capability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    quota: bool,
    runtime: str,
    acknowledged: bool,
    match: str,
) -> None:
    report = report_with(quota=quota, runtime=runtime)
    monkeypatch.setattr(DockerDriver, "capability_report", report)
    app = guarded_app(tmp_path, "prod", acknowledged=acknowledged)
    with pytest.raises(IsolationUnavailableError, match=match):
        async with app.router.lifespan_context(app):
            pytest.fail("the lifespan must not start")


async def test_prod_starts_on_a_fully_capable_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capable = report_with(quota=True, runtimes=("runc", "runsc"), runtime="runsc")
    monkeypatch.setattr(DockerDriver, "capability_report", capable)
    app = guarded_app(tmp_path, "prod")
    async with app.router.lifespan_context(app):
        pass


async def test_dev_tolerates_missing_capabilities_and_logs_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(DockerDriver, "capability_report", report_with(quota=False))
    app = guarded_app(tmp_path, "dev", acknowledged=False)
    with caplog.at_level(logging.WARNING, logger="sandfort.api.app"):
        async with app.router.lifespan_context(app):
            pass
    messages = [record.getMessage() for record in caplog.records]
    assert any("disk quota support" in message for message in messages)
    assert not any("egress" in message for message in messages)  # dev never asks for it


async def test_drivers_without_a_self_check_are_refused_in_prod_only() -> None:
    with pytest.raises(IsolationUnavailableError, match="object cannot run in prod"):
        await check_isolation(object(), Settings(environment="prod"))  # e.g. the fake driver

    await check_isolation(object(), Settings(environment="dev"))  # nothing to verify outside


# --- opt-in disk quota enforcement outside prod ---------------------------------------

QUOTA_GAP = "disk quota support (storage-opt size): storage driver 'overlay2' on 'extfs'"
RUNTIME_GAP = "container runtime 'kata' is not registered with the daemon"


class GapsDriver:
    """A driver stand-in with a fixed self-check result."""

    def __init__(self, gaps: list[str]) -> None:
        self._gaps = gaps

    async def isolation_gaps(self) -> list[str]:
        return self._gaps


async def test_dev_with_enforce_disk_quota_refuses_a_disk_quota_gap() -> None:
    settings = Settings(environment="dev", enforce_disk_quota=True)
    with pytest.raises(IsolationUnavailableError, match="disk quota support"):
        await check_isolation(GapsDriver([RUNTIME_GAP, QUOTA_GAP]), settings)


async def test_dev_without_enforce_disk_quota_only_logs_a_disk_quota_gap(
    caplog: pytest.LogCaptureFixture,
) -> None:
    settings = Settings(environment="dev", enforce_disk_quota=False)
    with caplog.at_level(logging.WARNING, logger="sandfort.api.app"):
        await check_isolation(GapsDriver([QUOTA_GAP]), settings)
    messages = [record.getMessage() for record in caplog.records]
    assert any("disk quota support" in m and "tolerated outside prod" in m for m in messages)


async def test_dev_with_enforce_disk_quota_only_logs_other_gaps(
    caplog: pytest.LogCaptureFixture,
) -> None:
    settings = Settings(environment="dev", enforce_disk_quota=True)
    with caplog.at_level(logging.WARNING, logger="sandfort.api.app"):
        await check_isolation(GapsDriver([RUNTIME_GAP]), settings)
    messages = [record.getMessage() for record in caplog.records]
    assert any("container runtime 'kata'" in m and "tolerated outside prod" in m for m in messages)


async def test_dev_with_enforce_disk_quota_starts_when_no_gap_is_reported() -> None:
    await check_isolation(GapsDriver([]), Settings(environment="dev", enforce_disk_quota=True))
