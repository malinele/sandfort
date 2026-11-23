"""Docker inventory (WP 3.6) and the capability report used for diagnostics.

The inventory lists only what the platform created: containers and volumes carrying the
``sandfort.managed=true`` label (filtered by the daemon and again here, so a loose daemon
filter can never widen it) and images tagged in the platform snapshot repository. Every
docker-py call runs through ``run_blocking``.

The capability report (WP 5.4) also reads ``docker info``: whether the storage driver can
honour ``storage_opt.size`` and whether the configured runtime is registered with the
daemon, and three more facts: user-namespace remapping, the default runtime and the cgroup
driver. ``missing_isolation`` turns a report into the findings the startup guard acts on.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sandfort.config import PROD_ENVIRONMENT, Settings
from sandfort.drivers.base import ImageInfo, InstanceState, InventoryInstance, VolumeInfo
from sandfort.drivers.docker.client import run_blocking, translate_errors
from sandfort.drivers.docker.labels import LABEL_MANAGED, managed_filters
from sandfort.drivers.errors import DriverError

# The local repository snapshot images are tagged into (services.snapshots.SNAPSHOT_REPOSITORY).
PLATFORM_IMAGE_REPOSITORY = "sandfort-snapshot"
PLATFORM_IMAGE_PREFIX = f"{PLATFORM_IMAGE_REPOSITORY}:"
UNKNOWN_VERSION = "unknown"
# overlay2 honours storage_opt.size only on an xfs backing filesystem (mounted with pquota);
# btrfs and zfs size their own subvolumes or datasets. Anything else is reported unsupported.
OVERLAY_DRIVER = "overlay2"
OVERLAY_QUOTA_FILESYSTEM = "xfs"
SELF_SIZING_DRIVERS = frozenset({"btrfs", "zfs"})
BACKING_FILESYSTEM_KEY = "Backing Filesystem"
STATUS_PAIR_LENGTH = 2
USERNS_SECURITY_OPTION = "name=userns"  # listed in docker info SecurityOptions when remapping is on
RUNC_COMMIT_KEY = "RuncCommit"  # docker info: {"ID": "v1.1.12-0-g51d5e94", ...}
DOCKER_BUILTIN_RUNTIME = "runc"  # what docker runs when the daemon reports no default runtime
_VERSION = re.compile(r"([0-9]+)\.([0-9]+)(?:\.([0-9]+))?")


@dataclass(frozen=True, slots=True)
class DockerCapabilities:
    daemon_version: str
    api_version: str
    disk_usage_available: bool
    storage_driver: str = ""  # "" when docker info is unreadable
    backing_filesystem: str = ""
    disk_quota_supported: bool = False
    runtimes: tuple[str, ...] = ()  # names registered with the daemon, sorted
    configured_runtime: str = ""  # "" = the daemon default runtime
    userns_remap: bool = False  # daemon-wide user-namespace remapping is active
    default_runtime: str = ""  # the daemon's default runtime ("" = not reported)
    cgroup_driver: str = ""  # "" = not reported
    runc_version: str = ""  # docker info RuncCommit ID, e.g. "v1.1.12-0-g51d5e94"; "" = none

    @property
    def runtime_available(self) -> bool:
        """True when no runtime is configured or the daemon lists the configured one."""
        return not self.configured_runtime or self.configured_runtime in self.runtimes


def disk_quota_supported(storage_driver: str, backing_filesystem: str) -> bool:
    """Whether the daemon can honour ``storage_opt.size``; unknown combinations answer False.

    docker info cannot show xfs mount options, so overlay2 on xfs without ``pquota`` still
    reports True here and surfaces as a create failure once quotas are enforced.
    """
    if storage_driver == OVERLAY_DRIVER:
        return backing_filesystem.lower() == OVERLAY_QUOTA_FILESYSTEM
    return storage_driver in SELF_SIZING_DRIVERS


EGRESS_FINDING = (
    "host egress enforcement: nothing in the process can verify the SANDFORT-EGRESS firewall;"
    " run deploy/host-setup.sh on this node after the daemon starts, then set"
    " SANDFORT_EGRESS_ACKNOWLEDGED=true"
)


def egress_findings(acknowledged: bool) -> list[str]:
    """The egress finding unless the operator acknowledged the host script is installed."""
    return [] if acknowledged else [EGRESS_FINDING]


def missing_isolation(
    report: DockerCapabilities,
    *,
    egress_acknowledged: bool = True,
    settings: Settings | None = None,
) -> list[str]:
    """One finding per isolation capability the host lacks; empty when nothing is missing.

    Egress filtering lives in host iptables, which the process cannot observe, so it is
    reported unless ``egress_acknowledged``. The default keeps diagnostics callers quiet;
    the prod startup guard passes the operator's setting. With ``settings`` the daemon-level
    findings of ``hardening_findings`` follow the existing ones.
    """
    driver = report.storage_driver or UNKNOWN_VERSION
    filesystem = report.backing_filesystem or UNKNOWN_VERSION
    findings = (
        (
            report.disk_quota_supported,
            f"disk quota support (storage-opt size): storage driver {driver!r} on backing"
            f" filesystem {filesystem!r} needs overlay2 on xfs with pquota, btrfs or zfs",
        ),
        (
            report.runtime_available,
            f"container runtime {report.configured_runtime!r}: not among the daemon's runtimes"
            f" {list(report.runtimes)}",
        ),
    )
    missing = [finding for present, finding in findings if not present]
    extra = hardening_findings(report, settings) if settings is not None else []
    return [*missing, *extra, *egress_findings(egress_acknowledged)]


DEFAULT_RUNTIME_FINDING = (
    "default runtime {default!r} is not among the configured sandbox runtimes {configured};"
    " tenant image builds run on it (advisory only: logged as a warning; prod refuses startup"
    " instead when SANDFORT_REQUIRE_BUILD_RUNTIME is on and a strong runtime is offered)"
)
USERNS_FINDING = (
    "user-namespace remapping: not active on the daemon (userns-remap in daemon.json);"
    " container root maps to host root except for tiers that opt out per container"
)


def configured_sandbox_runtimes(settings: Settings, daemon_default: str) -> set[str]:
    """Runtimes sandboxes run on; a tier mapped to "" runs on the daemon default runtime."""
    runtimes = {
        runtime.strip() or daemon_default for runtime in settings.isolation_tiers().values()
    }
    return {runtime for runtime in runtimes if runtime}


BUILD_RUNTIME_FINDING = (
    "build runtime: the daemon default runtime {default!r} is not one of the strong sandbox"
    " runtimes {strong}; tenant image builds run on the default runtime with docker's default"
    " capabilities, no pids limit and no seccomp. Set the daemon default-runtime to a strong"
    " runtime, or set SANDFORT_REQUIRE_BUILD_RUNTIME=false to accept the risk"
)
STRONG_RUNTIME_MARKERS = ("runsc", "kata")  # gVisor and Kata Containers runtime names


def is_strong_runtime(runtime: str) -> bool:
    """A runsc (gVisor) or kata runtime; anything else shares the host kernel (runc-class)."""
    return any(marker in runtime.lower() for marker in STRONG_RUNTIME_MARKERS)


def strong_sandbox_runtimes(settings: Settings, daemon_default: str) -> set[str]:
    """Configured tier runtimes that are a runsc (gVisor) or kata runtime."""
    return {
        runtime
        for runtime in configured_sandbox_runtimes(settings, daemon_default)
        if is_strong_runtime(runtime)
    }


ROOT_FINDING = (
    "root on a shared kernel: tiers {tiers} run on runc-class runtimes {runtimes} without"
    " user-namespace remapping, so container root is host root; turn on userns-remap in"
    " daemon.json (and keep those tiers out of SANDFORT_USERNS_HOST_TIERS), map them to a"
    " runsc or kata runtime, or set SANDFORT_ALLOW_ROOT_SHARED_KERNEL=true to accept the risk"
)
RUNC_OLD_FINDING = (
    "runc version: the daemon reports {found!r}, older than SANDFORT_MIN_RUNC_VERSION"
    " {minimum!r}; upgrade runc (containerd.io) on this node"
)
RUNC_UNREPORTED_FINDING = (
    "runc version: docker info reports none, so SANDFORT_MIN_RUNC_VERSION {minimum!r}"
    " cannot be verified"
)


def version_tuple(raw: str) -> tuple[int, int, int] | None:
    """``(1, 1, 12)`` from ``1.1.12`` or ``v1.1.12-0-g51d5e94``; None when nothing parses."""
    match = _VERSION.search(raw)
    if match is None:
        return None
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch or 0)


def root_on_host_tiers(report: DockerCapabilities, settings: Settings) -> dict[str, str]:
    """Tier -> runtime for offered tiers whose container root is host root.

    That is a runc-class runtime ("" = the daemon default; unreported = docker's runc) while
    remapping is off on the daemon or the tier opts out of it (``userns_host_tiers``).
    """
    found: dict[str, str] = {}
    for tier, runtime in settings.isolation_tiers().items():
        effective = runtime.strip() or report.default_runtime or DOCKER_BUILTIN_RUNTIME
        remapped = report.userns_remap and tier not in settings.userns_host_tiers
        if not is_strong_runtime(effective) and not remapped:
            found[tier] = effective
    return found


def runc_findings(report: DockerCapabilities, settings: Settings) -> list[str]:
    """Root on a runc-class tier (unless allowed) and a runc older than the configured floor."""
    findings: list[str] = []
    tiers = root_on_host_tiers(report, settings)
    if tiers and not settings.allow_root_shared_kernel:
        runtimes = sorted(set(tiers.values()))
        findings.append(ROOT_FINDING.format(tiers=sorted(tiers), runtimes=runtimes))
    minimum = settings.min_runc_version
    if not minimum:
        return findings
    found, wanted = version_tuple(report.runc_version), version_tuple(minimum)
    if found is None:
        findings.append(RUNC_UNREPORTED_FINDING.format(minimum=minimum))
    elif wanted is not None and found < wanted:
        findings.append(RUNC_OLD_FINDING.format(found=report.runc_version, minimum=minimum))
    return findings


def build_runtime_gap(report: DockerCapabilities, settings: Settings) -> list[str]:
    """The build-runtime finding when a strong tier runtime is offered but builds do not use it.

    Nothing is reported while the default runtime is itself a runsc or kata runtime, whatever
    the tiers map, or while no tier offers one: the default is then as strong as any tier.
    """
    if is_strong_runtime(report.default_runtime):
        return []
    strong = strong_sandbox_runtimes(settings, report.default_runtime)
    if not strong:
        return []
    default = report.default_runtime or UNKNOWN_VERSION
    return [BUILD_RUNTIME_FINDING.format(default=default, strong=sorted(strong))]


def _refuses_on_build_runtime(settings: Settings) -> bool:
    return settings.environment == PROD_ENVIRONMENT and settings.require_build_runtime


def hardening_findings(report: DockerCapabilities, settings: Settings) -> list[str]:
    """Daemon-level hardening gaps that count as missing isolation.

    The remapping finding is reported outside prod; in prod it is reported (and so refuses
    startup) only when ``require_userns_remap`` is set. In prod with ``require_build_runtime``
    the build-runtime finding refuses startup too. ``advisory_findings`` holds the rest.
    """
    findings: list[str] = []
    wants_remap = settings.environment != PROD_ENVIRONMENT or settings.require_userns_remap
    if wants_remap and not report.userns_remap:
        findings.append(USERNS_FINDING)
    if _refuses_on_build_runtime(settings):
        findings.extend(build_runtime_gap(report, settings))
    if settings.environment == PROD_ENVIRONMENT:
        findings.extend(runc_findings(report, settings))
    return findings


def advisory_findings(report: DockerCapabilities, settings: Settings) -> list[str]:
    """Findings that are logged as warnings and never refuse startup.

    The default-runtime finding applies (in prod and dev) when the daemon reports a default
    runtime that no configured tier uses. The remapping finding is advisory in prod while
    ``require_userns_remap`` is off, so the operator sees it before switching the flag on.
    """
    findings: list[str] = []
    configured = configured_sandbox_runtimes(settings, report.default_runtime)
    refused = _refuses_on_build_runtime(settings) and bool(build_runtime_gap(report, settings))
    if report.default_runtime and report.default_runtime not in configured and not refused:
        findings.append(
            DEFAULT_RUNTIME_FINDING.format(
                default=report.default_runtime, configured=sorted(configured)
            )
        )
    if (
        settings.environment == PROD_ENVIRONMENT
        and not settings.require_userns_remap
        and not report.userns_remap
    ):
        findings.append(USERNS_FINDING)
    if settings.environment != PROD_ENVIRONMENT:
        findings.extend(runc_findings(report, settings))  # prod refuses on them instead
    return findings


def _labels(raw: Any) -> dict[str, str]:
    if not isinstance(raw, Mapping):
        return {}
    return {str(key): str(value) for key, value in raw.items()}


def _is_managed(labels: Mapping[str, str]) -> bool:
    return labels.get(LABEL_MANAGED) == "true"


def runtime_state(status: str) -> InstanceState:
    """Map a docker container status; anything not alive (``dead``, ``removing``) is exited."""
    if status == "paused":
        return InstanceState.PAUSED
    if status in ("running", "restarting"):
        return InstanceState.RUNNING
    if status == "created":
        return InstanceState.CREATED
    return InstanceState.EXITED


async def list_instances(client: Any) -> list[InventoryInstance]:
    with translate_errors(None, "inventory.containers"):
        listing = await run_blocking(client.api.containers, all=True, filters=managed_filters())
    found: list[InventoryInstance] = []
    for entry in listing or []:
        labels = _labels(entry.get("Labels"))
        if _is_managed(labels):
            state = runtime_state(str(entry.get("State") or ""))
            found.append(InventoryInstance(str(entry["Id"]), labels, state))
    return found


async def list_volumes(client: Any) -> list[VolumeInfo]:
    with translate_errors(None, "inventory.volumes"):
        listing = await run_blocking(client.api.volumes, filters=managed_filters())
    found: list[VolumeInfo] = []
    for entry in (listing or {}).get("Volumes") or []:
        labels = _labels(entry.get("Labels"))
        if _is_managed(labels):
            name = str(entry["Name"])
            found.append(VolumeInfo(ref=name, name=name, labels=labels))
    return found


async def list_images(client: Any) -> list[ImageInfo]:
    """One entry per platform tag (an image with two platform tags is listed twice)."""
    with translate_errors(None, "inventory.images"):
        listing = await run_blocking(client.api.images)
    found: list[ImageInfo] = []
    for entry in listing or []:
        for tag in entry.get("RepoTags") or []:
            if str(tag).startswith(PLATFORM_IMAGE_PREFIX):
                size = int(entry.get("Size") or 0)
                found.append(
                    ImageInfo(ref=str(tag), digest=str(entry["Id"]), size_bytes=size, layer_count=0)
                )
    return found


def _driver_status(raw: Any) -> dict[str, str]:
    """``docker info`` DriverStatus is a list of ``[key, value]`` pairs."""
    if not isinstance(raw, list | tuple):
        return {}
    return {
        str(entry[0]): str(entry[1])
        for entry in raw
        if isinstance(entry, list | tuple) and len(entry) == STATUS_PAIR_LENGTH
    }


async def _daemon_info(client: Any) -> Mapping[str, Any]:
    try:
        with translate_errors(None, "daemon.info"):
            info = await run_blocking(client.api.info)
    except DriverError:
        return {}  # unreadable info reports no quota support and no runtimes: conservative
    return info if isinstance(info, Mapping) else {}


async def capability_report(client: Any, runtime: str = "") -> DockerCapabilities:
    """Version, disk usage api, disk quota and runtime support; never raises on a sick daemon.

    ``runtime`` is the runtime sandboxes are created with ("" = the daemon default).
    """
    daemon_version, api_version = UNKNOWN_VERSION, UNKNOWN_VERSION
    try:
        with translate_errors(None, "daemon.version"):
            version = await run_blocking(client.api.version)
        daemon_version = str(version.get("Version") or UNKNOWN_VERSION)
        api_version = str(version.get("ApiVersion") or UNKNOWN_VERSION)
    except DriverError:
        pass  # a report is for diagnostics: an unreadable version is itself the finding
    try:
        with translate_errors(None, "daemon.df"):
            await run_blocking(client.api.df)
        disk_usage_available = True
    except DriverError:
        disk_usage_available = False
    info = await _daemon_info(client)
    storage_driver = str(info.get("Driver") or "")
    backing = _driver_status(info.get("DriverStatus")).get(BACKING_FILESYSTEM_KEY, "")
    registered = info.get("Runtimes")
    names = registered if isinstance(registered, Mapping) else {}
    runtimes = tuple(sorted(str(name) for name in names))
    security = info.get("SecurityOptions")
    options = security if isinstance(security, list | tuple) else []
    userns_remap = any(USERNS_SECURITY_OPTION in str(option).split(",") for option in options)
    commit = info.get(RUNC_COMMIT_KEY)
    runc_version = str(commit.get("ID") or "") if isinstance(commit, Mapping) else ""
    return DockerCapabilities(
        daemon_version,
        api_version,
        disk_usage_available,
        storage_driver=storage_driver,
        backing_filesystem=backing,
        disk_quota_supported=disk_quota_supported(storage_driver, backing),
        runtimes=runtimes,
        configured_runtime=runtime,
        userns_remap=userns_remap,
        default_runtime=str(info.get("DefaultRuntime") or ""),
        cgroup_driver=str(info.get("CgroupDriver") or ""),
        runc_version=runc_version,
    )
