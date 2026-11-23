"""HostConfig builder from ResourceSpec + NetworkPolicy + settings (hardening asserted by tests).

``build_host_config`` returns keyword arguments for docker-py ``containers.create``. It
needs no daemon, so the mapping is unit-testable. ``options_from_settings`` turns the
deployment settings (runtime, seccomp profile, prod disk quotas) into ``HardeningOptions``
once, when the driver is built.

``/tmp`` stays in the root filesystem under every runtime, so the disk quota and snapshots
cover it. gVisor (runtime ``runsc``) would mount a private tmpfs there if ``/tmp`` were
empty at start; ``containers.start_container`` prevents that with a marker file, so the
host config needs no extra mount.

The cgroup parent is carried into every create when set. Tiers listed in
``userns_host_tiers`` (default: microvm, whose Kata runtime cannot run under user-namespace
remapping) get ``userns_mode="host"``; every other tier keeps the daemon's setting.

A spec may name an isolation tier (``domain.isolation``); the tier's runtime from the options'
tier map decides the ``runtime`` kwarg and the gVisor mode flag.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sandfort.config import (
    DEFAULT_GVISOR_DNS,
    DEFAULT_USERNS_HOST_TIERS,
    PROD_ENVIRONMENT,
    Settings,
    parse_nameservers,
)
from sandfort.domain.isolation import DEFAULT_TIER
from sandfort.domain.sandbox import egress_restricted
from sandfort.drivers.base import SandboxSpec
from sandfort.drivers.docker.disk_reserve import QUOTA_HEADROOM_BYTES
from sandfort.drivers.docker.networks import EGRESS_NETWORK_NAME, NETWORK_NAME
from sandfort.drivers.errors import DriverUnsupported

BYTES_PER_MIB = 1024 * 1024
BYTES_PER_GIB = 1024 * BYTES_PER_MIB
NANO_CPUS_PER_MILLICORE = 1_000_000
PIDS_LIMIT = 512
NOFILE_LIMIT = 4096
SHM_MAX_BYTES = 64 * BYTES_PER_MIB
SHM_MEMORY_DIVISOR = 4
LOG_DRIVER = "local"
LOG_MAX_SIZE = "10m"
LOG_MAX_FILES = "3"
NETWORK_NONE = "none"
NO_NEW_PRIVILEGES = "no-new-privileges:true"
# The engine API takes the profile body itself after this prefix, not a file path.
SECCOMP_OPT_PREFIX = "seccomp="
# Minimal add-back after ``cap_drop=ALL`` (architecture §1, container hardening).
CAPS_ADDED = (
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "SETUID",
    "SETGID",
    "KILL",
    "NET_BIND_SERVICE",
)
GVISOR_RUNTIME = "runsc"
USERNS_MODE_HOST = "host"  # per-container opt-out from daemon-wide userns remapping
GVISOR_TMP_PATH = "/tmp"  # must not be empty when runsc starts (see containers.py)
# What a default ``Settings`` yields, so ``options_from_settings(Settings())`` stays the default.
DEFAULT_GVISOR_NAMESERVERS = parse_nameservers(DEFAULT_GVISOR_DNS)


@dataclass(frozen=True, slots=True)
class HardeningOptions:
    """Deployment-level knobs; every default keeps the strictest portable behaviour."""

    user: str | None = None  # e.g. "1000:1000"; None keeps the image's user
    cgroup_parent: str | None = None  # e.g. "sandfort.slice"
    runtime: str | None = None  # e.g. "runsc" (gVisor)
    enforce_disk_quota: bool = False  # storage_opt.size needs overlay2 on XFS with pquota
    seccomp_profile: str | None = None  # compact profile JSON; None keeps docker's default
    gvisor: bool = False  # the default tier's runtime is runsc
    default_tier: str = DEFAULT_TIER  # the tier ``runtime``/``gvisor`` describe
    # Other offered tiers -> runtime ("" = daemon default); empty = only the default tier.
    tier_runtimes: Mapping[str, str] = field(default_factory=dict)
    # Written to /etc/resolv.conf of runsc containers after each start; () = leave it alone.
    gvisor_nameservers: tuple[str, ...] = DEFAULT_GVISOR_NAMESERVERS
    # Tiers created with the host user namespace (their runtime cannot run remapped).
    userns_host_tiers: tuple[str, ...] = DEFAULT_USERNS_HOST_TIERS


def load_seccomp_profile(path: str) -> str:
    """Read and validate a seccomp profile; return it as compact JSON for ``security_opt``."""
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"seccomp profile {path!r} is unreadable: {exc}") from exc
    try:
        profile = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"seccomp profile {path!r} is not valid JSON: {exc}") from exc
    if not isinstance(profile, dict):
        raise ValueError(f"seccomp profile {path!r} must be a JSON object")
    return json.dumps(profile, separators=(",", ":"), sort_keys=True)


def options_from_settings(settings: Settings) -> HardeningOptions:
    """Deployment knobs from settings; dev defaults give exactly ``HardeningOptions()``.

    ``runtime`` and ``gvisor`` describe the default tier (its mapped runtime, or
    ``container_runtime`` when no tier map is configured); ``tier_runtimes`` carries the map.
    The seccomp profile is read here, once, so a bad path fails at startup, not per create.
    Prod enforces the disk quota its startup self-check requires; outside prod
    ``enforce_disk_quota`` opts in.
    """
    tiers = settings.isolation_tiers()
    if settings.default_isolation not in tiers:  # from_env rejects this; direct builds may not
        raise ValueError(f"default isolation {settings.default_isolation!r} is not configured")
    runtime = tiers[settings.default_isolation].strip() or None
    path = settings.seccomp_profile_path.strip()
    return HardeningOptions(
        cgroup_parent=settings.cgroup_parent.strip() or None,
        runtime=runtime,
        enforce_disk_quota=settings.environment == PROD_ENVIRONMENT or settings.enforce_disk_quota,
        seccomp_profile=load_seccomp_profile(path) if path else None,
        gvisor=runtime == GVISOR_RUNTIME,
        default_tier=settings.default_isolation,
        tier_runtimes=dict(settings.isolation_runtimes),
        gvisor_nameservers=settings.gvisor_nameservers(),
        userns_host_tiers=tuple(settings.userns_host_tiers),
    )


def _runtime_for(spec: SandboxSpec, options: HardeningOptions) -> tuple[str | None, bool]:
    """The create ``runtime`` (None = daemon default) and the gVisor mode for ``spec``'s tier.

    A spec without a tier, or on the default tier, keeps the deployment default. A tier this
    node does not offer is refused rather than run on a weaker runtime.
    """
    tier = spec.isolation
    if tier is None or tier == options.default_tier:
        return options.runtime, options.gvisor
    if tier not in options.tier_runtimes:
        offered = ", ".join(options.tier_runtimes or [options.default_tier])
        raise DriverUnsupported(
            f"isolation {tier!r} is not configured on this node; available: {offered}"
        )
    runtime = options.tier_runtimes[tier].strip() or None
    return runtime, runtime == GVISOR_RUNTIME


def _security_opt(options: HardeningOptions) -> list[str]:
    if options.seccomp_profile is None:
        return [NO_NEW_PRIVILEGES]
    return [NO_NEW_PRIVILEGES, f"{SECCOMP_OPT_PREFIX}{options.seccomp_profile}"]


def _network_mode(spec: SandboxSpec) -> str:
    """No network when blocked (always wins), the egress bridge when allowlisted, else main."""
    if spec.network.block_all:
        return NETWORK_NONE
    if egress_restricted(spec.labels):
        return EGRESS_NETWORK_NAME
    return NETWORK_NAME


def build_host_config(
    spec: SandboxSpec, settings: Settings, options: HardeningOptions | None = None
) -> dict[str, Any]:
    """Map a ``SandboxSpec`` onto hardened docker-py create kwargs.

    ``settings`` is accepted so deployment-wide overrides can land here without a
    signature change; nothing in it relaxes the hardening today.
    """
    del settings
    chosen = options or HardeningOptions()
    resources = spec.resources
    memory_bytes = resources.memory_mib * BYTES_PER_MIB

    kwargs: dict[str, Any] = {
        "nano_cpus": resources.cpu_millicores * NANO_CPUS_PER_MILLICORE,
        "mem_limit": memory_bytes,
        "memswap_limit": memory_bytes,  # equal to mem_limit: no swap
        "pids_limit": PIDS_LIMIT,
        "shm_size": min(SHM_MAX_BYTES, memory_bytes // SHM_MEMORY_DIVISOR),
        "cap_drop": ["ALL"],
        "cap_add": list(CAPS_ADDED),
        "security_opt": _security_opt(chosen),
        "init": True,
        "privileged": False,
        "ulimits": [{"Name": "nofile", "Soft": NOFILE_LIMIT, "Hard": NOFILE_LIMIT}],
        "log_config": {
            "Type": LOG_DRIVER,
            "Config": {"max-size": LOG_MAX_SIZE, "max-file": LOG_MAX_FILES},
        },
        "network_mode": _network_mode(spec),
    }
    if chosen.user is not None:
        kwargs["user"] = chosen.user
    if chosen.cgroup_parent is not None:
        kwargs["cgroup_parent"] = chosen.cgroup_parent
    runtime, _ = _runtime_for(spec, chosen)
    if runtime is not None:
        kwargs["runtime"] = runtime
    if (spec.isolation or chosen.default_tier) in chosen.userns_host_tiers:
        kwargs["userns_mode"] = USERNS_MODE_HOST
    if chosen.enforce_disk_quota:
        # The headroom holds the reserve file (disk_reserve.py); users still get disk_gib.
        quota_bytes = resources.disk_gib * BYTES_PER_GIB + QUOTA_HEADROOM_BYTES
        kwargs["storage_opt"] = {"size": f"{quota_bytes}"}
    if spec.volumes:
        kwargs["volumes"] = {
            bind.volume_ref: {"bind": bind.mount_path, "mode": "ro" if bind.read_only else "rw"}
            for bind in spec.volumes
        }
    return kwargs
