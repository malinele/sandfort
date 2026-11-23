"""``admin_cli doctor``: one PASS/WARN/FAIL line per production-readiness check.

The Docker checks read the driver package's capability report and judge it with the same
findings the startup gate uses (``missing_isolation``, ``advisory_findings`` and, in prod,
``egress_findings``), so the doctor and the gate cannot disagree: a finding that refuses a
prod start is a FAIL here, one the gate only logs is a WARN. The remaining checks read
``Settings``. ``evaluate`` is pure; ``fetch_report`` is the only function that talks to docker.
"""

import asyncio
import json
from collections.abc import Callable, Sequence
from dataclasses import asdict

from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

import sandfort.api.app as startup_gate
from sandfort.admin_doctor_rows import (
    QUOTA_PREFIX,
    CheckResult,
    Findings,
    Status,
    audit_keys_row,
    capacity_row,
    catch_all_rows,
    gate_status,
    gate_verdict,
    root_row,
    webhook_row,
)
from sandfort.config import PROD_ENVIRONMENT, Settings
from sandfort.drivers.docker.capabilities import (
    EGRESS_FINDING,
    UNKNOWN_VERSION,
    USERNS_FINDING,
    DockerCapabilities,
    advisory_findings,
    capability_report,
    egress_findings,
    missing_isolation,
)
from sandfort.drivers.docker.client import make_client
from sandfort.drivers.docker.egress_probe import (
    PROBE_FINDING_PREFIX,
    DockerCanaryRunner,
    probe_findings,
)
from sandfort.drivers.docker.hardening import load_seccomp_profile
from sandfort.drivers.docker.lanes import configure_thread_limit
from sandfort.drivers.errors import DriverError

# Starts of the findings the capabilities module words as free text (no exported constant).
RUNTIME_PREFIX = "container runtime"
DEFAULT_RUNTIME_PREFIX = "default runtime"
PRODUCTION_DATABASES = ("postgresql",)
SQLITE_BACKEND = "sqlite"
DOCKER_DRIVER = "docker"
CGROUPFS_DRIVER = "cgroupfs"
NOT_REPORTED = "not reported"
DEFAULT_RUNTIME_LABEL = "daemon default"
FAILURE_EXIT_CODE = 1


def gate_findings(
    settings: Settings, report: DockerCapabilities | None, probe: Sequence[str] | None = None
) -> list[str]:
    """The findings ``check_isolation`` acts on: driver gaps, plus egress in prod.

    ``probe`` is the egress probe's findings (None = it did not run). When it ran it replaces
    the acknowledgement, which then only overrides its findings, as in ``egress_gaps``.
    """
    gaps = [] if report is None else missing_isolation(report, settings=settings)
    if settings.environment != PROD_ENVIRONMENT:
        return gaps
    if probe is None:
        return [*gaps, *egress_findings(settings.egress_acknowledged)]
    return gaps if settings.egress_acknowledged else [*gaps, *probe]


def default_tier_runtime(settings: Settings) -> str:
    """Runtime sandboxes are created with by default ("" = the daemon default runtime)."""
    return settings.isolation_tiers().get(settings.default_isolation, "").strip()


def _tiers_text(settings: Settings) -> str:
    pairs = settings.isolation_tiers().items()
    return ", ".join(f"{tier}={runtime or DEFAULT_RUNTIME_LABEL}" for tier, runtime in pairs)


def _daemon_check(report: DockerCapabilities) -> CheckResult:
    if report.daemon_version == UNKNOWN_VERSION:
        return CheckResult("docker daemon", Status.FAIL, "the daemon did not report its version")
    detail = f"version {report.daemon_version}, api {report.api_version}"
    if not report.disk_usage_available:
        return CheckResult("docker daemon", Status.WARN, f"{detail}; disk usage api unavailable")
    return CheckResult("docker daemon", Status.PASS, detail)


def _runtime_checks(
    settings: Settings, report: DockerCapabilities, found: Findings
) -> list[CheckResult]:
    registered = ", ".join(report.runtimes) or "none"
    runtimes = found.judge(
        "runtimes",
        lambda finding: finding.startswith(RUNTIME_PREFIX),
        f"registered: {registered}; tiers: {_tiers_text(settings)}",
    )
    if runtimes.status is Status.PASS:
        wanted = {rt for rt in settings.isolation_tiers().values() if rt}
        missing = sorted(wanted - set(report.runtimes))
        if missing:
            detail = f"tier runtimes not registered with the daemon: {missing}"
            runtimes = CheckResult("runtimes", Status.WARN, detail)
    default = found.judge(
        "default runtime",
        lambda finding: finding.startswith(DEFAULT_RUNTIME_PREFIX),
        f"daemon default {report.default_runtime or NOT_REPORTED}",
        f"daemon default {report.default_runtime!r} is used by no configured tier"
        " (tenant image builds run on it)",
    )
    return [runtimes, default]


def _docker_checks(
    settings: Settings, report: DockerCapabilities, found: Findings
) -> list[CheckResult]:
    storage_ok = f"{report.storage_driver} on {report.backing_filesystem or UNKNOWN_VERSION}"
    storage_bad = (
        f"{report.storage_driver or UNKNOWN_VERSION!r} on"
        f" {report.backing_filesystem or UNKNOWN_VERSION!r} cannot enforce a disk quota"
        " (needs overlay2 on xfs with pquota, btrfs or zfs)"
    )
    userns_bad = "user-namespace remapping is not active on the daemon (userns-remap)"
    cgroup_driver = CheckResult(
        "cgroup driver",
        Status.PASS if report.cgroup_driver else Status.WARN,
        report.cgroup_driver or "the daemon did not report a cgroup driver",
    )
    return [
        _daemon_check(report),
        found.judge(
            "storage and disk quota",
            lambda finding: finding.startswith(QUOTA_PREFIX),
            storage_ok,
            storage_bad,
        ),
        *_runtime_checks(settings, report, found),
        found.judge(
            "userns remap",
            lambda finding: finding == USERNS_FINDING,
            "daemon user-namespace remapping is active",
            userns_bad,
        ),
        root_row(found, report),
        cgroup_driver,
    ]


def _egress_probe_check(settings: Settings, probe: Sequence[str]) -> CheckResult:
    """The probe's verdict: FAIL when the gate refuses on it, WARN when it only logs it."""
    name = "egress probe"
    if not probe:
        return CheckResult(name, Status.PASS, "no probe target was reachable from a canary")
    detail = "; ".join(probe)
    if settings.environment != PROD_ENVIRONMENT:
        return CheckResult(name, Status.WARN, detail)
    if settings.egress_acknowledged:
        override = "tolerated: SANDFORT_EGRESS_ACKNOWLEDGED=true overrides the refusal"
        return CheckResult(name, Status.WARN, f"{override}: {detail}")
    return CheckResult(name, Status.FAIL, detail)


def _egress_check(
    settings: Settings, found: Findings, probe: Sequence[str] | None = None
) -> CheckResult:
    name = "egress acknowledged"
    found.consume([EGRESS_FINDING])
    if probe is not None and not settings.egress_acknowledged:
        return CheckResult(name, Status.PASS, "not needed: the egress probe verifies isolation")
    if settings.egress_acknowledged:
        return CheckResult(name, Status.PASS, "host-setup.sh acknowledged")
    bad = "SANDFORT_EGRESS_ACKNOWLEDGED is not set: the host egress firewall is unverified"
    if EGRESS_FINDING in found.gate:
        return CheckResult(name, gate_status(settings, EGRESS_FINDING), bad)
    return CheckResult(name, Status.WARN, bad)


def _seccomp_check(settings: Settings) -> CheckResult:
    path = settings.seccomp_profile_path.strip()
    if not path:
        return CheckResult("seccomp profile", Status.PASS, "docker default profile")
    try:
        load_seccomp_profile(path)
    except ValueError as exc:
        return CheckResult("seccomp profile", Status.FAIL, str(exc))
    return CheckResult("seccomp profile", Status.PASS, f"{path} is readable")


def _cgroup_parent_check(settings: Settings, report: DockerCapabilities | None) -> CheckResult:
    parent = settings.cgroup_parent.strip()
    if not parent:
        return CheckResult("cgroup parent", Status.PASS, "none set (docker default)")
    if report is not None and report.cgroup_driver == CGROUPFS_DRIVER:
        detail = f"{parent} is a systemd slice but the daemon uses the cgroupfs driver"
        return CheckResult("cgroup parent", Status.WARN, detail)
    return CheckResult("cgroup parent", Status.PASS, parent)


def _userns_tiers_check(settings: Settings) -> CheckResult:
    opted_out = sorted(set(settings.userns_host_tiers) & set(settings.isolation_tiers()))
    if opted_out:
        detail = f"tiers {opted_out} run in the host user namespace"
        return CheckResult("userns opt-out tiers", Status.WARN, detail)
    return CheckResult("userns opt-out tiers", Status.PASS, "no configured tier opts out")


def _require_remap_check(settings: Settings) -> CheckResult:
    if settings.require_userns_remap:
        return CheckResult("require userns remap", Status.PASS, "prod refuses start without it")
    status = Status.WARN if settings.environment == PROD_ENVIRONMENT else Status.PASS
    return CheckResult("require userns remap", status, "SANDFORT_REQUIRE_USERNS_REMAP is off")


def _fault_injection_check(settings: Settings) -> CheckResult:
    """The resize fault hook is a test aid: set, it must not linger into a production check."""
    name = "fault injection"
    if settings.fault_injection:
        active = ", ".join(settings.fault_injection)
        detail = f"SANDFORT_FAULT_INJECTION is set ({active}): unset it"
        return CheckResult(name, Status.FAIL, detail)
    return CheckResult(name, Status.PASS, "none set")


def _database_check(settings: Settings) -> CheckResult:
    try:
        backend = make_url(settings.database_url).get_backend_name()
    except ArgumentError:
        return CheckResult("database", Status.FAIL, "the database url cannot be parsed")
    if backend in PRODUCTION_DATABASES:
        return CheckResult("database", Status.PASS, f"scheme {backend}")
    prod = settings.environment == PROD_ENVIRONMENT
    status = Status.WARN if prod or backend != SQLITE_BACKEND else Status.PASS
    return CheckResult("database", status, f"scheme {backend}; production expects postgresql")


def _registries_check(settings: Settings) -> CheckResult:
    name = "allowed registries"
    if settings.allowed_registries:
        return CheckResult(name, Status.PASS, ", ".join(settings.allowed_registries))
    return CheckResult(name, Status.PASS, "any registry (SANDFORT_ALLOWED_REGISTRIES is empty)")


def _build_network_check(settings: Settings) -> CheckResult:
    network = settings.build_network.strip()
    return CheckResult("build network", Status.PASS, network or DEFAULT_RUNTIME_LABEL)


def _environment_check(settings: Settings) -> CheckResult:
    if settings.environment == PROD_ENVIRONMENT:
        return CheckResult("environment", Status.PASS, "prod")
    return CheckResult("environment", Status.WARN, f"{settings.environment}: gaps are tolerated")


def _driver_check(settings: Settings) -> CheckResult:
    """The start gate refuses a driver without an isolation self-check (not docker) in prod."""
    if settings.driver == DOCKER_DRIVER:
        return CheckResult("driver", Status.PASS, DOCKER_DRIVER)
    detail = startup_gate.NON_DOCKER_DRIVER_MESSAGE.format(driver=settings.driver)
    prod = settings.environment == PROD_ENVIRONMENT
    return CheckResult("driver", Status.FAIL if prod else Status.WARN, detail)


def evaluate(
    settings: Settings,
    report: DockerCapabilities | None,
    report_error: str = "",
    egress_probe: Sequence[str] | None = None,
) -> list[CheckResult]:
    """All checks for ``settings`` against ``report`` (None = the daemon could not be probed).

    ``egress_probe`` holds the egress probe's findings; None means it did not run, and the
    acknowledgement is then required in prod as before.
    """
    found = Findings(
        settings,
        gate_findings(settings, report, egress_probe),
        [] if report is None else advisory_findings(report, settings),
    )
    results = [_environment_check(settings), _driver_check(settings)]
    if report is None:
        detail = report_error or "the docker daemon could not be probed"
        results.append(CheckResult("docker daemon", Status.FAIL, detail))
    else:
        results.extend(_docker_checks(settings, report, found))
    if egress_probe is not None:
        found.consume(egress_probe)
        results.append(_egress_probe_check(settings, egress_probe))
    results.extend(
        [
            _egress_check(settings, found, egress_probe),
            webhook_row(settings),
            audit_keys_row(settings),
            capacity_row(settings),
            _seccomp_check(settings),
            _cgroup_parent_check(settings, report),
            _userns_tiers_check(settings),
            _require_remap_check(settings),
            _fault_injection_check(settings),
            _database_check(settings),
            _registries_check(settings),
            _build_network_check(settings),
        ]
    )
    results.extend(catch_all_rows(found))  # gate findings no named row consumed
    return results


async def fetch_report(settings: Settings) -> DockerCapabilities:
    """Probe the docker daemon with the driver package's capability report."""
    configure_thread_limit(settings.docker_thread_limit, settings.docker_bulk_threads)
    client = make_client(max_pool_size=settings.docker_thread_limit)
    try:
        return await capability_report(client, runtime=default_tier_runtime(settings))
    finally:
        client.close()


async def fetch_probe(settings: Settings) -> list[str]:
    """Run the egress probe against the local daemon; a failure to run is itself a finding."""
    configure_thread_limit(settings.docker_thread_limit, settings.docker_bulk_threads)
    try:
        client = make_client(max_pool_size=settings.docker_thread_limit)
    except (DriverError, OSError) as exc:
        return [f"{PROBE_FINDING_PREFIX} could not run: {exc}"]
    deadline = startup_gate.EGRESS_PROBE_DEADLINE_S  # the startup gate's, pull included
    try:
        return await asyncio.wait_for(
            probe_findings(DockerCanaryRunner(client), settings.egress_probe_image), deadline
        )
    except TimeoutError:
        message = startup_gate.EGRESS_PROBE_TIMEOUT
        return [message.format(prefix=PROBE_FINDING_PREFIX, deadline=deadline)]
    finally:
        client.close()


async def fetch_host(settings: Settings) -> tuple[DockerCapabilities, list[str] | None]:
    """The capability report and, when the probe is enabled, its findings (one event loop)."""
    report = await fetch_report(settings)
    return report, (await fetch_probe(settings) if settings.egress_probe_enabled() else None)


def has_failure(results: Sequence[CheckResult]) -> bool:
    return any(result.status is Status.FAIL for result in results)


def render_text(results: Sequence[CheckResult], *, gate_line: bool = False) -> str:
    """One ``STATUS name: detail`` line per check, a summary, optionally the gate verdict."""
    lines = [f"{result.status.value} {result.name}: {result.detail}" for result in results]
    counts = {status: sum(1 for r in results if r.status is status) for status in Status}
    lines.append(
        f"summary: {counts[Status.PASS]} pass, {counts[Status.WARN]} warn,"
        f" {counts[Status.FAIL]} fail"
    )
    if gate_line:
        lines.append(gate_verdict(results))
    return "\n".join(lines)


def render_json(results: Sequence[CheckResult]) -> str:
    """``{"verdict": <gate verdict line>, "checks": [{name, status, detail}, ...]}``."""
    payload = {"verdict": gate_verdict(results), "checks": [asdict(r) for r in results]}
    return json.dumps(payload, indent=2)


def run_doctor(settings: Settings, *, as_json: bool, echo: Callable[[str], object]) -> int:
    """Probe, print and return the exit code: 0 without a FAIL, 1 otherwise.

    The text output ends with the gate verdict in prod; the JSON always carries it.
    """
    report: DockerCapabilities | None = None
    probe: list[str] | None = None
    error = ""
    try:
        report, probe = asyncio.run(fetch_host(settings))
    except (DriverError, OSError) as exc:
        error = f"cannot probe the docker daemon: {exc}"
    results = evaluate(settings, report, error, probe)
    prod = settings.environment == PROD_ENVIRONMENT
    echo(render_json(results) if as_json else render_text(results, gate_line=prod))
    return FAILURE_EXIT_CODE if has_failure(results) else 0
