"""Doctor row types and the rows that mirror the start gate's own findings.

``Findings`` pairs the gate's findings with the advisory ones and records which of the gate's
were consumed by a named row, so ``catch_all_rows`` can turn every other gate finding into its
own row and nothing is reported twice. The configuration rows (webhook key, host capacity) take
their wording from ``sandfort.preflight``, the module the start gate itself uses.
"""

import base64
import hashlib
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from sandfort.audit_signing import AUDIT_SIGNING_KEY_ENV
from sandfort.config import (
    AUDIT_CHAIN_KEY_ENV,
    ENV_PREFIX,
    PROD_ENVIRONMENT,
    SIGNING_WITHOUT_CHAIN_KEY,
    Settings,
)
from sandfort.drivers.docker.capabilities import DockerCapabilities, root_on_host_tiers
from sandfort.preflight import (
    audit_key_findings,
    host_capacity_findings,
    tier_runtime_findings,
    webhook_key_findings,
)

QUOTA_PREFIX = "disk quota support"  # the prefix the startup gate also keys on
ROOT_PREFIX = "root on a shared kernel"
ROOT_ROW = "root on shared kernel"
ROOT_OVERRIDE = f"{ENV_PREFIX}ALLOW_ROOT_SHARED_KERNEL"
UNBOUNDED_OVERRIDE = f"{ENV_PREFIX}ALLOW_UNBOUNDED_HOST"
WEBHOOK_KEY_VAR = f"{ENV_PREFIX}WEBHOOK_SECRET_KEY"
CPU_VAR = f"{ENV_PREFIX}HOST_CAPACITY_CPU_MILLICORES"
MEMORY_VAR = f"{ENV_PREFIX}HOST_CAPACITY_MEMORY_MIB"
AUDIT_KEYS_ROW = "audit keys"
TIER_RUNTIMES_ROW = "tier runtimes"
DEFAULT_RUNTIME_VAR = f"{ENV_PREFIX}ALLOW_DEFAULT_RUNTIME_TIER"
FINGERPRINT_CHARS = 16  # hex characters of sha256(raw public key), as the CLI prints
GATE_REFUSES = "the start gate would refuse: {count} failing check(s)"
GATE_STARTS = "the start gate would start"


class Status(StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    status: Status
    detail: str


def gate_status(settings: Settings, finding: str) -> Status:
    """How the startup gate treats ``finding``: refuses the start (FAIL) or only logs (WARN)."""
    if settings.environment == PROD_ENVIRONMENT:
        return Status.FAIL
    if settings.enforce_disk_quota and finding.startswith(QUOTA_PREFIX):
        return Status.FAIL
    return Status.WARN


@dataclass(frozen=True, slots=True)
class Findings:
    settings: Settings
    gate: list[str]
    advisory: list[str]
    consumed: set[str] = field(default_factory=set)

    def consume(self, findings: Iterable[str]) -> None:
        """Mark gate findings as reported by a named row."""
        self.consumed.update(findings)

    def judge(
        self, name: str, match: Callable[[str], bool], ok: str, bad: str | None = None
    ) -> CheckResult:
        """PASS with ``ok`` unless a gate or advisory finding matches (then ``bad`` or it)."""
        gate_hits = [finding for finding in self.gate if match(finding)]
        if gate_hits:
            self.consume(gate_hits)
            return CheckResult(name, gate_status(self.settings, gate_hits[0]), bad or gate_hits[0])
        advisory_hit = next((finding for finding in self.advisory if match(finding)), None)
        if advisory_hit is not None:
            return CheckResult(name, Status.WARN, bad or advisory_hit)
        return CheckResult(name, Status.PASS, ok)


def root_row(found: Findings, report: DockerCapabilities) -> CheckResult:
    """Root on a shared kernel: the gate's finding, or PASS naming the override that accepts it."""
    ok = "no tier runs container root as host root"
    row = found.judge(ROOT_ROW, lambda finding: finding.startswith(ROOT_PREFIX), ok)
    tiers = root_on_host_tiers(report, found.settings)
    if row.status is Status.PASS and tiers and found.settings.allow_root_shared_kernel:
        detail = f"tiers {sorted(tiers)} run root on a shared kernel; accepted by {ROOT_OVERRIDE}"
        return CheckResult(ROOT_ROW, Status.PASS, detail)
    return row


def webhook_row(settings: Settings) -> CheckResult:
    name = "webhook secret"
    if settings.webhook_secret_key.strip():
        return CheckResult(name, Status.PASS, f"{WEBHOOK_KEY_VAR} is set")
    empty = f"{WEBHOOK_KEY_VAR} is empty"
    preflight = webhook_key_findings(settings)
    if preflight:
        return CheckResult(name, Status.FAIL, f"{empty}; {preflight[0]}")
    return CheckResult(name, Status.WARN, empty)


def key_fingerprint(public_key: str) -> str:
    """The first 16 hex characters of sha256 over the raw public key (the CLI's fingerprint)."""
    text = public_key.strip()
    raw = base64.b64decode((text + "=" * (-len(text) % 4)).encode("ascii"), altchars=b"-_")
    return hashlib.sha256(raw).hexdigest()[:FINGERPRINT_CHARS]


def audit_keys_row(settings: Settings) -> CheckResult:
    """The audit chain key and the head signing key together; never prints key material.

    Signing needs the chain key. A signing key alone is a FAIL only where the start refuses it
    (prod, the same ``audit_key_findings`` the preflight uses, so the verdict line is true); in
    dev and test the server starts with a warning, so the row is a WARN with the same detail.
    A malformed signing key is a FAIL everywhere (the settings load refuses it). A blank signing
    key counts as unset. Neither key is a FAIL in prod unless the unkeyed chain is acknowledged
    (again the preflight's own finding) and a WARN elsewhere. The chain key alone only warns.
    """
    chain = bool(settings.audit_chain_key.strip())
    try:
        signer = settings.audit_signer()  # None for a blank key
    except ValueError as exc:
        return CheckResult(AUDIT_KEYS_ROW, Status.FAIL, str(exc))
    if signer is not None and not chain:
        refused = bool(audit_key_findings(settings))
        status = Status.FAIL if refused else Status.WARN
        return CheckResult(AUDIT_KEYS_ROW, status, SIGNING_WITHOUT_CHAIN_KEY)
    if signer is not None:
        fingerprint = key_fingerprint(signer.public_key)
        detail = f"audit heads are signed; signing key fingerprint {fingerprint}"
        return CheckResult(AUDIT_KEYS_ROW, Status.PASS, detail)
    if chain:
        detail = f"exports are HMAC-chained but unsigned: {AUDIT_SIGNING_KEY_ENV} is not set"
        return CheckResult(AUDIT_KEYS_ROW, Status.WARN, detail)
    refusal = audit_key_findings(settings)  # prod, neither key, not acknowledged
    if refusal:
        return CheckResult(AUDIT_KEYS_ROW, Status.FAIL, refusal[0])
    detail = (
        f"{AUDIT_CHAIN_KEY_ENV} and {AUDIT_SIGNING_KEY_ENV} are not set: the audit chain is an"
        " unkeyed hash and exports are unsigned"
    )
    return CheckResult(AUDIT_KEYS_ROW, Status.WARN, detail)


def capacity_row(settings: Settings) -> CheckResult:
    name = "host capacity"
    cpu, memory = settings.host_capacity_cpu_millicores, settings.host_capacity_memory_mib
    blockers = host_capacity_findings(settings)
    if blockers:
        return CheckResult(name, Status.FAIL, blockers[0])
    if cpu > 0 and memory > 0:
        return CheckResult(name, Status.PASS, f"{cpu} millicores cpu, {memory} MiB memory")
    if settings.environment == PROD_ENVIRONMENT:
        unset = [var for var, value in ((CPU_VAR, cpu), (MEMORY_VAR, memory)) if value <= 0]
        if len(unset) == 1:
            detail = f"{unset[0]} is not set; accepted by {UNBOUNDED_OVERRIDE}=true"
        else:
            detail = f"no host-wide limit; accepted by {UNBOUNDED_OVERRIDE}=true"
        return CheckResult(name, Status.PASS, detail)
    detail = "not configured: admission has no host-wide limit (prod requires it)"
    return CheckResult(name, Status.WARN, detail)


def tier_runtime_row(settings: Settings) -> CheckResult:
    """Tiers mapped to an empty runtime: the preflight's finding, or PASS (never a WARN).

    A prod map that leaves tiers blank is refused by ``tier_runtime_findings`` unless
    ``allow_default_runtime_tier`` accepts the daemon default; the row mirrors that verdict.
    """
    findings = tier_runtime_findings(settings)
    if findings:
        return CheckResult(TIER_RUNTIMES_ROW, Status.FAIL, findings[0])
    if not settings.isolation_runtimes:
        return CheckResult(TIER_RUNTIMES_ROW, Status.PASS, "single-runtime mode: no tier map")
    tiers = settings.isolation_tiers()
    blank = sorted(tier for tier, runtime in tiers.items() if not runtime.strip())
    if settings.environment == PROD_ENVIRONMENT and blank:
        detail = (
            f"tiers {blank} run on the daemon default runtime; accepted by {DEFAULT_RUNTIME_VAR}"
        )
        return CheckResult(TIER_RUNTIMES_ROW, Status.PASS, detail)
    listed = ", ".join(f"{tier}={runtime}" for tier, runtime in tiers.items())
    return CheckResult(TIER_RUNTIMES_ROW, Status.PASS, f"tiers: {listed}")


def catch_all_rows(found: Findings) -> list[CheckResult]:
    """One row per gate finding no named row consumed, named from the text before the colon."""
    rows: list[CheckResult] = []
    for finding in found.gate:
        if finding in found.consumed:
            continue
        found.consume([finding])
        name = finding.split(":", 1)[0].strip() or finding
        rows.append(CheckResult(name, gate_status(found.settings, finding), finding))
    return rows


def gate_verdict(results: Sequence[CheckResult]) -> str:
    """The verdict line: it counts the FAIL rows, and any of them means the gate refuses."""
    failures = sum(1 for result in results if result.status is Status.FAIL)
    return GATE_REFUSES.format(count=failures) if failures else GATE_STARTS
