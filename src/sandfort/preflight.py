"""Prod start preflight: every configuration-level blocker, reported in one run.

``Settings.from_env`` validates the format of what is set; what a prod start still needs and
the operator has not provided is collected here, so one failed start lists all of it instead
of one blocker per attempt. ``prod_findings`` returns the findings (one message line each),
``check_preflight`` raises ``ConfigurationError`` carrying all of them. Checks that need the
running host (isolation capabilities, the egress probe) stay in ``sandfort.api.app``.
"""

from collections.abc import Iterable

from sandfort.config import (
    ENV_PREFIX,
    PROD_ENVIRONMENT,
    SIGNING_WITHOUT_CHAIN_KEY,
    Settings,
    check_tier_families,
)

__all__ = [
    "DEFAULT_RUNTIME_TIER_MESSAGE",
    "FERNET_KEY_COMMAND",
    "UNGUARDED_HOST_MESSAGE",
    "UNKEYED_AUDIT_CHAIN_MESSAGE",
    "WEBHOOK_KEY_MESSAGE",
    "ConfigurationError",
    "audit_key_findings",
    "check_preflight",
    "host_capacity_findings",
    "prod_findings",
    "tier_runtime_findings",
    "webhook_key_findings",
]

FERNET_KEY_COMMAND = (
    "python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
)
WEBHOOK_KEY_MESSAGE = (
    f"prod requires {ENV_PREFIX}WEBHOOK_SECRET_KEY so webhook secrets are encrypted at rest;"
    " it is a urlsafe base64 fernet key, generate one with: " + FERNET_KEY_COMMAND
)
UNGUARDED_HOST_MESSAGE = (
    "host capacity is not configured: prod requires SANDFORT_HOST_CAPACITY_CPU_MILLICORES and"
    " SANDFORT_HOST_CAPACITY_MEMORY_MIB (both above zero) so admission can refuse an over-full"
    " host; set SANDFORT_ALLOW_UNBOUNDED_HOST=true to start without a host-wide limit"
)
UNKEYED_AUDIT_CHAIN_MESSAGE = (
    "the audit chain key is unset: the chain is an unkeyed sha256 that anyone who can write the"
    " database can rewrite consistently; set SANDFORT_AUDIT_CHAIN_KEY (at least 32 bytes; rows"
    " written before the key stay verifiable while SANDFORT_AUDIT_CHAIN_ACCEPT_UNKEYED is true)"
    " or set SANDFORT_UNKEYED_AUDIT_CHAIN_ACKNOWLEDGED=true to start without one"
)
DEFAULT_RUNTIME_TIER_MESSAGE = (
    "tier mapping: tiers {tiers} map to an empty runtime, so they run on whatever the daemon"
    " default runtime is (runc, or runsc when the daemon default-runtime is runsc); name the"
    " runtime in SANDFORT_ISOLATION_RUNTIMES (for example container=runc) or set"
    " SANDFORT_ALLOW_DEFAULT_RUNTIME_TIER=true to accept the daemon default"
)


class ConfigurationError(ValueError):
    """A start was refused for configuration: ``findings`` holds every blocker, one line each."""

    def __init__(self, findings: Iterable[str]) -> None:
        self.findings = tuple(findings)
        super().__init__("\n".join(self.findings))


def webhook_key_findings(settings: Settings) -> list[str]:
    """The missing webhook secret key in prod; the format of a set key is checked on load."""
    if settings.environment != PROD_ENVIRONMENT or settings.webhook_secret_key.strip():
        return []
    return [WEBHOOK_KEY_MESSAGE]


def host_capacity_findings(settings: Settings) -> list[str]:
    """Unconfigured host capacity in prod (zero means unguarded), unless explicitly allowed."""
    if settings.environment != PROD_ENVIRONMENT or settings.allow_unbounded_host:
        return []
    if settings.host_capacity_cpu_millicores > 0 and settings.host_capacity_memory_mib > 0:
        return []
    return [UNGUARDED_HOST_MESSAGE]


def audit_key_findings(settings: Settings) -> list[str]:
    """The prod audit key blockers: a signing key without the chain key, or neither key.

    A signing key without the chain key is also refused by ``Settings.from_env``; settings built
    in code (constructor or ``replace``) skip ``from_env``, so the refusal is repeated here and
    the doctor's FAIL equals the start gate's refusal on every path. Neither key leaves the
    chain an unkeyed hash: ``from_env`` only warns and the refusal lives here, unless the
    operator set ``unkeyed_audit_chain_acknowledged``.
    """
    if settings.environment != PROD_ENVIRONMENT or settings.audit_chain_key.strip():
        return []
    if settings.audit_signing_key.strip():
        return [SIGNING_WITHOUT_CHAIN_KEY]
    if settings.unkeyed_audit_chain_acknowledged:
        return []
    return [UNKEYED_AUDIT_CHAIN_MESSAGE]


def tier_runtime_findings(settings: Settings) -> list[str]:
    """Prod tiers that run on the daemon default runtime, unless that is acknowledged.

    The family check runs first (it also covers settings built in code, which skip
    ``from_env``), so a blank gvisor or microvm runtime surfaces as that error. Legacy
    single-runtime mode and the no-map default are deliberately not flagged.
    """
    if settings.environment != PROD_ENVIRONMENT:
        return []
    tiers = settings.isolation_tiers()
    try:
        check_tier_families(tiers)
    except ValueError as exc:
        return [str(exc)]
    if settings.allow_default_runtime_tier or not settings.isolation_runtimes:
        return []
    empty = sorted(tier for tier, runtime in tiers.items() if not runtime.strip())
    if empty:
        return [DEFAULT_RUNTIME_TIER_MESSAGE.format(tiers=empty)]
    return []


def prod_findings(settings: Settings) -> list[str]:
    """Every configuration-level prod finding; empty outside prod and for a ready config."""
    return [
        *webhook_key_findings(settings),
        *host_capacity_findings(settings),
        *audit_key_findings(settings),
        *tier_runtime_findings(settings),
    ]


def check_preflight(settings: Settings) -> None:
    """Raise ``ConfigurationError`` with all findings when the prod configuration is unready."""
    findings = prod_findings(settings)
    if findings:
        raise ConfigurationError(findings)
