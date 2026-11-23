"""Prod start preflight: every configuration-level blocker, reported in one run.

``Settings.from_env`` validates the format of what is set; what a prod start still needs and
the operator has not provided is collected here, so one failed start lists all of it instead
of one blocker per attempt. ``prod_findings`` returns the findings (one message line each),
``check_preflight`` raises ``ConfigurationError`` carrying all of them. Checks that need the
running host (isolation capabilities, the egress probe) stay in ``sandfort.api.app``.
"""

from collections.abc import Iterable

from sandfort.config import ENV_PREFIX, PROD_ENVIRONMENT, SIGNING_WITHOUT_CHAIN_KEY, Settings

__all__ = [
    "FERNET_KEY_COMMAND",
    "UNGUARDED_HOST_MESSAGE",
    "WEBHOOK_KEY_MESSAGE",
    "ConfigurationError",
    "audit_key_findings",
    "check_preflight",
    "host_capacity_findings",
    "prod_findings",
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
    """A signing key without the chain key in prod; ``Settings.from_env`` refuses it as well.

    Settings built in code (constructor or ``replace``) skip ``from_env``, so the same refusal
    is repeated here and the doctor's FAIL equals the start gate's refusal on every path.
    """
    if settings.environment != PROD_ENVIRONMENT:
        return []
    if settings.audit_signing_key.strip() and not settings.audit_chain_key.strip():
        return [SIGNING_WITHOUT_CHAIN_KEY]
    return []


def prod_findings(settings: Settings) -> list[str]:
    """Every configuration-level prod finding; empty outside prod and for a ready config."""
    return [
        *webhook_key_findings(settings),
        *host_capacity_findings(settings),
        *audit_key_findings(settings),
    ]


def check_preflight(settings: Settings) -> None:
    """Raise ``ConfigurationError`` with all findings when the prod configuration is unready."""
    findings = prod_findings(settings)
    if findings:
        raise ConfigurationError(findings)
