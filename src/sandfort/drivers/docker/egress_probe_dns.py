"""Egress probe, DNS part (egress v2 design 6.2): a runc canary must not resolve a public name.

On the ``container`` tier Docker's embedded resolver forwards external names to the host's
upstream servers unless ``build_host_config`` points it at the DNS sink. The canary mirrors a
sandbox (egress net, ``dns=[sink]``) and runs ``getent hosts`` for a fixed public name. An
answer is a finding, which is the probe's existing "any success is a finding" rule.

Positive controls come first: ``getent`` exists (``READY``) and resolves a name from the
canary's own ``/etc/hosts`` (``LOCAL OK``), so a broken resolver tool cannot make every name
look refused. A missing marker or a non-zero exit means the canary could not run, never a pass.
The probe name is a constant, so no sandbox data reaches the sink or the logs.

This module does not import ``egress_probe`` (which imports it); ``DockerCanaryRunner`` there
runs the container and turns ``DnsCanaryError`` into ``EgressProbeError``.
"""

from typing import Protocol, TypeGuard, runtime_checkable

DNS_PROBE_NAME = "example.com"
LOCAL_NAME = "localhost"
READY_MARK = "READY"
LOCAL_MARK = "LOCAL OK"
RESOLVED_MARK = "RESOLVED"
MISSING_TOOL_STATUS = 3  # the canary's exit status when getent is missing
DNS_FINDING = (
    "{prefix}: a runc canary on {network} resolved a public name"
    " (expected no answer: the container-tier resolver forwards outside the host)"
)
DNS_CANARY_SCRIPT = (
    f"command -v getent >/dev/null 2>&1 || exit {MISSING_TOOL_STATUS}; echo {READY_MARK};"
    f" getent hosts {LOCAL_NAME} >/dev/null 2>&1 && echo '{LOCAL_MARK}';"
    f" getent hosts {DNS_PROBE_NAME} >/dev/null 2>&1 && echo {RESOLVED_MARK}; exit 0"
)


class DnsCanaryError(RuntimeError):
    """The DNS canary could not run; never read as a pass."""


@runtime_checkable
class DnsCanaryRunner(Protocol):
    """An optional extension of ``CanaryRunner``; runners without it skip the DNS check."""

    dns_sink: str  # the configured sink address; "" = no sink, so no DNS check

    async def resolves(self, network: str, image: str) -> bool:
        """Run one canary on ``network`` with the sink as its resolver; did it get an answer?"""
        ...


def parse_dns_canary(output: str, status: int) -> bool:
    """Whether the canary resolved the public name; ``DnsCanaryError`` when it did not run."""
    if status == MISSING_TOOL_STATUS:
        raise DnsCanaryError(f"canary exited with status {status}: getent is missing")
    if status != 0:
        raise DnsCanaryError(f"canary exited with status {status}")
    lines = {line.strip() for line in output.splitlines()}
    if READY_MARK not in lines:
        raise DnsCanaryError(f"canary did not print {READY_MARK}")
    if LOCAL_MARK not in lines:
        raise DnsCanaryError(f"canary did not print {LOCAL_MARK}: getent cannot resolve")
    return RESOLVED_MARK in lines


def dns_check_enabled(runner: object) -> TypeGuard[DnsCanaryRunner]:
    """True for a runner that offers the DNS canary and has a sink to mirror."""
    return isinstance(runner, DnsCanaryRunner) and bool(runner.dns_sink)
