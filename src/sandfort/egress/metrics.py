"""Decision counters for the egress proxy process (backlog B21).

Two counters, in a registry of their own: ``sandfort_egress_decisions_total`` counts every answer
to a CONNECT (``decision`` allow, deny or drop, the http ``status``, and a ``reason_class``), and
``sandfort_egress_connection_cap_hits_total`` counts the refusals that hit a connection cap, by
``scope``. Label values come from the constants below and nowhere else: no sandbox id, org id,
host name, address, token or digest is ever a label, and a refusal this module does not know is
counted as ``other``. The proxy is a separate process, so these counters are not part of the
api's ``/metrics`` catalog (``sandfort.observability.metrics``, which this module must not import:
it pulls in the database layer).

Counting is synchronous and never raises: a failing counter is tallied in ``failures`` and logged
once, and the connection it was counting is answered as before.
"""

import logging
from collections.abc import Mapping
from typing import Final

from prometheus_client import CollectorRegistry, Counter, disable_created_metrics, generate_latest

from sandfort.egress.relay import Deny

DECISIONS_TOTAL: Final = "sandfort_egress_decisions_total"
CAP_HITS_TOTAL: Final = "sandfort_egress_connection_cap_hits_total"
EGRESS_METRIC_NAMES: Final = frozenset({DECISIONS_TOTAL, CAP_HITS_TOTAL})

ALLOW: Final = "allow"
DENY: Final = "deny"
DROP: Final = "drop"
STATUS_ALLOW: Final = "200"
STATUS_NONE: Final = "none"  # a drop has no http status: nothing was answered
OTHER: Final = "other"
CLASS_ALLOWED: Final = "allowed"
CLASS_DROP: Final = "connection_error"
DENY_STATUSES: Final = frozenset({400, 403, 405, 407, 429, 431, 502, 503})
REASON_CLASSES: Final = frozenset(
    {
        "allowed",
        "connection_error",
        "malformed",
        "method",
        "credential",
        "credential_stale",
        "policy_missing",
        "port",
        "allowlist",
        "blocked_address",
        "cap_sandbox",
        "cap_source",
        "cap_global",
        "policy_unavailable",
        "resolve",
        "upstream",
        "other",
    }
)
CAP_SCOPES: Final[Mapping[str, str]] = {
    "cap_sandbox": "sandbox",
    "cap_source": "source",
    "cap_global": "global",
}
POLICY_UNAVAILABLE_DETAIL: Final = "egress policy unavailable"  # == admission.POLICY_UNAVAILABLE
# == the detail relay._read_line raises on an end of stream (relay cannot import this module)
CLIENT_CLOSED_DETAIL: Final = "connection closed before the request was complete"

# (status, detail before the first colon) -> reason class. The raw head is used on purpose: the
# deny log's ``reason_of`` folds digits, which would turn "v1 token superseded" into "v# ...".
_BY_DETAIL: Final[Mapping[tuple[int, str], str]] = {
    (407, "no credential"): "credential",
    (407, "credential is not basic"): "credential",
    (407, "credential is not decodable"): "credential",
    (407, "credential has no password"): "credential",
    (407, "invalid token"): "credential",
    (407, "username does not match the token"): "credential",
    (407, "credential epoch mismatch"): "credential_stale",
    (407, "v1 token superseded"): "credential_stale",
    (407, "no policy for sandbox"): "policy_missing",
    (403, "address is not in the allowlist"): "allowlist",
    (403, "host is not in the allowlist"): "allowlist",
    (403, "blocked address"): "blocked_address",
    (429, "too many unauthenticated connections"): "cap_source",
    (429, "too many concurrent connections for sandbox"): "cap_sandbox",
    (503, "global connection ceiling reached"): "cap_global",
    (503, POLICY_UNAVAILABLE_DETAIL): "policy_unavailable",
    (502, "host does not resolve"): "resolve",
    (502, "resolver returned a non-address"): "resolve",
    (502, "upstream connection failed"): "upstream",
}
_BY_STATUS: Final[Mapping[int, str]] = {400: "malformed", 431: "malformed", 405: "method"}

_log = logging.getLogger("sandfort.egress")

# Keeps the exposition to exactly the two counters (the library function is unannotated).
disable_created_metrics()  # type: ignore[no-untyped-call]


def status_label(status: int) -> str:
    """The status as a label value; a status the proxy never sends is ``other``."""
    return str(status) if status in DENY_STATUSES else OTHER


def closed_early(deny: Deny) -> bool:
    """Whether the client closed before it sent a full request (counted as a drop, not a deny)."""
    head = deny.detail.partition(":")[0].strip()
    return deny.status == 400 and head == CLIENT_CLOSED_DETAIL


def classify(deny: Deny) -> str:
    """The bounded reason class of a refusal, from its status and the start of its detail."""
    head = deny.detail.partition(":")[0].strip()
    known = _BY_DETAIL.get((deny.status, head))
    if known is not None:
        return known
    if deny.status == 403 and head.startswith("port ") and head.endswith(" is not allowed"):
        return "port"
    return _BY_STATUS.get(deny.status, OTHER)


class EgressMetrics:
    """The proxy's counters. Every method is synchronous and swallows its own failures."""

    def __init__(self) -> None:
        self.registry = CollectorRegistry(auto_describe=True)
        self._decisions = Counter(
            DECISIONS_TOTAL,
            "Egress proxy answers by decision, status and reason class.",
            labelnames=("decision", "status", "reason_class"),
            registry=self.registry,
        )
        self._cap_hits = Counter(
            CAP_HITS_TOTAL,
            "Egress connection-cap refusals by scope.",
            labelnames=("scope",),
            registry=self.registry,
        )
        self.failures = 0

    def allowed(self) -> None:
        """Count a tunnel that was admitted (the 200 is about to be written)."""
        try:
            self._decisions.labels(ALLOW, STATUS_ALLOW, CLASS_ALLOWED).inc()
        except Exception as exc:
            self._failed(exc)

    def denied(self, deny: Deny) -> None:
        """Count a refusal; a connection-cap refusal is also counted by scope.

        A client that closed before a full request is a drop, not a refusal: it was never read,
        so a port probe or a hung-up client does not count as a ``malformed`` request.
        """
        try:
            if closed_early(deny):
                self._decisions.labels(DROP, STATUS_NONE, CLASS_DROP).inc()
                return
            reason_class = classify(deny)
            self._decisions.labels(DENY, status_label(deny.status), reason_class).inc()
            scope = CAP_SCOPES.get(reason_class)
            if scope is not None:
                self._cap_hits.labels(scope).inc()
        except Exception as exc:
            self._failed(exc)

    def dropped(self, *, admitted: bool) -> None:
        """Count a connection that ended in an I/O error or timeout before any answer.

        With ``admitted`` (a tunnel was already open) the error is a tunnel ending, not a
        decision, so nothing is counted.
        """
        try:
            if not admitted:
                self._decisions.labels(DROP, STATUS_NONE, CLASS_DROP).inc()
        except Exception as exc:
            self._failed(exc)

    def value(self, name: str, labels: Mapping[str, str]) -> float:
        """The current value of one sample, ``0.0`` when it was never counted."""
        sample = self.registry.get_sample_value(name, dict(labels))
        return 0.0 if sample is None else sample

    def render(self) -> bytes:
        """The Prometheus text exposition of both counters."""
        return generate_latest(self.registry)

    def _failed(self, exc: Exception) -> None:
        self.failures += 1
        if self.failures == 1:
            _log.warning("egress metrics failed, counts are incomplete: %s", type(exc).__name__)
