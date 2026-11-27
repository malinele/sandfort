"""Egress decision counters: catalog, classification and failure isolation (backlog B21).

Hermetic: no sockets. The classifier is also checked against every refusal the egress package
can raise, found by reading its source, so a new refusal without a reason class fails here.
"""

import asyncio
import logging
import re
from pathlib import Path

import pytest

from sandfort.egress.admission import POLICY_UNAVAILABLE
from sandfort.egress.metrics import (
    _BY_DETAIL,
    CAP_HITS_TOTAL,
    CAP_SCOPES,
    CLIENT_CLOSED_DETAIL,
    DECISIONS_TOTAL,
    DENY_STATUSES,
    EGRESS_METRIC_NAMES,
    POLICY_UNAVAILABLE_DETAIL,
    REASON_CLASSES,
    EgressMetrics,
    classify,
)
from sandfort.egress.relay import Deny, read_request
from sandfort.observability.metrics import METRIC_NAMES

EGRESS_DIR = Path(__file__).resolve().parents[1] / "src" / "sandfort" / "egress"
RELAY_SOURCE = EGRESS_DIR / "relay.py"
CLIENT_CLOSED = Deny(400, "Bad Request", CLIENT_CLOSED_DETAIL)
MALFORMED_LABELS = {"decision": "deny", "status": "400", "reason_class": "malformed"}
DENY_SITE = re.compile(r'Deny\((\d{3}), "[^"]*", f?"([^"]*)"')
AUTH_SITE = re.compile(r'auth_required\("([^"]+)"\)')
PLACEHOLDER = re.compile(r"\{[^}]*\}")
MIN_DENY_SITES = 31
METHOD_DENY = Deny(405, "Method Not Allowed", "method is not CONNECT")
DENY_LABELS = {"decision": "deny", "status": "405", "reason_class": "method"}
DROP_LABELS = {"decision": "drop", "status": "none", "reason_class": "connection_error"}
OTHER_OTHER = {"decision": "deny", "status": "other", "reason_class": "other"}
FORBIDDEN_OTHER = {"decision": "deny", "status": "403", "reason_class": "other"}


class _Raising:
    def labels(self, *args: str, **kwargs: str) -> object:
        raise RuntimeError("boom")


def test_the_catalog_is_exactly_the_two_egress_counters() -> None:
    m = EgressMetrics()
    m.allowed()
    m.denied(METHOD_DENY)

    text = m.render().decode()

    assert EGRESS_METRIC_NAMES == {
        "sandfort_egress_decisions_total",
        "sandfort_egress_connection_cap_hits_total",
    }
    assert set(re.findall(r"^# TYPE (\S+)", text, re.MULTILINE)) == EGRESS_METRIC_NAMES
    assert "_created" not in text


def test_the_api_catalog_does_not_gain_the_egress_counters() -> None:
    assert METRIC_NAMES.isdisjoint(EGRESS_METRIC_NAMES)


@pytest.mark.parametrize(
    ("status", "detail", "expected"),
    [
        (407, "no credential", "credential"),
        (407, "credential is not basic", "credential"),
        (407, "credential is not decodable", "credential"),
        (407, "credential has no password", "credential"),
        (407, "invalid token", "credential"),
        (407, "username does not match the token", "credential"),
        (407, "credential epoch mismatch", "credential_stale"),
        (407, "v1 token superseded", "credential_stale"),
        (407, "no policy for sandbox", "policy_missing"),
        (403, "address is not in the allowlist", "allowlist"),
        (403, "host is not in the allowlist", "allowlist"),
        (403, "blocked address: translation prefix", "blocked_address"),
        (403, "blocked address: anything at all", "blocked_address"),
        (403, "port 25 is not allowed", "port"),
        (429, "too many unauthenticated connections", "cap_source"),
        (429, "too many concurrent connections for sandbox", "cap_sandbox"),
        (503, "global connection ceiling reached", "cap_global"),
        (503, "egress policy unavailable", "policy_unavailable"),
        (502, "host does not resolve", "resolve"),
        (502, "resolver returned a non-address", "resolve"),
        (502, "upstream connection failed", "upstream"),
        (400, "malformed request line", "malformed"),
        (431, "too many header lines", "malformed"),
        (405, "method is not CONNECT", "method"),
    ],
)
def test_classify_maps_each_known_refusal(status: int, detail: str, expected: str) -> None:
    assert classify(Deny(status, "Reason", detail)) == expected


def _deny_sites() -> list[tuple[int, str]]:
    sites: list[tuple[int, str]] = []
    for path in sorted(EGRESS_DIR.glob("*.py")):
        if path.name == "metrics_listener.py":  # its refusals answer a scrape, not a CONNECT
            continue
        text = path.read_text(encoding="utf-8")
        sites.extend((int(s), PLACEHOLDER.sub("1", d)) for s, d in DENY_SITE.findall(text))
        sites.extend((407, PLACEHOLDER.sub("1", d)) for d in AUTH_SITE.findall(text))
    return sites


def test_every_deny_site_in_the_egress_package_has_a_reason_class() -> None:
    sites = _deny_sites()

    assert len(sites) >= MIN_DENY_SITES
    unclassified = [site for site in sites if classify(Deny(site[0], "R", site[1])) == "other"]
    assert unclassified == []


def test_policy_unavailable_detail_matches_admission() -> None:
    assert POLICY_UNAVAILABLE_DETAIL == POLICY_UNAVAILABLE


def test_unknown_refusals_stay_bounded() -> None:
    m = EgressMetrics()

    m.denied(Deny(418, "I am a teapot", "teapot"))
    m.denied(Deny(403, "Forbidden", "new reason"))

    assert m.value(DECISIONS_TOTAL, OTHER_OTHER) == 1.0
    assert m.value(DECISIONS_TOTAL, FORBIDDEN_OTHER) == 1.0
    allowed_values = (
        {str(status) for status in DENY_STATUSES}
        | {"200", "none", "other"}
        | REASON_CLASSES
        | {"allow", "deny", "drop"}
        | set(CAP_SCOPES.values())
    )
    for family in m.registry.collect():
        for sample in family.samples:
            assert set(sample.labels.values()) <= allowed_values


def test_a_drop_counts_only_before_a_tunnel_was_admitted() -> None:
    m = EgressMetrics()

    m.dropped(admitted=True)
    assert m.value(DECISIONS_TOTAL, DROP_LABELS) == 0.0

    m.dropped(admitted=False)
    assert m.value(DECISIONS_TOTAL, DROP_LABELS) == 1.0


def test_cap_refusals_also_count_a_cap_hit_by_scope() -> None:
    m = EgressMetrics()

    m.denied(Deny(429, "Too Many Requests", "too many concurrent connections for sandbox"))
    m.denied(Deny(429, "Too Many Requests", "too many unauthenticated connections"))
    m.denied(Deny(503, "Service Unavailable", "global connection ceiling reached"))
    m.denied(Deny(403, "Forbidden", "host is not in the allowlist"))

    for scope in ("sandbox", "source", "global"):
        assert m.value(CAP_HITS_TOTAL, {"scope": scope}) == 1.0


def test_two_instances_keep_separate_counts() -> None:
    first, second = EgressMetrics(), EgressMetrics()

    first.denied(METHOD_DENY)

    assert first.value(DECISIONS_TOTAL, DENY_LABELS) == 1.0
    assert second.value(DECISIONS_TOTAL, DENY_LABELS) == 0.0


def test_a_failing_counter_never_raises_and_warns_once(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")
    m = EgressMetrics()
    monkeypatch.setattr(m, "_decisions", _Raising())

    m.allowed()
    m.denied(METHOD_DENY)
    m.dropped(admitted=False)

    assert m.failures == 3
    warnings = [msg for msg in caplog.messages if msg.startswith("egress metrics failed")]
    assert len(warnings) == 1


def test_the_client_closed_detail_is_the_string_relay_raises() -> None:
    assert f'"{CLIENT_CLOSED_DETAIL}"' in RELAY_SOURCE.read_text(encoding="utf-8")


async def test_read_request_raises_that_detail_when_the_client_closes_early() -> None:
    reader = asyncio.StreamReader()
    reader.feed_data(b"CONNECT upstream.test:443 HTTP/1.1\r\nHost: x\r\n")
    reader.feed_eof()

    with pytest.raises(Deny) as raised:
        await read_request(reader)

    assert raised.value.status == 400
    assert raised.value.detail == CLIENT_CLOSED_DETAIL


def test_a_client_that_closed_before_a_full_request_is_a_drop_not_a_deny() -> None:
    m = EgressMetrics()

    m.denied(CLIENT_CLOSED)

    assert m.value(DECISIONS_TOTAL, DROP_LABELS) == 1.0
    assert m.value(DECISIONS_TOTAL, MALFORMED_LABELS) == 0.0
    assert m.value(CAP_HITS_TOTAL, {"scope": "sandbox"}) == 0.0


def test_other_400_refusals_stay_malformed() -> None:
    m = EgressMetrics()

    m.denied(Deny(400, "Bad Request", "malformed request line"))
    m.denied(Deny(400, "Bad Request", "request line or header too long"))

    assert m.value(DECISIONS_TOTAL, MALFORMED_LABELS) == 2.0
    assert m.value(DECISIONS_TOTAL, DROP_LABELS) == 0.0


def test_the_drop_for_a_closed_client_survives_a_failing_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    m = EgressMetrics()
    monkeypatch.setattr(m, "_decisions", _Raising())

    m.denied(CLIENT_CLOSED)

    assert m.failures == 1


@pytest.mark.parametrize(("key", "reason_class"), sorted(_BY_DETAIL.items()))
def test_each_known_refusal_exports_its_exact_status_label(
    key: tuple[int, str], reason_class: str
) -> None:
    status, detail = key
    m = EgressMetrics()

    m.denied(Deny(status, "Reason", detail))

    labels = {"decision": "deny", "status": str(status), "reason_class": reason_class}
    assert m.value(DECISIONS_TOTAL, labels) == 1.0


@pytest.mark.parametrize(
    ("status", "detail", "reason_class"),
    [
        (403, "port 25 is not allowed", "port"),
        (400, "malformed request line", "malformed"),
        (431, "too many header lines", "malformed"),
        (405, "method is not CONNECT", "method"),
    ],
)
def test_the_other_refusals_export_their_exact_status_label(
    status: int, detail: str, reason_class: str
) -> None:
    m = EgressMetrics()

    m.denied(Deny(status, "Reason", detail))

    labels = {"decision": "deny", "status": str(status), "reason_class": reason_class}
    assert m.value(DECISIONS_TOTAL, labels) == 1.0
