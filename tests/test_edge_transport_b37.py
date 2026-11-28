"""B37: the example preview Ingress lifts the body limit.

The edge transport policy (TLS versions, HSTS, redirect, revocation) is written down."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
INGRESS = ROOT / "deploy" / "k8s" / "ingress.yaml"
OPERATIONS = ROOT / "docs" / "operations.md"
SECURITY = ROOT / "docs" / "security.md"
BODY_SIZE = "nginx.ingress.kubernetes.io/proxy-body-size"


def _ingresses() -> dict[str, dict[str, Any]]:
    docs = [d for d in yaml.safe_load_all(INGRESS.read_text(encoding="utf-8")) if d]
    return {d["metadata"]["name"]: d for d in docs if d["kind"] == "Ingress"}


def _transport_section() -> str:
    text = OPERATIONS.read_text(encoding="utf-8")
    after = text.split("### Edge transport policy", 1)[1]
    return after.split("\n## ", 1)[0]


def test_preview_ingress_raises_the_body_limit_to_512m() -> None:
    annotations = _ingresses()["sandfort-preview"]["metadata"]["annotations"]
    assert annotations.get(BODY_SIZE) == "512m"


def test_api_ingress_keeps_the_257m_upload_limit() -> None:
    annotations = _ingresses()["sandfort-api"]["metadata"]["annotations"]
    assert annotations.get(BODY_SIZE) == "257m"


def test_runbook_states_the_probed_transport_values() -> None:
    section = _transport_section()
    for fragment in (
        "ingress-nginx v1.13.3",
        "2026-11-27",
        "TLS 1.2 and TLS 1.3",
        "max-age=31536000; includeSubDomains",
        "308 Permanent Redirect",
        "OCSP",
        "CRL",
        "http://yr2.c.lencr.org/33.crl",
    ):
        assert fragment in section, fragment


def test_runbook_names_the_controller_keys_and_the_probes() -> None:
    section = _transport_section()
    for fragment in (
        "ssl-protocols",
        "hsts-max-age",
        "hsts-include-subdomains",
        "ssl-redirect",
        "curl -sI",
        "openssl s_client",
    ):
        assert fragment in section, fragment


def test_transport_subsection_stays_inside_the_tls_proxy_section() -> None:
    text = OPERATIONS.read_text(encoding="utf-8")
    section = text.split("## Behind a TLS-terminating proxy", 1)[1].split("\n## ", 1)[0]
    assert "### Edge transport policy" in section


def test_hardening_checklist_points_at_the_transport_section() -> None:
    text = SECURITY.read_text(encoding="utf-8")
    section = text.split("## 6. Operational hardening checklist", 1)[1].split("\n## ", 1)[0]
    assert "Edge transport policy" in section and "ssl-protocols" in section
