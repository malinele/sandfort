"""The example Ingress keeps token-bearing request lines out of the controller access log.

A preview URL carries ``sandfort_preview_token`` and the terminal and pty URLs a connect
``token``. The server never logs either value (round 94); the controller in front logs the raw
request line, so the example turns its access log off on both hosts (round 95).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
INGRESS = ROOT / "deploy" / "k8s" / "ingress.yaml"
OPERATIONS = ROOT / "docs" / "operations.md"
ACCESS_LOG = "nginx.ingress.kubernetes.io/enable-access-log"


def _ingresses() -> dict[str, dict[str, Any]]:
    docs = [d for d in yaml.safe_load_all(INGRESS.read_text(encoding="utf-8")) if d]
    return {d["metadata"]["name"]: d for d in docs if d["kind"] == "Ingress"}


def test_both_example_ingresses_turn_the_access_log_off() -> None:
    ingresses = _ingresses()
    assert set(ingresses) == {"sandfort-api", "sandfort-preview"}
    for name, ingress in ingresses.items():
        assert ingress["metadata"]["annotations"].get(ACCESS_LOG) == "false", name


def test_runbook_explains_the_edge_log() -> None:
    text = OPERATIONS.read_text(encoding="utf-8")
    section = text.split("## Behind a TLS-terminating proxy", 1)[1].split("\n## ", 1)[0]
    for fragment in ("sandfort_preview_token", "/terminal?token=", ACCESS_LOG, "REDACTED"):
        assert fragment in section, fragment
