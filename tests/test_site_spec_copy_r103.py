"""The committed docs site copies of the specification follow the repository file.

Round 103 added `browser_url` to openapi/sandfort.v1.json without rebuilding site/docs, so the
committed sidecar held the hash of the old file and the compact copy lacked the new field. The
expected values are computed here from the repository file, not taken from the site builder.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC_SOURCE = ROOT / "openapi" / "sandfort.v1.json"
SITE_DOCS = ROOT / "site" / "docs"
SIDECAR_LABEL = "openapi/sandfort.v1.json"


def _spec() -> dict[str, object]:
    spec: dict[str, object] = json.loads(SPEC_SOURCE.read_text(encoding="utf-8"))
    return spec


def test_committed_sidecar_is_the_sha256sum_line_of_the_specification() -> None:
    digest = hashlib.sha256(SPEC_SOURCE.read_bytes()).hexdigest()
    committed = (SITE_DOCS / "openapi.json.sha256").read_text(encoding="utf-8")
    assert committed == f"{digest}  {SIDECAR_LABEL}\n"


def test_committed_spec_copy_parses_to_the_specification() -> None:
    copy = json.loads((SITE_DOCS / "openapi.json").read_text(encoding="utf-8"))
    assert copy == _spec()


def test_committed_spec_copy_is_compact_and_keeps_the_key_order() -> None:
    committed = (SITE_DOCS / "openapi.json").read_text(encoding="utf-8")
    expected = json.dumps(_spec(), separators=(",", ":"), ensure_ascii=False, sort_keys=False)
    assert committed == expected


def test_committed_spec_copy_carries_the_preview_browser_url() -> None:
    copy = json.loads((SITE_DOCS / "openapi.json").read_text(encoding="utf-8"))
    properties = copy["components"]["schemas"]["PreviewTokenResponse"]["properties"]
    assert list(properties)[0] == "browser_url"
    assert properties["browser_url"]["title"] == "Browser Url"
