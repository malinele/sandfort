"""Round 100 (B36): docs state what the code does for ids, tokens, snapshots and previews."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = ROOT / "src" / "sandfort" / "db" / "models"
TABLENAME = re.compile(r'^\s*__tablename__\s*=\s*"([a-z_]+)"', re.MULTILINE)
TABLE_ROW = re.compile(r"^\| `([a-z_]+)` \|", re.MULTILINE)


def _raw(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _flat(relative: str) -> str:
    return " ".join(_raw(relative).split())


def _between(text: str, start: str, end: str) -> str:
    begin = text.index(start)
    return text[begin : text.index(end, begin)]


def _model_tables() -> set[str]:
    found: set[str] = set()
    for path in sorted(MODELS_DIR.glob("*.py")):
        found.update(TABLENAME.findall(path.read_text(encoding="utf-8")))
    return found


def _documented_tables() -> list[str]:
    section = _between(
        _raw("docs/architecture.md"), "## 4. Data model", "**Lifecycle transitions**"
    )
    return TABLE_ROW.findall(section)


def test_architecture_describes_the_real_id_format() -> None:
    text = _flat("docs/architecture.md")
    assert "prefixed ULID" not in text
    assert "snp_" not in text
    assert "75 random bits" in text
    assert "`snap_`" in text
    assert "sandfort-snapshot:<snap_id" in text


def test_architecture_preview_route_and_token_storage() -> None:
    text = _flat("docs/architecture.md")
    assert "preview-urls" not in text
    assert "/v1/sandboxes/{id}/preview-tokens" in text
    assert "for WS/preview" not in text
    assert "| `connect_tokens` |" not in text
    assert "There is no token table." in text


def test_architecture_snapshot_delete_answers_200() -> None:
    row = next(
        line
        for line in _raw("docs/architecture.md").splitlines()
        if line.startswith("| DELETE | `/v1/snapshots/{id}`")
    )
    assert "200" in row
    assert "`deleting`" in row
    assert "202" not in row


def test_connect_guide_snapshot_section_says_what_is_not_captured() -> None:
    section = _between(
        _flat("docs/connect-guide.md"),
        "### Snapshots Commit a running sandbox",
        "#### Exporting a snapshot",
    )
    for needle in (
        "It is independent of its source",
        "kept until you delete it",
        "`/dev/shm`",
        "running processes",
        "volumes mounted in the sandbox",
    ):
        assert needle in section


def test_connect_guide_preview_section_states_expiry_rules() -> None:
    section = _between(
        _flat("docs/connect-guide.md"),
        "## 4. Preview URLs",
        "## 5. Beta limits",
    )
    for needle in (
        "Expiry is checked when a request or a websocket handshake starts",
        "keeps running after `expires_at`",
        "a server restart ends every preview URL",
        "No endpoint revokes a token before it expires",
        "need no token",
    ):
        assert needle in section


def test_security_page_has_a_preview_content_section() -> None:
    section = _between(_flat("docs/security.md"), "### Preview content", "## 4. Control plane")
    for needle in (
        "tenant-controlled",
        "Public Suffix List",
        "document.cookie",
        "Content-Security-Policy",
        "X-Frame-Options",
        "clickjacking",
    ):
        assert needle in section


def test_security_page_states_encryption_at_rest_and_setuid_scope() -> None:
    text = _flat("docs/security.md")
    assert "No encryption at rest beyond the host's" in text
    assert "Setuid and setgid bits are inert on the `container` tier" in text
    assert "have not been measured" in text


def test_image_docstring_no_longer_calls_the_mutable_tag_pinned() -> None:
    text = _raw("sdk/python/src/sandfort_sdk/image.py")
    assert "the pinned ``python:3.12-slim``" not in text
    assert "which is mutable" in text


def test_architecture_ulid_mentions_all_deny_the_26_character_form() -> None:
    lines = [line for line in _raw("docs/architecture.md").splitlines() if "ULID" in line]
    assert lines
    for line in lines:
        assert "not a 26-character ULID" in line, line


def test_pagination_wording_does_not_call_the_ids_ulids() -> None:
    first = _raw("src/sandfort/api/pagination.py").splitlines()[0]
    assert "(id-ordered)" in first
    assert "ULID" not in _raw("src/sandfort/api/pagination.py")
    assert "cursor pagination over time-sortable ids" in _flat("docs/architecture.md")


def test_architecture_data_model_names_the_primary_key_exceptions() -> None:
    text = _flat("docs/architecture.md")
    assert "PKs are prefixed time-sortable ids" not in text
    for needle in (
        "the primary key of an entity table is a prefixed time-sortable id",
        "`nodes.id` is an operator-set `String(64)`",
        "`usage_intervals` and `quota_ledger` use an integer autoincrement `id`",
        "`quotas`, `idempotency_keys`, `org_memberships` and `usage_rollups`",
    ):
        assert needle in text, needle


def test_architecture_quota_ledger_row_matches_the_model() -> None:
    row = next(
        line
        for line in _raw("docs/architecture.md").splitlines()
        if line.startswith("| `quota_ledger` |")
    )
    assert "org_id PK" not in row
    for needle in ("id (integer autoincrement)", "sandbox_id", "vcpus", "reserved", "released"):
        assert needle in row, needle


def test_operations_tls11_probe_lowers_the_client_security_level() -> None:
    section = _between(_raw("docs/operations.md"), "### Edge transport policy", "## Client-facing")
    flat = " ".join(section.split())
    assert "-cipher DEFAULT@SECLEVEL=0" in flat
    assert 'grep -E "Protocol|Cipher is|alert|no protocols"' in flat
    assert "for v in tls1_1" not in flat
    for needle in ("no protocols available", "tlsv1 alert protocol version", "invalid command"):
        assert needle in flat, needle


def test_overlay_advisory_is_documented_as_startup_log_only() -> None:
    guide = _flat("docs/connect-guide.md")
    start = guide.index("registered without `--overlay2=none`")
    near = guide[start : start + 900]
    assert "only in the server startup log" in near
    assert "admin_cli doctor" in near
    doctor = _between(_flat("docs/operations.md"), "## Doctor:", "## Production start gate")
    for needle in ("overlay2=none", "server startup log", "has no row for it"):
        assert needle in doctor, needle


def test_architecture_data_model_table_names_exist_in_the_models() -> None:
    documented = _documented_tables()
    assert documented
    assert sorted(set(documented) - _model_tables()) == []


def test_architecture_data_model_has_one_row_per_model_table() -> None:
    documented = _documented_tables()
    assert len(documented) == len(set(documented))
    assert sorted(_model_tables() - set(documented)) == []


def test_architecture_names_the_real_outbox_rollup_and_mount_storage() -> None:
    text = _flat("docs/architecture.md")
    for stale in ("usage_daily", "sandbox_volume_mounts", "`events` (outbox)", "sampled hourly"):
        assert stale not in text, stale
    for needle in (
        "`sandfort.volume_mounts`",
        "`usage_rollups` once an hour",
        "`metering_sample_interval_s` (default 300 s)",
        "Snapshots and volumes are not metered.",
    ):
        assert needle in text, needle


def test_architecture_quota_risk_describes_the_per_sandbox_ledger() -> None:
    text = _flat("docs/architecture.md")
    assert "A single ledger row per org" not in text
    assert "One `quota_ledger` row per sandbox is inserted" in text
    assert "`SELECT ... FOR UPDATE` on the org row, then the org's quota row" in text


def test_operations_doctor_does_not_claim_it_cannot_disagree_with_the_gate() -> None:
    doctor = _between(_flat("docs/operations.md"), "## Doctor:", "## Production start gate")
    assert "cannot disagree" not in doctor
    for needle in (
        "does not call the start gate",
        "`gate_findings`",
        "`egress_gaps`",
        "rows built from `Settings`",
        "a prediction",
    ):
        assert needle in doctor, needle
