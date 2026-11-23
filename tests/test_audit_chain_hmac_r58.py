"""Keyed audit chain (HMAC-SHA256) and the signed head trailer of ``audit-export``."""

import contextlib
import json
import logging
from datetime import UTC, datetime

import pytest

from sandfort.config import Settings
from sandfort.db.repositories.ports import ChainedAuditEvent
from sandfort.domain.events import ActorType, AuditEvent
from sandfort.services import audit_chain, audit_chain_head
from sandfort.services.audit_chain import (
    ChainPolicy,
    ChainVerifier,
    FindingKind,
    HeadWatcher,
    SignedHead,
    keyed_link_hash,
    link_hash,
    parse_heads,
    sign_head,
    unkeyed_link_hash,
    verify_chain,
)

KEY = b"k" * 32
OTHER_KEY = b"o" * 32
ORG = "org_test"
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
KEY_ENV = "SANDFORT_AUDIT_CHAIN_KEY"
ACCEPT_ENV = "SANDFORT_AUDIT_CHAIN_ACCEPT_UNKEYED"


def make_event(index: int) -> AuditEvent:
    return AuditEvent(
        id=f"aud_{index:020d}",
        org_id=ORG,
        actor_type=ActorType.SYSTEM,
        action=f"test.step{index}",
        details={"n": index},
        occurred_at=NOW,
    )


def build_chain(count: int, keys: list[bytes | None]) -> list[ChainedAuditEvent]:
    """Rows chained in order; ``keys[i]`` keys row i (``None`` writes an unkeyed row)."""
    rows: list[ChainedAuditEvent] = []
    prev: str | None = None
    for index in range(count):
        event = make_event(index)
        key = keys[index]
        entry = unkeyed_link_hash(prev, event) if key is None else keyed_link_hash(key, prev, event)
        rows.append(ChainedAuditEvent(event=event, prev_hash=prev, entry_hash=entry))
        prev = entry
    return rows


def kinds(rows: list[ChainedAuditEvent], policy: ChainPolicy) -> list[tuple[FindingKind, str]]:
    return [(item.kind, item.row_id) for item in verify_chain(rows, policy)]


def test_keyed_hash_differs_from_unkeyed_and_between_keys() -> None:
    event = make_event(0)

    unkeyed = unkeyed_link_hash(None, event)
    keyed = keyed_link_hash(KEY, None, event)

    assert keyed != unkeyed
    assert keyed != keyed_link_hash(OTHER_KEY, None, event)
    assert len(keyed) == 64
    assert link_hash(None, event, KEY) == keyed
    assert link_hash(None, event) == unkeyed


def test_verify_passes_keyed_rows_and_rejects_wrong_key() -> None:
    rows = build_chain(4, [KEY] * 4)

    assert kinds(rows, ChainPolicy(key=KEY)) == []
    wrong = kinds(rows, ChainPolicy(key=OTHER_KEY))
    assert {kind for kind, _ in wrong} == {FindingKind.HASH_MISMATCH}
    assert len(wrong) == 4


def test_keyed_rows_fail_without_a_key() -> None:
    rows = build_chain(2, [KEY] * 2)

    assert len(kinds(rows, ChainPolicy(key=None))) == 2


def test_mixed_rows_accepted_only_with_the_flag_and_counted() -> None:
    rows = build_chain(4, [None, None, KEY, KEY])

    verifier = ChainVerifier(policy=ChainPolicy(key=KEY, accept_unkeyed=True))
    for row in rows:
        verifier.check(row)
    assert verifier.verdict().ok
    assert verifier.unkeyed_accepted == 2
    assert verifier.verdict().unkeyed_accepted == 2

    strict = kinds(rows, ChainPolicy(key=KEY, accept_unkeyed=False))
    assert strict == [
        (FindingKind.HASH_MISMATCH, rows[0].event.id),
        (FindingKind.HASH_MISMATCH, rows[1].event.id),
    ]


def test_unkeyed_row_after_a_keyed_row_is_a_finding() -> None:
    rows = build_chain(3, [None, KEY, None])

    found = kinds(rows, ChainPolicy(key=KEY, accept_unkeyed=True))

    assert found == [(FindingKind.HASH_MISMATCH, rows[2].event.id)]


def test_tampering_is_detected_in_keyed_chain() -> None:
    rows = build_chain(3, [KEY] * 3)
    forged_event = rows[1].event.model_copy(update={"action": "test.forged"})
    forged = ChainedAuditEvent(
        event=forged_event, prev_hash=rows[1].prev_hash, entry_hash=rows[1].entry_hash
    )

    assert kinds([rows[0], forged, rows[2]], ChainPolicy(key=KEY)) == [
        (FindingKind.HASH_MISMATCH, forged_event.id)
    ]


def test_database_writer_without_the_key_cannot_rewrite_history() -> None:
    rows = build_chain(3, [KEY] * 3)
    event = rows[1].event.model_copy(update={"action": "test.rewritten"})
    rewritten: list[ChainedAuditEvent] = [rows[0]]
    prev = rows[0].entry_hash
    for source in (event, rows[2].event):
        entry = unkeyed_link_hash(prev, source)  # all an attacker without the key can compute
        rewritten.append(ChainedAuditEvent(event=source, prev_hash=prev, entry_hash=entry))
        prev = entry

    found = kinds(rewritten, ChainPolicy(key=KEY, accept_unkeyed=True))

    assert [row_id for _, row_id in found] == [event.id, rows[2].event.id]


def test_head_trailer_round_trips_and_detects_forgery() -> None:
    head = sign_head(KEY, ORG, "aud_x", "ab" * 32)

    parsed = parse_heads([head.to_line(), "", json.dumps({"id": "row"})])

    assert parsed == [head]
    assert parsed[0].valid(KEY)
    assert not parsed[0].valid(OTHER_KEY)
    tampered = json.loads(head.to_line())
    tampered["row_id"] = "aud_earlier"
    assert not parse_heads([json.dumps(tampered)])[0].valid(KEY)


def test_parse_heads_rejects_malformed_trailer() -> None:
    with pytest.raises(ValueError, match="audit head"):
        parse_heads([json.dumps({"type": "audit_head", "org_id": ORG})])


def test_head_watcher_detects_truncation() -> None:
    rows = build_chain(4, [KEY] * 4)
    last = rows[-1]
    assert last.entry_hash is not None
    head = sign_head(KEY, ORG, last.event.id, last.entry_hash)

    full = HeadWatcher(head)
    for row in rows:
        full.observe(row)
    truncated = HeadWatcher(head)
    for row in rows[:3]:
        truncated.observe(row)

    assert full.finding() is None
    finding = truncated.finding()
    assert finding is not None
    assert finding.kind is FindingKind.HEAD_MISSING
    assert finding.row_id == last.event.id


def test_head_watcher_flags_a_head_row_with_another_hash() -> None:
    rows = build_chain(2, [KEY] * 2)
    head = sign_head(KEY, ORG, rows[1].event.id, "cd" * 32)

    watcher = HeadWatcher(head)
    for row in rows:
        watcher.observe(row)

    finding = watcher.finding()
    assert finding is not None
    assert finding.kind is FindingKind.HEAD_MISSING


def test_settings_read_key_and_flag_from_env() -> None:
    env = {KEY_ENV: "k" * 32, ACCEPT_ENV: "false"}

    settings = Settings.from_env(env)

    assert settings.audit_chain_key == "k" * 32
    assert settings.audit_chain_accept_unkeyed is False
    defaults = Settings.from_env({})
    assert defaults.audit_chain_key == ""
    assert defaults.audit_chain_accept_unkeyed is True


def test_short_key_is_refused() -> None:
    with pytest.raises(ValueError, match="AUDIT_CHAIN_KEY"):
        Settings.from_env({KEY_ENV: "short"})


def test_prod_warns_when_key_is_unset(caplog: pytest.LogCaptureFixture) -> None:
    prod = {
        "SANDFORT_ENVIRONMENT": "prod",
        "SANDFORT_WEBHOOK_SECRET_KEY": "A" * 43 + "=",
    }
    with caplog.at_level(logging.WARNING), contextlib.suppress(ValueError):
        Settings.from_env(prod)  # other prod requirements may refuse; the warning comes first

    assert any("AUDIT_CHAIN_KEY" in record.getMessage() for record in caplog.records)


def test_policy_from_env_follows_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(KEY_ENV, raising=False)
    monkeypatch.delenv(ACCEPT_ENV, raising=False)
    assert ChainPolicy.from_env() == ChainPolicy(key=None, accept_unkeyed=True)

    monkeypatch.setenv(KEY_ENV, "k" * 32)
    monkeypatch.setenv(ACCEPT_ENV, "0")

    assert ChainPolicy.from_env() == ChainPolicy(key=KEY, accept_unkeyed=False)


NON_ASCII = "\u00e9" * 64


def test_head_symbols_live_in_the_head_module_and_are_reexported() -> None:
    for name in ("SignedHead", "HeadWatcher", "sign_head", "parse_heads", "HEAD_TYPE"):
        assert getattr(audit_chain, name) is getattr(audit_chain_head, name)
    assert "def sign_head" not in open(audit_chain.__file__).read()


@pytest.mark.parametrize("key", [None, KEY])
def test_non_ascii_stored_hash_is_a_finding_not_a_type_error(key: bytes | None) -> None:
    event = make_event(0)
    row = ChainedAuditEvent(event=event, prev_hash=None, entry_hash=NON_ASCII)

    found = kinds([row], ChainPolicy(key=key))

    assert found == [(FindingKind.HASH_MISMATCH, event.id)]


def test_non_ascii_signature_and_head_hash_do_not_raise() -> None:
    rows = build_chain(2, [KEY] * 2)
    forged = SignedHead(ORG, rows[1].event.id, "ab" * 32, NON_ASCII)
    assert not forged.valid(KEY)

    head = sign_head(KEY, ORG, rows[1].event.id, NON_ASCII)
    watcher = HeadWatcher(head)
    for row in rows:
        watcher.observe(row)
    finding = watcher.finding()
    assert finding is not None
    assert finding.kind is FindingKind.HEAD_MISSING

    odd = ChainedAuditEvent(event=rows[1].event, prev_hash=None, entry_hash=NON_ASCII)
    other = HeadWatcher(sign_head(KEY, ORG, rows[1].event.id, rows[1].entry_hash or ""))
    other.observe(odd)
    assert other.finding() is not None


def test_non_ascii_prev_hash_does_not_raise() -> None:
    rows = build_chain(2, [KEY] * 2)
    odd = ChainedAuditEvent(event=rows[1].event, prev_hash=NON_ASCII, entry_hash=rows[1].entry_hash)

    found = kinds([rows[0], odd], ChainPolicy(key=KEY))

    assert (FindingKind.LINK_BROKEN, rows[1].event.id) in found


@pytest.mark.parametrize("accept", [True, False])
def test_unkeyed_tail_with_a_key_is_a_finding_whatever_the_flag(accept: bool) -> None:
    rows = build_chain(3, [None] * 3)

    found = kinds(rows, ChainPolicy(key=KEY, accept_unkeyed=accept))

    assert found
    assert (FindingKind.HASH_MISMATCH, rows[-1].event.id) in found


def test_whole_unkeyed_history_is_one_tail_finding_when_flag_is_on() -> None:
    rows = build_chain(3, [None] * 3)

    findings = list(verify_chain(rows, ChainPolicy(key=KEY, accept_unkeyed=True)))

    assert [item.row_id for item in findings] == [rows[-1].event.id]
    assert "newest" in findings[0].detail


def test_unkeyed_tail_after_keyed_rows_is_reported_once_per_row() -> None:
    rows = build_chain(3, [KEY, KEY, None])

    found = kinds(rows, ChainPolicy(key=KEY, accept_unkeyed=True))

    assert found == [(FindingKind.HASH_MISMATCH, rows[2].event.id)]


def test_migrated_chain_with_a_keyed_tail_passes_and_counts_the_prefix() -> None:
    rows = build_chain(4, [None, None, KEY, KEY])
    verifier = ChainVerifier(policy=ChainPolicy(key=KEY, accept_unkeyed=True))
    for row in rows:
        verifier.check(row)

    verdict = verifier.verdict()

    assert verdict.ok
    assert verdict.unkeyed_accepted == 2


def test_unkeyed_chain_without_a_key_has_no_tail_finding() -> None:
    rows = build_chain(3, [None] * 3)

    assert kinds(rows, ChainPolicy(key=None)) == []


@pytest.mark.parametrize("bound", [None, 5])
def test_verifier_fails_on_unkeyed_tail_in_both_modes(bound: int | None) -> None:
    rows = build_chain(3, [None] * 3)
    verifier = ChainVerifier(max_findings=bound, policy=ChainPolicy(key=KEY))
    for row in rows:
        verifier.check(row)

    verdict = verifier.verdict()
    again = verifier.verdict()

    assert not verdict.ok
    assert verdict.findings_total == 1
    assert [item.row_id for item in verdict.findings] == [rows[-1].event.id]
    assert again.findings_total == 1
