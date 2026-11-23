"""Tamper evidence for the audit trail (WP 5.5): a per-org hash chain over audit rows.

Each row stores ``prev_hash`` (the hash of the org's previous row, ``None`` for the first)
and ``hash = sha256(prev_hash + canonical(row))`` in hex. ``canonical`` covers the immutable
fields only (never ip or user agent) as compact JSON with sorted keys.

Verification seeds from the FIRST row's stored ``prev_hash``, so retention that prunes a
prefix keeps the rest verifiable. Rows without a hash at the very start of an org's trail
predate the chain and are skipped; an unhashed row after a hashed one is a finding.
Rows are ordered by id; the recorder keeps ids increasing per org (``successor_id``).

Keyed chain (``SANDFORT_AUDIT_CHAIN_KEY``, at least 32 bytes): the row hash is then
``HMAC-SHA256(key, prev_hash + canonical(row))``, so a database writer without the key cannot
recompute a rewritten history. Rows written before the key was set stay unkeyed; verify
accepts them (and counts them) while ``SANDFORT_AUDIT_CHAIN_ACCEPT_UNKEYED`` is true, but only
before the first keyed row of an org: an unkeyed row after a keyed one is a finding. With the
key set, a chain whose newest row is unkeyed is a finding whatever the flag says, so a writer
without the key cannot swap in a self-consistent unkeyed history. That finding is a
``hash_mismatch`` and never a calm verdict: the rows alone cannot tell a key enabled after the
last event from keyed rows deleted by a database writer, so nothing here advises writing an
event to clear it; compare against an earlier export with ``--head``.
``audit-export`` appends one signed head line per org (last row id, its hash, an HMAC over
them) and ``audit-verify --head`` checks the live chain still reaches it (truncation); that
code lives in ``audit_chain_head`` and is re-exported here. Hashes are compared as bytes.

An operator can acknowledge historical findings with an ``audit.chain_reanchored`` event
(``audit-reanchor``). Acknowledging never rewrites or hides a row: ``ChainVerifier`` still
finds every break, it only reports those at or before the latest event's
``acknowledged_through`` row separately, and they no longer fail the verify. Only a row
written by the platform-admin actor counts as a re-anchor. The event records the
``operator`` who ran the command and a ``reason_code`` next to the free-text ``note``; older
events without them read as ``None``.
"""

import hashlib
import hmac
import json
import os
import secrets
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from sandfort.config import Settings, audit_chain_accept_unkeyed_from, audit_chain_key_from
from sandfort.db.repositories.ports import ChainedAuditEvent, UnitOfWorkPort
from sandfort.domain.events import ActorType, AuditEvent, AuditOutcome
from sandfort.ids import ALPHABET, BODY_LENGTH, parse_id
from sandfort.services.audit_chain_head import HEAD_TYPE as HEAD_TYPE
from sandfort.services.audit_chain_head import HeadWatcher as HeadWatcher
from sandfort.services.audit_chain_head import SignedHead as SignedHead
from sandfort.services.audit_chain_head import digest_equal
from sandfort.services.audit_chain_head import invalid_head_finding as invalid_head_finding
from sandfort.services.audit_chain_head import parse_heads as parse_heads
from sandfort.services.audit_chain_head import sign_head as sign_head

MAX_ID_STEP = 1 << 20
REANCHOR_ACTION = "audit.chain_reanchored"
REANCHOR_LOOKUP_PAGE = 100


class ReanchorReason(StrEnum):
    """Why an operator acknowledged the findings (``reason_code`` of the re-anchor event)."""

    INCIDENT_ACKNOWLEDGED = "incident_acknowledged"
    MIGRATION = "migration"
    OTHER = "other"


class FindingKind(StrEnum):
    HASH_MISMATCH = "hash_mismatch"  # stored hash differs from the recomputed one
    LINK_BROKEN = "link_broken"  # prev_hash is not the previous row's stored hash
    MISSING_HASH = "missing_hash"  # an unhashed row inside the chain
    HEAD_MISSING = "head_missing"  # an exported head is not reached by the live chain
    HEAD_INVALID = "head_invalid"  # an exported head carries a bad signature


UNKEYED_NEWEST_DETAIL = (
    "newest row is unkeyed while the chain key is set: either the key was enabled after the "
    "last event, or keyed rows were deleted; the two cannot be told apart from the rows alone; "
    "compare against an earlier export with --head"
)


@dataclass(frozen=True, slots=True)
class ChainFinding:
    kind: FindingKind
    org_id: str
    row_id: str
    detail: str

    def render(self) -> str:
        return f"{self.org_id} {self.row_id} {self.kind.value}: {self.detail}"


def canonical_row(event: AuditEvent) -> str:
    """The immutable fields of one audit row as compact, key-sorted JSON."""
    payload = {
        "id": event.id,
        "org_id": event.org_id,
        "actor_type": event.actor_type.value,
        "actor_id": event.actor_id,
        "action": event.action,
        "target_type": event.target_type,
        "target_id": event.target_id,
        "outcome": event.outcome.value,
        "request_id": event.request_id,
        "details": event.details,
        "occurred_at": event.occurred_at.isoformat(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@dataclass(frozen=True, slots=True)
class ChainPolicy:
    """How a chain is hashed and verified: the HMAC key (``None`` = unkeyed) and the flag."""

    key: bytes | None = None
    accept_unkeyed: bool = True

    @classmethod
    def from_mapping(cls, source: Mapping[str, str]) -> "ChainPolicy":
        key = audit_chain_key_from(source)
        return cls(
            key=key.encode() if key else None,
            accept_unkeyed=audit_chain_accept_unkeyed_from(source),
        )

    @classmethod
    def from_env(cls) -> "ChainPolicy":
        """The policy of the process environment (what the recorder and the API verify use)."""
        return cls.from_mapping(os.environ)

    @classmethod
    def from_settings(cls, settings: Settings) -> "ChainPolicy":
        key = settings.audit_chain_key.strip()
        return cls(
            key=key.encode() if key else None, accept_unkeyed=settings.audit_chain_accept_unkeyed
        )


def unkeyed_link_hash(prev_hash: str | None, event: AuditEvent) -> str:
    """``sha256(prev_hash + canonical(event))`` as hex; the first row links to ``""``."""
    return hashlib.sha256(((prev_hash or "") + canonical_row(event)).encode()).hexdigest()


def keyed_link_hash(key: bytes, prev_hash: str | None, event: AuditEvent) -> str:
    """``HMAC-SHA256(key, prev_hash + canonical(event))`` as hex."""
    material = ((prev_hash or "") + canonical_row(event)).encode()
    return hmac.new(key, material, hashlib.sha256).hexdigest()


def link_hash(prev_hash: str | None, event: AuditEvent, key: bytes | None = None) -> str:
    """The hash a new row gets: keyed with ``key`` or the environment's key, else unkeyed."""
    chain_key = ChainPolicy.from_env().key if key is None else key
    if chain_key is None:
        return unkeyed_link_hash(prev_hash, event)
    return keyed_link_hash(chain_key, prev_hash, event)


def export_line(row: ChainedAuditEvent) -> str:
    """One ndjson line: every audit field plus ``prev_hash`` and ``hash``, keys sorted."""
    record = row.event.model_dump(mode="json")
    record["prev_hash"] = row.prev_hash
    record["hash"] = row.entry_hash
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def successor_id(previous: str) -> str:
    """An audit id sorting after ``previous``, same prefix and width, randomly stepped.

    Ids from the clock can tie or invert within one millisecond; the chain is ordered by id,
    so the recorder uses this when a fresh id would not sort after the org's newest row.
    """
    prefix, body = parse_id(previous)
    value = 0
    for char in body:
        value = value * len(ALPHABET) + ALPHABET.index(char)
    value += secrets.randbelow(MAX_ID_STEP) + 1
    chars: list[str] = []
    for _ in range(BODY_LENGTH):
        value, digit = divmod(value, len(ALPHABET))
        chars.append(ALPHABET[digit])
    return f"{prefix}_{''.join(reversed(chars))}"


class ChainWalker:
    """Incremental verifier for one org's rows, fed in id order (works page by page).

    The first hashed row seeds the walk: its own hash is checked, its ``prev_hash`` is not.
    Feeding an anchor row first therefore verifies the chain from that row on.
    """

    def __init__(self, policy: ChainPolicy | None = None) -> None:
        self._policy = ChainPolicy.from_env() if policy is None else policy
        self._previous_hash: str | None = None
        self._started = False
        self._keyed_seen = False
        self._unkeyed_accepted = 0
        self._tail_unkeyed: AuditEvent | None = None  # newest hashed row, if accepted unkeyed

    @property
    def unkeyed_accepted(self) -> int:
        """Unkeyed rows accepted so far next to a keyed chain."""
        return self._unkeyed_accepted

    def _hash_problem(self, row: ChainedAuditEvent, stored: str) -> str | None:
        """Why the stored hash is wrong (``None`` when it is right under the policy)."""
        key = self._policy.key
        unkeyed = unkeyed_link_hash(row.prev_hash, row.event)
        self._tail_unkeyed = None
        if key is None:
            return None if digest_equal(unkeyed, stored) else "recomputed hash differs"
        if digest_equal(keyed_link_hash(key, row.prev_hash, row.event), stored):
            self._keyed_seen = True
            return None
        if not digest_equal(unkeyed, stored):
            return "recomputed hash differs"
        if not self._policy.accept_unkeyed:
            return "unkeyed row in a keyed chain (unkeyed rows are not accepted)"
        if self._keyed_seen:
            return "unkeyed row after a keyed row"
        self._unkeyed_accepted += 1
        self._tail_unkeyed = row.event
        return None

    def tail_finding(self) -> ChainFinding | None:
        """With a key set, a finding when the newest hashed row is an accepted unkeyed one.

        Call it once, after the last row. Without a key, or when the newest row is keyed or
        already a finding of its own, there is nothing to add. Otherwise it is a
        ``hash_mismatch`` with an honest detail: it may be a key enabled after the last event
        or keyed rows deleted, and the rows cannot say which. An unkeyed row after a keyed one
        is the ``hash_mismatch`` that ``check`` reports on that row.
        """
        event = self._tail_unkeyed
        if event is None:
            return None
        return _finding(FindingKind.HASH_MISMATCH, event, UNKEYED_NEWEST_DETAIL)

    def check(self, row: ChainedAuditEvent) -> list[ChainFinding]:
        event = row.event
        if row.entry_hash is None:
            if not self._started:
                return []  # written before the chain existed
            return [_finding(FindingKind.MISSING_HASH, event, "row has no hash")]
        findings: list[ChainFinding] = []
        problem = self._hash_problem(row, row.entry_hash)
        if problem is not None:
            findings.append(_finding(FindingKind.HASH_MISMATCH, event, problem))
        if self._started and (row.prev_hash or "") != (self._previous_hash or ""):
            findings.append(_finding(FindingKind.LINK_BROKEN, event, "prev_hash does not link"))
        self._started = True
        self._previous_hash = row.entry_hash
        return findings


def verify_chain(
    rows: Iterable[ChainedAuditEvent], policy: ChainPolicy | None = None
) -> Iterator[ChainFinding]:
    """Yield one finding per mismatch in one org's rows, given in insertion (id) order."""
    walker = ChainWalker(policy)
    for row in rows:
        yield from walker.check(row)
    tail = walker.tail_finding()
    if tail is not None:
        yield tail


def _finding(kind: FindingKind, event: AuditEvent, detail: str) -> ChainFinding:
    return ChainFinding(kind=kind, org_id=event.org_id, row_id=event.id, detail=detail)


def reanchor_through(event: AuditEvent) -> str | None:
    """The ``acknowledged_through`` row id of a well-formed re-anchor event, else ``None``.

    Only the admin command writes a re-anchor, as the platform-admin actor; a row with the
    action but another actor type acknowledges nothing. A re-anchor can only acknowledge
    rows before itself; one that names itself or a later row, or carries no row id,
    acknowledges nothing.
    """
    if (
        event.action != REANCHOR_ACTION
        or event.outcome != AuditOutcome.SUCCESS
        or event.actor_type != ActorType.PLATFORM_ADMIN
    ):
        return None
    through = event.details.get("acknowledged_through")
    if not isinstance(through, str) or through >= event.id:
        return None
    return through


@dataclass(frozen=True, slots=True)
class Reanchor:
    """An effective re-anchor event: its id, the last row it acknowledges and who and why.

    ``operator``, ``reason_code``, ``findings`` and ``note`` are ``None`` when the event does
    not carry them as the expected type (older events have no operator or reason code).
    """

    event_id: str
    through: str
    occurred_at: datetime
    operator: str | None = None
    reason_code: str | None = None
    findings: int | None = None
    note: str | None = None


def _detail_str(details: dict[str, object], name: str) -> str | None:
    value = details.get(name)
    return value if isinstance(value, str) else None


def reanchor_of(event: AuditEvent) -> Reanchor | None:
    """The :class:`Reanchor` an effective re-anchor event stands for, else ``None``."""
    through = reanchor_through(event)
    if through is None:
        return None
    details = event.details
    findings = details.get("findings")
    return Reanchor(
        event_id=event.id,
        through=through,
        occurred_at=event.occurred_at,
        operator=_detail_str(details, "operator"),
        reason_code=_detail_str(details, "reason_code"),
        findings=findings if type(findings) is int else None,
        note=_detail_str(details, "note"),
    )


async def find_latest_reanchor(
    uow: UnitOfWorkPort, org_id: str, *, not_before: str | None = None
) -> Reanchor | None:
    """The newest effective re-anchor of one org, looked up before a walk (a page at a time).

    ``not_before`` is the first row id the walk will see (an anchor): earlier events are not
    part of that walk and are ignored, as an in-walk scan would ignore them.
    """
    cursor: str | None = None
    while True:
        page = await uow.audit.list(
            org_id,
            action=REANCHOR_ACTION,
            cursor=cursor,
            limit=REANCHOR_LOOKUP_PAGE,
            order="desc",
        )
        for event in page:
            if not_before is not None and event.id < not_before:
                return None
            found = reanchor_of(event)
            if found is not None:
                return found
        if len(page) < REANCHOR_LOOKUP_PAGE:
            return None
        cursor = page[-1].id


@dataclass(frozen=True, slots=True)
class ChainVerdict:
    """The outcome of verifying one org's rows, with re-anchored findings set apart."""

    findings: list[ChainFinding]  # not acknowledged: these fail the verify (maybe capped)
    acknowledged: int  # findings covered by the latest re-anchor event
    reanchored_by: str | None  # id of that event
    findings_total: int = 0  # every unacknowledged finding, whether stored or not
    reanchor: Reanchor | None = None  # that event in full (operator, reason code, note)
    unkeyed_accepted: int = 0  # unkeyed rows accepted next to a keyed chain

    @property
    def ok(self) -> bool:
        return not self.findings


class ChainVerifier:
    """``ChainWalker`` plus re-anchor handling, fed one org's rows in id order.

    Two modes. By default the latest re-anchor event is discovered during the walk, so every
    finding is kept until ``verdict`` sorts them (memory grows with the findings; the admin
    commands use this). With ``max_findings`` the caller looks the re-anchor up first
    (``find_latest_reanchor``) and passes it as ``reanchor``: acknowledged findings are only
    counted, at most ``max_findings`` open ones are stored, and the rest only counted.
    """

    def __init__(
        self,
        *,
        max_findings: int | None = None,
        reanchor: Reanchor | None = None,
        policy: ChainPolicy | None = None,
    ) -> None:
        if max_findings is not None and max_findings < 1:
            raise ValueError("max_findings must be at least 1")
        self._walker = ChainWalker(policy)
        self._found: list[ChainFinding] = []
        self._max = max_findings
        self._known = reanchor
        self._reanchor: Reanchor | None = None  # the latest one seen in the walk
        self._open_total = 0
        self._acknowledged = 0
        self._finished = False

    @property
    def all_findings(self) -> list[ChainFinding]:
        """Every finding so far, acknowledged or not (the default mode only)."""
        if self._max is not None:
            raise RuntimeError("a bounded verifier does not keep acknowledged findings")
        return list(self._found)

    @property
    def unkeyed_accepted(self) -> int:
        return self._walker.unkeyed_accepted

    def check(self, row: ChainedAuditEvent) -> None:
        findings = self._walker.check(row)
        if self._max is None:
            self._found.extend(findings)
            found = reanchor_of(row.event)
            if found is not None:
                self._reanchor = found
            return
        self._record_bounded(findings, self._max)

    def _finish(self) -> None:
        """Add the unkeyed-tail finding once, after the last row."""
        if self._finished:
            return
        self._finished = True
        tail = self._walker.tail_finding()
        if tail is None:
            return
        if self._max is None:
            self._found.append(tail)
        else:
            self._record_bounded([tail], self._max)

    def _record_bounded(self, findings: list[ChainFinding], limit: int) -> None:
        for finding in findings:
            if self._known is not None and finding.row_id <= self._known.through:
                self._acknowledged += 1
                continue
            self._open_total += 1
            if len(self._found) < limit:
                self._found.append(finding)

    def verdict(self) -> ChainVerdict:
        self._finish()
        if self._max is not None:
            known = self._known
            return ChainVerdict(
                findings=list(self._found),
                acknowledged=self._acknowledged,
                reanchored_by=None if known is None else known.event_id,
                findings_total=self._open_total,
                reanchor=known,
                unkeyed_accepted=self.unkeyed_accepted,
            )
        if self._reanchor is None:
            return ChainVerdict(
                findings=list(self._found),
                acknowledged=0,
                reanchored_by=None,
                findings_total=len(self._found),
                unkeyed_accepted=self.unkeyed_accepted,
            )
        latest = self._reanchor
        open_findings = [item for item in self._found if item.row_id > latest.through]
        return ChainVerdict(
            findings=open_findings,
            acknowledged=len(self._found) - len(open_findings),
            reanchored_by=latest.event_id,
            findings_total=len(open_findings),
            reanchor=latest,
            unkeyed_accepted=self.unkeyed_accepted,
        )
