"""Signed head of an audit chain: the trailer of ``audit-export`` and its verification.

``audit-export`` appends one line per org (last row id, its hash, an HMAC over them with the
chain key). ``audit-verify --head`` parses those lines and checks that the live chain still
reaches each head, which detects truncation. This module does not import ``audit_chain`` at
import time (``audit_chain`` re-exports these names); findings are built with a local import.

With ``SANDFORT_AUDIT_SIGNING_KEY`` set (``Settings.audit_signer``, never the environment
directly) the head also carries ``alg`` (``ed25519``), ``public_key``, ``signed_at`` (UTC ISO
8601, to the second) and ``signature`` (urlsafe base64), an Ed25519 signature over the canonical
JSON of the head without ``signature`` and ``hmac``, so ``signed_at`` is covered and an older
signed head can be told from a newer one. ``verify_head_signature`` checks it with the
public key alone. An auditor can therefore prove that an export reached a head the server
signed, and that the exported row hashes up to it relink (each row's ``prev_hash`` is the
previous row's ``hash``, the last one is the head's ``hash``). The auditor cannot recompute the
keyed MACs of those hashes, so this is evidence of the exported chain's shape and of the signed
head, not a replacement for ``audit-verify`` with the chain key on the server side.

Heads written since round 63 (after v0.1.0-beta.66) also bind the export's content (see
``audit_export_digest``): ``row_count``, ``first_row_id`` and ``export_sha256`` are part of the
signed payload and of the HMAC. A head without them (older servers) still parses and
verifies as before.
"""

import hashlib
import hmac
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sandfort.db.repositories.ports import ChainedAuditEvent
from sandfort.services.audit_export_digest import (
    BINDING_FIELDS,
    SHA256_HEX_CHARS,
    ExportBinding,
)
from sandfort.services.audit_head_signing import (
    ALG,
    HeadSigner,
    canonical_payload,
    format_signed_at,
    load_public_key,
    parse_signed_at,
    public_key_to_text,
    verify_payload,
)

if TYPE_CHECKING:
    from sandfort.services.audit_chain import ChainFinding

HEAD_TYPE = "audit_head"
FILTER_FIELDS = ("filtered", "filters")
SUMMARY_TYPE = "export_summary"
# ``alg``, ``public_key`` and ``signature`` come together or not at all. ``signed_at`` is
# covered by the signature but optional on parse: exports from beta.60 to beta.64 carry the
# three-field block without it ("legacy", verified but undated).
REQUIRED_SIGNATURE_FIELDS = ("alg", "public_key", "signature")
SIGNATURE_FIELDS = (*REQUIRED_SIGNATURE_FIELDS, "signed_at")


class HeadSignatureError(ValueError):
    """A head line whose Ed25519 signature cannot be established with the given public key."""


@dataclass(frozen=True, slots=True)
class HeadClaim:
    """What a verified head signature covers: an org's chain row, its hash and when it was
    signed (UTC), so a reader can prefer the newest of several signed heads.

    ``signed_at`` is ``None`` for a legacy head (beta.60 to beta.64): verified but undated.
    """

    org_id: str
    row_id: str
    entry_hash: str
    signed_at: datetime | None


def digest_equal(left: str, right: str) -> bool:
    """Constant-time equality of two strings, compared as bytes.

    ``hmac.compare_digest`` raises ``TypeError`` for non-ASCII ``str``; hashes read from the
    database or a head file are untrusted text, so both sides are encoded first.
    """
    return hmac.compare_digest(
        left.encode("utf-8", "surrogatepass"), right.encode("utf-8", "surrogatepass")
    )


def _head_mac(key: bytes, org_id: str, row_id: str, entry_hash: str) -> str:
    material = json.dumps([HEAD_TYPE, org_id, row_id, entry_hash], separators=(",", ":"))
    return hmac.new(key, material.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()


def _bound_head_mac(key: bytes, head: "SignedHead") -> str:
    """The MAC of a head that binds content: the legacy fields plus the three binding fields
    (and, for a filtered export, the marker and its filters)."""
    parts: list[Any] = [
        HEAD_TYPE,
        head.org_id,
        head.row_id,
        head.entry_hash,
        head.row_count,
        head.first_row_id,
        head.export_sha256,
    ]
    if head.filtered:
        parts += ["filtered", [list(pair) for pair in head.filters or ()]]
    material = json.dumps(parts, separators=(",", ":"))
    return hmac.new(key, material.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class SignedHead:
    """The newest row of one org's chain at export time, signed with the chain key."""

    org_id: str
    row_id: str
    entry_hash: str
    mac: str
    alg: str | None = None
    public_key: str | None = None
    signature: str | None = None
    signed_at: str | None = None
    row_count: int | None = None
    first_row_id: str | None = None
    export_sha256: str | None = None
    filtered: bool | None = None
    filters: tuple[tuple[str, str], ...] | None = None

    @property
    def binds_content(self) -> bool:
        """Whether the head carries the content binding (``row_count`` and ``export_sha256``)."""
        return self.row_count is not None and self.export_sha256 is not None

    def to_record(self) -> dict[str, Any]:
        """The head as a mapping; the ``SIGNATURE_FIELDS`` and binding fields only when set."""
        record: dict[str, Any] = {
            "type": HEAD_TYPE,
            "org_id": self.org_id,
            "row_id": self.row_id,
            "hash": self.entry_hash,
            "hmac": self.mac,
        }
        for name in SIGNATURE_FIELDS:
            value = getattr(self, name)
            if value is not None:
                record[name] = value
        if self.binds_content:
            for name in BINDING_FIELDS:
                record[name] = getattr(self, name)
        if self.filtered:
            record["filtered"] = True
            record["filters"] = dict(self.filters or ())
        return record

    def to_line(self) -> str:
        """The trailer line of ``audit-export``: compact JSON, keys sorted."""
        return json.dumps(
            self.to_record(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )

    def valid(self, key: bytes) -> bool:
        if self.binds_content:
            expected = _bound_head_mac(key, self)
        else:
            expected = _head_mac(key, self.org_id, self.row_id, self.entry_hash)
        return digest_equal(expected, self.mac)


def sign_head(
    key: bytes,
    org_id: str,
    row_id: str,
    entry_hash: str,
    signer: HeadSigner | None = None,
    signed_at: datetime | None = None,
    binding: ExportBinding | None = None,
    filters: Mapping[str, str] | None = None,
) -> SignedHead:
    """The head of ``row_id``: HMAC with ``key``, plus an Ed25519 signature with ``signer``.

    ``binding`` (the export's row count, first row id and SHA-256) is written into the head and
    covered by the HMAC and the signature; ``None`` writes the legacy head without it.
    ``filters`` (the given ``request_id``/``outcome``/``from``/``to`` values, needs ``binding``)
    marks the head ``filtered: true``: the export is not a contiguous run of the chain, so a
    reader must not check neighbour linkage; ``row_id`` is then the last exported row.

    ``signer`` is ``Settings.audit_signer()`` of the caller; ``None`` means the head carries
    the HMAC only (the process environment is never consulted, so the key that signs is the
    one ``/v1/status`` publishes). ``signed_at`` (timezone-aware, default now) is written as
    UTC ISO 8601 and covered by the signature. The MAC does not depend on the signature.
    """
    head = SignedHead(org_id, row_id, entry_hash, _head_mac(key, org_id, row_id, entry_hash))
    if binding is not None:
        head = replace(
            head,
            row_count=binding.row_count,
            first_row_id=binding.first_row_id,
            export_sha256=binding.export_sha256,
        )
        if filters is not None:
            head = replace(head, filtered=True, filters=tuple(sorted(filters.items())))
        head = replace(head, mac=_bound_head_mac(key, head))
    if signer is None:
        return head
    stamped = format_signed_at(signed_at if signed_at is not None else datetime.now(UTC))
    announced = replace(head, alg=ALG, public_key=signer.public_key, signed_at=stamped)
    return replace(announced, signature=signer.sign(canonical_payload(announced.to_record())))


def verify_head_signature(line: str, public_key: bytes | str) -> HeadClaim:
    """Verify the Ed25519 signature of a head ``line`` with ``public_key`` alone.

    ``public_key`` is the raw 32 bytes or their urlsafe base64 text (``audit_public_key`` of
    ``GET /v1/status``). Returns the org, row id, entry hash and ``signed_at`` (UTC) the
    signature covers; a legacy head without ``signed_at`` verifies with ``signed_at`` ``None``
    (undated; dropping the field from a dated head breaks the signature). Raises
    ``HeadSignatureError`` when the line is not a signed head, names another key than
    ``public_key``, its signature does not verify, or its ``signed_at`` is empty or not ISO 8601
    in UTC. No secret is needed: the HMAC (``hmac``) is not checked here and is not part of what
    is signed.
    """
    try:
        key = load_public_key(public_key)
    except ValueError:
        raise HeadSignatureError("public key is not a valid Ed25519 public key") from None
    record = _head_record(line)
    if record["alg"] != ALG:
        raise HeadSignatureError(f"unsupported head signature algorithm {record['alg']!r}")
    if not digest_equal(record["public_key"], public_key_to_text(key)):
        raise HeadSignatureError("head names a different public key than the one given")
    if not verify_payload(key, canonical_payload(record), record["signature"]):
        raise HeadSignatureError("head signature does not verify")
    signed_at: datetime | None = None
    if "signed_at" in record:
        try:
            signed_at = parse_signed_at(record["signed_at"])
        except ValueError:
            raise HeadSignatureError("head signed_at is not ISO 8601 in UTC") from None
    return HeadClaim(record["org_id"], record["row_id"], record["hash"], signed_at)


def _head_record(line: str) -> dict[str, Any]:
    """The fields of a signed head ``line``; ``HeadSignatureError`` when any is missing.

    ``signed_at`` may be absent (legacy head) but not empty or not a string.
    """
    try:
        record = json.loads(line)
    except ValueError:
        raise HeadSignatureError("head line is not JSON") from None
    if not isinstance(record, dict) or record.get("type") != HEAD_TYPE:
        raise HeadSignatureError("line is not an audit_head")
    needed = ("org_id", "row_id", "hash", *REQUIRED_SIGNATURE_FIELDS)
    if not all(isinstance(record.get(name), str) and record[name] for name in needed):
        raise HeadSignatureError("head is not signed: it lacks a signature field")
    if "signed_at" in record and not _text(record["signed_at"]):
        raise HeadSignatureError("head signed_at is empty")
    return dict(record)


def _text(value: object) -> bool:
    """True for a non-empty string."""
    return isinstance(value, str) and bool(value)


def summary_line(rows: int, filters: Iterable[str]) -> str:
    """The unsigned trailer of a REST export that is filtered or has no chain key.

    It names no row and carries no MAC, so it cannot anchor anything; it only tells a reader
    how many rows the export held and which filters cut it (sorted names).
    """
    record = {"type": SUMMARY_TYPE, "rows": rows, "filters": sorted(filters)}
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def export_trailer(
    key: bytes | None,
    org_id: str,
    last: ChainedAuditEvent | None,
    rows: int,
    filters: Iterable[str],
    signer: HeadSigner | None = None,
    binding: ExportBinding | None = None,
    filtered_by: Mapping[str, str] | None = None,
) -> str:
    """The last line of a REST export: the signed head, or else the summary.

    ``last`` is the last row the export itself carried (``None`` for an empty export), so the
    head only ever names an exported row. ``signer`` is the server's ``Settings.audit_signer()``
    (``None`` = HMAC only); ``binding`` is the digest of the lines just streamed (see
    ``audit_export_digest``). ``filtered_by`` (the values of the ``request_id``/``outcome``
    filters, and the period bounds if given) makes it a ``filtered: true`` head. Without a chain
    key, or for an empty export, the unsigned ``export_summary`` is written.
    """
    if key is not None and last is not None and last.entry_hash is not None:
        head = sign_head(
            key, org_id, last.event.id, last.entry_hash, signer, None, binding, filtered_by
        )
        return head.to_line()
    return summary_line(rows, filters)


def parse_heads(lines: Iterable[str]) -> list[SignedHead]:
    """The head trailers among ndjson ``lines`` (rows and blank lines are skipped).

    Raises ``ValueError`` on a line that is not JSON, a head with a missing field or a partial
    signature block. ``signed_at`` is optional (the legacy three-field block of beta.60 to
    beta.64 parses with ``signed_at`` ``None``), but a ``signed_at`` alone, or an empty one, is
    refused. ``row_count``, ``first_row_id`` and ``export_sha256`` come together or not at all
    (a head from before round 63 has none).
    """
    heads: list[SignedHead] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            raise ValueError(f"audit head file: line {number} is not JSON") from None
        if not isinstance(record, dict) or record.get("type") != HEAD_TYPE:
            continue
        values = [record.get(name) for name in ("org_id", "row_id", "hash", "hmac")]
        if not all(isinstance(value, str) and value for value in values):
            raise ValueError(f"audit head on line {number} lacks org_id, row_id, hash or hmac")
        org_id, row_id, entry_hash, mac = values
        block = [record.get(name) for name in REQUIRED_SIGNATURE_FIELDS]
        stamp = record.get("signed_at")
        present = any(value is not None for value in (*block, stamp))
        complete = all(_text(value) for value in block) and (stamp is None or _text(stamp))
        if present and not complete:
            raise ValueError(
                f"audit head on line {number} has an incomplete signature block"
                f" ({', '.join(REQUIRED_SIGNATURE_FIELDS)}, optional signed_at)"
            )
        alg, public_key, signature = (None if value is None else str(value) for value in block)
        signed_at = None if stamp is None else str(stamp)
        count, first, digest = _parse_binding(record, number)
        filtered, filter_pairs = _parse_filters(record, number, count is not None)
        heads.append(
            SignedHead(
                str(org_id),
                str(row_id),
                str(entry_hash),
                str(mac),
                alg,
                public_key,
                signature,
                signed_at,
                count,
                first,
                digest,
                filtered,
                filter_pairs,
            )
        )
    return heads


def _parse_filters(
    record: dict[str, Any], number: int, bound: bool
) -> tuple[bool | None, tuple[tuple[str, str], ...] | None]:
    """``filtered: true`` with its ``filters``, or neither; a filtered head must bind content."""
    if not any(name in record for name in FILTER_FIELDS):
        return None, None
    filters = record.get("filters")
    if (
        bound
        and record.get("filtered") is True
        and isinstance(filters, dict)
        and all(isinstance(k, str) and isinstance(v, str) for k, v in filters.items())
    ):
        return True, tuple(sorted(filters.items()))
    raise ValueError(
        f"audit head on line {number} has an incomplete or malformed filtered marker"
        f" ({', '.join(FILTER_FIELDS)}, needs the content binding)"
    )


def _parse_binding(
    record: dict[str, Any], number: int
) -> tuple[int | None, str | None, str | None]:
    """The binding fields of a head record: all three valid, or none (a legacy head)."""
    if not any(name in record for name in BINDING_FIELDS):
        return None, None, None
    count, first, digest = (record.get(name) for name in BINDING_FIELDS)
    if (
        all(name in record for name in BINDING_FIELDS)
        and isinstance(count, int)
        and not isinstance(count, bool)
        and count >= 0
        and (first is None or _text(first))
        and isinstance(digest, str)
        and len(digest) == SHA256_HEX_CHARS
    ):
        return count, None if first is None else str(first), digest
    raise ValueError(
        f"audit head on line {number} has an incomplete or malformed content binding"
        f" ({', '.join(BINDING_FIELDS)})"
    )


def _head_finding(head: SignedHead, kind_name: str, detail: str) -> "ChainFinding":
    from sandfort.services.audit_chain import ChainFinding, FindingKind

    return ChainFinding(FindingKind[kind_name], head.org_id, head.row_id, detail)


class HeadWatcher:
    """Checks that a walk over one org's rows reaches an exported head (truncation check)."""

    def __init__(self, head: SignedHead) -> None:
        self._head = head
        self._seen: str | None = None
        self._reached = False

    def observe(self, row: ChainedAuditEvent) -> None:
        if row.event.id == self._head.row_id:
            self._reached = True
            self._seen = row.entry_hash

    def finding(self) -> "ChainFinding | None":
        head = self._head
        if not self._reached:
            detail = "exported head row is gone: the chain was truncated or pruned past it"
        elif not digest_equal(self._seen or "", head.entry_hash):
            detail = "exported head row now has a different hash"
        else:
            return None
        return _head_finding(head, "HEAD_MISSING", detail)


def invalid_head_finding(head: SignedHead) -> "ChainFinding":
    return _head_finding(head, "HEAD_INVALID", "head signature does not verify")
