"""Auditor-side check of the signed ``audit_head`` trailer of an audit export.

The server signs the head with Ed25519 when ``SANDFORT_AUDIT_SIGNING_KEY`` is set and publishes the
public key as ``audit_public_key`` on ``GET /v1/status``. Checking needs that public key alone: no
secret. The key is the trust anchor and must come from the caller (pinned, or read from the status
route of the server being audited). A head names its own ``public_key`` too, but a forger can sign
with any key and name it there, so the line's key is never trusted: it is only compared with the
anchor, and a difference is reason ``"key_mismatch"``. The canonical form below is a copy of the
server's, kept here on purpose so the SDK never imports server code: the head without
``signature`` and ``hmac``, as compact JSON with sorted keys and ASCII only. The ``hmac`` field is
not signed and is not checked here.

Heads written by servers since round 63 also carry ``row_count``, ``first_row_id`` and
``export_sha256`` (signed): the export's event-line count, the id of its first line and a SHA-256
over the exact bytes of every event line. :func:`parse_head` validates their shape; the file checks
live in :mod:`sandfort_sdk.audit_export`.
"""

import base64
import binascii
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sandfort_sdk.models import _as_dict, _optional_str

HEAD_TYPE = "audit_head"
ALG = "ed25519"
KEY_BYTES = 32
UNSIGNED_FIELDS = ("signature", "hmac")
REASON_UNSIGNED = "unsigned"
REASON_SIGNATURE = "signature"
REASON_KEY_MISMATCH = "key_mismatch"
REASON_UNDATED = "undated"
REASON_FUTURE = "future_signed_at"
BINDING_FIELDS = ("row_count", "first_row_id", "export_sha256")
SHA256_HEX_CHARS = 64
STANDARD_TO_URLSAFE = str.maketrans("+/", "-_")
FILTER_FIELDS = ("filtered", "filters")
MAX_FUTURE_SKEW = timedelta(minutes=5)
EARLIEST_SIGNED_AT = datetime(1970, 1, 2, tzinfo=UTC)
STATUS_KEY = "status"
KEY_ERROR = "public key must be an Ed25519 key: 32 bytes in urlsafe base64"
KEY_REQUIRED = "a trusted public key is required: pass one, or 'status' on the audit facade"
NO_STATUS_KEY = "the server publishes no audit_public_key; pass the public key explicitly"


@dataclass(frozen=True, slots=True)
class HeadVerification:
    """The outcome of :func:`verify_head`.

    ``row_id`` and ``entry_hash`` are what the head claims, whether or not the signature holds;
    trust them only when ``ok`` is true. ``public_key`` is the trusted key checked against
    (urlsafe base64), never the key the line names. ``reason`` is ``None`` when ``ok``, else
    ``"unsigned"``, ``"key_mismatch"`` (the line names another key than the trusted one),
    ``"signature"``, ``"undated"`` (the signature verifies but the head has no valid
    ``signed_at``: absent, without a UTC offset or before 1970-01-02) or ``"future_signed_at"``
    (``signed_at`` is more than 5 minutes ahead of this machine's clock). ``signed_at`` is the
    head's timestamp: RFC 3339 with a UTC offset, covered by the signature. It is always set
    when ``ok`` is true, and ``None`` when the head carries no valid one.

    Removed in this release: the ``anchored`` field. The trusted key always comes from the caller
    or the status route (``public_key`` is required), so the field was always true and carried no
    information. The remaining fields keep their order, so ``signed_at`` now follows ``reason``
    directly.
    """

    ok: bool
    row_id: str
    entry_hash: str
    public_key: str
    reason: str | None
    signed_at: datetime | None = None


def _b64decode(text: str) -> bytes:
    stripped = text.strip()
    padded = stripped + "=" * (-len(stripped) % 4)
    try:
        return base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raise ValueError("not urlsafe base64") from None


def _key_text(value: str | bytes) -> str:
    """The canonical urlsafe base64 text of a public key; ``ValueError`` when not 32 bytes.

    A key in standard base64 (``+`` and ``/``) is accepted as well as urlsafe (``-`` and ``_``).
    """
    try:
        raw = (
            _b64decode(value.translate(STANDARD_TO_URLSAFE))
            if isinstance(value, str)
            else bytes(value)
        )
    except ValueError:
        raise ValueError(KEY_ERROR) from None
    if len(raw) != KEY_BYTES:
        raise ValueError(KEY_ERROR)
    return base64.urlsafe_b64encode(raw).decode("ascii")


def canonical_payload(record: Mapping[str, object]) -> bytes:
    """The bytes a head signature covers (the server's canonical form)."""
    body = {name: value for name, value in record.items() if name not in UNSIGNED_FIELDS}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def parse_head(head_line: str | Mapping[str, Any]) -> dict[str, Any]:
    """The fields of an ``audit_head`` line; ``ValueError`` when it is not a usable head."""
    if isinstance(head_line, str):
        try:
            record: Any = json.loads(head_line)
        except RecursionError:
            raise ValueError("head line is nested too deeply") from None
        except ValueError:
            raise ValueError("head line is not JSON") from None
    elif isinstance(head_line, Mapping):
        record = dict(head_line)
    else:
        raise ValueError("head must be a JSON line or a mapping")
    if not isinstance(record, dict):
        raise ValueError("head line is not a JSON object")
    if record.get("type") != HEAD_TYPE:
        raise ValueError("line is not an audit_head")
    for name in ("row_id", "hash"):
        if not isinstance(record.get(name), str) or not record[name]:
            raise ValueError(f"audit_head lacks a non-empty {name!r}")
    _check_binding(record)
    return record


def head_binding(record: Mapping[str, Any]) -> tuple[int, str | None, str] | None:
    """``(row_count, first_row_id, export_sha256)`` of a parsed head; ``None`` for a legacy head
    that carries none of them. Call it on a record that :func:`parse_head` accepted."""
    if not any(name in record for name in BINDING_FIELDS):
        return None
    return record["row_count"], record["first_row_id"], record["export_sha256"]


def head_is_filtered(record: Mapping[str, Any]) -> bool:
    """Whether a parsed head marks a filtered export (``filtered: true``)."""
    return record.get("filtered") is True


def _check_filters(record: Mapping[str, Any]) -> None:
    """``filtered`` and ``filters`` come together, ``filtered`` is true, and the head binds
    content; or neither is present."""
    if not any(name in record for name in FILTER_FIELDS):
        return
    filters = record.get("filters")
    if (
        record.get("filtered") is True
        and all(name in record for name in BINDING_FIELDS)
        and isinstance(filters, dict)
        and all(isinstance(k, str) and isinstance(v, str) for k, v in filters.items())
    ):
        return
    raise ValueError(
        "audit_head has an incomplete or malformed filtered marker (filtered, filters)"
    )


def _check_binding(record: Mapping[str, Any]) -> None:
    """The three content fields come together and have their shapes, or none is present."""
    _check_filters(record)
    if not any(name in record for name in BINDING_FIELDS):
        return
    count, first, digest = (record.get(name) for name in BINDING_FIELDS)
    if (
        all(name in record for name in BINDING_FIELDS)
        and isinstance(count, int)
        and not isinstance(count, bool)
        and count >= 0
        and (first is None or (isinstance(first, str) and first))
        and isinstance(digest, str)
        and len(digest) == SHA256_HEX_CHARS
    ):
        return
    raise ValueError(
        f"audit_head has an incomplete or malformed content binding ({', '.join(BINDING_FIELDS)})"
    )


def _absent(value: object) -> bool:
    return value is None or value == ""


def _signature_holds(key_text: str, record: Mapping[str, Any], signature: str) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(_b64decode(key_text))
        payload = canonical_payload(record)
        key.verify(_b64decode(signature), payload)
    except (InvalidSignature, ValueError, TypeError, RecursionError):
        return False
    return True


def trusted_key_text(public_key: str | bytes | None) -> str:
    """The canonical text of the caller's trust anchor; ``ValueError`` when missing or malformed."""
    if public_key is None:
        raise ValueError(KEY_REQUIRED)
    return _key_text(public_key)


def _signed_at(record: Mapping[str, Any]) -> datetime | None:
    """The head's ``signed_at`` when it is an ISO 8601 text with a UTC offset, else ``None``."""
    value = record.get("signed_at")
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    if moment.utcoffset() is None or moment < EARLIEST_SIGNED_AT:
        return None
    return moment


def _names_other_key(record: Mapping[str, Any], trusted: str) -> bool:
    """Whether the line names a key that is not the trusted one (a malformed one counts)."""
    named = record.get("public_key")
    if not isinstance(named, str) or not named:
        return False
    try:
        return _key_text(named) != trusted
    except ValueError:
        return True


def verify_head(head_line: str | Mapping[str, Any], public_key: str | bytes) -> HeadVerification:
    """Check the Ed25519 signature of a head against ``public_key``, the trust anchor.

    ``public_key`` is required (urlsafe base64 text or the 32 raw bytes) and must come from the
    caller or from the status route of the audited server, never from the line. The key the line
    names is only compared with it: another key gives ``ok=False`` with reason ``"key_mismatch"``,
    so a head forged and signed with the forger's own key is refused. Raises ``ValueError`` for a
    malformed line or a missing or malformed ``public_key``. An unsigned head, a wrong key and a
    tampered line give ``ok=False`` with a ``reason``.

    ``ok`` also needs a valid ``signed_at`` (RFC 3339 with a UTC offset, as the server writes
    it). A head whose signature verifies but that lacks one returns ``ok=False`` with reason
    ``"undated"``, so a legacy head cannot be mistaken for a fresh one. Heads written by servers
    from beta.60 to beta.64 carry no ``signed_at`` and fall in that class, as does a
    ``signed_at`` before 1970-01-02. A ``signed_at`` more than 5 minutes ahead of the local clock
    gives reason ``"future_signed_at"``: a head cannot be dated in the future.
    """
    record = parse_head(head_line)
    trusted = trusted_key_text(public_key)
    signed_at = _signed_at(record)

    row_id, entry_hash = record["row_id"], record["hash"]

    def outcome(ok: bool, reason: str | None) -> HeadVerification:
        return HeadVerification(ok, row_id, entry_hash, trusted, reason, signed_at)

    signature, alg = record.get("signature"), record.get("alg")
    if _absent(signature) or _absent(alg):
        return outcome(False, REASON_UNSIGNED)
    if alg != ALG or not isinstance(signature, str):
        return outcome(False, REASON_SIGNATURE)
    if _names_other_key(record, trusted):
        return outcome(False, REASON_KEY_MISMATCH)
    if not _signature_holds(trusted, record, signature):
        return outcome(False, REASON_SIGNATURE)
    if signed_at is None:
        return outcome(False, REASON_UNDATED)
    if signed_at > datetime.now(UTC) + MAX_FUTURE_SKEW:
        return outcome(False, REASON_FUTURE)
    return outcome(True, None)


def public_key_from_status(data: Any) -> str | None:
    """``audit_public_key`` of a status document; ``None`` when unset or empty."""
    raw = _as_dict(data, "status")
    value = _optional_str(raw.get("audit_public_key"), "status audit_public_key")
    return value or None
