"""Ed25519 signing of the audit head (``SANDFORT_AUDIT_SIGNING_KEY``).

The key is an Ed25519 private key: raw 32 bytes in urlsafe base64, or a PEM block (PKCS#8, no
passphrase). It is optional; empty means the head carries only its HMAC. This module is a
top-level leaf: it imports only the standard library and ``cryptography``, so
``sandfort.config`` can validate the setting without depending on ``sandfort.services``
(``sandfort.services.audit_head_signing`` re-exports it). It never logs or echoes key material
and never reads the process environment: the signer comes from ``Settings.audit_signer``.
"""

import base64
import binascii
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import lru_cache

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

AUDIT_SIGNING_KEY_ENV = "SANDFORT_AUDIT_SIGNING_KEY"
ALG = "ed25519"
KEY_BYTES = 32
PEM_MARKER = "-----BEGIN"
ESCAPED_NEWLINE = "\\n"
# Fields of an ``audit_head`` line that the signature does not cover.
UNSIGNED_FIELDS = ("signature", "hmac")
SIGNED_AT_TIMESPEC = "seconds"


def _b64decode(text: str) -> bytes:
    """Urlsafe base64 with or without padding; ``ValueError`` when it is not base64."""
    stripped = text.strip()
    padded = stripped + "=" * (-len(stripped) % 4)
    try:
        return base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raise ValueError("not urlsafe base64") from None


def b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def parse_signing_key(text: str) -> Ed25519PrivateKey:
    """The private key in ``text`` (raw urlsafe base64 or PEM); ``ValueError`` when malformed.

    The message names the expected formats only; it never contains the value.
    """
    value = text.strip()
    try:
        if PEM_MARKER in value:
            pem = value if "\n" in value else value.replace(ESCAPED_NEWLINE, "\n")
            loaded = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
            if not isinstance(loaded, Ed25519PrivateKey):
                raise ValueError("not an Ed25519 key")
            return loaded
        raw = _b64decode(value)
        if len(raw) != KEY_BYTES:
            raise ValueError("wrong length")
        return Ed25519PrivateKey.from_private_bytes(raw)
    except (ValueError, TypeError, UnicodeEncodeError):
        raise ValueError(
            "must be an Ed25519 private key: 32 raw bytes in urlsafe base64, or a PEM block"
        ) from None


def public_key_to_text(public: Ed25519PublicKey) -> str:
    """The raw 32-byte public key in urlsafe base64."""
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return b64encode(raw)


def public_key_text(key: Ed25519PrivateKey) -> str:
    """The raw 32-byte public key of the private ``key`` in urlsafe base64."""
    return public_key_to_text(key.public_key())


def canonical_payload(record: Mapping[str, object]) -> bytes:
    """The bytes a head signature covers: the head without ``signature`` and ``hmac``.

    Compact JSON, keys sorted, ASCII only: the form ``SignedHead.to_line`` writes.
    """
    body = {name: value for name, value in record.items() if name not in UNSIGNED_FIELDS}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def format_signed_at(moment: datetime) -> str:
    """``moment`` as UTC ISO 8601 to the second; ``ValueError`` for a naive datetime."""
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("signed_at must be timezone-aware (UTC)")
    return moment.astimezone(UTC).isoformat(timespec=SIGNED_AT_TIMESPEC)


def parse_signed_at(text: str) -> datetime:
    """The UTC instant of a ``signed_at`` value; ``ValueError`` unless ISO 8601 at UTC."""
    moment = datetime.fromisoformat(text)
    if moment.utcoffset() != timedelta(0):
        raise ValueError("signed_at is not ISO 8601 in UTC")
    return moment.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class HeadSigner:
    """An Ed25519 signing key with its public key derived once."""

    private: Ed25519PrivateKey = field(repr=False)
    public_key: str

    def sign(self, payload: bytes) -> str:
        return b64encode(self.private.sign(payload))


@lru_cache(maxsize=8)
def signer_from_text(text: str) -> HeadSigner | None:
    """The signer for a setting value (``None`` for an empty one); parsed once per value.

    Raises ``ValueError`` (naming the formats, never the value) when ``text`` is malformed.
    """
    if not text.strip():
        return None
    private = parse_signing_key(text)
    return HeadSigner(private, public_key_text(private))


def load_public_key(value: bytes | str) -> Ed25519PublicKey:
    """A public key from its raw 32 bytes or its urlsafe base64 text; ``ValueError`` otherwise."""
    raw = _b64decode(value) if isinstance(value, str) else value
    if len(raw) != KEY_BYTES:
        raise ValueError("an Ed25519 public key is 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def verify_payload(public_key: Ed25519PublicKey, payload: bytes, signature: str) -> bool:
    """Whether ``signature`` (urlsafe base64) is ``public_key``'s signature over ``payload``."""
    try:
        public_key.verify(_b64decode(signature), payload)
    except (InvalidSignature, ValueError):
        return False
    return True
