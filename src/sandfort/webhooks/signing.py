"""Standard Webhooks signing (https://www.standardwebhooks.com).

A delivery carries three headers: ``webhook-id`` (stable per event, so receivers can
deduplicate retries), ``webhook-timestamp`` (unix seconds) and ``webhook-signature``, one or
more space separated ``v1,<base64 hmac-sha256>`` entries. The signed content is
``{id}.{timestamp}.{payload}`` and the HMAC key is the base64-decoded endpoint secret with its
``whsec_`` prefix stripped.
"""

import base64
import binascii
import hashlib
import hmac
import secrets
import time
from collections.abc import Mapping

SECRET_PREFIX = "whsec_"
SECRET_BYTES = 32
ID_HEADER = "webhook-id"
TIMESTAMP_HEADER = "webhook-timestamp"
SIGNATURE_HEADER = "webhook-signature"
SIGNATURE_VERSION = "v1"
DEFAULT_TOLERANCE_S = 300


def generate_secret() -> str:
    """A fresh endpoint secret: ``whsec_`` plus the base64 of 32 random bytes."""
    return SECRET_PREFIX + base64.b64encode(secrets.token_bytes(SECRET_BYTES)).decode()


def _key(secret: str) -> bytes:
    body = secret.removeprefix(SECRET_PREFIX)
    try:
        return base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("webhook secret is not valid base64") from None


def compute_signature(secret: str, message_id: str, timestamp: int, payload: bytes) -> str:
    """The ``v1,<base64>`` signature entry for one message."""
    content = f"{message_id}.{timestamp}.".encode() + payload
    digest = hmac.new(_key(secret), content, hashlib.sha256).digest()
    return f"{SIGNATURE_VERSION},{base64.b64encode(digest).decode()}"


def sign_headers(secret: str, message_id: str, timestamp: int, payload: bytes) -> dict[str, str]:
    """The three delivery headers for ``payload``."""
    return {
        ID_HEADER: message_id,
        TIMESTAMP_HEADER: str(timestamp),
        SIGNATURE_HEADER: compute_signature(secret, message_id, timestamp, payload),
    }


def verify(
    secret: str,
    headers: Mapping[str, str],
    payload: bytes,
    *,
    now: int | None = None,
    tolerance_s: int = DEFAULT_TOLERANCE_S,
) -> bool:
    """True when a signature entry matches and the timestamp is within ``tolerance_s``."""
    lowered = {name.lower(): value for name, value in headers.items()}
    try:
        message_id = lowered[ID_HEADER]
        timestamp = int(lowered[TIMESTAMP_HEADER])
        supplied = lowered[SIGNATURE_HEADER].split()
    except (KeyError, ValueError):
        return False
    current = int(time.time()) if now is None else now
    if abs(current - timestamp) > tolerance_s:
        return False
    expected = compute_signature(secret, message_id, timestamp, payload)
    return any(hmac.compare_digest(expected, entry) for entry in supplied)
