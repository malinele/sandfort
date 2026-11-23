"""Signed route tokens: the proof that a forwarded toolbox request was sent by a platform node.

Token format ``sfr_<payload>.<signature>``: ``payload`` is the base64url (unpadded) JSON claims
``sbx``, ``node``, ``iat`` and ``exp``, serialized with sorted keys and compact separators, and
``signature`` the base64url HMAC-SHA-256 of ``payload`` under the routing secret. This mirrors
``sandfort.egress.tokens``. A token names one sandbox and one owner node and lives for
``ROUTE_TOKEN_TTL_S`` seconds; it carries no principal, so the owner still authenticates the
caller. Verification rejects every non-canonical spelling (base64 before the signature check,
JSON before any claim is read). Every failure raises the same generic ``InvalidRouteToken``: a
wrong secret is indistinguishable from a tampered payload or a misrouted hop, and no token
material reaches an error message.
"""

import base64
import binascii
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

ROUTE_PREFIX = "sfr_"
ROUTE_TOKEN_TTL_S = 30
MAX_FUTURE_SKEW_S = 5  # an ``iat`` further ahead of the verifier's clock is refused
INVALID_ROUTE_MESSAGE = "invalid route token"
_CLAIM_KEYS = frozenset({"sbx", "node", "iat", "exp"})
_SEPARATOR = "."
_B64URL_PATTERN = re.compile(r"[A-Za-z0-9_-]+")


class InvalidRouteToken(Exception):
    """The token is not genuine, well formed, live or for this hop; the message is generic."""

    def __init__(self) -> None:
        super().__init__(INVALID_ROUTE_MESSAGE)


@dataclass(frozen=True, slots=True)
class RouteClaims:
    sandbox_id: str
    node_id: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class _Parts:
    payload: str
    payload_bytes: bytes
    signature: bytes


def mint_route_token(secret: str, *, sandbox_id: str, node_id: str, now: datetime) -> str:
    """Sign one hop of ``sandbox_id`` to the owner ``node_id``.

    The token is valid from ``now`` for ``ROUTE_TOKEN_TTL_S`` seconds.
    """
    if not secret:
        raise ValueError("routing secret must not be empty")
    if not sandbox_id:
        raise ValueError("sandbox id must not be empty")
    if not node_id:
        raise ValueError("node id must not be empty")
    issued = int(now.timestamp())
    body: dict[str, object] = {
        "sbx": sandbox_id,
        "node": node_id,
        "iat": issued,
        "exp": issued + ROUTE_TOKEN_TTL_S,
    }
    payload = _b64encode(_canonical_json(body))
    return f"{ROUTE_PREFIX}{payload}{_SEPARATOR}{_b64encode(_sign(secret, payload))}"


def verify_route_token(
    secret: str, token: str, *, node_id: str, sandbox_id: str, now: datetime
) -> RouteClaims:
    """Return the claims of a genuine, live token for exactly ``node_id`` and ``sandbox_id``.

    Raise ``InvalidRouteToken`` otherwise.
    """
    if not secret:
        raise InvalidRouteToken
    parts = _split(token)
    if not hmac.compare_digest(_sign(secret, parts.payload), parts.signature):
        raise InvalidRouteToken
    claims = _claims(_decode_json(parts.payload_bytes))
    if now >= claims.expires_at:
        raise InvalidRouteToken
    if claims.issued_at > now + timedelta(seconds=MAX_FUTURE_SKEW_S):
        raise InvalidRouteToken
    if claims.expires_at - claims.issued_at > timedelta(seconds=ROUTE_TOKEN_TTL_S):
        raise InvalidRouteToken
    if claims.node_id != node_id or claims.sandbox_id != sandbox_id:
        raise InvalidRouteToken
    return claims


def _sign(secret: str, payload: str) -> bytes:
    return hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest()


def _canonical_json(body: dict[str, object]) -> bytes:
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode("ascii")


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    if _B64URL_PATTERN.fullmatch(text) is None:
        raise InvalidRouteToken
    try:
        decoded = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise InvalidRouteToken from None
    if _b64encode(decoded) != text:  # reject non-canonical spellings (nonzero trailing bits)
        raise InvalidRouteToken
    return decoded


def _split(token: str) -> _Parts:
    if not token.startswith(ROUTE_PREFIX):
        raise InvalidRouteToken
    payload, sep, signature = token[len(ROUTE_PREFIX) :].partition(_SEPARATOR)
    if not sep or _SEPARATOR in signature or _B64URL_PATTERN.fullmatch(payload) is None:
        raise InvalidRouteToken
    payload_bytes = _b64decode(payload)  # canonical-encoding check before any other step
    return _Parts(payload=payload, payload_bytes=payload_bytes, signature=_b64decode(signature))


def _decode_json(raw: bytes) -> dict[str, Any]:
    try:
        decoded = json.loads(raw)
    except ValueError:  # JSONDecodeError and UnicodeDecodeError are both ValueErrors
        raise InvalidRouteToken from None
    if not isinstance(decoded, dict) or frozenset(decoded) != _CLAIM_KEYS:
        raise InvalidRouteToken
    if _canonical_json(decoded) != raw:  # reject re-ordered keys, whitespace and escapes
        raise InvalidRouteToken
    return decoded


def _claims(body: dict[str, Any]) -> RouteClaims:
    try:
        return RouteClaims(
            sandbox_id=_text(body["sbx"]),
            node_id=_text(body["node"]),
            issued_at=_instant(body["iat"]),
            expires_at=_instant(body["exp"]),
        )
    except (KeyError, ValueError, OverflowError, OSError):
        raise InvalidRouteToken from None


def _text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("claim must be a non-empty string")
    return value


def _instant(value: object) -> datetime:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("timestamp must be an integer")
    return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=value)

