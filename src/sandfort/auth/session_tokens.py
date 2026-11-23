"""Stateless, signed, short-lived user session tokens for the single sign-on flow.

Token format ``sfs_<payload>.<signature>``: ``payload`` is the base64url (unpadded)
JSON claims and ``signature`` the base64url HMAC-SHA-256 of ``payload`` under the
server's session secret. The ``sfs_`` prefix is distinct from API keys (``sf_``),
so the bearer path can tell them apart without a lookup. Timestamps are whole
epoch seconds. Every verification failure raises the same generic ``Unauthorized``
so a wrong secret is indistinguishable from a tampered payload, and no token
material is ever logged or put in an error message.
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

from pydantic import BaseModel, ConfigDict

from sandfort.domain.user import OrgRole
from sandfort.errors import Unauthorized
from sandfort.ids import JOB, new_id

SESSION_PREFIX = "sfs_"
SESSION_ID_PREFIX = "ses"
INVALID_SESSION_MESSAGE = "invalid session token"
_SEPARATOR = "."
_B64URL_PATTERN = re.compile(r"[A-Za-z0-9_-]+")


class SessionClaims(BaseModel):
    model_config = ConfigDict(frozen=True)

    token_id: str
    user_id: str
    org_id: str
    role: OrgRole
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class _Parts:
    payload: str
    signature: bytes


def new_session_token_id() -> str:
    """Same body as other ids, under the ``ses`` prefix (the id registry is frozen)."""
    return f"{SESSION_ID_PREFIX}_{new_id(JOB).partition('_')[2]}"


def is_session_token(token: str) -> bool:
    return token.startswith(SESSION_PREFIX)


def mint_session_token(
    secret: str,
    *,
    user_id: str,
    org_id: str,
    role: OrgRole,
    now: datetime,
    ttl_s: int,
) -> str:
    """Sign a session for ``user_id`` in ``org_id`` valid from ``now`` for ``ttl_s`` seconds."""
    if not secret:
        raise ValueError("session secret must not be empty")
    if ttl_s <= 0:
        raise ValueError("session ttl must be positive")
    issued = int(now.timestamp())
    body = {
        "jti": new_session_token_id(),
        "sub": user_id,
        "org": org_id,
        "role": role.value,
        "iat": issued,
        "exp": issued + ttl_s,
    }
    payload = _b64encode(json.dumps(body, separators=(",", ":"), sort_keys=True).encode())
    return f"{SESSION_PREFIX}{payload}{_SEPARATOR}{_b64encode(_sign(secret, payload))}"


def verify_session_token(secret: str, token: str, now: datetime) -> SessionClaims:
    """Return the claims of a genuine, unexpired token; raise ``Unauthorized`` otherwise."""
    if not secret:
        raise _invalid()
    parts = _split(token)
    if not hmac.compare_digest(_sign(secret, parts.payload), parts.signature):
        raise _invalid()
    claims = _claims(_decode_json(parts.payload))
    if now >= claims.expires_at:
        raise _invalid()
    return claims


def _invalid() -> Unauthorized:
    return Unauthorized(INVALID_SESSION_MESSAGE)


def _sign(secret: str, payload: str) -> bytes:
    return hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest()


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    if _B64URL_PATTERN.fullmatch(text) is None:
        raise _invalid()
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise _invalid() from None


def _split(token: str) -> _Parts:
    if not token.startswith(SESSION_PREFIX):
        raise _invalid()
    payload, sep, signature = token[len(SESSION_PREFIX) :].partition(_SEPARATOR)
    if not sep or _SEPARATOR in signature or _B64URL_PATTERN.fullmatch(payload) is None:
        raise _invalid()
    return _Parts(payload=payload, signature=_b64decode(signature))


def _decode_json(payload: str) -> dict[str, Any]:
    try:
        decoded = json.loads(_b64decode(payload))
    except ValueError:  # JSONDecodeError and UnicodeDecodeError are both ValueErrors
        raise _invalid() from None
    if not isinstance(decoded, dict):
        raise _invalid()
    return decoded


def _claims(body: dict[str, Any]) -> SessionClaims:
    try:
        text = {key: _text(body[key]) for key in ("jti", "sub", "org", "role")}
        return SessionClaims(
            token_id=text["jti"],
            user_id=text["sub"],
            org_id=text["org"],
            role=OrgRole(text["role"]),
            issued_at=_instant(body["iat"]),
            expires_at=_instant(body["exp"]),
        )
    except (KeyError, ValueError, OverflowError, OSError):
        raise _invalid() from None


def _text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("claim must be a non-empty string")
    return value


def _instant(value: object) -> datetime:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("timestamp must be an integer")
    return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=value)
