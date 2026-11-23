"""Signed egress tokens: the proxy credential that carries a sandbox's allowlist.

Token format ``sfe_<payload>.<signature>``: ``payload`` is the base64url (unpadded) JSON
claims and ``signature`` the base64url HMAC-SHA-256 of ``payload`` under the egress secret.
This mirrors ``sandfort.auth.session_tokens``. The allowlist is immutable for the life of a
sandbox, so the expiry only bounds the damage of a leaked token. The lifetime is a setting
(``Settings.egress_token_ttl_s``, default 7 days) that callers pass in; a sandbox with an
auto-delete horizon gets that horizon plus one day instead, never more than the setting
(``token_lifetime_s``). A token is minted when a sandbox is created and baked into its
environment. The lifecycle core mints a fresh one only when a reset recreates the container
(``Lifecycle.refresh_egress``); a start reuses the container and keeps its token, so a
sandbox that outlives its token needs a reset. The proxy also rejects tokens whose lifetime
exceeds its own limit, except tokens issued before ``LEGACY_TOKEN_CUTOVER``:
earlier releases minted them for up to 400 days, and they stay valid until they expire, so an
upgrade does not cut every existing allowlisted sandbox off.
Every verification failure raises the same generic ``InvalidEgressToken``: a wrong secret is
indistinguishable from a tampered payload, and no token material reaches an error message.
"""

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sandfort.config import DEFAULT_EGRESS_TOKEN_TTL_S, egress_limits_from

EGRESS_PREFIX = "sfe_"
EGRESS_TOKEN_TTL_S = DEFAULT_EGRESS_TOKEN_TTL_S
# Tokens issued before this instant predate the lifetime limit (minted for up to 400 days).
LEGACY_TOKEN_CUTOVER = datetime(2026, 11, 11, tzinfo=UTC)
AUTO_DELETE_GRACE_S = 24 * 3600  # a token outlives the auto-delete horizon by one day
INVALID_EGRESS_MESSAGE = "invalid egress token"
_SEPARATOR = "."
_B64URL_PATTERN = re.compile(r"[A-Za-z0-9_-]+")


class InvalidEgressToken(Exception):
    """The token is not genuine, not well formed or expired; the message is always generic."""

    def __init__(self) -> None:
        super().__init__(INVALID_EGRESS_MESSAGE)


@dataclass(frozen=True, slots=True)
class EgressClaims:
    sandbox_id: str
    allowlist: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class _Parts:
    payload: str
    signature: bytes


def mint_egress_token(
    secret: str,
    *,
    sandbox_id: str,
    allowlist: tuple[str, ...] | list[str],
    now: datetime,
    ttl_s: int | None = None,
) -> str:
    """Sign ``allowlist`` for ``sandbox_id``, valid from ``now`` for ``ttl_s`` seconds.

    Server code passes ``ttl_s`` (the settings value, threaded through ``compose_proxy_env``).
    Without it the lifetime falls back to ``SANDFORT_EGRESS_TOKEN_TTL_S`` (default 7 days),
    kept only for callers that do not pass the setting yet.
    """
    if not secret:
        raise ValueError("egress secret must not be empty")
    if not sandbox_id:
        raise ValueError("sandbox id must not be empty")
    lifetime = egress_limits_from(os.environ).token_ttl_s if ttl_s is None else ttl_s
    if lifetime <= 0:
        raise ValueError("token lifetime must be positive")
    issued = int(now.timestamp())
    body = {
        "sbx": sandbox_id,
        "allow": list(allowlist),
        "iat": issued,
        "exp": issued + lifetime,
    }
    payload = _b64encode(json.dumps(body, separators=(",", ":"), sort_keys=True).encode())
    return f"{EGRESS_PREFIX}{payload}{_SEPARATOR}{_b64encode(_sign(secret, payload))}"


def token_lifetime_s(max_ttl_s: int, auto_delete_minutes: int | None) -> int:
    """Lifetime of a new token: the auto-delete horizon plus one day, at most ``max_ttl_s``.

    ``None`` or a negative ``auto_delete_minutes`` (auto-delete off) gives ``max_ttl_s``.
    """
    if auto_delete_minutes is None or auto_delete_minutes < 0:
        return max_ttl_s
    return min(auto_delete_minutes * 60 + AUTO_DELETE_GRACE_S, max_ttl_s)


def exceeds_lifetime(claims: EgressClaims, max_lifetime_s: int, now: datetime) -> bool:
    """True when ``claims`` were minted for longer than the limit or are older than it."""
    limit = timedelta(seconds=max_lifetime_s)
    return claims.expires_at - claims.issued_at > limit or now >= claims.issued_at + limit


def is_legacy(claims: EgressClaims, cutover: datetime) -> bool:
    """True when the token was issued before ``cutover`` (a token that predates the limit)."""
    return claims.issued_at < cutover


def verify_egress_token(
    secret: str,
    token: str,
    now: datetime,
    max_lifetime_s: int | None = None,
    *,
    legacy_before: datetime | None = None,
) -> EgressClaims:
    """Return the claims of a genuine, unexpired token; raise ``InvalidEgressToken`` otherwise.

    With ``max_lifetime_s`` a token minted for longer than that is refused too, and any token
    is refused once ``max_lifetime_s`` have passed since it was issued. With ``legacy_before``
    a token issued before that instant skips the lifetime limit; its own expiry still applies.
    """
    if not secret:
        raise InvalidEgressToken
    parts = _split(token)
    if not hmac.compare_digest(_sign(secret, parts.payload), parts.signature):
        raise InvalidEgressToken
    claims = _claims(_decode_json(parts.payload))
    if now >= claims.expires_at:
        raise InvalidEgressToken
    if max_lifetime_s is None:
        return claims
    if legacy_before is not None and is_legacy(claims, legacy_before):
        return claims
    if exceeds_lifetime(claims, max_lifetime_s, now):
        raise InvalidEgressToken
    return claims


def _sign(secret: str, payload: str) -> bytes:
    return hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest()


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    if _B64URL_PATTERN.fullmatch(text) is None:
        raise InvalidEgressToken
    try:
        decoded = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise InvalidEgressToken from None
    if _b64encode(decoded) != text:  # reject non-canonical spellings (nonzero trailing bits)
        raise InvalidEgressToken
    return decoded


def _split(token: str) -> _Parts:
    if not token.startswith(EGRESS_PREFIX):
        raise InvalidEgressToken
    payload, sep, signature = token[len(EGRESS_PREFIX) :].partition(_SEPARATOR)
    if not sep or _SEPARATOR in signature or _B64URL_PATTERN.fullmatch(payload) is None:
        raise InvalidEgressToken
    _b64decode(payload)  # canonical-encoding check before any other verification step
    return _Parts(payload=payload, signature=_b64decode(signature))


def _decode_json(payload: str) -> dict[str, Any]:
    try:
        decoded = json.loads(_b64decode(payload))
    except ValueError:  # JSONDecodeError and UnicodeDecodeError are both ValueErrors
        raise InvalidEgressToken from None
    if not isinstance(decoded, dict):
        raise InvalidEgressToken
    return decoded


def _claims(body: dict[str, Any]) -> EgressClaims:
    try:
        allow = body["allow"]
        if not isinstance(allow, list):
            raise ValueError("allow must be a list")
        return EgressClaims(
            sandbox_id=_text(body["sbx"]),
            allowlist=tuple(_text(entry) for entry in allow),
            issued_at=_instant(body["iat"]),
            expires_at=_instant(body["exp"]),
        )
    except (KeyError, ValueError, OverflowError, OSError):
        raise InvalidEgressToken from None


def _text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("claim must be a non-empty string")
    return value


def _instant(value: object) -> datetime:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("timestamp must be an integer")
    return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=value)
