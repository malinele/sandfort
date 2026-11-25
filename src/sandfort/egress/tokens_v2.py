"""Signed v2 egress tokens: the credential that names a sandbox and a credential epoch.

Token format ``sfe2_<payload>.<signature>``, encoded like ``sandfort.egress.tokens`` (unpadded
base64url JSON, canonical spellings only). The claims are ``{"v": 2, "sbx": <sandbox id>,
"ep": <credential epoch>, "iat": ..., "exp": ...}``: there is no allowlist claim, the proxy
looks the policy up (docs/egress-v2-design.md section 5). The signature is the HMAC-SHA-256 of
the payload under ``token_v2_key(secret)``, a key derived from the egress secret, so a token
signed with the raw secret (v1 style) never verifies here, and the prefix keeps the two
verifiers apart: this one refuses every ``sfe_`` token and ``verify_egress_token`` refuses
every ``sfe2_`` token. There is no legacy rule for v2. Every failure raises the generic
``InvalidEgressToken`` of ``sandfort.egress.tokens``.
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

from sandfort.egress.policy_wire import token_v2_key
from sandfort.egress.tokens import EGRESS_TOKEN_TTL_S, InvalidEgressToken

EGRESS_V2_PREFIX = "sfe2_"
TOKEN_VERSION = 2
_SEPARATOR = "."
_B64URL_PATTERN = re.compile(r"[A-Za-z0-9_-]+")


@dataclass(frozen=True, slots=True)
class EgressClaimsV2:
    sandbox_id: str
    epoch: int
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class _Parts:
    payload: str
    signature: bytes


def mint_egress_token_v2(
    secret: str,
    *,
    sandbox_id: str,
    epoch: int,
    now: datetime,
    ttl_s: int | None = None,
) -> str:
    """Sign ``sandbox_id`` and ``epoch``, valid from ``now`` for ``ttl_s`` seconds."""
    if not secret:
        raise ValueError("egress secret must not be empty")
    if not sandbox_id:
        raise ValueError("sandbox id must not be empty")
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
        raise ValueError("epoch must be a non-negative integer")
    lifetime = EGRESS_TOKEN_TTL_S if ttl_s is None else ttl_s
    if lifetime <= 0:
        raise ValueError("token lifetime must be positive")
    issued = int(now.timestamp())
    body = {
        "v": TOKEN_VERSION,
        "sbx": sandbox_id,
        "ep": epoch,
        "iat": issued,
        "exp": issued + lifetime,
    }
    payload = _b64encode(json.dumps(body, separators=(",", ":"), sort_keys=True).encode())
    key = token_v2_key(secret)
    return f"{EGRESS_V2_PREFIX}{payload}{_SEPARATOR}{_b64encode(_sign(key, payload))}"


def verify_egress_token_v2(
    secret: str,
    token: str,
    now: datetime,
    max_lifetime_s: int | None = None,
) -> EgressClaimsV2:
    """Return the claims of a genuine, unexpired v2 token; raise ``InvalidEgressToken`` else.

    With ``max_lifetime_s`` a token minted for longer than that is refused too, and any token
    is refused once ``max_lifetime_s`` have passed since it was issued.
    """
    if not secret:
        raise InvalidEgressToken
    parts = _split(token)
    if not hmac.compare_digest(_sign(token_v2_key(secret), parts.payload), parts.signature):
        raise InvalidEgressToken
    claims = _claims(_decode_json(parts.payload))
    if now >= claims.expires_at:
        raise InvalidEgressToken
    if max_lifetime_s is not None:
        limit = timedelta(seconds=max_lifetime_s)
        if claims.expires_at - claims.issued_at > limit or now >= claims.issued_at + limit:
            raise InvalidEgressToken
    return claims


def _sign(key: bytes, payload: str) -> bytes:
    return hmac.new(key, payload.encode("ascii"), hashlib.sha256).digest()


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
    if not token.startswith(EGRESS_V2_PREFIX):
        raise InvalidEgressToken
    payload, sep, signature = token[len(EGRESS_V2_PREFIX) :].partition(_SEPARATOR)
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


def _claims(body: dict[str, Any]) -> EgressClaimsV2:
    try:
        if _whole(body["v"]) != TOKEN_VERSION:
            raise ValueError("not a v2 token")
        return EgressClaimsV2(
            sandbox_id=_text(body["sbx"]),
            epoch=_whole(body["ep"]),
            issued_at=_instant(body["iat"]),
            expires_at=_instant(body["exp"]),
        )
    except (KeyError, ValueError, OverflowError, OSError):
        raise InvalidEgressToken from None


def _text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("claim must be a non-empty string")
    return value


def _whole(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("claim must be a non-negative integer")
    return value


def _instant(value: object) -> datetime:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("timestamp must be an integer")
    return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=value)
