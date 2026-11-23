"""OpenID Connect identity token verification for the single sign-on exchange.

``OidcVerifier`` fetches the provider's JSON web key set from ``oidc_jwks_url`` with the
httpx async client, reuses it for ``oidc_jwks_cache_s`` seconds of the injected clock, and
checks an identity token: the signing key is resolved by ``kid``, only RS256 is accepted,
and signature, issuer and audience are verified by pyjwt. Expiry (and ``nbf`` when present)
is checked against the injected clock rather than the wall clock pyjwt would read, with
``CLOCK_LEEWAY_S`` of leeway. The token needs a header type of ``JWT``, an ``iat`` no older
than ``MAX_TOKEN_AGE_S``, ``email_verified`` exactly ``true`` and, for a list audience, an
``azp`` equal to the configured audience. A non-empty ascii email claim is required and
returned lowercased.

Every failure is a generic ``Unauthorized``: neither the token nor the key set url ever
appears in an error message or a log line. pyjwt is reached only through the small typed
wrappers at the bottom of this module.
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx
import jwt
from jwt.types import Options
from pydantic import BaseModel, ConfigDict

from sandfort.clock import Clock
from sandfort.config import Settings
from sandfort.errors import Unauthorized

logger = logging.getLogger(__name__)

REQUIRED_ALGORITHM = "RS256"
RSA_KEY_TYPE = "RSA"
JWKS_TIMEOUT_S = 5.0
MAX_JWKS_BYTES = 256 * 1024
INVALID_TOKEN_MESSAGE = "invalid identity token"
NOT_CONFIGURED_MESSAGE = "single sign-on is not configured"
KEYS_UNAVAILABLE_MESSAGE = "identity provider keys are unavailable"
MAX_TOKEN_AGE_S = 300
CLOCK_LEEWAY_S = 60
IDENTITY_TOKEN_TYPE = "jwt"
_REQUIRED_CLAIMS = ("exp", "iat", "iss", "aud", "sub", "email")


class IdentityClaims(BaseModel):
    """What the exchange needs from a verified identity token."""

    model_config = ConfigDict(frozen=True)

    subject: str
    email: str


@dataclass(frozen=True, slots=True)
class _CachedKeys:
    keys: jwt.PyJWKSet
    fetched_at: datetime


class OidcVerifier:
    def __init__(self, settings: Settings, clock: Clock) -> None:
        self._issuer = settings.oidc_issuer
        self._audience = settings.oidc_audience
        self._jwks_url = settings.oidc_jwks_url
        self._org_id = settings.oidc_org_id
        self._cache_s = settings.oidc_jwks_cache_s
        self._clock = clock
        self._cached: _CachedKeys | None = None

    @property
    def configured(self) -> bool:
        """True only when issuer, audience, key set url and org are all set."""
        return all((self._issuer, self._audience, self._jwks_url, self._org_id))

    async def verify(self, token: str) -> IdentityClaims:
        """Return the claims of a genuine, unexpired token; raise ``Unauthorized`` otherwise."""
        if not self.configured:
            raise Unauthorized(NOT_CONFIGURED_MESSAGE)
        key_id = _key_id(token)  # malformed tokens are refused before any fetch
        signing_key = _signing_key(await self._key_set(), key_id)
        payload = _decode(token, signing_key, issuer=self._issuer, audience=self._audience)
        _check_audience(payload, self._audience)
        _check_times(payload, self._clock.now())
        return _claims(payload)

    async def _key_set(self) -> jwt.PyJWKSet:
        now = self._clock.now()
        cached = self._cached
        if cached is not None and self._is_fresh(cached, now):
            return cached.keys
        keys = await _fetch_key_set(self._jwks_url)
        self._cached = _CachedKeys(keys=keys, fetched_at=now)
        return keys

    def _is_fresh(self, cached: _CachedKeys, now: datetime) -> bool:
        age_s = (now - cached.fetched_at).total_seconds()
        return 0 <= age_s < self._cache_s


def _invalid() -> Unauthorized:
    return Unauthorized(INVALID_TOKEN_MESSAGE)


async def _fetch_key_set(url: str) -> jwt.PyJWKSet:
    try:
        async with httpx.AsyncClient(timeout=JWKS_TIMEOUT_S) as client:
            response = await client.get(url, headers={"accept": "application/json"})
        response.raise_for_status()
        if len(response.content) > MAX_JWKS_BYTES:
            raise ValueError("key set document is too large")
        document: object = response.json()
        if not isinstance(document, dict):
            raise ValueError("key set document must be a JSON object")
        return _parse_key_set(document)
    except (httpx.HTTPError, httpx.InvalidURL, ValueError, jwt.PyJWTError) as exc:
        # Only the exception type: httpx messages carry the url.
        logger.warning("OIDC key set unavailable: %s", type(exc).__name__)
        raise Unauthorized(KEYS_UNAVAILABLE_MESSAGE) from None


def _parse_key_set(document: dict[str, Any]) -> jwt.PyJWKSet:
    return jwt.PyJWKSet.from_dict(document)


def _key_id(token: str) -> str:
    header = _unverified_header(token)
    key_id = header.get("kid")
    if header.get("alg") != REQUIRED_ALGORITHM or not isinstance(key_id, str) or not key_id:
        raise _invalid()
    token_type = header.get("typ")
    if not isinstance(token_type, str) or token_type.casefold() != IDENTITY_TOKEN_TYPE:
        raise _invalid()
    return key_id


def _unverified_header(token: str) -> dict[str, Any]:
    try:
        return jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise _invalid() from None


def _signing_key(keys: jwt.PyJWKSet, key_id: str) -> jwt.PyJWK:
    try:
        key = keys[key_id]
    except KeyError:
        raise _invalid() from None
    if key.key_type != RSA_KEY_TYPE or key.algorithm_name != REQUIRED_ALGORITHM:
        raise _invalid()
    return key


def _decode(token: str, key: jwt.PyJWK, *, issuer: str, audience: str) -> dict[str, Any]:
    """Signature, issuer and audience; the time claims are left to ``_check_times``."""
    options: Options = {
        "require": list(_REQUIRED_CLAIMS),
        "verify_exp": False,
        "verify_nbf": False,
        "verify_iat": False,
    }
    try:
        return jwt.decode(
            token,
            key,
            algorithms=[REQUIRED_ALGORITHM],
            options=options,
            audience=audience,
            issuer=issuer,
        )
    except jwt.PyJWTError:
        raise _invalid() from None


def _check_audience(payload: dict[str, Any], audience: str) -> None:
    """A list audience is only valid when the authorized party is this client."""
    if isinstance(payload.get("aud"), list) and payload.get("azp") != audience:
        raise _invalid()


def _check_times(payload: dict[str, Any], now: datetime) -> None:
    instant = now.timestamp()
    expires = _epoch(payload.get("exp"))
    if expires is None or instant >= expires + CLOCK_LEEWAY_S:
        raise _invalid()
    issued = _epoch(payload.get("iat"))
    if issued is None or issued > instant + CLOCK_LEEWAY_S or instant - issued > MAX_TOKEN_AGE_S:
        raise _invalid()
    if "nbf" in payload:
        not_before = _epoch(payload["nbf"])
        if not_before is None or instant + CLOCK_LEEWAY_S < not_before:
            raise _invalid()


def _epoch(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _claims(payload: dict[str, Any]) -> IdentityClaims:
    subject = payload.get("sub")
    email = payload.get("email")
    if payload.get("email_verified") is not True:  # absent, "false" and the like are refused
        raise _invalid()
    if not isinstance(subject, str) or not subject or not isinstance(email, str):
        raise _invalid()
    if not email.isascii():  # before lowercasing: the Kelvin sign would fold to ascii "k"
        raise _invalid()
    normalised = email.strip().lower()
    if not normalised:
        raise _invalid()
    return IdentityClaims(subject=subject, email=normalised)
