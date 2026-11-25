"""Credential parsing of the egress proxy: Basic header, v1 or v2 token, username match.

``authenticate`` decodes ``Proxy-Authorization: Basic base64(<sandbox_id>:<egress token>)`` and
verifies the token locally (signature, expiry, lifetime limit). A token starting with
``sfe2_`` goes to ``verify_egress_token_v2`` and anything else to ``verify_egress_token``, so
the v2 verifier never sees an ``sfe_`` token and the v1 path is unchanged. Every failure is a
407 ``Deny`` whose detail is for the log only. The result, ``EgressCredential``, is what the
admission steps decide on: a v1 credential carries its claims allowlist, a v2 credential its
credential epoch.
"""

import base64
import binascii
import hmac
import logging
from dataclasses import dataclass
from datetime import datetime

from sandfort.egress.relay import Deny, auth_required
from sandfort.egress.tokens import (
    EgressClaims,
    InvalidEgressToken,
    exceeds_lifetime,
    is_legacy,
    verify_egress_token,
)
from sandfort.egress.tokens_v2 import EGRESS_V2_PREFIX, verify_egress_token_v2

_log = logging.getLogger("sandfort.egress")


@dataclass(frozen=True, slots=True)
class EgressCredential:
    """A verified token: ``allowlist`` is empty and ``epoch`` set for v2, ``epoch`` None for v1."""

    sandbox_id: str
    version: int
    allowlist: tuple[str, ...]
    epoch: int | None
    issued_at: datetime
    expires_at: datetime


def _verified(
    secret: str,
    token: str,
    now: datetime,
    max_lifetime_s: int | None,
    legacy_before: datetime | None,
) -> EgressCredential:
    if token.startswith(EGRESS_V2_PREFIX):
        claims_v2 = verify_egress_token_v2(secret, token, now, max_lifetime_s)
        return EgressCredential(
            sandbox_id=claims_v2.sandbox_id,
            version=2,
            allowlist=(),
            epoch=claims_v2.epoch,
            issued_at=claims_v2.issued_at,
            expires_at=claims_v2.expires_at,
        )
    claims = verify_egress_token(secret, token, now, max_lifetime_s, legacy_before=legacy_before)
    return EgressCredential(
        sandbox_id=claims.sandbox_id,
        version=1,
        allowlist=claims.allowlist,
        epoch=None,
        issued_at=claims.issued_at,
        expires_at=claims.expires_at,
    )


def authenticate(
    secret: str,
    header: str | None,
    *,
    now: datetime,
    max_lifetime_s: int | None,
    legacy_before: datetime | None,
) -> EgressCredential:
    """The credential in ``header``; raise a 407 ``Deny`` when it is absent or not genuine."""
    if header is None:
        raise auth_required("no credential")
    scheme, _, encoded = header.partition(" ")
    if scheme.lower() != "basic":
        raise auth_required("credential is not basic")
    try:
        decoded = base64.b64decode(encoded.strip(), validate=True).decode("utf-8")
    except (binascii.Error, ValueError):
        raise auth_required("credential is not decodable") from None
    username, sep, token = decoded.partition(":")
    if not sep:
        raise auth_required("credential has no password")
    try:
        credential = _verified(secret, token, now, max_lifetime_s, legacy_before)
    except InvalidEgressToken:
        raise auth_required("invalid token") from None
    if not hmac.compare_digest(username.encode(), credential.sandbox_id.encode()):
        raise auth_required("username does not match the token")
    return credential


def note_legacy(
    noted: set[str],
    credential: EgressCredential,
    now: datetime,
    *,
    max_lifetime_s: int | None,
    cutover: datetime | None,
) -> None:
    """Log, once per sandbox, a token accepted only because it predates the cut-over."""
    if credential.version != 1 or max_lifetime_s is None or cutover is None:
        return
    if credential.sandbox_id in noted:
        return
    claims = EgressClaims(
        credential.sandbox_id, credential.allowlist, credential.issued_at, credential.expires_at
    )
    if is_legacy(claims, cutover) and exceeds_lifetime(claims, max_lifetime_s, now):
        noted.add(credential.sandbox_id)
        _log.warning(
            "accepted legacy egress token sandbox=%s issued_at=%s expires_at=%s",
            credential.sandbox_id,
            credential.issued_at.isoformat(),
            credential.expires_at.isoformat(),
        )


__all__ = ["Deny", "EgressCredential", "authenticate", "note_legacy"]
