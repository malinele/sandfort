"""FastAPI dependency: ``Authorization: Bearer`` header -> Principal (401 on failure).

The app factory wires an ``AuthContext`` (pepper, unit-of-work factory, clock)
onto ``app.state`` with ``install_auth``. Wrong, revoked and expired keys all
raise ``Unauthorized``; ``last_used_at`` is written at most once per
``LAST_USED_DEBOUNCE`` per key.

A revoked or expired key whose secret verified is known, so its org id, key id and reason are
put on ``request.state`` (``REFUSED_KEY_STATE_ATTR``) and the error handler audits the refusal
as ``request.denied`` on that org's chain. Throttle: at most one such row per key per
``REFUSAL_AUDIT_WINDOW`` (60 s) per process, kept in a bounded in-memory map (oldest entries
dropped), so a client hammering with a revoked key cannot flood the chain. The throttle has two
steps: ``refusal_due`` (a check, no side effect) runs when the key is refused, and
``mark_refusal_audited`` runs in the error handler only after the audit row was committed. A
failed write therefore leaves the key due and the next refusal tries again. Missing, malformed,
unknown and wrong-secret keys name no org and stay unaudited.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from fastapi import FastAPI, Request

from sandfort.auth.api_keys import hash_api_key, parse_prefix, verify_api_key
from sandfort.auth.label_scope import (
    set_key_sandbox_cap,
    set_label_scope,
    set_shared_volume_labels,
)
from sandfort.auth.principal import Principal
from sandfort.auth.session_tokens import is_session_token, verify_session_token
from sandfort.clock import Clock, SystemClock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.org import ApiKey
from sandfort.domain.user import role_scopes
from sandfort.errors import InternalError, Unauthorized

AUTH_STATE_ATTR = "sandfort_auth"
# request.state attribute holding the Principal once authentication succeeded
PRINCIPAL_STATE_ATTR = "sandfort_principal"
BEARER_SCHEME = "bearer"
LAST_USED_DEBOUNCE = timedelta(seconds=60)
INVALID_KEY_MESSAGE = "invalid API key"
# request.state attribute holding a ``RefusedKey`` when a stored key's secret matched but the
# key is revoked or expired, so the error handler can audit the refusal on that key's org.
REFUSED_KEY_STATE_ATTR = "sandfort_refused_key"
REASON_REVOKED = "revoked"
REASON_EXPIRED = "expired"
# Throttle for the refusal audit: at most one row per key per window per process. The map holds
# the time of the last committed row per key. It is bounded; the oldest entries are dropped first,
# so a flood of distinct keys cannot grow it.
REFUSAL_AUDIT_WINDOW = timedelta(seconds=60)
REFUSAL_SEEN_MAX = 1024
_REFUSAL_SEEN: dict[str, datetime] = {}


@dataclass(frozen=True, slots=True)
class RefusedKey:
    """A stored key whose secret verified but which was refused (not a Principal)."""

    org_id: str
    key_id: str
    reason: str
    at: datetime  # when the key was refused; the throttle slot is marked with it


class _StoredKeyRefused(Unauthorized):
    """A 401 for a revoked or expired key; carries which key, for the audit trail."""

    def __init__(self, message: str, stored: ApiKey, reason: str, now: datetime) -> None:
        super().__init__(message)
        self.refused = RefusedKey(org_id=stored.org_id, key_id=stored.id, reason=reason, at=now)


# Verified against when the prefix is unknown so both failure paths cost one HMAC.
_DUMMY_HASH = hash_api_key("", "sf_unused_00000000_" + "0" * 43)


@dataclass(frozen=True, slots=True)
class AuthContext:
    pepper: str
    uow_factory: Callable[[], UnitOfWorkPort]
    clock: Clock = field(default_factory=SystemClock)
    session_secret: str = ""  # empty disables user session tokens
    sso_org_id: str = ""  # when set, session tokens must carry this org; empty = no check


def install_auth(app: FastAPI, context: AuthContext) -> None:
    """Make ``context`` available to ``authenticate`` for every request on ``app``."""
    setattr(app.state, AUTH_STATE_ATTR, context)


async def authenticate(request: Request) -> Principal:
    context = _auth_context(request)
    key = _bearer_token(request.headers.get("authorization"))
    if is_session_token(key):
        return _stash(request, await _session_principal(context, key))
    try:
        prefix = parse_prefix(key)
    except ValueError:
        raise Unauthorized(INVALID_KEY_MESSAGE) from None

    now = context.clock.now()
    async with context.uow_factory() as uow:
        try:
            stored = _verified(context.pepper, key, await uow.api_keys.get_by_prefix(prefix), now)
        except _StoredKeyRefused as refusal:
            if refusal_due(refusal.refused.key_id, now):
                setattr(request.state, REFUSED_KEY_STATE_ATTR, refusal.refused)
            raise
        if _should_touch(stored.last_used_at, now):
            await uow.api_keys.touch_last_used(stored.id, now)
            await uow.commit()

    principal = Principal(
        org_id=stored.org_id,
        key_id=stored.id,
        scopes=stored.scopes,
        is_platform_admin=stored.is_platform_admin,
        sandbox_labels=stored.sandbox_labels,
        max_sandboxes=stored.max_sandboxes,
        shared_volume_labels=stored.shared_volume_labels,
    )
    return _stash(request, principal)


def _stash(request: Request, principal: Principal) -> Principal:
    """Remember the authenticated caller so a later refusal can be audited on its org.

    Also publishes the caller's sandbox label scope and sandbox cap for the rest of the request
    (dependencies and the endpoint run in the same task, so they see them).
    """
    setattr(request.state, PRINCIPAL_STATE_ATTR, principal)
    set_label_scope(principal.sandbox_labels)
    set_key_sandbox_cap(principal.max_sandboxes)
    set_shared_volume_labels(principal.shared_volume_labels)
    return principal


async def _session_principal(context: AuthContext, token: str) -> Principal:
    if not context.session_secret:
        raise Unauthorized(INVALID_KEY_MESSAGE)
    claims = verify_session_token(context.session_secret, token, context.clock.now())
    if context.sso_org_id and claims.org_id != context.sso_org_id:
        raise Unauthorized(INVALID_KEY_MESSAGE)
    async with context.uow_factory() as uow:
        user = await uow.users.get(claims.user_id)
        membership = await uow.memberships.get(claims.user_id, claims.org_id)
    if user is None or user.disabled_at is not None:
        raise Unauthorized(INVALID_KEY_MESSAGE)
    if membership is None or membership.role != claims.role:
        raise Unauthorized(INVALID_KEY_MESSAGE)
    return Principal(
        org_id=claims.org_id,
        key_id=claims.token_id,
        scopes=role_scopes(claims.role),
        user_id=claims.user_id,
    )


def _auth_context(request: Request) -> AuthContext:
    context = getattr(request.app.state, AUTH_STATE_ATTR, None)
    if not isinstance(context, AuthContext):
        raise InternalError("authentication is not configured")
    return context


def _bearer_token(header: str | None) -> str:
    if not header:
        raise Unauthorized("missing Authorization header")
    scheme, _, token = header.partition(" ")
    token = token.strip()
    if scheme.lower() != BEARER_SCHEME or not token:
        raise Unauthorized("Authorization header must use the Bearer scheme")
    return token


def _verified(pepper: str, key: str, stored: ApiKey | None, now: datetime) -> ApiKey:
    if stored is None:
        verify_api_key(pepper, key, _DUMMY_HASH)
        raise Unauthorized(INVALID_KEY_MESSAGE)
    if not verify_api_key(pepper, key, stored.secret_hash):
        raise Unauthorized(INVALID_KEY_MESSAGE)
    if stored.revoked_at is not None:
        raise _StoredKeyRefused("API key has been revoked", stored, REASON_REVOKED, now)
    if stored.expires_at is not None and stored.expires_at <= now:
        raise _StoredKeyRefused("API key has expired", stored, REASON_EXPIRED, now)
    return stored


def refusal_due(key_id: str, now: datetime) -> bool:
    """True when a refusal of ``key_id`` at ``now`` should be audited: no row in the last 60 s.

    A pure check; it does not take the slot. ``mark_refusal_audited`` does, once the row is
    committed, so a failed audit write leaves the key due.
    """
    last = _REFUSAL_SEEN.get(key_id)
    return last is None or not timedelta(0) <= now - last < REFUSAL_AUDIT_WINDOW


def mark_refusal_audited(key_id: str, now: datetime) -> None:
    """Take the key's throttle slot; call only after its audit row was committed.

    The map stays bounded: the oldest entries are dropped beyond ``REFUSAL_SEEN_MAX``.
    """
    _REFUSAL_SEEN.pop(key_id, None)
    _REFUSAL_SEEN[key_id] = now
    while len(_REFUSAL_SEEN) > REFUSAL_SEEN_MAX:
        del _REFUSAL_SEEN[next(iter(_REFUSAL_SEEN))]


def _should_touch(last_used_at: datetime | None, now: datetime) -> bool:
    return last_used_at is None or now - last_used_at >= LAST_USED_DEBOUNCE
