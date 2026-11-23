"""SCIM bearer-token authentication: ``Authorization: Bearer sf_scim_...`` -> Principal.

See docs/scim-design.md section 4 (the SCIM token). The token is looked up by its prefix in
``scim_tokens`` only, never in ``api_keys``, and verified with ``verify_api_key`` exactly like an
API key. So the token is a plain 401 on every ordinary route (``authenticate`` finds no such
prefix in ``api_keys``), and an API key or session token is a 401 here.

An unknown prefix is verified against a dummy hash so both failure paths cost one HMAC. A
revoked token is refused after its hash checks out. ``last_used_at`` is written at most once per
``LAST_USED_DEBOUNCE`` per token. The returned ``Principal`` carries the token id as ``key_id``
and ``role_scopes(max_role)`` as scopes, so the role ceiling is enforced by the existing scope
checks in ``UserAdminService``; it is meant for SCIM handlers only. No message names the token.
"""

from collections.abc import Callable
from dataclasses import dataclass, field

from fastapi import FastAPI, Request

from sandfort.auth.api_keys import hash_api_key, parse_prefix, verify_api_key
from sandfort.auth.authenticate import INVALID_KEY_MESSAGE, _bearer_token, _should_touch
from sandfort.auth.principal import Principal
from sandfort.clock import Clock, SystemClock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.scim import ScimToken
from sandfort.domain.user import role_scopes
from sandfort.errors import InternalError, Unauthorized

SCIM_AUTH_STATE_ATTR = "sandfort_scim_auth"
REVOKED_MESSAGE = "SCIM token has been revoked"

# Verified against when the prefix is unknown so both failure paths cost one HMAC.
_DUMMY_HASH = hash_api_key("", "sf_scim_unused00_" + "0" * 43)


@dataclass(frozen=True, slots=True)
class ScimAuthenticator:
    pepper: str
    uow_factory: Callable[[], UnitOfWorkPort]
    clock: Clock = field(default_factory=SystemClock)

    async def authenticate(self, authorization: str | None) -> Principal:
        """Resolve a bearer SCIM token to its principal; ``Unauthorized`` (401) otherwise."""
        token = _bearer_token(authorization)
        try:
            prefix = parse_prefix(token)
        except ValueError:
            raise Unauthorized(INVALID_KEY_MESSAGE) from None

        now = self.clock.now()
        async with self.uow_factory() as uow:
            stored = self._verified(token, await uow.scim_tokens.get_by_prefix(prefix))
            if _should_touch(stored.last_used_at, now):
                await uow.scim_tokens.touch_last_used(stored.id, now)
                await uow.commit()
        return Principal(
            org_id=stored.org_id,
            key_id=stored.id,
            scopes=role_scopes(stored.max_role),
        )

    def _verified(self, token: str, stored: ScimToken | None) -> ScimToken:
        if stored is None:
            verify_api_key(self.pepper, token, _DUMMY_HASH)
            raise Unauthorized(INVALID_KEY_MESSAGE)
        if not verify_api_key(self.pepper, token, stored.secret_hash):
            raise Unauthorized(INVALID_KEY_MESSAGE)
        if stored.revoked_at is not None:
            raise Unauthorized(REVOKED_MESSAGE)
        return stored


def install_scim_auth(app: FastAPI, authenticator: ScimAuthenticator) -> None:
    """Make ``authenticator`` available to ``authenticate_scim`` on ``app``."""
    setattr(app.state, SCIM_AUTH_STATE_ATTR, authenticator)


async def authenticate_scim(request: Request) -> Principal:
    """FastAPI dependency for SCIM paths: the SCIM token's principal, else 401."""
    authenticator = getattr(request.app.state, SCIM_AUTH_STATE_ATTR, None)
    if not isinstance(authenticator, ScimAuthenticator):
        raise InternalError("SCIM authentication is not configured")
    return await authenticator.authenticate(request.headers.get("authorization"))
