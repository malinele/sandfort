"""Single sign-on: exchange a verified OIDC identity token for a platform session.

The identity token is checked by ``OidcVerifier``; its email names a known user who must
hold a membership in ``oidc_org_id``. An unknown email, a missing membership and a
disabled user all raise the same ``Unauthorized`` so the exchange never reveals which
emails are registered. The session is minted with the configured session secret and
lifetime; an empty secret refuses the exchange. A successful exchange records
``session.created`` against the configured org, attributed (like every action a session
later takes) to the session's token id.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from sandfort.auth.oidc import IdentityClaims, OidcVerifier
from sandfort.auth.session_tokens import SessionClaims, mint_session_token, verify_session_token
from sandfort.clock import Clock
from sandfort.config import Settings
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.events import ActorType
from sandfort.domain.user import OrgRole
from sandfort.errors import InternalError, Unauthorized
from sandfort.services.audit import AuditRecorder

SESSION_CREATED = "session.created"
TARGET_TYPE = "user"
SSO_METHOD = "oidc"
SESSIONS_DISABLED_MESSAGE = "user sessions are not enabled"
UNKNOWN_IDENTITY_MESSAGE = "identity is not a member of this platform"


@dataclass(frozen=True, slots=True)
class SsoSession:
    """A freshly minted session token with its expiry and the role it carries."""

    token: str
    expires_at: datetime
    role: OrgRole


class SsoService:
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWorkPort],
        verifier: OidcVerifier,
        clock: Clock,
        settings: Settings,
        recorder: AuditRecorder | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._verifier = verifier
        self._clock = clock
        self._settings = settings
        self._recorder = recorder or AuditRecorder(clock)

    async def exchange(self, identity_token: str) -> SsoSession:
        """Verify ``identity_token`` and mint a session in the configured org."""
        if not self._settings.session_secret:
            raise Unauthorized(SESSIONS_DISABLED_MESSAGE)
        identity = await self._verifier.verify(identity_token)
        org_id = self._settings.oidc_org_id
        async with self._uow_factory() as uow:
            user = await uow.users.get_by_email(identity.email)
            membership = None if user is None else await uow.memberships.get(user.id, org_id)
            if user is None or membership is None or user.disabled_at is not None:
                raise Unauthorized(UNKNOWN_IDENTITY_MESSAGE)
            token, claims = self._mint(user.id, org_id, membership.role)
            await self._audit(uow, claims, identity)
            await uow.commit()
        return SsoSession(token=token, expires_at=claims.expires_at, role=claims.role)

    def _mint(self, user_id: str, org_id: str, role: OrgRole) -> tuple[str, SessionClaims]:
        secret = self._settings.session_secret
        now = self._clock.now()
        try:
            token = mint_session_token(
                secret,
                user_id=user_id,
                org_id=org_id,
                role=role,
                now=now,
                ttl_s=self._settings.session_ttl_s,
            )
        except ValueError:
            raise InternalError("user session lifetime is misconfigured") from None
        # Read the claims back so the expiry and token id are exactly what the token says.
        return token, verify_session_token(secret, token, now)

    async def _audit(
        self, uow: UnitOfWorkPort, claims: SessionClaims, identity: IdentityClaims
    ) -> None:
        await self._recorder.record(
            uow,
            org_id=claims.org_id,
            actor_type=ActorType.API_KEY,
            actor_id=claims.token_id,
            action=SESSION_CREATED,
            target_type=TARGET_TYPE,
            target_id=claims.user_id,
            details={
                "method": SSO_METHOD,
                "email": identity.email,
                "subject": identity.subject,
                "role": claims.role.value,
                "expires_at": claims.expires_at.isoformat(),
            },
        )
