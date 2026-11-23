"""SCIM token administration: mint with role attenuation, list metadata, revoke, touch.

See docs/scim-design.md section 4 (the SCIM token, token management and audit). The token is
produced by ``generate_api_key(pepper, env="scim")`` (``sf_scim_<prefix8>_<secret43>``) and only
its salted HMAC hash is stored, exactly like an API key. ``mint`` returns the plaintext once.

``max_role`` attenuates like key creation: the minter must hold every scope ``role_scopes``
maps that role to, else ``ScopeEscalation`` (403) is raised before anything is read or written.
An org may hold at most ``MAX_ACTIVE_SCIM_TOKENS`` active tokens (``InvalidState``, 409), so
rotation (mint, switch the provider, revoke) works and the table stays bounded.

Revoking is idempotent: revoking a revoked token returns it unchanged and records no second
audit event. Audit details carry the name, prefix and ``max_role``, never the token or its hash.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from sandfort.auth.api_keys import generate_api_key
from sandfort.auth.principal import Principal
from sandfort.clock import Clock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.events import ActorType
from sandfort.domain.scim import ScimToken
from sandfort.domain.user import OrgRole, role_scopes
from sandfort.errors import InvalidState, NotFound, ValidationFailed
from sandfort.ids import new_scim_token_id
from sandfort.services.api_key_admin import ScopeEscalation
from sandfort.services.audit import AuditRecorder

TOKEN_CREATED = "scim_token.created"
TOKEN_REVOKED = "scim_token.revoked"
TARGET_TYPE = "scim_token"
TOKEN_ENV = "scim"
MAX_ACTIVE_SCIM_TOKENS = 5
MAX_NAME_CHARS = 255  # width of the ``scim_tokens.name`` column


@dataclass(frozen=True, slots=True)
class CreatedScimToken:
    """The stored metadata plus the plaintext ``token``, which exists only in this value."""

    record: ScimToken
    token: str = field(repr=False)


def _require_grantable(principal: Principal, max_role: OrgRole) -> None:
    """Reject a ``max_role`` whose scopes are not a subset of the minter's scopes."""
    excess = sorted(scope.value for scope in role_scopes(max_role) - principal.scopes)
    if excess:
        raise ScopeEscalation(
            f"a SCIM token cannot carry role {max_role.value}: the minter lacks "
            + ", ".join(excess),
            details={"max_role": max_role.value, "excess_scopes": excess},
        )


def _clean_name(name: str) -> str:
    cleaned = name.strip()
    if not cleaned:
        raise ValidationFailed("a SCIM token needs a name")
    if len(cleaned) > MAX_NAME_CHARS:
        raise ValidationFailed(f"a SCIM token name is at most {MAX_NAME_CHARS} characters")
    return cleaned


class ScimTokenService:
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWorkPort],
        pepper: str,
        clock: Clock,
        recorder: AuditRecorder | None = None,
    ) -> None:
        if not pepper:
            raise ValueError("an API key pepper is required to issue SCIM tokens")
        self._uow_factory = uow_factory
        self._pepper = pepper
        self._clock = clock
        self._recorder = recorder or AuditRecorder(clock)

    async def mint(self, principal: Principal, name: str, max_role: OrgRole) -> CreatedScimToken:
        """Issue a token in the caller's org whose role ceiling is ``max_role``."""
        _require_grantable(principal, max_role)
        cleaned = _clean_name(name)
        generated = generate_api_key(self._pepper, env=TOKEN_ENV)
        record = ScimToken(
            id=new_scim_token_id(),
            org_id=principal.org_id,
            name=cleaned,
            prefix=generated.prefix,
            secret_hash=generated.secret_hash,
            max_role=max_role,
            created_by=principal.key_id,
            created_at=self._clock.now(),
        )
        details = {"name": cleaned, "prefix": record.prefix, "max_role": max_role.value}
        async with self._uow_factory() as uow:
            existing = await uow.scim_tokens.list_for_org(principal.org_id)
            active = sum(1 for token in existing if token.revoked_at is None)
            if active >= MAX_ACTIVE_SCIM_TOKENS:
                raise InvalidState(
                    f"the org already has {MAX_ACTIVE_SCIM_TOKENS} active SCIM tokens;"
                    " revoke one first",
                    details={"max_active": MAX_ACTIVE_SCIM_TOKENS},
                )
            await uow.scim_tokens.add(record)
            await self._audit(uow, principal, TOKEN_CREATED, record.id, details)
            await uow.commit()
        return CreatedScimToken(record=record, token=generated.key)

    async def list_tokens(self, org_id: str) -> Sequence[ScimToken]:
        """Every token of the org, revoked ones included, oldest first."""
        async with self._uow_factory() as uow:
            return await uow.scim_tokens.list_for_org(org_id)

    async def revoke(self, principal: Principal, token_id: str) -> ScimToken:
        """Revoke ``token_id`` in the caller's org; revoking a revoked token is a no-op."""
        now = self._clock.now()
        async with self._uow_factory() as uow:
            current = await self._require(uow, principal.org_id, token_id)
            if current.revoked_at is not None:
                return current
            if not await uow.scim_tokens.revoke(principal.org_id, token_id, now):
                # A concurrent revoke won; report the token as that call left it.
                return await self._require(uow, principal.org_id, token_id)
            details = {
                "name": current.name,
                "prefix": current.prefix,
                "max_role": current.max_role.value,
            }
            await self._audit(uow, principal, TOKEN_REVOKED, token_id, details)
            await uow.commit()
        return current.model_copy(update={"revoked_at": now})

    async def touch_last_used(self, token_id: str) -> None:
        """Record that ``token_id`` authenticated just now; callers debounce the writes."""
        async with self._uow_factory() as uow:
            await uow.scim_tokens.touch_last_used(token_id, self._clock.now())
            await uow.commit()

    async def _require(self, uow: UnitOfWorkPort, org_id: str, token_id: str) -> ScimToken:
        for token in await uow.scim_tokens.list_for_org(org_id):
            if token.id == token_id:
                return token
        raise NotFound(f"scim token {token_id} not found")

    async def _audit(
        self,
        uow: UnitOfWorkPort,
        principal: Principal,
        action: str,
        token_id: str,
        details: Mapping[str, Any],
    ) -> None:
        await self._recorder.record(
            uow,
            org_id=principal.org_id,
            actor_type=ActorType.API_KEY,
            actor_id=principal.key_id,
            action=action,
            target_type=TARGET_TYPE,
            target_id=token_id,
            details=details,
        )
