"""User administration: add, list, re-role and remove members of the caller's org (RBAC).

Emails are stored lowercased and identify a user across orgs: adding a member whose email is
already known reuses that user and only adds a membership, so one person can belong to many
orgs. A second membership in the same org is a ``Conflict`` (409). User creation and the
membership each record an audit event in the same unit of work as the write.

Changing a role or removing a member only touches the membership in the caller's org; the
user row stays because it may belong to other orgs. A member of another org is ``NotFound``.
An operation that would leave the org without an admin is ``InvalidState`` (409).

``update_member`` is the single write entry point for identity-provider provisioning (SCIM): it
applies a role change, an external id change or a removal in one unit of work, with the same
guards and audit records as the calls above. The external id belongs to the membership (it is
per org); a refused step leaves every other step unwritten.

Granting a role attenuates exactly like issuing a key: adding a member as ``role`` or re-roling
one to it requires the caller to hold every scope ``role_scopes(role)`` maps that role to, in
addition to ``api_keys:admin``. Otherwise ``ScopeEscalation`` (403) is raised before anything is
read or written, so a key can never mint a member (and, through SSO, a session) holding scopes
the key itself lacks. As in key creation, platform-admin principals get no bypass.
"""

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, Final

from sandfort.auth.principal import Principal
from sandfort.clock import Clock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.events import ActorType
from sandfort.domain.org import Scope
from sandfort.domain.user import OrgMembership, OrgRole, User, role_scopes
from sandfort.errors import (
    ALREADY_EXISTS,
    Conflict,
    InternalError,
    InvalidState,
    NotFound,
    ValidationFailed,
)
from sandfort.ids import JOB, new_id
from sandfort.services.api_key_admin import ScopeEscalation
from sandfort.services.audit import AuditRecorder

USER_PREFIX = "usr"
USER_CREATED = "user.created"
MEMBERSHIP_ADDED = "membership.added"
MEMBERSHIP_ROLE_CHANGED = "membership.role_changed"
MEMBERSHIP_REMOVED = "membership.removed"
MEMBERSHIP_EXTERNAL_ID_CHANGED = "membership.external_id_changed"
TARGET_TYPE = "user"
MAX_EXTERNAL_ID_CHARS = 255  # the width of ``org_memberships.external_id``


class Unset(Enum):
    """Type of ``UNSET``: "leave the external id alone", as opposed to ``None`` (clear it)."""

    UNSET = "unset"


UNSET: Final = Unset.UNSET


@dataclass(frozen=True, slots=True)
class Member:
    """A user together with the role and external id it holds in one org."""

    user: User
    role: OrgRole
    external_id: str | None = None


def new_user_id() -> str:
    """Time-sortable ``usr_`` id (the shared id module has no user prefix)."""
    return f"{USER_PREFIX}_{new_id(JOB).partition('_')[2]}"


def normalise_email(email: str) -> str:
    return email.strip().lower()


def _sorted_values(scopes: Iterable[Scope]) -> list[str]:
    return sorted(scope.value for scope in scopes)


def _require_grantable(principal: Principal, role: OrgRole) -> None:
    """Reject granting ``role`` when its scopes are not a subset of the caller's scopes."""
    excess = _sorted_values(role_scopes(role) - principal.scopes)
    if excess:
        raise ScopeEscalation(
            f"role {role.value} grants scope(s) the caller lacks: {', '.join(excess)}",
            details={"role": role.value, "excess_scopes": excess},
        )


def _member_not_found(user_id: str) -> NotFound:
    return NotFound(f"member {user_id} not found")


async def _require_membership(uow: UnitOfWorkPort, org_id: str, user_id: str) -> OrgMembership:
    membership = await uow.memberships.get(user_id, org_id)
    if membership is None:
        raise _member_not_found(user_id)
    return membership


async def _require_user(uow: UnitOfWorkPort, user_id: str) -> User:
    user = await uow.users.get(user_id)
    if user is None:
        raise InternalError(f"membership references unknown user {user_id}")
    return user


async def _ensure_another_admin(uow: UnitOfWorkPort, org_id: str, user_id: str) -> None:
    """Reject demoting or removing ``user_id`` when it is the org's only admin."""
    memberships = await uow.memberships.list_for_org(org_id)
    admins = sum(1 for membership in memberships if membership.role is OrgRole.ADMIN)
    if admins <= 1:
        raise InvalidState(
            "the org must keep at least one admin",
            details={"user_id": user_id, "admins": admins},
        )


def _member(user: User, membership: OrgMembership) -> Member:
    return Member(user=user, role=membership.role, external_id=membership.external_id)


def _check_external_id(external_id: str) -> None:
    """Reject a blank or over-long external id before anything is read or written."""
    if not external_id.strip() or len(external_id) > MAX_EXTERNAL_ID_CHARS:
        raise ValidationFailed(f"external id must be 1 to {MAX_EXTERNAL_ID_CHARS} characters")


def _external_id_taken() -> Conflict:
    return Conflict(
        "external id already used by another member of the org", reason=ALREADY_EXISTS
    )


class UserAdminService:
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWorkPort],
        clock: Clock,
        recorder: AuditRecorder | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._recorder = recorder or AuditRecorder(clock)

    async def create_member(
        self,
        principal: Principal,
        email: str,
        display_name: str,
        role: OrgRole,
        *,
        external_id: str | None = None,
    ) -> Member:
        """Add ``email`` to the caller's org as ``role``, creating the user when it is new.

        ``external_id`` is stored on the membership; another member of the org holding it is a
        ``Conflict`` and nothing is written.
        """
        _require_grantable(principal, role)
        if external_id is not None:
            _check_external_id(external_id)
        normalised = normalise_email(email)
        now = self._clock.now()
        async with self._uow_factory() as uow:
            user = await uow.users.get_by_email(normalised)
            if user is None:
                user = User(
                    id=new_user_id(),
                    email=normalised,
                    display_name=display_name,
                    created_at=now,
                )
                await uow.users.add(user)
                created = {"email": normalised}
                await self._audit(uow, principal, USER_CREATED, user.id, created)
            if await uow.memberships.get(user.id, principal.org_id) is not None:
                raise Conflict(
                    f"user {normalised} is already a member of this org",
                    reason=ALREADY_EXISTS,
                    details={"user_id": user.id},
                )
            added: dict[str, Any] = {"email": normalised, "role": role.value}
            if external_id is not None:
                holder = await uow.memberships.get_by_external_id(principal.org_id, external_id)
                if holder is not None:
                    raise _external_id_taken()
                added["external_id"] = external_id
            membership = OrgMembership(
                user_id=user.id,
                org_id=principal.org_id,
                role=role,
                created_at=now,
                external_id=external_id,
            )
            await uow.memberships.add(membership)
            await self._audit(uow, principal, MEMBERSHIP_ADDED, user.id, added)
            await uow.commit()
        return Member(user=user, role=role, external_id=external_id)

    async def list_members(self, org_id: str) -> Sequence[Member]:
        """Every member of the org with its role, oldest membership first."""
        async with self._uow_factory() as uow:
            memberships = await uow.memberships.list_for_org(org_id)
            members: list[Member] = []
            for membership in memberships:
                user = await uow.users.get(membership.user_id)
                if user is None:
                    message = f"membership references unknown user {membership.user_id}"
                    raise InternalError(message)
                members.append(_member(user, membership))
        return members

    async def get_member(self, org_id: str, user_id: str) -> Member:
        """The member ``user_id`` of the org; a user outside the org is ``NotFound``."""
        async with self._uow_factory() as uow:
            membership = await _require_membership(uow, org_id, user_id)
            user = await _require_user(uow, user_id)
        return _member(user, membership)

    async def find_member_by_email(self, org_id: str, email: str) -> Member | None:
        """The member of the org with ``email``; ``None`` when there is no such member."""
        async with self._uow_factory() as uow:
            user = await uow.users.get_by_email(normalise_email(email))
            if user is None:
                return None
            membership = await uow.memberships.get(user.id, org_id)
        return None if membership is None else _member(user, membership)

    async def change_member_role(
        self, principal: Principal, user_id: str, role: OrgRole
    ) -> Member:
        """Give ``user_id`` the ``role`` in the caller's org; the same role is a no-op."""
        _require_grantable(principal, role)
        org_id = principal.org_id
        async with self._uow_factory() as uow:
            current = await _require_membership(uow, org_id, user_id)
            user = await _require_user(uow, user_id)
            if current.role is role:
                return _member(user, current)
            if current.role is OrgRole.ADMIN:
                await _ensure_another_admin(uow, org_id, user_id)
            updated = await uow.memberships.update_role(user_id, org_id, role, self._clock.now())
            if updated is None:
                raise _member_not_found(user_id)
            changed = {"from_role": current.role.value, "role": updated.role.value}
            await self._audit(uow, principal, MEMBERSHIP_ROLE_CHANGED, user_id, changed)
            await uow.commit()
        return _member(user, updated)

    async def remove_member(self, principal: Principal, user_id: str) -> None:
        """Drop ``user_id``'s membership in the caller's org; the user itself is kept."""
        async with self._uow_factory() as uow:
            current = await _require_membership(uow, principal.org_id, user_id)
            await self._drop_membership(uow, principal, current)
            await uow.commit()

    async def update_member(
        self,
        principal: Principal,
        user_id: str,
        *,
        role: OrgRole | None = None,
        external_id: str | None | Unset = UNSET,
        deactivate: bool = False,
    ) -> Member:
        """Apply a role change, an external id change or a removal in one unit of work.

        ``role=None`` keeps the role; ``external_id=UNSET`` keeps the id and ``None`` clears it.
        ``deactivate`` removes the membership, ignores the other arguments and returns the member
        as it was. The role ceiling is checked first, the last-admin guard before any write, and
        a refused or failing step discards the others, so the change is all or nothing.
        """
        if deactivate:
            return await self._deactivate(principal, user_id)
        if role is not None:
            _require_grantable(principal, role)
        if not isinstance(external_id, Unset) and external_id is not None:
            _check_external_id(external_id)
        async with self._uow_factory() as uow:
            current = await _require_membership(uow, principal.org_id, user_id)
            user = await _require_user(uow, user_id)
            membership = current
            if role is not None and role is not current.role:
                membership = await self._apply_role(uow, principal, membership, role)
            if not isinstance(external_id, Unset) and external_id != membership.external_id:
                membership = await self._apply_external_id(uow, principal, membership, external_id)
            if membership is not current:
                await uow.commit()
        return _member(user, membership)

    async def _deactivate(self, principal: Principal, user_id: str) -> Member:
        async with self._uow_factory() as uow:
            current = await _require_membership(uow, principal.org_id, user_id)
            user = await _require_user(uow, user_id)
            await self._drop_membership(uow, principal, current)
            await uow.commit()
        return _member(user, current)

    async def _drop_membership(
        self, uow: UnitOfWorkPort, principal: Principal, current: OrgMembership
    ) -> None:
        """Guard, delete and audit a removal; the caller commits."""
        if current.role is OrgRole.ADMIN:
            await _ensure_another_admin(uow, current.org_id, current.user_id)
        if not await uow.memberships.delete(current.user_id, current.org_id):
            raise _member_not_found(current.user_id)
        removed: dict[str, Any] = {"role": current.role.value}
        if current.external_id is not None:
            removed["external_id"] = current.external_id
        await self._audit(uow, principal, MEMBERSHIP_REMOVED, current.user_id, removed)

    async def _apply_role(
        self, uow: UnitOfWorkPort, principal: Principal, current: OrgMembership, role: OrgRole
    ) -> OrgMembership:
        if current.role is OrgRole.ADMIN:
            await _ensure_another_admin(uow, current.org_id, current.user_id)
        updated = await uow.memberships.update_role(
            current.user_id, current.org_id, role, self._clock.now()
        )
        if updated is None:
            raise _member_not_found(current.user_id)
        changed = {"from_role": current.role.value, "role": updated.role.value}
        await self._audit(uow, principal, MEMBERSHIP_ROLE_CHANGED, current.user_id, changed)
        return updated

    async def _apply_external_id(
        self,
        uow: UnitOfWorkPort,
        principal: Principal,
        current: OrgMembership,
        external_id: str | None,
    ) -> OrgMembership:
        updated = await uow.memberships.set_external_id(
            current.user_id, current.org_id, external_id, self._clock.now()
        )
        if updated is None:
            raise _member_not_found(current.user_id)
        changed = {"from_external_id": current.external_id, "external_id": updated.external_id}
        action = MEMBERSHIP_EXTERNAL_ID_CHANGED
        await self._audit(uow, principal, action, current.user_id, changed)
        return updated

    async def _audit(
        self,
        uow: UnitOfWorkPort,
        principal: Principal,
        action: str,
        user_id: str,
        details: Mapping[str, Any],
    ) -> None:
        await self._recorder.record(
            uow,
            org_id=principal.org_id,
            actor_type=ActorType.API_KEY,
            actor_id=principal.key_id,
            action=action,
            target_type=TARGET_TYPE,
            target_id=user_id,
            details=details,
        )
