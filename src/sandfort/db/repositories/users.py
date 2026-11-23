"""SQLAlchemy implementation of ``UserRepository`` and ``MembershipRepository``."""

from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sandfort.db.models.users import OrgMembershipRow, UserRow
from sandfort.db.support import as_utc, flush_or_conflict, opt_utc, rowcount
from sandfort.domain.user import OrgMembership, OrgRole, User
from sandfort.errors import ALREADY_EXISTS, Conflict


def _user_entity(row: UserRow) -> User:
    return User(
        id=row.id,
        email=row.email,
        display_name=row.display_name,
        created_at=as_utc(row.created_at),
        disabled_at=opt_utc(row.disabled_at),
    )


def _membership_entity(row: OrgMembershipRow) -> OrgMembership:
    return OrgMembership(
        user_id=row.user_id,
        org_id=row.org_id,
        role=OrgRole(row.role),
        created_at=as_utc(row.created_at),
        external_id=row.external_id,
    )


class SqlUserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, user: User) -> None:
        created_at = as_utc(user.created_at)
        self._session.add(
            UserRow(
                id=user.id,
                email=user.email,
                display_name=user.display_name,
                disabled_at=opt_utc(user.disabled_at),
                created_at=created_at,
                updated_at=created_at,
            )
        )
        await flush_or_conflict(self._session, "user id or email already exists")

    async def get(self, user_id: str) -> User | None:
        row = await self._session.get(UserRow, user_id, populate_existing=True)
        return None if row is None else _user_entity(row)

    async def get_by_email(self, email: str) -> User | None:
        stmt = (
            select(UserRow)
            .where(UserRow.email == email.strip().lower())
            .execution_options(populate_existing=True)
        )
        row = (await self._session.execute(stmt)).scalar_one_or_none()
        return None if row is None else _user_entity(row)


class SqlMembershipRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, membership: OrgMembership) -> None:
        created_at = as_utc(membership.created_at)
        self._session.add(
            OrgMembershipRow(
                user_id=membership.user_id,
                org_id=membership.org_id,
                role=membership.role.value,
                external_id=membership.external_id,
                created_at=created_at,
                updated_at=created_at,
            )
        )
        await flush_or_conflict(self._session, "membership already exists or user/org unknown")

    async def get(self, user_id: str, org_id: str) -> OrgMembership | None:
        row = await self._session.get(
            OrgMembershipRow, (user_id, org_id), populate_existing=True
        )
        return None if row is None else _membership_entity(row)

    async def list_for_org(self, org_id: str) -> Sequence[OrgMembership]:
        stmt = (
            select(OrgMembershipRow)
            .where(OrgMembershipRow.org_id == org_id)
            .order_by(OrgMembershipRow.created_at, OrgMembershipRow.user_id)
            .execution_options(populate_existing=True)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_membership_entity(row) for row in rows]

    async def update_role(
        self, user_id: str, org_id: str, role: OrgRole, at: datetime
    ) -> OrgMembership | None:
        stmt = (
            update(OrgMembershipRow)
            .where(OrgMembershipRow.user_id == user_id, OrgMembershipRow.org_id == org_id)
            .values(role=role.value, updated_at=as_utc(at))
            .execution_options(synchronize_session=False)
        )
        if rowcount(await self._session.execute(stmt)) == 0:
            return None
        return await self.get(user_id, org_id)

    async def get_by_external_id(self, org_id: str, external_id: str) -> OrgMembership | None:
        stmt = (
            select(OrgMembershipRow)
            .where(OrgMembershipRow.org_id == org_id, OrgMembershipRow.external_id == external_id)
            .execution_options(populate_existing=True)
        )
        row = (await self._session.execute(stmt)).scalar_one_or_none()
        return None if row is None else _membership_entity(row)

    async def set_external_id(
        self, user_id: str, org_id: str, external_id: str | None, at: datetime
    ) -> OrgMembership | None:
        stmt = (
            update(OrgMembershipRow)
            .where(OrgMembershipRow.user_id == user_id, OrgMembershipRow.org_id == org_id)
            .values(external_id=external_id, updated_at=as_utc(at))
            .execution_options(synchronize_session=False)
        )
        try:
            result = await self._session.execute(stmt)
        except IntegrityError as exc:
            raise Conflict(
                "external id already used by another member of the org", reason=ALREADY_EXISTS
            ) from exc
        if rowcount(result) == 0:
            return None
        return await self.get(user_id, org_id)

    async def delete(self, user_id: str, org_id: str) -> bool:
        stmt = (
            delete(OrgMembershipRow)
            .where(OrgMembershipRow.user_id == user_id, OrgMembershipRow.org_id == org_id)
            .execution_options(synchronize_session=False)
        )
        return rowcount(await self._session.execute(stmt)) > 0
