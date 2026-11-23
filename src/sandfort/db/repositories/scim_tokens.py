"""SQLAlchemy implementation of ``ScimTokenRepository``."""

from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sandfort.db.models.scim_tokens import ScimTokenRow
from sandfort.db.support import as_utc, flush_or_conflict, opt_utc, rowcount
from sandfort.domain.scim import ScimToken
from sandfort.domain.user import OrgRole


def _to_entity(row: ScimTokenRow) -> ScimToken:
    return ScimToken(
        id=row.id,
        org_id=row.org_id,
        name=row.name,
        prefix=row.prefix,
        secret_hash=row.secret_hash,
        max_role=OrgRole(row.max_role),
        last_used_at=opt_utc(row.last_used_at),
        revoked_at=opt_utc(row.revoked_at),
        created_by=row.created_by,
        created_at=as_utc(row.created_at),
    )


class SqlScimTokenRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, token: ScimToken) -> None:
        created_at = as_utc(token.created_at)
        self._session.add(
            ScimTokenRow(
                id=token.id,
                org_id=token.org_id,
                name=token.name,
                prefix=token.prefix,
                secret_hash=token.secret_hash,
                max_role=token.max_role.value,
                last_used_at=opt_utc(token.last_used_at),
                revoked_at=opt_utc(token.revoked_at),
                created_by=token.created_by,
                created_at=created_at,
                updated_at=created_at,
            )
        )
        await flush_or_conflict(self._session, "scim token id or prefix already exists")

    async def get_by_prefix(self, prefix: str) -> ScimToken | None:
        stmt = (
            select(ScimTokenRow)
            .where(ScimTokenRow.prefix == prefix)
            .execution_options(populate_existing=True)
        )
        row = (await self._session.execute(stmt)).scalar_one_or_none()
        return None if row is None else _to_entity(row)

    async def list_for_org(self, org_id: str) -> Sequence[ScimToken]:
        stmt = (
            select(ScimTokenRow)
            .where(ScimTokenRow.org_id == org_id)
            .order_by(ScimTokenRow.id)
            .execution_options(populate_existing=True)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_to_entity(row) for row in rows]

    async def revoke(self, org_id: str, token_id: str, at: datetime) -> bool:
        stmt = (
            update(ScimTokenRow)
            .where(
                ScimTokenRow.id == token_id,
                ScimTokenRow.org_id == org_id,
                ScimTokenRow.revoked_at.is_(None),
            )
            .values(revoked_at=as_utc(at))
            .execution_options(synchronize_session=False)
        )
        return rowcount(await self._session.execute(stmt)) > 0

    async def touch_last_used(self, token_id: str, at: datetime) -> None:
        stmt = (
            update(ScimTokenRow)
            .where(ScimTokenRow.id == token_id)
            .values(last_used_at=as_utc(at))
            .execution_options(synchronize_session=False)
        )
        await self._session.execute(stmt)
