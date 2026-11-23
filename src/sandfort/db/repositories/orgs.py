"""SQLAlchemy implementation of ``OrgRepository``."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sandfort.db.models.orgs import OrgRow
from sandfort.db.support import as_utc, flush_or_conflict
from sandfort.domain.org import Org, OrgStatus


def _to_entity(row: OrgRow) -> Org:
    return Org(
        id=row.id,
        name=row.name,
        slug=row.slug,
        status=OrgStatus(row.status),
        created_at=as_utc(row.created_at),
    )


class SqlOrgRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, org: Org) -> None:
        created_at = as_utc(org.created_at)
        self._session.add(
            OrgRow(
                id=org.id,
                name=org.name,
                slug=org.slug,
                status=org.status.value,
                created_at=created_at,
                updated_at=created_at,
            )
        )
        await flush_or_conflict(self._session, "organization id or slug already exists")

    async def get(self, org_id: str) -> Org | None:
        row = await self._session.get(OrgRow, org_id, populate_existing=True)
        return None if row is None else _to_entity(row)

    async def get_by_slug(self, slug: str) -> Org | None:
        stmt = select(OrgRow).where(OrgRow.slug == slug).execution_options(populate_existing=True)
        row = (await self._session.execute(stmt)).scalar_one_or_none()
        return None if row is None else _to_entity(row)
