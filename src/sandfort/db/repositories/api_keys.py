"""SQLAlchemy implementation of ``ApiKeyRepository``."""

from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sandfort.db.models.api_keys import ApiKeyRow
from sandfort.db.support import as_utc, flush_or_conflict, opt_utc, rowcount
from sandfort.domain.org import ApiKey, Scope


def _to_entity(row: ApiKeyRow) -> ApiKey:
    return ApiKey(
        id=row.id,
        org_id=row.org_id,
        name=row.name,
        prefix=row.prefix,
        secret_hash=row.secret_hash,
        scopes=frozenset(Scope(value) for value in row.scopes),
        is_platform_admin=row.is_platform_admin,
        sandbox_labels=None if not row.sandbox_labels else dict(row.sandbox_labels),
        max_sandboxes=row.max_sandboxes,
        shared_volume_labels=None
        if not row.shared_volume_labels
        else dict(row.shared_volume_labels),
        last_used_at=opt_utc(row.last_used_at),
        expires_at=opt_utc(row.expires_at),
        revoked_at=opt_utc(row.revoked_at),
        created_by=row.created_by,
        created_at=as_utc(row.created_at),
    )


class SqlApiKeyRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, key: ApiKey) -> None:
        created_at = as_utc(key.created_at)
        self._session.add(
            ApiKeyRow(
                id=key.id,
                org_id=key.org_id,
                name=key.name,
                prefix=key.prefix,
                secret_hash=key.secret_hash,
                scopes=sorted(scope.value for scope in key.scopes),
                is_platform_admin=key.is_platform_admin,
                sandbox_labels=dict(key.sandbox_labels) if key.sandbox_labels else None,
                max_sandboxes=key.max_sandboxes,
                shared_volume_labels=(
                    dict(key.shared_volume_labels) if key.shared_volume_labels else None
                ),
                last_used_at=opt_utc(key.last_used_at),
                expires_at=opt_utc(key.expires_at),
                revoked_at=opt_utc(key.revoked_at),
                created_by=key.created_by,
                created_at=created_at,
                updated_at=created_at,
            )
        )
        await flush_or_conflict(self._session, "api key id or prefix already exists")

    async def get_by_prefix(self, prefix: str) -> ApiKey | None:
        stmt = (
            select(ApiKeyRow)
            .where(ApiKeyRow.prefix == prefix)
            .execution_options(populate_existing=True)
        )
        row = (await self._session.execute(stmt)).scalar_one_or_none()
        return None if row is None else _to_entity(row)

    async def list_for_org(self, org_id: str) -> Sequence[ApiKey]:
        stmt = (
            select(ApiKeyRow)
            .where(ApiKeyRow.org_id == org_id)
            .order_by(ApiKeyRow.id)
            .execution_options(populate_existing=True)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_to_entity(row) for row in rows]

    async def revoke(self, org_id: str, key_id: str, at: datetime) -> bool:
        stmt = (
            update(ApiKeyRow)
            .where(
                ApiKeyRow.id == key_id,
                ApiKeyRow.org_id == org_id,
                ApiKeyRow.revoked_at.is_(None),
            )
            .values(revoked_at=as_utc(at))
            .execution_options(synchronize_session=False)
        )
        return rowcount(await self._session.execute(stmt)) > 0

    async def touch_last_used(self, key_id: str, at: datetime) -> None:
        stmt = (
            update(ApiKeyRow)
            .where(ApiKeyRow.id == key_id)
            .values(last_used_at=as_utc(at))
            .execution_options(synchronize_session=False)
        )
        await self._session.execute(stmt)
