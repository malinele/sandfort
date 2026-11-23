"""SQLAlchemy implementation of ``VolumeRepository``.

Every method filters on ``org_id`` in SQL, so another org's volume is indistinguishable from
a missing one.
"""

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import and_, delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sandfort.db.models.volumes import VolumeRow
from sandfort.db.repositories.ports import LABEL_FILTER_KEY
from sandfort.db.support import as_utc, rowcount
from sandfort.domain.volume import Volume, VolumeState
from sandfort.errors import ALREADY_EXISTS, NAME_TAKEN, Conflict, Unprocessable

MAX_PAGE_SIZE = 200
# Markers of the failed constraint in the driver text (SQLite and Postgres respectively).
_FOREIGN_KEY_MARKER = "foreign key"
_NAME_MARKERS = ("volumes.name", "uq_volumes_org_id_name")
_ID_MARKERS = ("volumes.id", "pk_volumes")
# The org the volume points at does not exist; distinct from a taken name or id.
ORG_NOT_FOUND = "org_not_found"


def _conflict_error(volume: Volume, exc: IntegrityError) -> Conflict:
    """Say which constraint failed: the org (foreign key), the name, the id, or another one."""
    detail = str(exc.orig).lower()
    if _FOREIGN_KEY_MARKER in detail:
        return Conflict("volume cannot be created: its org does not exist", reason=ORG_NOT_FOUND)
    if any(marker in detail for marker in _NAME_MARKERS):
        return Conflict(f"volume {volume.name!r} already exists in this org", reason=NAME_TAKEN)
    if any(marker in detail for marker in _ID_MARKERS):
        return Conflict(f"volume id {volume.id} already exists", reason=ALREADY_EXISTS)
    return Conflict("could not create the volume (constraint conflict)")


def _to_entity(row: VolumeRow) -> Volume:
    return Volume(
        id=row.id,
        org_id=row.org_id,
        name=row.name,
        provider_volume_name=row.provider_volume_name,
        state=VolumeState(row.state),
        sampled_size_bytes=row.sampled_size_bytes,
        labels=dict(row.labels),
        restoring_since=None if row.restoring_since is None else as_utc(row.restoring_since),
        created_at=as_utc(row.created_at),
    )


class SqlVolumeRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, volume: Volume) -> None:
        self._session.add(
            VolumeRow(
                id=volume.id,
                org_id=volume.org_id,
                name=volume.name,
                provider_volume_name=volume.provider_volume_name,
                state=volume.state.value,
                sampled_size_bytes=volume.sampled_size_bytes,
                labels=dict(volume.labels),
                restoring_since=(
                    None if volume.restoring_since is None else as_utc(volume.restoring_since)
                ),
                created_at=as_utc(volume.created_at),
            )
        )
        try:
            await self._session.flush()
        except IntegrityError as exc:
            raise _conflict_error(volume, exc) from exc

    async def get(self, org_id: str, volume_id: str) -> Volume | None:
        return await self._get_one(VolumeRow.org_id == org_id, VolumeRow.id == volume_id)

    async def get_by_name(self, org_id: str, name: str) -> Volume | None:
        return await self._get_one(VolumeRow.org_id == org_id, VolumeRow.name == name)

    async def list(
        self,
        org_id: str,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> Sequence[Volume]:
        """Volumes of ``org_id`` by id; with ``labels``, only those carrying every pair."""
        stmt = select(VolumeRow).where(VolumeRow.org_id == org_id)
        if labels:
            for key in labels:  # the key becomes a JSON path, so only the safe charset is bound
                if LABEL_FILTER_KEY.fullmatch(key) is None:
                    raise Unprocessable(
                        f"label filter key {key!r} must be 1 to 63 characters of A-Z, a-z, 0-9, "
                        "'_', '.', '/' or '-'"
                    )
            pairs = [VolumeRow.labels[key].as_string() == value for key, value in labels.items()]
            stmt = stmt.where(and_(*pairs))
        if cursor is not None:
            stmt = stmt.where(VolumeRow.id > cursor)
        stmt = (
            stmt.order_by(VolumeRow.id)
            .limit(max(1, min(limit, MAX_PAGE_SIZE)))
            .execution_options(populate_existing=True)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_to_entity(row) for row in rows]

    async def set_state(self, org_id: str, volume_id: str, state: VolumeState) -> Volume | None:
        return await self._update(org_id, volume_id, state=state.value)

    async def set_sampled_size(self, org_id: str, volume_id: str, size_bytes: int) -> Volume | None:
        return await self._update(org_id, volume_id, sampled_size_bytes=size_bytes)

    async def set_restoring_since(
        self, org_id: str, volume_id: str, since: datetime | None
    ) -> Volume | None:
        return await self._update(org_id, volume_id, restoring_since=since)

    async def clear_restoring_if(self, org_id: str, volume_id: str, observed: datetime) -> bool:
        stmt = (
            update(VolumeRow)
            .where(
                VolumeRow.org_id == org_id,
                VolumeRow.id == volume_id,
                VolumeRow.restoring_since == as_utc(observed),
            )
            .values(restoring_since=None)
            .execution_options(synchronize_session=False)
        )
        return rowcount(await self._session.execute(stmt)) > 0

    async def list_restoring(self) -> Sequence[Volume]:
        """Every volume, of any org, whose restore marker is set (start-up recovery)."""
        stmt = (
            select(VolumeRow)
            .where(VolumeRow.restoring_since.is_not(None))
            .order_by(VolumeRow.id)
            .execution_options(populate_existing=True)
        )
        return [_to_entity(row) for row in (await self._session.execute(stmt)).scalars().all()]

    async def delete(self, org_id: str, volume_id: str) -> bool:
        stmt = (
            delete(VolumeRow)
            .where(VolumeRow.org_id == org_id, VolumeRow.id == volume_id)
            .execution_options(synchronize_session=False)
        )
        return rowcount(await self._session.execute(stmt)) > 0

    async def _update(self, org_id: str, volume_id: str, **values: Any) -> Volume | None:
        stmt = (
            update(VolumeRow)
            .where(VolumeRow.org_id == org_id, VolumeRow.id == volume_id)
            .values(**values)
            .execution_options(synchronize_session=False)
        )
        if rowcount(await self._session.execute(stmt)) == 0:
            return None
        return await self.get(org_id, volume_id)

    async def _get_one(self, *criteria: Any) -> Volume | None:
        stmt = select(VolumeRow).where(*criteria).execution_options(populate_existing=True)
        row = (await self._session.execute(stmt)).scalar_one_or_none()
        return None if row is None else _to_entity(row)
