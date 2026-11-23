"""SQLAlchemy implementation of ``SnapshotRepository``.

Every method filters on ``org_id`` in SQL, so another org's snapshot is indistinguishable
from a missing one. ``mark_ready`` is an addition beyond the frozen port (the port can only
move ``state``): it records the committed digest and layer count, guarded on ``pending`` so a
snapshot that is being deleted is never revived. ``has_pending_from_source`` is another
addition: sandbox delete asks it so a snapshot's source is not destroyed mid-commit.
"""

from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import and_, delete, exists, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sandfort.db.models.snapshots import SnapshotRow
from sandfort.db.repositories.ports import LABEL_FILTER_KEY
from sandfort.db.support import as_utc, rowcount
from sandfort.domain.snapshot import Snapshot, SnapshotState
from sandfort.errors import ALREADY_EXISTS, NAME_TAKEN, Conflict, Unprocessable

MAX_PAGE_SIZE = 200
# Markers of the failed constraint in the driver text (SQLite and Postgres respectively).
_FOREIGN_KEY_MARKER = "foreign key"
_NAME_MARKERS = ("snapshots.name", "uq_snapshots_org_id_name")
_ID_MARKERS = ("snapshots.id", "pk_snapshots")
# The org the snapshot points at does not exist; distinct from a taken name or id.
ORG_NOT_FOUND = "org_not_found"


def _conflict_error(snapshot: Snapshot, exc: IntegrityError) -> Conflict:
    """Say which constraint failed: the org (foreign key), the name, the id, or another one."""
    detail = str(exc.orig).lower()
    if _FOREIGN_KEY_MARKER in detail:
        return Conflict("snapshot cannot be created: its org does not exist", reason=ORG_NOT_FOUND)
    if any(marker in detail for marker in _NAME_MARKERS):
        return Conflict(f"snapshot {snapshot.name!r} already exists in this org", reason=NAME_TAKEN)
    if any(marker in detail for marker in _ID_MARKERS):
        return Conflict(f"snapshot id {snapshot.id} already exists", reason=ALREADY_EXISTS)
    return Conflict("could not create the snapshot (constraint conflict)")


def _to_entity(row: SnapshotRow) -> Snapshot:
    return Snapshot(
        id=row.id,
        org_id=row.org_id,
        name=row.name,
        image_ref=row.image_ref,
        digest=row.digest,
        layer_count=row.layer_count,
        state=SnapshotState(row.state),
        source_sandbox_id=row.source_sandbox_id,
        spec_hash=row.spec_hash,
        isolation=row.isolation,
        labels=dict(row.labels),
        created_at=as_utc(row.created_at),
    )


class SqlSnapshotRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, snapshot: Snapshot) -> None:
        self._session.add(
            SnapshotRow(
                id=snapshot.id,
                org_id=snapshot.org_id,
                name=snapshot.name,
                image_ref=snapshot.image_ref,
                digest=snapshot.digest,
                layer_count=snapshot.layer_count,
                state=snapshot.state.value,
                source_sandbox_id=snapshot.source_sandbox_id,
                spec_hash=snapshot.spec_hash,
                isolation=snapshot.isolation,
                labels=dict(snapshot.labels),
                created_at=as_utc(snapshot.created_at),
            )
        )
        try:
            await self._session.flush()
        except IntegrityError as exc:
            raise _conflict_error(snapshot, exc) from exc

    async def get(self, org_id: str, snapshot_id: str) -> Snapshot | None:
        return await self._get_one(SnapshotRow.org_id == org_id, SnapshotRow.id == snapshot_id)

    async def get_by_name(self, org_id: str, name: str) -> Snapshot | None:
        return await self._get_one(SnapshotRow.org_id == org_id, SnapshotRow.name == name)

    async def list(
        self,
        org_id: str,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> Sequence[Snapshot]:
        """Snapshots of ``org_id`` by id; with ``labels``, only those carrying every pair."""
        stmt = select(SnapshotRow).where(SnapshotRow.org_id == org_id)
        if labels:
            for key in labels:  # the key becomes a JSON path, so only the safe charset is bound
                if LABEL_FILTER_KEY.fullmatch(key) is None:
                    raise Unprocessable(
                        f"label filter key {key!r} must be 1 to 63 characters of A-Z, a-z, 0-9, "
                        "'_', '.', '/' or '-'"
                    )
            pairs = [SnapshotRow.labels[key].as_string() == value for key, value in labels.items()]
            stmt = stmt.where(and_(*pairs))
        if cursor is not None:
            stmt = stmt.where(SnapshotRow.id > cursor)
        stmt = (
            stmt.order_by(SnapshotRow.id)
            .limit(max(1, min(limit, MAX_PAGE_SIZE)))
            .execution_options(populate_existing=True)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_to_entity(row) for row in rows]

    async def set_state(
        self, org_id: str, snapshot_id: str, state: SnapshotState
    ) -> Snapshot | None:
        return await self._update(org_id, snapshot_id, state=state.value)

    async def mark_ready(
        self, org_id: str, snapshot_id: str, *, digest: str, layer_count: int
    ) -> Snapshot | None:
        """Pending to ready with its image facts; ``None`` when the row is gone or not pending."""
        return await self._update(
            org_id,
            snapshot_id,
            SnapshotRow.state == SnapshotState.PENDING.value,
            state=SnapshotState.READY.value,
            digest=digest,
            layer_count=layer_count,
        )

    async def has_pending_from_source(self, org_id: str, sandbox_id: str) -> bool:
        """Whether a snapshot of ``sandbox_id`` in ``org_id`` is still committing."""
        stmt = select(
            exists().where(
                SnapshotRow.org_id == org_id,
                SnapshotRow.source_sandbox_id == sandbox_id,
                SnapshotRow.state == SnapshotState.PENDING.value,
            )
        )
        return bool((await self._session.execute(stmt)).scalar())

    async def delete(self, org_id: str, snapshot_id: str) -> bool:
        stmt = (
            delete(SnapshotRow)
            .where(SnapshotRow.org_id == org_id, SnapshotRow.id == snapshot_id)
            .execution_options(synchronize_session=False)
        )
        return rowcount(await self._session.execute(stmt)) > 0

    async def _update(
        self, org_id: str, snapshot_id: str, *guards: Any, **values: Any
    ) -> Snapshot | None:
        stmt = (
            update(SnapshotRow)
            .where(SnapshotRow.org_id == org_id, SnapshotRow.id == snapshot_id, *guards)
            .values(**values)
            .execution_options(synchronize_session=False)
        )
        if rowcount(await self._session.execute(stmt)) == 0:
            return None
        return await self.get(org_id, snapshot_id)

    async def _get_one(self, *criteria: Any) -> Snapshot | None:
        stmt = select(SnapshotRow).where(*criteria).execution_options(populate_existing=True)
        row = (await self._session.execute(stmt)).scalar_one_or_none()
        return None if row is None else _to_entity(row)
