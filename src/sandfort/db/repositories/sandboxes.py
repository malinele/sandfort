"""SQLAlchemy implementation of ``SandboxRepository``.

Every tenant-facing method filters on ``org_id`` in SQL, so another org's
row is indistinguishable from a missing one. ``update`` is a compare-and-set
on ``version``.
"""

import logging
import time
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import Text, and_, case, cast, false, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sandfort.db.base import utcnow
from sandfort.db.models.sandboxes import SandboxRow
from sandfort.db.repositories.ports import SortOrder, StandbyClaim
from sandfort.db.support import as_utc, flush_or_conflict, opt_utc, rowcount
from sandfort.domain.resources import ResourceSpec
from sandfort.domain.sandbox import STOP_CAUSE_UNKNOWN, NetworkPolicy, Sandbox, SandboxState
from sandfort.errors import CONCURRENT_UPDATE, NAME_TAKEN, Conflict, NotFound

logger = logging.getLogger(__name__)

MAX_PAGE_SIZE = 200
# The unreadable-labels diagnostic (a COUNT with the guard regex over the org's labels text) runs
# at most once per org per interval, per process. ``_unreadable_checked_at`` maps org id to the
# monotonic time of its last check; it holds one float per org that ever ran a labelled query.
UNREADABLE_CHECK_INTERVAL_S = 600.0
_unreadable_checked_at: dict[str, float] = {}
_monotonic = time.monotonic  # module attribute so tests can drive the clock
CLAIM_ATTEMPTS = 3  # a lost race for one standby retries with the next one
# A standby in one of these states is not (or no longer) part of the pool's capacity.
_DEAD_STATES = (
    SandboxState.DESTROYING.value,
    SandboxState.DESTROYED.value,
    SandboxState.ERROR.value,
)
# Raw labels JSON text holding a ``\u`` escape Postgres cannot turn into text: NUL, or a lone
# UTF-16 surrogate (rows written before the round-53 input guard). The pattern walks the text
# token by token (plain char, escaped char, valid ``\u`` escape or high+low pair) up to a bad
# escape, so an escaped backslash or a valid pair (an emoji) never matches. A low surrogate at a
# token boundary is always lone: a valid pair is only ever consumed whole. Plain regex, no
# lookaround: Postgres ARE (``~``) and Python ``re`` (SQLite ``REGEXP``) read it the same way.
_HEX = "[0-9a-fA-F]"
_HIGH = rf"[dD][89abAB]{_HEX}{{2}}"
_LOW = rf"[dD][c-fC-F]{_HEX}{{2}}"
_PLAIN_ESCAPE = (
    rf"[1-9a-cA-CeEfF]{_HEX}{{3}}|[dD][0-7]{_HEX}{{2}}"
    rf"|0(?:[1-9a-fA-F]{_HEX}{{2}}|0[1-9a-fA-F]{_HEX}|00[1-9a-fA-F])"
)
_NOT_LOW_NEXT = r"(?:$|[^\\]|\\[^u]|\\u(?:[^dD]|[dD][^c-fC-F]))"
_BAD_ESCAPE = rf"0000|{_LOW}|{_HIGH}{_NOT_LOW_NEXT}"
UNREADABLE_LABELS = (
    rf"^(?:[^\\]|\\[^u]|\\u(?:{_HIGH}\\u{_LOW}|{_PLAIN_ESCAPE}))*\\u(?:{_BAD_ESCAPE})"
)


def _to_entity(row: SandboxRow) -> Sandbox:
    return Sandbox(
        id=row.id,
        org_id=row.org_id,
        name=row.name,
        state=SandboxState(row.state),
        desired_state=SandboxState(row.desired_state),
        image_ref=row.image_ref,
        driver=row.driver,
        driver_ref=row.driver_ref,
        resources=ResourceSpec(
            cpu_millicores=row.cpu_millicores,
            memory_mib=row.memory_mib,
            disk_gib=row.disk_gib,
        ),
        env=dict(row.env),
        labels=dict(row.labels),
        network=NetworkPolicy.model_validate(row.network_policy),
        public=row.public,
        auto_stop_minutes=row.auto_stop_minutes,
        auto_delete_minutes=row.auto_delete_minutes,
        last_activity_at=opt_utc(row.last_activity_at),
        started_at=opt_utc(row.started_at),
        stopped_at=opt_utc(row.stopped_at),
        error_reason=row.error_reason,
        error_code=row.error_code,
        created_at=as_utc(row.created_at),
        updated_at=as_utc(row.updated_at),
        deleted_at=opt_utc(row.deleted_at),
        version=row.version,
        standby=row.standby,
        spec_hash=row.spec_hash,
        node_id=row.node_id,
        egress_allowlist=None if row.egress_allowlist is None else tuple(row.egress_allowlist),
        snapshot=row.snapshot,
        stop_cause=row.stop_cause,
        egress_policy_generation=row.egress_policy_generation,
        egress_credential_epoch=row.egress_credential_epoch,
    )


def label_match(labels: Mapping[str, str]) -> Any:
    """One criterion: the row carries every pair of ``labels`` (non-empty mapping).

    The per-key extraction (``->>`` on Postgres) raises on an unreadable escape and aborts the
    whole query. The ``CASE`` guarantees it is never evaluated for such a row, which simply
    does not match; repair it with ``sandfort-admin repair-labels``.
    """
    column: Any = SandboxRow.labels
    pairs = [column[key].as_string() == value for key, value in labels.items()]
    return case((unreadable_labels(), false()), else_=and_(*pairs))


def unreadable_labels() -> Any:
    """The guard predicate on the raw labels text (no extraction, so it never raises)."""
    return cast(SandboxRow.labels, Text).regexp_match(UNREADABLE_LABELS)


def _mutable_values(sandbox: Sandbox) -> dict[str, Any]:
    """Columns that change over a sandbox's life (everything but identity and versioning).

    ``node_id`` is left out on purpose: placement stamps it after ``add``, and a write from an
    entity loaded before the stamp must not move the sandbox back to the default node.
    """
    return {
        "name": sandbox.name,
        "state": sandbox.state.value,
        "desired_state": sandbox.desired_state.value,
        "image_ref": sandbox.image_ref,
        "driver": sandbox.driver,
        "driver_ref": sandbox.driver_ref,
        "cpu_millicores": sandbox.resources.cpu_millicores,
        "memory_mib": sandbox.resources.memory_mib,
        "disk_gib": sandbox.resources.disk_gib,
        "env": dict(sandbox.env),
        "labels": dict(sandbox.labels),
        "network_policy": sandbox.network.model_dump(mode="json"),
        "public": sandbox.public,
        "auto_stop_minutes": sandbox.auto_stop_minutes,
        "auto_delete_minutes": sandbox.auto_delete_minutes,
        "last_activity_at": opt_utc(sandbox.last_activity_at),
        "started_at": opt_utc(sandbox.started_at),
        "stopped_at": opt_utc(sandbox.stopped_at),
        "error_reason": sandbox.error_reason,
        "error_code": sandbox.error_code,
        "stop_cause": sandbox.stop_cause,
        "deleted_at": opt_utc(sandbox.deleted_at),
        "standby": sandbox.standby,
        "spec_hash": sandbox.spec_hash,
        "egress_allowlist": (
            None if sandbox.egress_allowlist is None else list(sandbox.egress_allowlist)
        ),
        "egress_policy_generation": sandbox.egress_policy_generation,
        "egress_credential_epoch": sandbox.egress_credential_epoch,
    }


class SqlSandboxRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, sandbox: Sandbox) -> None:
        self._session.add(
            SandboxRow(
                id=sandbox.id,
                org_id=sandbox.org_id,
                created_at=as_utc(sandbox.created_at),
                updated_at=as_utc(sandbox.updated_at),
                version=sandbox.version,
                snapshot=sandbox.snapshot,  # fixed at create
                **_mutable_values(sandbox),
            )
        )
        await flush_or_conflict(
            self._session,
            "a sandbox with this name already exists in this organization; "
            "choose a different name or delete the existing one",
            reason=NAME_TAKEN,
        )

    async def get(self, org_id: str, sandbox_id: str) -> Sandbox | None:
        return await self._get_one(SandboxRow.org_id == org_id, SandboxRow.id == sandbox_id)

    async def get_by_name(self, org_id: str, name: str) -> Sandbox | None:
        return await self._get_one(SandboxRow.org_id == org_id, SandboxRow.name == name)

    async def list(
        self,
        org_id: str,
        *,
        state: SandboxState | None = None,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 50,
        order: SortOrder = "asc",
        stop_cause: str | None = None,
    ) -> Sequence[Sandbox]:
        """One page; ``stop_cause`` keeps the sandboxes that show that cause.

        Only ``stopping`` and ``stopped`` rows show one: the filter is an equality on the stored
        column inside those states, and ``unknown`` means the column is NULL inside them.
        """
        extra: list[Any] = []
        if state is not None:
            extra.append(SandboxRow.state == state.value)
        if stop_cause is not None:
            shown = (SandboxState.STOPPING.value, SandboxState.STOPPED.value)
            extra.append(SandboxRow.state.in_(shown))
            if stop_cause == STOP_CAUSE_UNKNOWN:
                extra.append(SandboxRow.stop_cause.is_(None))
            else:
                extra.append(SandboxRow.stop_cause == stop_cause)
        return await self._page(
            org_id, extra=extra, labels=labels, cursor=cursor, limit=limit, order=order
        )

    async def list_live(
        self,
        org_id: str,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 50,
        order: SortOrder = "asc",
    ) -> Sequence[Sandbox]:
        """``list`` without a state filter, minus the ``destroyed`` tombstones."""
        live = (SandboxRow.state != SandboxState.DESTROYED.value,)
        return await self._page(
            org_id, extra=live, labels=labels, cursor=cursor, limit=limit, order=order
        )

    async def count_in_scope(self, org_id: str, labels: Mapping[str, str]) -> int:
        """Live sandboxes (not destroyed, not standby) carrying every pair of ``labels``."""
        scope = (
            SandboxRow.org_id == org_id,
            SandboxRow.standby.is_(False),
            SandboxRow.state != SandboxState.DESTROYED.value,
        )
        stmt = select(func.count()).where(*scope)
        if labels:
            stmt = stmt.where(label_match(labels))
            await self._warn_unreadable(org_id, scope)
        return int((await self._session.execute(stmt)).scalar_one())

    async def _warn_unreadable(self, org_id: str, scope: tuple[Any, ...]) -> None:
        """Rate-limited diagnostic: count guard-excluded rows and warn, once per org per interval.

        The count scans the org's labels text with the guard regex, so it never runs on every
        labelled request: the timestamp is taken before the query (a failing or slow count is
        not retried by the next request), and a request inside the interval does no extra work.
        """
        now = _monotonic()
        last = _unreadable_checked_at.get(org_id)
        if last is not None and now - last < UNREADABLE_CHECK_INTERVAL_S:
            return
        _unreadable_checked_at[org_id] = now
        stmt = select(func.count()).where(*scope, unreadable_labels())
        excluded = int((await self._session.execute(stmt)).scalar_one())
        if excluded:
            msg = "label filter skipped %d row(s) of org %s with unreadable labels; run %s"
            logger.warning(msg, excluded, org_id, f"sandfort-admin repair-labels --org {org_id}")

    async def _page(
        self,
        org_id: str,
        *,
        extra: Sequence[Any],
        labels: Mapping[str, str] | None,
        cursor: str | None,
        limit: int,
        order: SortOrder,
    ) -> Sequence[Sandbox]:
        """The one query behind ``list`` and ``list_live``; ``extra`` adds state criteria.

        The cursor is the last id of the previous page: ``desc`` continues with smaller ids.
        """
        scope = (SandboxRow.org_id == org_id, SandboxRow.standby.is_(False), *extra)
        stmt = select(SandboxRow).where(*scope)
        if labels:
            stmt = stmt.where(label_match(labels))
            await self._warn_unreadable(org_id, scope)
        newest_first = order == "desc"
        if cursor is not None:
            stmt = stmt.where(SandboxRow.id < cursor if newest_first else SandboxRow.id > cursor)
        stmt = (
            stmt.order_by(SandboxRow.id.desc() if newest_first else SandboxRow.id)
            .limit(max(1, min(limit, MAX_PAGE_SIZE)))
            .execution_options(populate_existing=True)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_to_entity(row) for row in rows]

    async def update(self, org_id: str, sandbox: Sandbox, *, expected_version: int) -> Sandbox:
        """Write ``sandbox`` if the stored version is ``expected_version``; bump the version.

        Raises ``Conflict`` on a stale version and ``NotFound`` when the sandbox
        does not exist in ``org_id``.
        """
        new_version = expected_version + 1
        updated_at = utcnow()
        stmt = (
            update(SandboxRow)
            .where(
                SandboxRow.id == sandbox.id,
                SandboxRow.org_id == org_id,
                SandboxRow.version == expected_version,
            )
            .values(version=new_version, updated_at=updated_at, **_mutable_values(sandbox))
            .execution_options(synchronize_session=False)
        )
        try:
            result = await self._session.execute(stmt)
        except IntegrityError as exc:
            raise Conflict("sandbox name already exists in this org", reason=NAME_TAKEN) from exc
        if rowcount(result) == 0:
            if await self.get(org_id, sandbox.id) is None:
                raise NotFound(f"sandbox {sandbox.id} not found")
            raise Conflict(
                f"sandbox {sandbox.id} was modified concurrently",
                reason=CONCURRENT_UPDATE,
                details={"expected_version": expected_version},
            )
        return sandbox.model_copy(update={"version": new_version, "updated_at": updated_at})

    async def list_for_reconciler(self) -> Sequence[Sandbox]:
        """System path: every non-destroyed sandbox across all orgs."""
        stmt = (
            select(SandboxRow)
            .where(SandboxRow.state != SandboxState.DESTROYED.value)
            .order_by(SandboxRow.id)
            .execution_options(populate_existing=True)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_to_entity(row) for row in rows]

    async def list_for_egress_policy(self, sandbox_ids: Sequence[str]) -> Sequence[Sandbox]:
        """System path for the internal policy route: sandboxes by id across all orgs."""
        stmt = (
            select(SandboxRow)
            .where(SandboxRow.id.in_(list(sandbox_ids)))
            .execution_options(populate_existing=True)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_to_entity(row) for row in rows]

    async def list_for_node(self, node_id: str) -> Sequence[Sandbox]:
        """System path: every non-destroyed sandbox owned by ``node_id``."""
        stmt = (
            select(SandboxRow)
            .where(SandboxRow.state != SandboxState.DESTROYED.value, SandboxRow.node_id == node_id)
            .order_by(SandboxRow.id)
            .execution_options(populate_existing=True)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_to_entity(row) for row in rows]

    async def list_autostop_candidates(self, node_id: str | None = None) -> Sequence[Sandbox]:
        """System path: non-destroyed sandboxes the idle scanner may stop; standbys never are.

        With ``node_id`` only that node's sandboxes are returned.
        """
        stmt = select(SandboxRow).where(
            SandboxRow.state != SandboxState.DESTROYED.value, SandboxRow.standby.is_(False)
        )
        if node_id is not None:
            stmt = stmt.where(SandboxRow.node_id == node_id)
        stmt = stmt.order_by(SandboxRow.id).execution_options(populate_existing=True)
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_to_entity(row) for row in rows]

    async def claim_standby(
        self, org_id: str, spec_hash: str, claim: StandbyClaim
    ) -> Sandbox | None:
        """Turn one started standby of ``spec_hash`` into a normal sandbox, or return ``None``.

        A single ``UPDATE`` guarded on ``standby`` flips the flag and sets the name, so two
        concurrent claims can never take the same row; the loser tries the next standby. A
        ``Conflict`` means the requested name is taken. Pure database work: no driver call.
        """
        for _ in range(CLAIM_ATTEMPTS):
            pick = (
                select(SandboxRow.id)
                .where(
                    SandboxRow.org_id == org_id,
                    SandboxRow.spec_hash == spec_hash,
                    SandboxRow.standby.is_(True),
                    SandboxRow.state == SandboxState.STARTED.value,
                )
                .order_by(SandboxRow.id)
                .limit(1)
            )
            candidate = (await self._session.execute(pick)).scalar_one_or_none()
            if candidate is None:
                return None
            stmt = (
                update(SandboxRow)
                .where(
                    SandboxRow.id == candidate,
                    SandboxRow.org_id == org_id,
                    SandboxRow.standby.is_(True),
                )
                .values(
                    standby=False,
                    name=claim.name or candidate,
                    labels=dict(claim.labels),
                    public=claim.public,
                    auto_stop_minutes=claim.auto_stop_minutes,
                    auto_delete_minutes=claim.auto_delete_minutes,
                    last_activity_at=opt_utc(claim.at),
                    updated_at=claim.at,
                    version=SandboxRow.version + 1,
                )
                .execution_options(synchronize_session=False)
            )
            try:
                result = await self._session.execute(stmt)
            except IntegrityError as exc:
                raise Conflict(
                    "sandbox name already exists in this org", reason=NAME_TAKEN
                ) from exc
            if rowcount(result) == 1:
                return await self._get_one(SandboxRow.org_id == org_id, SandboxRow.id == candidate)
        return None

    async def count_standby(self, org_id: str, spec_hash: str) -> int:
        """Standbys of ``spec_hash`` that count toward the pool (building or ready)."""
        stmt = select(func.count()).where(
            SandboxRow.org_id == org_id,
            SandboxRow.spec_hash == spec_hash,
            SandboxRow.standby.is_(True),
            SandboxRow.state.not_in(_DEAD_STATES),
        )
        return int((await self._session.execute(stmt)).scalar_one())

    async def _get_one(self, *criteria: Any) -> Sandbox | None:
        stmt = select(SandboxRow).where(*criteria).execution_options(populate_existing=True)
        row = (await self._session.execute(stmt)).scalar_one_or_none()
        return None if row is None else _to_entity(row)
