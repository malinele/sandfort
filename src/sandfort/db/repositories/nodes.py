"""SQLAlchemy implementation of ``NodeRepository``."""

from collections.abc import Mapping, Sequence

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sandfort.db.models.jobs import JobRow
from sandfort.db.models.nodes import NodeRow
from sandfort.db.models.sandboxes import SandboxRow
from sandfort.db.support import as_utc
from sandfort.domain.node import Node, NodeRoute, NodeState
from sandfort.domain.sandbox import SandboxState


def _to_entity(row: NodeRow) -> Node:
    return Node(
        id=row.id,
        name=row.name,
        max_sandboxes=row.max_sandboxes,
        state=NodeState(row.state),
        last_heartbeat_at=as_utc(row.last_heartbeat_at),
        internal_url=row.internal_url,
        egress_ready=row.egress_ready,
        egress_ready_at=None if row.egress_ready_at is None else as_utc(row.egress_ready_at),
    )


class SqlNodeRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert_heartbeat(self, node: Node) -> None:
        beat = as_utc(node.last_heartbeat_at)
        ready_at = beat if node.egress_ready else None  # the same instant as the beat itself
        row = await self._session.get(NodeRow, node.id, populate_existing=True)
        if row is None:
            self._session.add(
                NodeRow(
                    id=node.id,
                    name=node.name,
                    max_sandboxes=node.max_sandboxes,
                    state=node.state.value,
                    last_heartbeat_at=beat,
                    internal_url=node.internal_url,
                    egress_ready=node.egress_ready,
                    egress_ready_at=ready_at,
                    created_at=beat,
                    updated_at=beat,
                )
            )
        else:
            row.name = node.name
            row.max_sandboxes = node.max_sandboxes
            row.state = node.state.value
            row.last_heartbeat_at = beat
            row.internal_url = node.internal_url
            row.egress_ready = node.egress_ready
            row.egress_ready_at = ready_at
            row.updated_at = beat
        await self._session.flush()

    async def list_nodes(self) -> Sequence[Node]:
        stmt = select(NodeRow).order_by(NodeRow.id).execution_options(populate_existing=True)
        return [_to_entity(row) for row in (await self._session.execute(stmt)).scalars()]

    async def route_for_sandbox(self, sandbox_id: str) -> NodeRoute | None:
        stmt = (
            select(NodeRow)
            .join(SandboxRow, SandboxRow.node_id == NodeRow.id)
            .where(SandboxRow.id == sandbox_id)
            .execution_options(populate_existing=True)
        )
        row = (await self._session.execute(stmt)).scalars().first()
        if row is None:
            return None
        return NodeRoute(
            node_id=row.id,
            internal_url=row.internal_url,
            state=NodeState(row.state),
            last_heartbeat_at=as_utc(row.last_heartbeat_at),
        )

    async def running_counts(self, org_id: str | None = None) -> Mapping[str, int]:
        stmt = (
            select(SandboxRow.node_id, func.count())
            .where(SandboxRow.state == SandboxState.STARTED.value)
            .group_by(SandboxRow.node_id)
        )
        if org_id is not None:
            stmt = stmt.where(SandboxRow.org_id == org_id)
        return {node_id: count for node_id, count in (await self._session.execute(stmt)).all()}

    async def assign_sandbox(self, sandbox_id: str, node_id: str) -> None:
        stmt = update(SandboxRow).where(SandboxRow.id == sandbox_id).values(node_id=node_id)
        await self._session.execute(stmt)

    async def assign_job(self, job_id: str, node_id: str) -> None:
        stmt = update(JobRow).where(JobRow.id == job_id).values(node_id=node_id)
        await self._session.execute(stmt)
