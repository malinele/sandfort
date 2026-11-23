"""Node registry: this worker's periodic heartbeat, and the listing placement will read.

Each worker upserts its own row (configured id, capacity, ``active``) every interval. A node
whose last heartbeat is older than ``HEARTBEAT_STALE_AFTER`` is reported ``stale``; nothing is
removed or moved because of it in this slice. The stamp helpers record the owning node on a
sandbox or job row; the default node is the column default, so they skip it (no extra SQL).
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta

from sandfort.clock import Clock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.node import DEFAULT_NODE_ID, Node, NodeState
from sandfort.workers.reconciler import PassLoop

HEARTBEAT_STALE_AFTER = timedelta(seconds=90)


@dataclass(frozen=True, slots=True)
class NodeStatus:
    node: Node
    running_sandboxes: int
    stale: bool


async def stamp_sandbox(uow: UnitOfWorkPort, sandbox_id: str, node_id: str) -> None:
    if node_id != DEFAULT_NODE_ID:
        await uow.nodes.assign_sandbox(sandbox_id, node_id)


async def stamp_job(uow: UnitOfWorkPort, job_id: str, node_id: str) -> None:
    if node_id != DEFAULT_NODE_ID:
        await uow.nodes.assign_job(job_id, node_id)


async def pick_node(uow: UnitOfWorkPort, clock: Clock, local_node_id: str) -> str:
    """The least loaded active, fresh node below capacity; ``local_node_id`` if none qualifies.

    An empty registry or no qualifying node never fails a create: it lands on the local node.
    """
    nodes = await uow.nodes.list_nodes()
    if not nodes:
        return local_node_id
    counts = await uow.nodes.running_counts()
    now = clock.now()
    open_nodes = [
        (counts.get(node.id, 0), node.id)
        for node in nodes
        if node.state is NodeState.ACTIVE
        and now - node.last_heartbeat_at <= HEARTBEAT_STALE_AFTER
        and not (node.max_sandboxes and counts.get(node.id, 0) >= node.max_sandboxes)
    ]
    return min(open_nodes)[1] if open_nodes else local_node_id


class NodeRegistry:
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWorkPort],
        clock: Clock,
        *,
        node_id: str,
        max_sandboxes: int,
        interval_s: float,
        internal_url: str = "",
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._node_id = node_id
        self._max_sandboxes = max_sandboxes
        self._internal_url = internal_url
        self._loop = PassLoop("node-heartbeat", self.heartbeat, interval_s)

    @property
    def running(self) -> bool:
        return self._loop.running

    def start(self) -> None:
        self._loop.start()

    async def stop(self) -> None:
        await self._loop.stop()

    async def heartbeat(self) -> Node:
        """Create or refresh this node's row."""
        node = Node(
            id=self._node_id,
            name=self._node_id,
            max_sandboxes=self._max_sandboxes,
            state=NodeState.ACTIVE,
            last_heartbeat_at=self._clock.now(),
            internal_url=self._internal_url,
        )
        async with self._uow_factory() as uow:
            await uow.nodes.upsert_heartbeat(node)
            await uow.commit()
        return node

    async def list_nodes(self) -> list[NodeStatus]:
        """Every node with its started-sandbox count and a staleness flag."""
        now = self._clock.now()
        async with self._uow_factory() as uow:
            nodes = await uow.nodes.list_nodes()
            counts = await uow.nodes.running_counts()
        return [
            NodeStatus(
                node=node,
                running_sandboxes=counts.get(node.id, 0),
                stale=now - node.last_heartbeat_at > HEARTBEAT_STALE_AFTER,
            )
            for node in nodes
        ]
