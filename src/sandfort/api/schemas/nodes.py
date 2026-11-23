"""Response schema of ``GET /v1/nodes``: one registry row with the caller org's load on it."""

from collections.abc import Mapping, Sequence
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from sandfort.domain.node import NodeState
from sandfort.services.node_registry import NodeStatus


class NodeResponse(BaseModel):
    """``max_sandboxes`` of zero means the node admits an unlimited number."""

    model_config = ConfigDict(frozen=True)

    id: str
    state: NodeState
    max_sandboxes: int
    running_sandboxes: int = Field(
        description=(
            "Started sandboxes of the caller's org on this node. Sandboxes of other orgs on "
            "the same host are not counted, so this is not the host-wide load."
        )
    )
    last_heartbeat_at: datetime
    stale: bool


def node_responses(
    statuses: Sequence[NodeStatus], running_by_node: Mapping[str, int]
) -> list[NodeResponse]:
    """One response per registry row; ``running_by_node`` holds the caller org's counts."""
    return [
        NodeResponse(
            id=item.node.id,
            state=item.node.state,
            max_sandboxes=item.node.max_sandboxes,
            running_sandboxes=running_by_node.get(item.node.id, 0),
            last_heartbeat_at=item.node.last_heartbeat_at,
            stale=item.stale,
        )
        for item in statuses
    ]
