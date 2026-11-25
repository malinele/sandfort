"""Node entity: one worker process and the docker daemon it drives."""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

DEFAULT_NODE_ID = "local"


class NodeState(StrEnum):
    ACTIVE = "active"
    DRAINING = "draining"


class Node(BaseModel):
    """``max_sandboxes`` of zero means unlimited."""

    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    max_sandboxes: int = Field(default=0, ge=0)
    state: NodeState = NodeState.ACTIVE
    last_heartbeat_at: datetime
    internal_url: str = ""
    egress_ready: bool = False  # proxy address, secret and policy URL all configured
    # The heartbeat time at which ``egress_ready`` was written (equal to ``last_heartbeat_at`` of
    # a new-code beat). Code that predates the flag advances only ``last_heartbeat_at``, so a
    # ready flag older than the last beat is stale and does not count. Set by the repository.
    egress_ready_at: datetime | None = None


class NodeRoute(BaseModel):
    """Where a sandbox's owning node can be reached; callers judge staleness themselves."""

    model_config = ConfigDict(frozen=True)

    node_id: str
    internal_url: str
    state: NodeState
    last_heartbeat_at: datetime
