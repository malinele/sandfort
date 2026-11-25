"""Table ``nodes``: the registry of worker nodes (placement reads it in a later slice)."""

from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, Integer, String, false
from sqlalchemy.orm import Mapped, mapped_column

from sandfort.db.base import Base, TimestampMixin
from sandfort.db.support import in_check
from sandfort.domain.node import NodeState


class NodeRow(TimestampMixin, Base):
    __tablename__ = "nodes"
    __table_args__ = (CheckConstraint(in_check("state", NodeState), name="state"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    max_sandboxes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default=NodeState.ACTIVE.value)
    last_heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    internal_url: Mapped[str] = mapped_column(
        String(255), nullable=False, default="", server_default=""
    )
    # True while the node's latest heartbeat had a proxy address, a secret and a policy URL.
    egress_ready: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    # The beat that wrote ``egress_ready``; older than ``last_heartbeat_at`` means a worker that
    # does not know the flag has beaten since, so the flag is stale (placement fails closed).
    egress_ready_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
