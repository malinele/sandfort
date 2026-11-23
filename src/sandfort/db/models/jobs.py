"""Table ``jobs``: durable background work queue (leased by workers)."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from sandfort.db.base import Base, TimestampMixin, utcnow
from sandfort.db.support import in_check
from sandfort.domain.node import DEFAULT_NODE_ID


class JobState(StrEnum):
    QUEUED = "queued"
    LEASED = "leased"
    DONE = "done"
    FAILED = "failed"
    DEAD = "dead"


class JobRow(TimestampMixin, Base):
    __tablename__ = "jobs"
    __table_args__ = (
        CheckConstraint(in_check("state", JobState), name="state"),
        Index("ix_jobs_state_run_after", "state", "run_after"),
        Index("ix_jobs_node_id", "node_id"),
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(30), ForeignKey("organizations.id"), nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    run_after: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    node_id: Mapped[str] = mapped_column(
        String(64), nullable=False, default=DEFAULT_NODE_ID, server_default=DEFAULT_NODE_ID
    )
