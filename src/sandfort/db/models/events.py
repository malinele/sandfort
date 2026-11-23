"""Table ``outbox_events``: the transactional outbox (D5), delivered at least once.

Rows are written in the same unit of work as the state change they describe;
the webhook dispatcher (WP 4.2) reads undispatched rows and stamps ``dispatched_at``.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from sandfort.db.base import Base, utcnow


class OutboxEventRow(Base):
    __tablename__ = "outbox_events"
    __table_args__ = (Index("ix_outbox_events_dispatched_at", "dispatched_at"),)

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(30), ForeignKey("organizations.id"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
