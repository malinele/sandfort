"""Table ``audit_events`` (append-only); see architecture.md section 4.

The repository exposes no UPDATE or DELETE path. ``prev_hash``/``hash`` are
reserved for the P5 hash chain.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, CheckConstraint, DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from sandfort.db.base import Base
from sandfort.db.support import in_check
from sandfort.domain.events import ActorType, AuditOutcome


class AuditRow(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint(in_check("actor_type", ActorType), name="actor_type"),
        CheckConstraint(in_check("outcome", AuditOutcome), name="outcome"),
        Index("ix_audit_events_org_id_occurred_at", "org_id", "occurred_at"),
        Index("ix_audit_events_org_id_request_id", "org_id", "request_id"),
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(30), ForeignKey("organizations.id"), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
