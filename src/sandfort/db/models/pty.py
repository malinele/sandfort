"""Table ``pty_sessions``; see architecture.md section 4."""

from datetime import datetime
from enum import StrEnum

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from sandfort.db.base import Base, utcnow
from sandfort.db.support import in_check


class PtySessionState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"


class PtySessionRow(Base):
    __tablename__ = "pty_sessions"
    __table_args__ = (
        CheckConstraint(in_check("state", PtySessionState), name="state"),
        Index("ix_pty_sessions_org_id_sandbox_id", "org_id", "sandbox_id"),
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(30), ForeignKey("organizations.id"), nullable=False)
    sandbox_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("sandboxes.id"), nullable=False
    )
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    rows: Mapped[int] = mapped_column(Integer, nullable=False)
    cols: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
