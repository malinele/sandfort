"""Tables ``exec_sessions`` and ``exec_commands``; see architecture.md section 4."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from sandfort.db.base import Base, TimestampMixin, utcnow
from sandfort.db.support import in_check


class ExecSessionState(StrEnum):
    ACTIVE = "active"
    CLOSED = "closed"


class ExecCommandState(StrEnum):
    RUNNING = "running"
    EXITED = "exited"
    KILLED = "killed"


class ExecSessionRow(TimestampMixin, Base):
    __tablename__ = "exec_sessions"
    __table_args__ = (
        CheckConstraint(in_check("state", ExecSessionState), name="state"),
        Index("ix_exec_sessions_org_id_sandbox_id", "org_id", "sandbox_id"),
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(30), ForeignKey("organizations.id"), nullable=False)
    sandbox_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("sandboxes.id"), nullable=False
    )
    cwd: Mapped[str | None] = mapped_column(Text, nullable=True)
    env: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    state: Mapped[str] = mapped_column(String(16), nullable=False)


class ExecCommandRow(Base):
    __tablename__ = "exec_commands"
    __table_args__ = (
        CheckConstraint(in_check("state", ExecCommandState), name="state"),
        Index("ix_exec_commands_org_id_sandbox_id", "org_id", "sandbox_id"),
        Index("ix_exec_commands_session_id", "session_id"),
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(30), ForeignKey("organizations.id"), nullable=False)
    sandbox_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("sandboxes.id"), nullable=False
    )
    session_id: Mapped[str | None] = mapped_column(
        String(30), ForeignKey("exec_sessions.id"), nullable=True
    )
    argv: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    stdout_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    stderr_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
