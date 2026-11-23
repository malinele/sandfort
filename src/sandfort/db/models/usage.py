"""Tables ``usage_intervals`` and ``usage_rollups`` mirroring ``sandfort.domain.usage`` (D9).

Rollups are keyed by (org, period, dimension) so a rerun upserts instead of
double counting (WP 4.3).
"""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Float, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from sandfort.db.base import Base
from sandfort.db.support import in_check
from sandfort.domain.usage import UsageDimension


class UsageIntervalRow(Base):
    __tablename__ = "usage_intervals"
    __table_args__ = (
        CheckConstraint(in_check("dimension", UsageDimension), name="dimension"),
        Index("ix_usage_intervals_org_id_ended_at", "org_id", "ended_at"),
        Index("ix_usage_intervals_sandbox_id_ended_at", "sandbox_id", "ended_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(String(30), ForeignKey("organizations.id"), nullable=False)
    sandbox_id: Mapped[str] = mapped_column(String(30), nullable=False)
    dimension: Mapped[str] = mapped_column(String(16), nullable=False)
    amount: Mapped[float] = mapped_column(Float, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class UsageRollupRow(Base):
    __tablename__ = "usage_rollups"
    __table_args__ = (CheckConstraint(in_check("dimension", UsageDimension), name="dimension"),)

    org_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("organizations.id"), primary_key=True
    )
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    dimension: Mapped[str] = mapped_column(String(16), primary_key=True)
    total: Mapped[float] = mapped_column(Float, nullable=False)
