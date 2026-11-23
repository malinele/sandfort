"""Tables ``quotas`` (per-org limits) and ``quota_ledger`` (per-sandbox reservations).

A ``NULL`` limit is unlimited. Ledger rows are released, never deleted, so a
recount can always be reconciled against history (WP 4.1).
"""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Float, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from sandfort.db.base import Base, TimestampMixin, utcnow
from sandfort.db.support import in_check
from sandfort.domain.quota import LedgerEntryState


class QuotaRow(Base):
    __tablename__ = "quotas"

    org_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("organizations.id"), primary_key=True
    )
    max_vcpus: Mapped[float | None] = mapped_column(Float, nullable=True)
    max_memory_mib: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_disk_gib: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_sandboxes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class QuotaLedgerRow(TimestampMixin, Base):
    __tablename__ = "quota_ledger"
    __table_args__ = (
        CheckConstraint(in_check("state", LedgerEntryState), name="state"),
        Index("ix_quota_ledger_org_id_state", "org_id", "state"),
        Index("ix_quota_ledger_sandbox_id", "sandbox_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(String(30), ForeignKey("organizations.id"), nullable=False)
    sandbox_id: Mapped[str] = mapped_column(String(30), nullable=False)
    vcpus: Mapped[float] = mapped_column(Float, nullable=False)
    memory_mib: Mapped[int] = mapped_column(Integer, nullable=False)
    disk_gib: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
