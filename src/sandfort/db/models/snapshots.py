"""Table ``snapshots``: named images an org can start sandboxes from."""

from datetime import datetime

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from sandfort.db.base import Base, utcnow
from sandfort.db.support import in_check
from sandfort.domain.snapshot import SnapshotState


class SnapshotRow(Base):
    __tablename__ = "snapshots"
    __table_args__ = (
        CheckConstraint(in_check("state", SnapshotState), name="state"),
        UniqueConstraint("org_id", "name", name="uq_snapshots_org_id_name"),
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(30), ForeignKey("organizations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    image_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    digest: Mapped[str] = mapped_column(String(128), nullable=False)
    layer_count: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    source_sandbox_id: Mapped[str | None] = mapped_column(String(30), nullable=True)
    spec_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    isolation: Mapped[str | None] = mapped_column(String(16), nullable=True)
    cpu_millicores: Mapped[int | None] = mapped_column(Integer, nullable=True)
    memory_mib: Mapped[int | None] = mapped_column(Integer, nullable=True)
    disk_gib: Mapped[int | None] = mapped_column(Integer, nullable=True)
    labels: Mapped[dict[str, str]] = mapped_column(
        JSON, nullable=False, default=dict, server_default=text("'{}'")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
