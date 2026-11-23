"""Table ``volumes``: persistent named volumes owned by an org."""

from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from sandfort.db.base import Base, utcnow
from sandfort.db.support import in_check
from sandfort.domain.volume import VolumeState


class VolumeRow(Base):
    __tablename__ = "volumes"
    __table_args__ = (
        CheckConstraint(in_check("state", VolumeState), name="state"),
        UniqueConstraint("org_id", "name", name="uq_volumes_org_id_name"),
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(30), ForeignKey("organizations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    provider_volume_name: Mapped[str] = mapped_column(String(255), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    sampled_size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    labels: Mapped[dict[str, str]] = mapped_column(
        JSON, nullable=False, default=dict, server_default=text("'{}'")
    )
    restoring_since: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, server_default=None
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
