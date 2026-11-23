"""Table ``api_keys``; see architecture.md section 4."""

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from sandfort.db.base import Base, TimestampMixin


class ApiKeyRow(TimestampMixin, Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    prefix: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    secret_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    is_platform_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    sandbox_labels: Mapped[dict[str, str] | None] = mapped_column(
        JSON(none_as_null=True), nullable=True
    )
    max_sandboxes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    shared_volume_labels: Mapped[dict[str, str] | None] = mapped_column(
        JSON(none_as_null=True), nullable=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
