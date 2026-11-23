"""Table ``scim_tokens``; see scim-design.md section 4 (the SCIM token)."""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from sandfort.db.base import Base, TimestampMixin
from sandfort.db.support import in_check
from sandfort.domain.user import OrgRole


class ScimTokenRow(TimestampMixin, Base):
    __tablename__ = "scim_tokens"
    __table_args__ = (CheckConstraint(in_check("max_role", OrgRole), name="max_role"),)

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    prefix: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    secret_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    max_role: Mapped[str] = mapped_column(String(16), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
