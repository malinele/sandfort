"""Tables ``users`` and ``org_memberships``; see architecture.md section 4."""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from sandfort.db.base import Base, TimestampMixin
from sandfort.db.support import in_check
from sandfort.domain.user import OrgRole


class UserRow(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class OrgMembershipRow(TimestampMixin, Base):
    __tablename__ = "org_memberships"
    __table_args__ = (
        CheckConstraint(in_check("role", OrgRole), name="role"),
        UniqueConstraint("org_id", "external_id", name="uq_org_memberships_org_id_external_id"),
    )

    user_id: Mapped[str] = mapped_column(String(30), ForeignKey("users.id"), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("organizations.id"), primary_key=True, index=True
    )
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    external_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
