"""Table ``organizations``; see architecture.md section 4."""

from sqlalchemy import CheckConstraint, String
from sqlalchemy.orm import Mapped, mapped_column

from sandfort.db.base import Base, TimestampMixin
from sandfort.db.support import in_check
from sandfort.domain.org import OrgStatus


class OrgRow(TimestampMixin, Base):
    __tablename__ = "organizations"
    __table_args__ = (CheckConstraint(in_check("status", OrgStatus), name="status"),)

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(63), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=OrgStatus.ACTIVE.value)
