"""Table ``sandboxes``; see architecture.md section 4.

``snapshot_id`` and ``sandbox_volume_mounts`` arrive with the
phases that introduce their parent tables.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    false,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from sandfort.db.base import Base, TimestampMixin, VersionMixin
from sandfort.db.support import in_check
from sandfort.domain.node import DEFAULT_NODE_ID
from sandfort.domain.sandbox import SandboxState

# Names are unique only among sandboxes that are not destroyed, errored or destroying; destroyed
# rows are history, an errored sandbox must not block re-creating its name, and a sandbox on its
# way out (destroying) must not reserve its name against a live one.
_LIVE_NAME_ONLY = text(
    f"state NOT IN ('{SandboxState.DESTROYED.value}', '{SandboxState.ERROR.value}', "
    f"'{SandboxState.DESTROYING.value}')"
)


class SandboxRow(TimestampMixin, VersionMixin, Base):
    __tablename__ = "sandboxes"
    __table_args__ = (
        CheckConstraint(in_check("state", SandboxState), name="state"),
        CheckConstraint(in_check("desired_state", SandboxState), name="desired_state"),
        Index(
            "ix_sandboxes_org_id_name_live",
            "org_id",
            "name",
            unique=True,
            sqlite_where=_LIVE_NAME_ONLY,
            postgresql_where=_LIVE_NAME_ONLY,
        ),
        Index("ix_sandboxes_state", "state"),
        Index("ix_sandboxes_spec_hash", "spec_hash"),
        Index("ix_sandboxes_node_id", "node_id"),
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(30), ForeignKey("organizations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    desired_state: Mapped[str] = mapped_column(String(16), nullable=False)
    image_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    driver: Mapped[str] = mapped_column(String(32), nullable=False)
    driver_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cpu_millicores: Mapped[int] = mapped_column(Integer, nullable=False)
    memory_mib: Mapped[int] = mapped_column(Integer, nullable=False)
    disk_gib: Mapped[int] = mapped_column(Integer, nullable=False)
    env: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
    labels: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
    network_policy: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    public: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    auto_stop_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    auto_delete_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    last_activity_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_code: Mapped[str | None] = mapped_column(Text, nullable=True)  # domain ERROR_CODES
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    standby: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    spec_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    node_id: Mapped[str] = mapped_column(
        String(64), nullable=False, default=DEFAULT_NODE_ID, server_default=DEFAULT_NODE_ID
    )
    # JSON list of allowlisted hosts; SQL NULL (not JSON null) keeps today's egress.
    egress_allowlist: Mapped[list[str] | None] = mapped_column(
        JSON(none_as_null=True), nullable=True
    )
    # The snapshot id or image reference the create named; NULL for older rows or no snapshot.
    snapshot: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Why the sandbox stopped (domain STOP_CAUSES, never "unknown"); NULL when not stopped.
    stop_cause: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 0: no allowlist, or a legacy v1 token. 1 at a v2 create, plus 1 per effective PATCH.
    egress_policy_generation: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    # Raised by 1 each time a reset re-mints the token; the token carries it, and a mismatch
    # revokes the token.
    egress_credential_epoch: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
