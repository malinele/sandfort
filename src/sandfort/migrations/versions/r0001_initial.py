"""initial schema: organizations, api_keys, sandboxes, idempotency_keys, audit_events

Revision ID: 0001
Revises:
"""

from collections.abc import Sequence
from datetime import datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SANDBOX_STATES = (
    "'pending', 'creating', 'started', 'stopping', 'stopped', "
    "'starting', 'destroying', 'destroyed', 'error'"
)


def _timestamp(name: str, *, nullable: bool = False) -> sa.Column[datetime]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(30), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(63), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        _timestamp("created_at"),
        _timestamp("updated_at"),
        sa.CheckConstraint(
            "status IN ('active', 'suspended')", name=op.f("ck_organizations_status")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_organizations")),
        sa.UniqueConstraint("slug", name=op.f("uq_organizations_slug")),
    )

    op.create_table(
        "api_keys",
        sa.Column("id", sa.String(30), nullable=False),
        sa.Column("org_id", sa.String(30), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("prefix", sa.String(64), nullable=False),
        sa.Column("secret_hash", sa.String(128), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("is_platform_admin", sa.Boolean(), nullable=False),
        _timestamp("last_used_at", nullable=True),
        _timestamp("expires_at", nullable=True),
        _timestamp("revoked_at", nullable=True),
        sa.Column("created_by", sa.String(64), nullable=True),
        _timestamp("created_at"),
        _timestamp("updated_at"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], name=op.f("fk_api_keys_org_id_organizations")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_api_keys")),
        sa.UniqueConstraint("prefix", name=op.f("uq_api_keys_prefix")),
    )
    op.create_index(op.f("ix_api_keys_org_id"), "api_keys", ["org_id"])

    op.create_table(
        "sandboxes",
        sa.Column("id", sa.String(30), nullable=False),
        sa.Column("org_id", sa.String(30), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("desired_state", sa.String(16), nullable=False),
        sa.Column("image_ref", sa.String(512), nullable=False),
        sa.Column("driver", sa.String(32), nullable=False),
        sa.Column("driver_ref", sa.String(255), nullable=True),
        sa.Column("cpu_millicores", sa.Integer(), nullable=False),
        sa.Column("memory_mib", sa.Integer(), nullable=False),
        sa.Column("disk_gib", sa.Integer(), nullable=False),
        sa.Column("env", sa.JSON(), nullable=False),
        sa.Column("labels", sa.JSON(), nullable=False),
        sa.Column("network_policy", sa.JSON(), nullable=False),
        sa.Column("public", sa.Boolean(), nullable=False),
        sa.Column("auto_stop_minutes", sa.Integer(), nullable=False),
        sa.Column("auto_delete_minutes", sa.Integer(), nullable=False),
        _timestamp("last_activity_at", nullable=True),
        _timestamp("started_at", nullable=True),
        _timestamp("stopped_at", nullable=True),
        sa.Column("error_reason", sa.Text(), nullable=True),
        _timestamp("deleted_at", nullable=True),
        _timestamp("created_at"),
        _timestamp("updated_at"),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(f"state IN ({SANDBOX_STATES})", name=op.f("ck_sandboxes_state")),
        sa.CheckConstraint(
            f"desired_state IN ({SANDBOX_STATES})", name=op.f("ck_sandboxes_desired_state")
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], name=op.f("fk_sandboxes_org_id_organizations")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sandboxes")),
        sa.UniqueConstraint("org_id", "name", name="uq_sandboxes_org_id_name"),
    )
    op.create_index("ix_sandboxes_state", "sandboxes", ["state"])

    op.create_table(
        "idempotency_keys",
        sa.Column("org_id", sa.String(30), nullable=False),
        sa.Column("key", sa.String(255), nullable=False),
        sa.Column("request_hash", sa.String(128), nullable=False),
        sa.Column("response_status", sa.Integer(), nullable=False),
        sa.Column("response_body", sa.JSON(), nullable=False),
        _timestamp("expires_at"),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_idempotency_keys_org_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("org_id", "key", name=op.f("pk_idempotency_keys")),
    )
    op.create_index("ix_idempotency_keys_expires_at", "idempotency_keys", ["expires_at"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(30), nullable=False),
        sa.Column("org_id", sa.String(30), nullable=False),
        sa.Column("actor_type", sa.String(16), nullable=False),
        sa.Column("actor_id", sa.String(64), nullable=True),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=True),
        sa.Column("target_id", sa.String(64), nullable=True),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("request_id", sa.String(64), nullable=True),
        sa.Column("ip", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.String(512), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        _timestamp("occurred_at"),
        sa.Column("prev_hash", sa.String(64), nullable=True),
        sa.Column("hash", sa.String(64), nullable=True),
        sa.CheckConstraint(
            "actor_type IN ('api_key', 'system', 'platform_admin')",
            name=op.f("ck_audit_events_actor_type"),
        ),
        sa.CheckConstraint(
            "outcome IN ('success', 'denied', 'error')", name=op.f("ck_audit_events_outcome")
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], name=op.f("fk_audit_events_org_id_organizations")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
    )
    op.create_index("ix_audit_events_org_id_occurred_at", "audit_events", ["org_id", "occurred_at"])


def downgrade() -> None:
    op.drop_index("ix_audit_events_org_id_occurred_at", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_index("ix_idempotency_keys_expires_at", table_name="idempotency_keys")
    op.drop_table("idempotency_keys")
    op.drop_index("ix_sandboxes_state", table_name="sandboxes")
    op.drop_table("sandboxes")
    op.drop_index(op.f("ix_api_keys_org_id"), table_name="api_keys")
    op.drop_table("api_keys")
    op.drop_table("organizations")
