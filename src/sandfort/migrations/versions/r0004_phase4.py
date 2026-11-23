"""phase 4 schema: quotas, quota ledger, outbox, webhooks, usage

Revision ID: 0004
Revises: 0003
"""

from collections.abc import Sequence
from datetime import datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _timestamp(name: str, *, nullable: bool = False) -> sa.Column[datetime]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _org_fk(table: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["org_id"], ["organizations.id"], name=op.f(f"fk_{table}_org_id_organizations")
    )


def _create_quota_tables() -> None:
    op.create_table(
        "quotas",
        sa.Column("org_id", sa.String(30), nullable=False),
        sa.Column("max_vcpus", sa.Float(), nullable=True),
        sa.Column("max_memory_mib", sa.Integer(), nullable=True),
        sa.Column("max_disk_gib", sa.Integer(), nullable=True),
        sa.Column("max_sandboxes", sa.Integer(), nullable=True),
        _timestamp("updated_at"),
        _org_fk("quotas"),
        sa.PrimaryKeyConstraint("org_id", name=op.f("pk_quotas")),
    )
    op.create_table(
        "quota_ledger",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("org_id", sa.String(30), nullable=False),
        sa.Column("sandbox_id", sa.String(30), nullable=False),
        sa.Column("vcpus", sa.Float(), nullable=False),
        sa.Column("memory_mib", sa.Integer(), nullable=False),
        sa.Column("disk_gib", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        _timestamp("created_at"),
        _timestamp("updated_at"),
        sa.CheckConstraint(
            "state IN ('reserved', 'released')", name=op.f("ck_quota_ledger_state")
        ),
        _org_fk("quota_ledger"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_quota_ledger")),
    )
    op.create_index("ix_quota_ledger_org_id_state", "quota_ledger", ["org_id", "state"])
    op.create_index("ix_quota_ledger_sandbox_id", "quota_ledger", ["sandbox_id"])


def _create_event_tables() -> None:
    op.create_table(
        "outbox_events",
        sa.Column("id", sa.String(30), nullable=False),
        sa.Column("org_id", sa.String(30), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        _timestamp("created_at"),
        _timestamp("dispatched_at", nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        _org_fk("outbox_events"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_outbox_events")),
    )
    op.create_index("ix_outbox_events_dispatched_at", "outbox_events", ["dispatched_at"])

    op.create_table(
        "webhook_endpoints",
        sa.Column("id", sa.String(30), nullable=False),
        sa.Column("org_id", sa.String(30), nullable=False),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("secret", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        sa.Column("event_types", sa.JSON(), nullable=False),
        _timestamp("created_at"),
        _org_fk("webhook_endpoints"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_webhook_endpoints")),
    )
    op.create_table(
        "webhook_deliveries",
        sa.Column("id", sa.String(30), nullable=False),
        sa.Column("endpoint_id", sa.String(30), nullable=False),
        sa.Column("event_id", sa.String(30), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        _timestamp("next_attempt_at", nullable=True),
        sa.Column("last_status", sa.Integer(), nullable=True),
        _timestamp("created_at"),
        _timestamp("updated_at"),
        sa.CheckConstraint(
            "state IN ('pending', 'delivered', 'failed', 'disabled')",
            name=op.f("ck_webhook_deliveries_state"),
        ),
        sa.ForeignKeyConstraint(
            ["endpoint_id"],
            ["webhook_endpoints.id"],
            name=op.f("fk_webhook_deliveries_endpoint_id_webhook_endpoints"),
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["outbox_events.id"],
            name=op.f("fk_webhook_deliveries_event_id_outbox_events"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_webhook_deliveries")),
        sa.UniqueConstraint(
            "endpoint_id", "event_id", name=op.f("uq_webhook_deliveries_endpoint_id_event_id")
        ),
    )
    op.create_index(
        "ix_webhook_deliveries_state_next_attempt_at",
        "webhook_deliveries",
        ["state", "next_attempt_at"],
    )


def _create_usage_tables() -> None:
    dimension_check = "dimension IN ('vcpu', 'memory_mib', 'disk_gib')"
    op.create_table(
        "usage_intervals",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("org_id", sa.String(30), nullable=False),
        sa.Column("sandbox_id", sa.String(30), nullable=False),
        sa.Column("dimension", sa.String(16), nullable=False),
        sa.Column("amount", sa.Float(), nullable=False),
        _timestamp("started_at"),
        _timestamp("ended_at", nullable=True),
        sa.CheckConstraint(dimension_check, name=op.f("ck_usage_intervals_dimension")),
        _org_fk("usage_intervals"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_usage_intervals")),
    )
    op.create_index(
        "ix_usage_intervals_org_id_ended_at", "usage_intervals", ["org_id", "ended_at"]
    )
    op.create_index(
        "ix_usage_intervals_sandbox_id_ended_at", "usage_intervals", ["sandbox_id", "ended_at"]
    )
    op.create_table(
        "usage_rollups",
        sa.Column("org_id", sa.String(30), nullable=False),
        _timestamp("period_start"),
        sa.Column("dimension", sa.String(16), nullable=False),
        sa.Column("total", sa.Float(), nullable=False),
        sa.CheckConstraint(dimension_check, name=op.f("ck_usage_rollups_dimension")),
        _org_fk("usage_rollups"),
        sa.PrimaryKeyConstraint(
            "org_id", "period_start", "dimension", name=op.f("pk_usage_rollups")
        ),
    )


def upgrade() -> None:
    _create_quota_tables()
    _create_event_tables()
    _create_usage_tables()


def downgrade() -> None:
    op.drop_table("usage_rollups")
    op.drop_index("ix_usage_intervals_sandbox_id_ended_at", table_name="usage_intervals")
    op.drop_index("ix_usage_intervals_org_id_ended_at", table_name="usage_intervals")
    op.drop_table("usage_intervals")
    op.drop_index("ix_webhook_deliveries_state_next_attempt_at", table_name="webhook_deliveries")
    op.drop_table("webhook_deliveries")
    op.drop_table("webhook_endpoints")
    op.drop_index("ix_outbox_events_dispatched_at", table_name="outbox_events")
    op.drop_table("outbox_events")
    op.drop_index("ix_quota_ledger_sandbox_id", table_name="quota_ledger")
    op.drop_index("ix_quota_ledger_org_id_state", table_name="quota_ledger")
    op.drop_table("quota_ledger")
    op.drop_table("quotas")
