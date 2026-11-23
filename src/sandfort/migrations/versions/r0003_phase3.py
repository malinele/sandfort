"""phase 3 schema: jobs, snapshots, volumes

Revision ID: 0003
Revises: 0002
"""

from collections.abc import Sequence
from datetime import datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _timestamp(name: str, *, nullable: bool = False) -> sa.Column[datetime]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def upgrade() -> None:
    op.create_table(
        "jobs",
        sa.Column("id", sa.String(30), nullable=False),
        sa.Column("org_id", sa.String(30), nullable=False),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        _timestamp("run_after"),
        _timestamp("lease_expires_at", nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        _timestamp("created_at"),
        _timestamp("updated_at"),
        sa.CheckConstraint(
            "state IN ('queued', 'leased', 'done', 'failed', 'dead')",
            name=op.f("ck_jobs_state"),
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], name=op.f("fk_jobs_org_id_organizations")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_jobs")),
    )
    op.create_index("ix_jobs_state_run_after", "jobs", ["state", "run_after"])

    op.create_table(
        "snapshots",
        sa.Column("id", sa.String(30), nullable=False),
        sa.Column("org_id", sa.String(30), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("image_ref", sa.String(512), nullable=False),
        sa.Column("digest", sa.String(128), nullable=False),
        sa.Column("layer_count", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("source_sandbox_id", sa.String(30), nullable=True),
        sa.Column("spec_hash", sa.String(64), nullable=True),
        _timestamp("created_at"),
        sa.CheckConstraint(
            "state IN ('pending', 'ready', 'error', 'deleting')",
            name=op.f("ck_snapshots_state"),
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], name=op.f("fk_snapshots_org_id_organizations")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_snapshots")),
        sa.UniqueConstraint("org_id", "name", name=op.f("uq_snapshots_org_id_name")),
    )

    op.create_table(
        "volumes",
        sa.Column("id", sa.String(30), nullable=False),
        sa.Column("org_id", sa.String(30), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("provider_volume_name", sa.String(255), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("sampled_size_bytes", sa.BigInteger(), nullable=True),
        _timestamp("created_at"),
        sa.CheckConstraint("state IN ('ready', 'deleting')", name=op.f("ck_volumes_state")),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], name=op.f("fk_volumes_org_id_organizations")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_volumes")),
        sa.UniqueConstraint("org_id", "name", name=op.f("uq_volumes_org_id_name")),
    )


def downgrade() -> None:
    op.drop_table("volumes")
    op.drop_table("snapshots")
    op.drop_index("ix_jobs_state_run_after", table_name="jobs")
    op.drop_table("jobs")
