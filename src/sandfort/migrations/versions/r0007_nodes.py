"""multi-node schema: nodes registry, node_id on sandboxes and jobs

Revision ID: 0007
Revises: 0006
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

LOCAL = "local"


def upgrade() -> None:
    op.create_table(
        "nodes",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("max_sandboxes", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("state IN ('active', 'draining')", name="state"),
    )
    for table in ("sandboxes", "jobs"):
        with op.batch_alter_table(table) as batch:
            batch.add_column(
                sa.Column("node_id", sa.String(64), nullable=False, server_default=LOCAL)
            )
            batch.create_index(f"ix_{table}_node_id", ["node_id"])


def downgrade() -> None:
    for table in ("jobs", "sandboxes"):
        with op.batch_alter_table(table) as batch:
            batch.drop_index(f"ix_{table}_node_id")
            batch.drop_column("node_id")
    op.drop_table("nodes")
