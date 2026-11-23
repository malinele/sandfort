"""snapshots: labels column

A JSON object of string labels per snapshot, so a label-scoped key can own snapshots like it
owns volumes. Existing rows get the empty mapping.

Revision ID: 0024
Revises: 0023
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0024"
down_revision: str | None = "0023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("snapshots") as batch:
        batch.add_column(
            sa.Column("labels", sa.JSON(), nullable=False, server_default=sa.text("'{}'"))
        )


def downgrade() -> None:
    with op.batch_alter_table("snapshots") as batch:
        batch.drop_column("labels")
