"""volumes: labels column

A JSON object of string labels per volume, so a label-scoped key can own volumes. Existing
rows get the empty mapping.

Revision ID: 0021
Revises: 0020
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: str | None = "0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("volumes") as batch:
        batch.add_column(
            sa.Column("labels", sa.JSON(), nullable=False, server_default=sa.text("'{}'"))
        )


def downgrade() -> None:
    with op.batch_alter_table("volumes") as batch:
        batch.drop_column("labels")
