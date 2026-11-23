"""node address: internal_url column on nodes (empty string means not advertised)

Revision ID: 0009
Revises: 0008
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("nodes") as batch:
        batch.add_column(
            sa.Column("internal_url", sa.String(length=255), nullable=False, server_default="")
        )


def downgrade() -> None:
    with op.batch_alter_table("nodes") as batch:
        batch.drop_column("internal_url")
