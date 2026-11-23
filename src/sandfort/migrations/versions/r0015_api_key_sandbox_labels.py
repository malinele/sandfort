"""api_keys: optional sandbox_labels column scoping a key to labelled sandboxes

Null means the key is unscoped (it reaches every sandbox of its org, as before). A JSON object
of label name to value restricts the key to sandboxes carrying every pair; nothing reads the
column for enforcement yet.

Revision ID: 0015
Revises: 0014
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("api_keys") as batch:
        batch.add_column(sa.Column("sandbox_labels", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("api_keys") as batch:
        batch.drop_column("sandbox_labels")
