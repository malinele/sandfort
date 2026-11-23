"""api_keys: optional shared_volume_labels column for read-only shared volumes

Null means the key has no shared volumes (as before). A label map lets a label-scoped key list
and get the volumes whose labels contain every pair, and mount them read-only.

Revision ID: 0023
Revises: 0022
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0023"
down_revision: str | None = "0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("api_keys") as batch:
        batch.add_column(
            sa.Column("shared_volume_labels", sa.JSON(none_as_null=True), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("api_keys") as batch:
        batch.drop_column("shared_volume_labels")
