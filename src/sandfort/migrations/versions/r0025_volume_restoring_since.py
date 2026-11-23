"""volumes: restoring_since column

A UTC time set while a restore extracts into the volume and cleared when it ended. A value
found at server start means the process died mid-restore, so the volume may hold part of the
archive and is emptied by the start-up recovery. Existing rows get NULL.

Revision ID: 0025
Revises: 0024
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0025"
down_revision: str | None = "0024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("volumes") as batch:
        batch.add_column(
            sa.Column(
                "restoring_since",
                sa.DateTime(timezone=True),
                nullable=True,
                server_default=None,
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("volumes") as batch:
        batch.drop_column("restoring_since")
