"""webhook_deliveries: delivery detail columns

Adds ``event_type``, ``payload_sha256`` (hash of the signed body, never the body),
``last_error`` (short sanitised transport reason) and ``attempt_history`` (JSON list, one entry
per attempt). Existing rows get NULL fields and the empty history.

Revision ID: 0022
Revises: 0021
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("webhook_deliveries") as batch:
        batch.add_column(sa.Column("event_type", sa.String(64), nullable=True))
        batch.add_column(sa.Column("payload_sha256", sa.String(64), nullable=True))
        batch.add_column(sa.Column("last_error", sa.String(200), nullable=True))
        batch.add_column(
            sa.Column(
                "attempt_history", sa.JSON(), nullable=False, server_default=sa.text("'[]'")
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("webhook_deliveries") as batch:
        batch.drop_column("attempt_history")
        batch.drop_column("last_error")
        batch.drop_column("payload_sha256")
        batch.drop_column("event_type")
