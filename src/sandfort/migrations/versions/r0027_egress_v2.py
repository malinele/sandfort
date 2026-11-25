"""sandboxes: egress policy generation and credential epoch (egress v2, round 3)

``egress_policy_generation`` is 0 for a sandbox without an allowlist and for a legacy sandbox
whose proxy credential is a v1 token; a v2 create stores 1 and every effective PATCH of the
allowlist adds 1. ``egress_credential_epoch`` is raised by 1 each time a reset re-mints the
token; the token carries it, and a mismatch revokes the token. Both columns are NOT NULL with
server default 0, so existing rows read generation 0 and epoch 0 and nothing is backfilled.

Revision ID: 0027
Revises: 0026
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0027"
down_revision: str | None = "0026"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("sandboxes") as batch:
        batch.add_column(
            sa.Column("egress_policy_generation", sa.Integer(), nullable=False, server_default="0")
        )
        batch.add_column(
            sa.Column("egress_credential_epoch", sa.Integer(), nullable=False, server_default="0")
        )


def downgrade() -> None:
    with op.batch_alter_table("sandboxes") as batch:
        batch.drop_column("egress_credential_epoch")
        batch.drop_column("egress_policy_generation")
