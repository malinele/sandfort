"""nodes: egress_ready (egress v2, round 5)

``egress_ready`` is true while a node's latest heartbeat reported a proxy address, a secret and
a policy URL. It is NOT NULL with server default false, so existing rows read false and a
node counts for allowlisted placement only after it has heartbeated with the new code (fail
closed until then). ``egress_ready_at`` (nullable) is the beat that wrote the flag: a worker
rolled back to code without the flag advances ``last_heartbeat_at`` but not ``egress_ready_at``,
so placement sees a ready time older than the last beat and fails closed.

Revision ID: 0028
Revises: 0027
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0028"
down_revision: str | None = "0027"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("nodes") as batch:
        batch.add_column(
            sa.Column("egress_ready", sa.Boolean(), nullable=False, server_default=sa.false())
        )
        batch.add_column(sa.Column("egress_ready_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("nodes") as batch:
        batch.drop_column("egress_ready_at")
        batch.drop_column("egress_ready")
