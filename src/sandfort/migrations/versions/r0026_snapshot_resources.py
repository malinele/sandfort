"""snapshots: resource columns recording the allocation of the sandbox a snapshot was taken from

``cpu_millicores``, ``memory_mib`` and ``disk_gib`` are null for snapshots registered from a
public image or built from an image spec, and for snapshots taken before resources were
recorded. A create that sets ``inherit_resources`` adopts them only when all three are set.

Revision ID: 0026
Revises: 0025
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0026"
down_revision: str | None = "0025"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("snapshots") as batch:
        batch.add_column(sa.Column("cpu_millicores", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("memory_mib", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("disk_gib", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("snapshots") as batch:
        batch.drop_column("disk_gib")
        batch.drop_column("memory_mib")
        batch.drop_column("cpu_millicores")
