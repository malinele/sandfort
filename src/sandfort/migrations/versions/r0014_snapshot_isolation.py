"""snapshots: isolation column recording the tier of the sandbox a snapshot was taken from

Null for snapshots registered from a public image or built from an image spec, and for
snapshots taken before tiers were recorded: a sandbox created from them uses the tier the
request names or the deployment default.

Revision ID: 0014
Revises: 0013
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("snapshots") as batch:
        batch.add_column(sa.Column("isolation", sa.String(length=16), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("snapshots") as batch:
        batch.drop_column("isolation")
