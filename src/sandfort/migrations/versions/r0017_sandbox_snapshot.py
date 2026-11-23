"""sandboxes: optional snapshot column recording what a sandbox was created from

Null means no recorded source: the sandbox predates the column or was created with no snapshot.
Otherwise it holds the ``snap_`` snapshot id or the image reference given at create.

Revision ID: 0017
Revises: 0016
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("sandboxes") as batch:
        batch.add_column(sa.Column("snapshot", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("sandboxes") as batch:
        batch.drop_column("snapshot")
