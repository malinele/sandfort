"""sandboxes: optional stop_cause column

Null means the sandbox is not stopping or stopped, or it stopped before the column existed
(the API shows ``unknown`` then). Otherwise it holds one of the stored causes in
``sandfort.domain.sandbox.STOP_CAUSES``. No backfill.

Revision ID: 0020
Revises: 0019
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0020"
down_revision: str | None = "0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("sandboxes") as batch:
        batch.add_column(sa.Column("stop_cause", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("sandboxes") as batch:
        batch.drop_column("stop_cause")
