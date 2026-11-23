"""sandboxes: optional error_code column next to error_reason

Null means no error, or an error recorded before the column existed. Otherwise it holds one
of the fixed codes in ``sandfort.domain.sandbox.ERROR_CODES``.

Revision ID: 0018
Revises: 0017
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("sandboxes") as batch:
        batch.add_column(sa.Column("error_code", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("sandboxes") as batch:
        batch.drop_column("error_code")
