"""api_keys: optional max_sandboxes column capping a label-scoped key's sandboxes

Null means the key has no cap (as before). An integer is the most non-destroyed sandboxes
carrying the key's ``sandbox_labels`` that a create under the key may leave behind; it is only
set together with a label scope.

Revision ID: 0016
Revises: 0015
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("api_keys") as batch:
        batch.add_column(sa.Column("max_sandboxes", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("api_keys") as batch:
        batch.drop_column("max_sandboxes")
