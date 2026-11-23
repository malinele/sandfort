"""phase 8 schema: warm pool columns on sandboxes (standby flag, spec hash)

Revision ID: 0006
Revises: 0005
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "sandboxes",
        sa.Column("standby", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("sandboxes", sa.Column("spec_hash", sa.String(64), nullable=True))
    op.create_index("ix_sandboxes_spec_hash", "sandboxes", ["spec_hash"])


def downgrade() -> None:
    op.drop_index("ix_sandboxes_spec_hash", table_name="sandboxes")
    op.drop_column("sandboxes", "spec_hash")
    op.drop_column("sandboxes", "standby")
