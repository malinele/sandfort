"""Sandbox names are unique per org only among sandboxes that are not destroyed

Replaces the plain unique constraint over (org_id, name) with a partial unique index, so a
destroyed sandbox no longer reserves its name.

Revision ID: 0011
Revises: 0010
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_UNIQUE = "uq_sandboxes_org_id_name"
LIVE_NAME_INDEX = "ix_sandboxes_org_id_name_live"
LIVE_ONLY = sa.text("state != 'destroyed'")


def upgrade() -> None:
    with op.batch_alter_table("sandboxes") as batch:
        batch.drop_constraint(OLD_UNIQUE, type_="unique")
    op.create_index(
        LIVE_NAME_INDEX,
        "sandboxes",
        ["org_id", "name"],
        unique=True,
        sqlite_where=LIVE_ONLY,
        postgresql_where=LIVE_ONLY,
    )


def downgrade() -> None:
    # Fails if a destroyed and a live sandbox of one org share a name: that is the data the
    # old constraint cannot hold, so it has to be resolved by hand before downgrading.
    op.drop_index(LIVE_NAME_INDEX, table_name="sandboxes")
    with op.batch_alter_table("sandboxes") as batch:
        batch.create_unique_constraint(OLD_UNIQUE, ["org_id", "name"])
