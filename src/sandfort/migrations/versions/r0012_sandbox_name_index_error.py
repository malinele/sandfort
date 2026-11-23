"""Sandbox names are unique per org only among sandboxes that are neither destroyed nor errored

Widens the partial unique index over (org_id, name) so an errored sandbox no longer reserves
its name, the same way a destroyed one already does not.

Revision ID: 0012
Revises: 0011
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

LIVE_NAME_INDEX = "ix_sandboxes_org_id_name_live"
LIVE_ONLY = sa.text("state NOT IN ('destroyed', 'error')")
NOT_DESTROYED = sa.text("state != 'destroyed'")


def _recreate_index(where: sa.TextClause) -> None:
    op.drop_index(LIVE_NAME_INDEX, table_name="sandboxes")
    op.create_index(
        LIVE_NAME_INDEX,
        "sandboxes",
        ["org_id", "name"],
        unique=True,
        sqlite_where=where,
        postgresql_where=where,
    )


def upgrade() -> None:
    _recreate_index(LIVE_ONLY)


def downgrade() -> None:
    # Fails if an errored and a live sandbox of one org share a name: that is the data the
    # old index cannot hold, so it has to be resolved by hand before downgrading.
    _recreate_index(NOT_DESTROYED)
