"""Sandbox names are unique per org only among sandboxes not destroyed, errored or destroying

Widens the partial unique index over (org_id, name) so a sandbox on its way out (destroying) no
longer reserves its name against a live one: deleting an errored sandbox moves it through
destroying, and that step used to collide with a live sandbox of the same name.

Revision ID: 0013
Revises: 0012
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

LIVE_NAME_INDEX = "ix_sandboxes_org_id_name_live"
LIVE_ONLY = sa.text("state NOT IN ('destroyed', 'error', 'destroying')")
NOT_DESTROYED_OR_ERROR = sa.text("state NOT IN ('destroyed', 'error')")


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
    # Fails if a destroying sandbox and a live one of one org share a name: that is the data
    # the old index cannot hold, so it has to be resolved by hand before downgrading.
    _recreate_index(NOT_DESTROYED_OR_ERROR)
