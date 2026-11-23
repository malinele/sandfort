"""audit_events: index (org_id, request_id) for the request_id filter

The list and export routes filter one org's rows by ``request_id``; without this index the
lookup scans the org's whole audit chain.

Revision ID: 0019
Revises: 0018
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

INDEX_NAME = "ix_audit_events_org_id_request_id"


def upgrade() -> None:
    op.create_index(INDEX_NAME, "audit_events", ["org_id", "request_id"])


def downgrade() -> None:
    op.drop_index(INDEX_NAME, table_name="audit_events")
