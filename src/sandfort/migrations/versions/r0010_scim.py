"""SCIM schema: scim_tokens table and org_memberships.external_id (unique per org)

Revision ID: 0010
Revises: 0009
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

EXTERNAL_ID_UNIQUE = "uq_org_memberships_org_id_external_id"


def upgrade() -> None:
    op.create_table(
        "scim_tokens",
        sa.Column("id", sa.String(30), nullable=False),
        sa.Column("org_id", sa.String(30), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("prefix", sa.String(64), nullable=False),
        sa.Column("secret_hash", sa.String(128), nullable=False),
        sa.Column("max_role", sa.String(16), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "max_role IN ('admin', 'developer', 'viewer')", name=op.f("ck_scim_tokens_max_role")
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], name=op.f("fk_scim_tokens_org_id_organizations")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scim_tokens")),
        sa.UniqueConstraint("prefix", name=op.f("uq_scim_tokens_prefix")),
    )
    op.create_index("ix_scim_tokens_org_id", "scim_tokens", ["org_id"])
    with op.batch_alter_table("org_memberships") as batch:
        batch.add_column(sa.Column("external_id", sa.String(length=255), nullable=True))
        batch.create_unique_constraint(EXTERNAL_ID_UNIQUE, ["org_id", "external_id"])


def downgrade() -> None:
    with op.batch_alter_table("org_memberships") as batch:
        batch.drop_constraint(EXTERNAL_ID_UNIQUE, type_="unique")
        batch.drop_column("external_id")
    op.drop_index("ix_scim_tokens_org_id", table_name="scim_tokens")
    op.drop_table("scim_tokens")
