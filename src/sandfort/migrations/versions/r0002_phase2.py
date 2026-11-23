"""phase 2 schema: exec_sessions, exec_commands, pty_sessions

Revision ID: 0002
Revises: 0001
"""

from collections.abc import Sequence
from datetime import datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _timestamp(name: str, *, nullable: bool = False) -> sa.Column[datetime]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def upgrade() -> None:
    op.create_table(
        "exec_sessions",
        sa.Column("id", sa.String(30), nullable=False),
        sa.Column("org_id", sa.String(30), nullable=False),
        sa.Column("sandbox_id", sa.String(30), nullable=False),
        sa.Column("cwd", sa.Text(), nullable=True),
        sa.Column("env", sa.JSON(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        _timestamp("created_at"),
        _timestamp("updated_at"),
        sa.CheckConstraint("state IN ('active', 'closed')", name=op.f("ck_exec_sessions_state")),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], name=op.f("fk_exec_sessions_org_id_organizations")
        ),
        sa.ForeignKeyConstraint(
            ["sandbox_id"], ["sandboxes.id"], name=op.f("fk_exec_sessions_sandbox_id_sandboxes")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_exec_sessions")),
    )
    op.create_index(
        "ix_exec_sessions_org_id_sandbox_id", "exec_sessions", ["org_id", "sandbox_id"]
    )

    op.create_table(
        "exec_commands",
        sa.Column("id", sa.String(30), nullable=False),
        sa.Column("org_id", sa.String(30), nullable=False),
        sa.Column("sandbox_id", sa.String(30), nullable=False),
        sa.Column("session_id", sa.String(30), nullable=True),
        sa.Column("argv", sa.JSON(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("stdout_bytes", sa.Integer(), nullable=False),
        sa.Column("stderr_bytes", sa.Integer(), nullable=False),
        _timestamp("created_at"),
        _timestamp("finished_at", nullable=True),
        sa.CheckConstraint(
            "state IN ('running', 'exited', 'killed')", name=op.f("ck_exec_commands_state")
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], name=op.f("fk_exec_commands_org_id_organizations")
        ),
        sa.ForeignKeyConstraint(
            ["sandbox_id"], ["sandboxes.id"], name=op.f("fk_exec_commands_sandbox_id_sandboxes")
        ),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["exec_sessions.id"],
            name=op.f("fk_exec_commands_session_id_exec_sessions"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_exec_commands")),
    )
    op.create_index(
        "ix_exec_commands_org_id_sandbox_id", "exec_commands", ["org_id", "sandbox_id"]
    )
    op.create_index("ix_exec_commands_session_id", "exec_commands", ["session_id"])

    op.create_table(
        "pty_sessions",
        sa.Column("id", sa.String(30), nullable=False),
        sa.Column("org_id", sa.String(30), nullable=False),
        sa.Column("sandbox_id", sa.String(30), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("rows", sa.Integer(), nullable=False),
        sa.Column("cols", sa.Integer(), nullable=False),
        _timestamp("created_at"),
        _timestamp("closed_at", nullable=True),
        sa.CheckConstraint("state IN ('open', 'closed')", name=op.f("ck_pty_sessions_state")),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], name=op.f("fk_pty_sessions_org_id_organizations")
        ),
        sa.ForeignKeyConstraint(
            ["sandbox_id"], ["sandboxes.id"], name=op.f("fk_pty_sessions_sandbox_id_sandboxes")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_pty_sessions")),
    )
    op.create_index("ix_pty_sessions_org_id_sandbox_id", "pty_sessions", ["org_id", "sandbox_id"])


def downgrade() -> None:
    op.drop_index("ix_pty_sessions_org_id_sandbox_id", table_name="pty_sessions")
    op.drop_table("pty_sessions")
    op.drop_index("ix_exec_commands_session_id", table_name="exec_commands")
    op.drop_index("ix_exec_commands_org_id_sandbox_id", table_name="exec_commands")
    op.drop_table("exec_commands")
    op.drop_index("ix_exec_sessions_org_id_sandbox_id", table_name="exec_sessions")
    op.drop_table("exec_sessions")
