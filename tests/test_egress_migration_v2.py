"""Egress v2 round 3, migration r0027 (docs/egress-v2-design.md sections 3.2 and 3.3).

The sandboxes table gains ``egress_policy_generation`` and ``egress_credential_epoch``, both
INTEGER NOT NULL with ``server_default`` 0 and no backfill: a row that existed before the
migration reads generation 0 (no allowlist, or a legacy v1 token) and epoch 0. The downgrade
drops both columns and the table still selects. Plain sqlite3 against a temp file, so the
expected values come from the contract and not from the ORM mapping under test.
"""

import sqlite3
from contextlib import closing
from pathlib import Path

from alembic import command
from alembic.config import Config

ROOT = Path(__file__).resolve().parents[1]
STAMP = "2026-11-24 12:00:00"
ORG = "org_mig"
GENERATION = "egress_policy_generation"
EPOCH = "egress_credential_epoch"
BEFORE = "0026"
HEAD = "0027"
INTEGER_COLUMN_SQL_TYPE = "INTEGER"


def alembic_config(db_path: Path) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")
    return config


def sandbox_columns(db_path: Path) -> dict[str, tuple[str, int, str | None]]:
    """Column name -> (declared type, notnull flag, default expression) of ``sandboxes``."""
    with closing(sqlite3.connect(db_path)) as connection:
        rows = connection.execute("PRAGMA table_info(sandboxes)").fetchall()
    return {row[1]: (row[2], row[3], row[4]) for row in rows}


def schema_version(db_path: Path) -> list[tuple[str]]:
    with closing(sqlite3.connect(db_path)) as connection:
        return connection.execute("SELECT version_num FROM alembic_version").fetchall()


def insert_sandbox(db_path: Path, sandbox_id: str, allowlist: str | None) -> None:
    """A row written with the 0026 column set only, as an older server would have left it."""
    with closing(sqlite3.connect(db_path)) as connection:
        connection.execute(
            "INSERT INTO organizations (id, name, slug, status, created_at, updated_at)"
            " VALUES (?, 'Mig', ?, 'active', ?, ?) ON CONFLICT (id) DO NOTHING",
            (ORG, ORG, STAMP, STAMP),
        )
        connection.execute(
            "INSERT INTO sandboxes (id, org_id, name, state, desired_state, image_ref, driver,"
            " cpu_millicores, memory_mib, disk_gib, env, labels, network_policy, public,"
            " auto_stop_minutes, auto_delete_minutes, created_at, updated_at, version,"
            " egress_allowlist)"
            " VALUES (?, ?, ?, 'started', 'started', 'alpine:3.20', 'fake',"
            " 1000, 512, 1, '{}', '{}', '{}', 0, 15, -1, ?, ?, 1, ?)",
            (sandbox_id, ORG, sandbox_id, STAMP, STAMP, allowlist),
        )
        connection.commit()


def read_egress_columns(db_path: Path, sandbox_id: str) -> tuple[int, int]:
    with closing(sqlite3.connect(db_path)) as connection:
        row = connection.execute(
            f"SELECT {GENERATION}, {EPOCH} FROM sandboxes WHERE id = ?", (sandbox_id,)
        ).fetchone()
    assert row is not None
    return row[0], row[1]


def test_the_columns_are_absent_at_0026(tmp_path: Path) -> None:
    db_path = tmp_path / "before.db"

    command.upgrade(alembic_config(db_path), BEFORE)

    columns = sandbox_columns(db_path)
    assert GENERATION not in columns
    assert EPOCH not in columns


def test_a_fresh_upgrade_to_head_has_both_columns_as_not_null_integers_defaulting_to_zero(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "head.db"

    command.upgrade(alembic_config(db_path), HEAD)

    columns = sandbox_columns(db_path)
    for name in (GENERATION, EPOCH):
        declared, notnull, default = columns[name]
        assert declared == INTEGER_COLUMN_SQL_TYPE
        assert notnull == 1
        assert default is not None
        assert default.strip("'\"") == "0"
    assert schema_version(db_path) == [(HEAD,)]


def test_rows_that_predate_the_migration_read_generation_zero_and_epoch_zero(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "legacy.db"
    config = alembic_config(db_path)
    command.upgrade(config, BEFORE)
    insert_sandbox(db_path, "sbx_legacy_open", None)
    insert_sandbox(db_path, "sbx_legacy_listed", '["api.example.com"]')

    command.upgrade(config, HEAD)

    # No backfill: even a row with a stored allowlist stays at 0, the legacy v1 marker.
    assert read_egress_columns(db_path, "sbx_legacy_open") == (0, 0)
    assert read_egress_columns(db_path, "sbx_legacy_listed") == (0, 0)


def test_a_row_inserted_after_the_migration_without_the_columns_also_reads_zero(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "defaults.db"
    command.upgrade(alembic_config(db_path), HEAD)

    insert_sandbox(db_path, "sbx_default", '["api.example.com"]')

    assert read_egress_columns(db_path, "sbx_default") == (0, 0)


def test_the_downgrade_drops_both_columns_and_the_table_still_selects(tmp_path: Path) -> None:
    db_path = tmp_path / "down.db"
    config = alembic_config(db_path)
    command.upgrade(config, BEFORE)
    insert_sandbox(db_path, "sbx_keep", '["api.example.com"]')
    command.upgrade(config, HEAD)

    command.downgrade(config, BEFORE)

    columns = sandbox_columns(db_path)
    assert GENERATION not in columns
    assert EPOCH not in columns
    assert schema_version(db_path) == [(BEFORE,)]
    with closing(sqlite3.connect(db_path)) as connection:
        rows = connection.execute("SELECT id, egress_allowlist FROM sandboxes").fetchall()
    assert rows == [("sbx_keep", '["api.example.com"]')]


def test_the_migration_can_be_applied_again_after_a_downgrade(tmp_path: Path) -> None:
    db_path = tmp_path / "again.db"
    config = alembic_config(db_path)
    command.upgrade(config, HEAD)
    command.downgrade(config, BEFORE)

    command.upgrade(config, HEAD)

    columns = sandbox_columns(db_path)
    assert GENERATION in columns
    assert EPOCH in columns
    assert schema_version(db_path) == [(HEAD,)]
