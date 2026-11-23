"""SCIM schema: migration 0010 up and down, and the external id uniqueness rule."""

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

ROOT = Path(__file__).resolve().parents[1]
STAMP = "2026-11-02 12:00:00"
ORG_A = "org_a"
ORG_B = "org_b"


def alembic_config(db_path: Path) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")
    return config


def table_names(db_path: Path) -> set[str]:
    with closing(sqlite3.connect(db_path)) as connection:
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        return {row[0] for row in rows}


def membership_columns(db_path: Path) -> set[str]:
    with closing(sqlite3.connect(db_path)) as connection:
        rows = connection.execute("PRAGMA table_info(org_memberships)").fetchall()
    return {row[1] for row in rows}


def schema_version(db_path: Path) -> list[tuple[str]]:
    with closing(sqlite3.connect(db_path)) as connection:
        return connection.execute("SELECT version_num FROM alembic_version").fetchall()


def seed_orgs_and_users(connection: sqlite3.Connection) -> None:
    for org_id in (ORG_A, ORG_B):
        connection.execute(
            "INSERT INTO organizations (id, name, slug, status, created_at, updated_at)"
            " VALUES (?, ?, ?, 'active', ?, ?)",
            (org_id, org_id, org_id, STAMP, STAMP),
        )
    for index in range(1, 4):
        connection.execute(
            "INSERT INTO users (id, email, display_name, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (f"usr_{index}", f"u{index}@example.com", f"U{index}", STAMP, STAMP),
        )


def add_membership(
    connection: sqlite3.Connection, user_id: str, org_id: str, external_id: str | None
) -> None:
    connection.execute(
        "INSERT INTO org_memberships (user_id, org_id, role, external_id, created_at, updated_at)"
        " VALUES (?, ?, 'viewer', ?, ?, ?)",
        (user_id, org_id, external_id, STAMP, STAMP),
    )


def migrated_to_0010(tmp_path: Path) -> Path:
    db_path = tmp_path / "scim.db"
    command.upgrade(alembic_config(db_path), "0010")
    return db_path


def test_upgrade_creates_scim_schema_and_downgrade_removes_it(tmp_path: Path) -> None:
    db_path = tmp_path / "migrated.db"
    config = alembic_config(db_path)

    command.upgrade(config, "0010")
    upgraded_tables = table_names(db_path)
    upgraded_columns = membership_columns(db_path)
    upgraded_version = schema_version(db_path)
    command.downgrade(config, "0009")
    downgraded_tables = table_names(db_path)
    downgraded_columns = membership_columns(db_path)
    downgraded_version = schema_version(db_path)

    assert "scim_tokens" in upgraded_tables
    assert "external_id" in upgraded_columns
    assert upgraded_version == [("0010",)]
    assert "scim_tokens" not in downgraded_tables
    assert "external_id" not in downgraded_columns
    assert downgraded_version == [("0009",)]


def test_scim_tokens_has_the_designed_columns(tmp_path: Path) -> None:
    db_path = migrated_to_0010(tmp_path)

    with closing(sqlite3.connect(db_path)) as connection:
        rows = connection.execute("PRAGMA table_info(scim_tokens)").fetchall()

    assert {row[1] for row in rows} == {
        "id",
        "org_id",
        "name",
        "prefix",
        "secret_hash",
        "max_role",
        "last_used_at",
        "revoked_at",
        "created_by",
        "created_at",
        "updated_at",
    }


def test_duplicate_external_id_in_one_org_is_rejected(tmp_path: Path) -> None:
    db_path = migrated_to_0010(tmp_path)

    with closing(sqlite3.connect(db_path)) as connection:
        seed_orgs_and_users(connection)
        add_membership(connection, "usr_1", ORG_A, "ext-1")
        with pytest.raises(sqlite3.IntegrityError):
            add_membership(connection, "usr_2", ORG_A, "ext-1")


def test_same_external_id_in_two_orgs_is_allowed(tmp_path: Path) -> None:
    db_path = migrated_to_0010(tmp_path)

    with closing(sqlite3.connect(db_path)) as connection:
        seed_orgs_and_users(connection)
        add_membership(connection, "usr_1", ORG_A, "ext-1")
        add_membership(connection, "usr_1", ORG_B, "ext-1")
        count = connection.execute("SELECT COUNT(*) FROM org_memberships").fetchone()

    assert count == (2,)


def test_two_null_external_ids_in_one_org_are_allowed(tmp_path: Path) -> None:
    db_path = migrated_to_0010(tmp_path)

    with closing(sqlite3.connect(db_path)) as connection:
        seed_orgs_and_users(connection)
        add_membership(connection, "usr_1", ORG_A, None)
        add_membership(connection, "usr_2", ORG_A, None)
        count = connection.execute(
            "SELECT COUNT(*) FROM org_memberships WHERE external_id IS NULL"
        ).fetchone()

    assert count == (2,)


def test_downgrade_keeps_existing_memberships(tmp_path: Path) -> None:
    db_path = migrated_to_0010(tmp_path)
    with closing(sqlite3.connect(db_path)) as connection:
        seed_orgs_and_users(connection)
        add_membership(connection, "usr_1", ORG_A, "ext-1")
        connection.commit()

    command.downgrade(alembic_config(db_path), "0009")

    with closing(sqlite3.connect(db_path)) as connection:
        rows = connection.execute("SELECT user_id, org_id, role FROM org_memberships").fetchall()
    assert rows == [("usr_1", ORG_A, "viewer")]
