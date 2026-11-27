"""B6: ``bootstrap`` and ``create-org`` write the first audit rows of the new org.

Two rows open the new org's own chain: ``org.created`` and ``api_key.created`` (the key row has
the shape ``create-key`` writes). Both are recorded as ``platform_admin`` ``sandfort-admin``. The
plaintext key never reaches the audit table. A refused provisioning writes nothing to any chain,
and a failing audit write rolls the org and the key back (one transaction, WP D5).
Sync tests: the admin CLI runs its own event loop.
"""

import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from typer.testing import CliRunner, Result

from sandfort import admin_cli, admin_provision_audit
from sandfort.auth.scopes import ALL_SCOPES

ROOT = Path(__file__).resolve().parents[1]
PEPPER = "test-pepper"
CHAIN_KEY = "k" * 32
CHAIN_KEY_ENV = "SANDFORT_AUDIT_CHAIN_KEY"
KEY_PATTERN = re.compile(r"sf_live_[a-z0-9]{8}_[A-Za-z0-9_-]{43}")
RUNNER = CliRunner()
BOOTSTRAP = ["bootstrap", "--org-name", "Acme", "--org-slug", "acme"]
CREATE_TENANT = ["create-org", "--org-name", "Tenant", "--org-slug", "tenant"]
EXPECTED_ACTIONS = ["org.created", "api_key.created"]


@pytest.fixture
def db_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    path = tmp_path / "provision-audit.db"
    url = f"sqlite+aiosqlite:///{path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    monkeypatch.setenv("SANDFORT_DATABASE_URL", url)
    monkeypatch.setenv("SANDFORT_API_KEY_PEPPER", PEPPER)
    monkeypatch.delenv(CHAIN_KEY_ENV, raising=False)
    return path


def _rows(db_path: Path, sql: str, *params: Any) -> list[sqlite3.Row]:
    with closing(sqlite3.connect(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        return list(connection.execute(sql, params))


def _run(*args: str) -> Result:
    return RUNNER.invoke(admin_cli.app, list(args))


def _key_of(result: Result) -> str:
    assert result.exit_code == 0, result.output
    [key] = KEY_PATTERN.findall(result.stdout)
    return key


def _org_id(db_path: Path, slug: str) -> str:
    [row] = _rows(db_path, "SELECT id FROM organizations WHERE slug = ?", slug)
    return str(row["id"])


def _chain(db_path: Path, org_id: str) -> list[sqlite3.Row]:
    return _rows(db_path, "SELECT * FROM audit_events WHERE org_id = ? ORDER BY id", org_id)


def _audit_count(db_path: Path) -> int:
    return len(_rows(db_path, "SELECT id FROM audit_events"))


def test_bootstrap_writes_org_created_then_key_created(db_path: Path) -> None:
    _key_of(_run(*BOOTSTRAP))
    org_id = _org_id(db_path, "acme")
    [key_row] = _rows(db_path, "SELECT id, prefix FROM api_keys WHERE org_id = ?", org_id)

    org_event, key_event = _chain(db_path, org_id)

    assert [org_event["action"], key_event["action"]] == EXPECTED_ACTIONS
    for event in (org_event, key_event):
        assert event["actor_type"] == "platform_admin"
        assert event["actor_id"] == "sandfort-admin"
        assert event["outcome"] == "success"
    assert org_event["target_type"] == "organization"
    assert org_event["target_id"] == org_id
    assert key_event["target_type"] == "api_key"
    assert key_event["target_id"] == key_row["id"]
    assert key_event["prev_hash"] == org_event["hash"]
    assert org_event["prev_hash"] is None


def test_org_created_details_name_the_org_and_the_command(db_path: Path) -> None:
    _key_of(_run(*BOOTSTRAP))
    _key_of(_run(*CREATE_TENANT))

    [acme_org, _] = _chain(db_path, _org_id(db_path, "acme"))
    [tenant_org, _] = _chain(db_path, _org_id(db_path, "tenant"))

    assert json.loads(acme_org["details"]) == {
        "name": "Acme",
        "slug": "acme",
        "created_via": "bootstrap",
        "default_quota": None,
    }
    assert json.loads(tenant_org["details"])["created_via"] == "create-org"


def test_key_created_details_match_the_create_key_shape(db_path: Path) -> None:
    _key_of(_run(*BOOTSTRAP))
    org_id = _org_id(db_path, "acme")
    [key_row] = _rows(db_path, "SELECT prefix FROM api_keys WHERE org_id = ?", org_id)

    _, key_event = _chain(db_path, org_id)

    assert json.loads(key_event["details"]) == {
        "name": "bootstrap-admin",
        "prefix": key_row["prefix"],
        "scopes": sorted(scope.value for scope in ALL_SCOPES),
        "sandbox_labels": None,
        "max_sandboxes": None,
        "shared_volume_labels": None,
        "expires_at": None,
        "is_platform_admin": True,
    }


def test_tenant_key_row_records_is_platform_admin_false(db_path: Path) -> None:
    _key_of(_run(*CREATE_TENANT, "--no-platform-admin"))

    _, key_event = _chain(db_path, _org_id(db_path, "tenant"))

    assert json.loads(key_event["details"])["is_platform_admin"] is False


def test_default_org_quota_is_recorded_in_the_org_row(
    db_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SANDFORT_DEFAULT_ORG_MAX_SANDBOXES", "5")
    _key_of(_run(*BOOTSTRAP))

    org_event, _ = _chain(db_path, _org_id(db_path, "acme"))

    quota = json.loads(org_event["details"])["default_quota"]
    assert quota["max_sandboxes"] == 5
    assert quota["max_vcpus"] is None


def test_the_plaintext_key_is_nowhere_in_the_audit_table(db_path: Path) -> None:
    key = _key_of(_run(*BOOTSTRAP))
    secret_part = key.split("_", 3)[3]

    dump = json.dumps([dict(row) for row in _rows(db_path, "SELECT * FROM audit_events")])

    assert len(_rows(db_path, "SELECT id FROM audit_events")) == len(EXPECTED_ACTIONS)
    assert key not in dump
    assert secret_part not in dump


@pytest.mark.parametrize("keyed", [False, True], ids=["unkeyed", "keyed"])
def test_audit_verify_passes_on_a_freshly_provisioned_org(
    db_path: Path, monkeypatch: pytest.MonkeyPatch, keyed: bool
) -> None:
    if keyed:
        monkeypatch.setenv(CHAIN_KEY_ENV, CHAIN_KEY)
    _key_of(_run(*BOOTSTRAP))
    _key_of(_run(*CREATE_TENANT, "--no-platform-admin"))

    result = _run("audit-verify")

    assert result.exit_code == 0, result.output
    assert "ok: 4 audit rows verified" in result.output
    assert "unkeyed" not in result.output


def test_a_key_issued_later_extends_the_genesis_chain(db_path: Path) -> None:
    _key_of(_run(*BOOTSTRAP))
    org_id = _org_id(db_path, "acme")

    _key_of(_run("create-key", "--org-slug", "acme", "--name", "later"))
    rows = _chain(db_path, org_id)

    assert [row["action"] for row in rows] == [*EXPECTED_ACTIONS, "api_key.created"]
    assert rows[2]["prev_hash"] == rows[1]["hash"]
    assert _run("audit-verify").exit_code == 0


def test_duplicate_slug_is_refused_and_writes_no_audit_row(db_path: Path) -> None:
    _key_of(_run(*BOOTSTRAP))
    before = _audit_count(db_path)

    result = _run("create-org", "--org-name", "Again", "--org-slug", "acme")

    assert result.exit_code == 1
    assert _audit_count(db_path) == before
    assert len(_rows(db_path, "SELECT id FROM organizations")) == 1


def test_second_bootstrap_is_refused_and_writes_no_audit_row(db_path: Path) -> None:
    _key_of(_run(*BOOTSTRAP))
    before = _audit_count(db_path)

    result = _run("bootstrap", "--org-name", "Second", "--org-slug", "second")

    assert result.exit_code == 1
    assert _audit_count(db_path) == before
    assert _rows(db_path, "SELECT id FROM organizations WHERE slug = 'second'") == []


def test_a_failing_audit_write_rolls_back_the_org_and_the_key(
    db_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("audit store down")

    monkeypatch.setattr(admin_provision_audit.AuditRecorder, "record", boom)

    result = _run(*BOOTSTRAP)

    assert result.exit_code != 0
    assert _rows(db_path, "SELECT id FROM organizations") == []
    assert _rows(db_path, "SELECT id FROM api_keys") == []
    assert _audit_count(db_path) == 0
