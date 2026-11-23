"""Round 35: ``sandfort-admin create-key`` issues a replacement org-wide key for an existing org.

Sync tests: the admin CLI runs its own event loop. The printed key is checked against the
real app: ``GET /v1/api-keys`` lists only the authenticated org's keys, so one call proves
both "authenticates" and "for that org and no other".
"""

import asyncio
import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from typer.testing import CliRunner, Result

from sandfort import admin_cli
from sandfort.api.app import create_app
from sandfort.auth.scopes import ALL_SCOPES
from sandfort.config import Settings

ROOT = Path(__file__).resolve().parents[1]
PEPPER = "test-pepper"
KEY_PATTERN = re.compile(r"sf_live_[a-z0-9]{8}_[A-Za-z0-9_-]{43}")
KEYS_URL = "/v1/api-keys"
CREATED = "api_key.created"
RUNNER = CliRunner()
CREATE_ACME = ["create-org", "--org-name", "Acme", "--org-slug", "acme"]
CREATE_OTHER = ["create-org", "--org-name", "Other", "--org-slug", "other"]


@pytest.fixture
def db_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    path = tmp_path / "create-key.db"
    url = f"sqlite+aiosqlite:///{path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    monkeypatch.setenv("SANDFORT_DATABASE_URL", url)
    monkeypatch.setenv("SANDFORT_API_KEY_PEPPER", PEPPER)
    return path


def _rows(db_path: Path, sql: str, *params: Any) -> list[sqlite3.Row]:
    with closing(sqlite3.connect(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        return list(connection.execute(sql, params))


def _org_id(db_path: Path, slug: str) -> str:
    [row] = _rows(db_path, "SELECT id FROM organizations WHERE slug = ?", slug)
    return str(row["id"])


def _provision_two_orgs() -> tuple[str, str]:
    """Create ``acme`` and ``other``; return their original plaintext keys."""
    keys = []
    for args in (CREATE_ACME, CREATE_OTHER):
        result = RUNNER.invoke(admin_cli.app, args)
        assert result.exit_code == 0, result.output
        keys.append(KEY_PATTERN.findall(result.stdout)[0])
    return keys[0], keys[1]


def _key_names_seen_by(db_path: Path, key: str) -> tuple[int, set[str]]:
    async def call() -> tuple[int, set[str]]:
        settings = Settings(
            driver="fake", database_url=f"sqlite+aiosqlite:///{db_path}", api_key_pepper=PEPPER
        )
        app = create_app(settings)
        try:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
                response = await http.get(KEYS_URL, headers={"Authorization": f"Bearer {key}"})
        finally:
            await app.state.engine.dispose()
        if not response.is_success:
            return response.status_code, set()
        return response.status_code, {row["name"] for row in response.json()["data"]}

    return asyncio.run(call())


def _create_key(*args: str) -> Result:
    return RUNNER.invoke(admin_cli.app, ["create-key", *args])


def test_printed_key_authenticates_for_that_org_and_no_other(db_path: Path) -> None:
    old_acme, old_other = _provision_two_orgs()

    result = _create_key("--org-slug", "acme", "--name", "replacement")

    assert result.exit_code == 0, result.output
    [new_key] = KEY_PATTERN.findall(result.stdout)
    assert result.stdout.count(new_key) == 1
    assert new_key not in result.stderr
    assert "Store this key now; it cannot be shown again." in result.stderr
    assert "sandfort login" in result.stderr
    assert new_key not in {old_acme, old_other}
    assert _key_names_seen_by(db_path, new_key) == (200, {"bootstrap-admin", "replacement"})
    assert _key_names_seen_by(db_path, old_other) == (200, {"bootstrap-admin"})
    [stored] = _rows(db_path, "SELECT * FROM api_keys WHERE name = 'replacement'")
    assert stored["org_id"] == _org_id(db_path, "acme")
    assert stored["created_by"] == "sandfort-admin"
    assert new_key not in "".join(str(value) for value in tuple(stored))  # only the hash is kept


def test_key_is_org_wide_with_the_full_scope_set_and_default_name(db_path: Path) -> None:
    _provision_two_orgs()

    result = _create_key("--org-slug", "acme")

    assert result.exit_code == 0, result.output
    [stored] = _rows(db_path, "SELECT * FROM api_keys WHERE name = 'admin'")
    assert stored["is_platform_admin"] == 0
    assert stored["sandbox_labels"] is None
    assert stored["max_sandboxes"] is None
    assert stored["expires_at"] is None
    assert set(json.loads(stored["scopes"])) == {scope.value for scope in ALL_SCOPES}


def test_org_id_selects_the_org(db_path: Path) -> None:
    _provision_two_orgs()
    other_id = _org_id(db_path, "other")

    result = _create_key("--org-id", other_id, "--name", "by-id")

    assert result.exit_code == 0, result.output
    [stored] = _rows(db_path, "SELECT org_id FROM api_keys WHERE name = 'by-id'")
    assert stored["org_id"] == other_id


def test_audit_event_is_recorded_without_the_secret(db_path: Path) -> None:
    _provision_two_orgs()
    org_id = _org_id(db_path, "acme")

    result = _create_key("--org-slug", "acme", "--name", "audited")

    assert result.exit_code == 0, result.output
    [new_key] = KEY_PATTERN.findall(result.stdout)
    [key_row] = _rows(db_path, "SELECT id, prefix FROM api_keys WHERE name = 'audited'")
    [event] = _rows(
        db_path, "SELECT * FROM audit_events WHERE action = ? AND org_id = ?", CREATED, org_id
    )
    assert event["actor_id"] == "sandfort-admin"
    assert event["actor_type"] == "platform_admin"
    assert event["target_type"] == "api_key"
    assert event["target_id"] == key_row["id"]
    details = json.loads(event["details"])
    assert details["name"] == "audited"
    assert details["prefix"] == key_row["prefix"]
    assert new_key not in "".join(str(value) for value in tuple(event))
    other_events = _rows(
        db_path, "SELECT id FROM audit_events WHERE action = ? AND org_id != ?", CREATED, org_id
    )
    assert other_events == []


def test_unknown_slug_exits_1_and_writes_nothing(db_path: Path) -> None:
    _provision_two_orgs()
    keys_before = len(_rows(db_path, "SELECT id FROM api_keys"))

    result = _create_key("--org-slug", "ghost")

    assert result.exit_code == 1
    assert "error: unknown organisation ghost" in result.stderr
    assert KEY_PATTERN.findall(result.output) == []
    assert len(_rows(db_path, "SELECT id FROM api_keys")) == keys_before
    assert _rows(db_path, "SELECT id FROM audit_events WHERE action = ?", CREATED) == []


def test_unknown_org_id_exits_1(db_path: Path) -> None:
    result = _create_key("--org-id", "org_missing")

    assert result.exit_code == 1
    assert "error: unknown organisation org_missing" in result.stderr


@pytest.mark.parametrize("args", [[], ["--org-slug", "acme", "--org-id", "org_x"]])
def test_exactly_one_org_selector_is_required(db_path: Path, args: list[str]) -> None:
    result = _create_key(*args)

    assert result.exit_code == 1
    assert "exactly one of --org-slug and --org-id" in result.stderr


def test_platform_admin_flag_sets_the_flag(db_path: Path) -> None:
    _provision_two_orgs()

    result = _create_key("--org-slug", "acme", "--name", "root", "--platform-admin")

    assert result.exit_code == 0, result.output
    [stored] = _rows(db_path, "SELECT is_platform_admin FROM api_keys WHERE name = 'root'")
    assert stored["is_platform_admin"] == 1


def _post_key_via_api(db_path: Path, key: str) -> None:
    async def call() -> None:
        settings = Settings(
            driver="fake", database_url=f"sqlite+aiosqlite:///{db_path}", api_key_pepper=PEPPER
        )
        app = create_app(settings)
        try:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
                response = await http.post(
                    KEYS_URL,
                    json={"name": "via-api", "scopes": ["sandboxes:read"]},
                    headers={"Authorization": f"Bearer {key}"},
                )
        finally:
            await app.state.engine.dispose()
        assert response.status_code == 201, response.text

    asyncio.run(call())


def test_cli_event_details_match_the_api_event_keys_and_order(db_path: Path) -> None:
    old_acme, _ = _provision_two_orgs()
    _post_key_via_api(db_path, old_acme)
    assert _create_key("--org-slug", "acme", "--name", "by-cli").exit_code == 0

    [api_event] = _rows(
        db_path,
        "SELECT details FROM audit_events WHERE action = ? AND actor_type = 'api_key'",
        CREATED,
    )
    [cli_event] = _rows(
        db_path,
        "SELECT details FROM audit_events WHERE action = ? AND actor_type = 'platform_admin'",
        CREATED,
    )

    api_details = json.loads(api_event["details"])
    cli_details = json.loads(cli_event["details"])
    assert set(cli_details) == set(api_details)
    assert list(cli_details) == list(api_details)
    for unset in ("sandbox_labels", "max_sandboxes", "expires_at"):
        assert cli_details[unset] is None
    assert api_details["is_platform_admin"] is False
    assert cli_details["is_platform_admin"] is False


def _recorded_is_platform_admin(db_path: Path, key_name: str) -> object:
    [key_row] = _rows(db_path, "SELECT id FROM api_keys WHERE name = ?", key_name)
    [event] = _rows(
        db_path,
        "SELECT details FROM audit_events WHERE action = ? AND target_id = ?",
        CREATED,
        key_row["id"],
    )
    return json.loads(event["details"])["is_platform_admin"]


def test_platform_admin_flag_is_recorded_true_in_the_audit_details(db_path: Path) -> None:
    _provision_two_orgs()

    result = _create_key("--org-slug", "acme", "--name", "root", "--platform-admin")

    assert result.exit_code == 0, result.output
    assert _recorded_is_platform_admin(db_path, "root") is True


def test_plain_create_key_records_false_in_the_audit_details(db_path: Path) -> None:
    _provision_two_orgs()

    result = _create_key("--org-slug", "acme", "--name", "plain")

    assert result.exit_code == 0, result.output
    assert _recorded_is_platform_admin(db_path, "plain") is False


def test_requires_pepper(db_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SANDFORT_API_KEY_PEPPER")

    result = _create_key("--org-slug", "acme")

    assert result.exit_code == 1
    assert "SANDFORT_API_KEY_PEPPER" in result.stderr


def test_rejects_a_blank_key_name(db_path: Path) -> None:
    result = _create_key("--org-slug", "acme", "--name", "  ")

    assert result.exit_code == 1
    assert "key name must be" in result.stderr
