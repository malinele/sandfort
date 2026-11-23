"""Round 59: ``sandfort-admin revoke-key`` revokes a key from the host, no API key needed.

The lost-key runbook mints a replacement and revokes the old key over the API. When the lost
key is a platform-admin key (the bootstrap key) a plain replacement gets 403, so the operator
with database access revokes it directly. Sync tests: the admin CLI runs its own event loop.
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
from sandfort.config import Settings

ROOT = Path(__file__).resolve().parents[1]
PEPPER = "test-pepper"
KEY_PATTERN = re.compile(r"sf_live_[a-z0-9]{8}_[A-Za-z0-9_-]{43}")
KEYS_URL = "/v1/api-keys"
REVOKED = "api_key.revoked"
RUNNER = CliRunner()
CREATE_ACME = ["create-org", "--org-name", "Acme", "--org-slug", "acme"]
CREATE_OTHER = ["create-org", "--org-name", "Other", "--org-slug", "other"]


@pytest.fixture
def db_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    path = tmp_path / "revoke-key.db"
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


def _admin(*args: str) -> Result:
    return RUNNER.invoke(admin_cli.app, list(args))


def _provision() -> str:
    """Create ``acme`` and ``other``; return acme's bootstrap (platform-admin) plaintext key."""
    first = _admin(*CREATE_ACME)
    assert first.exit_code == 0, first.output
    assert _admin(*CREATE_OTHER).exit_code == 0
    return KEY_PATTERN.findall(first.stdout)[0]


def _new_key(name: str, org: str = "acme", *extra: str) -> str:
    result = _admin("create-key", "--org-slug", org, "--name", name, *extra)
    assert result.exit_code == 0, result.output
    return KEY_PATTERN.findall(result.stdout)[0]


def _key_row(db_path: Path, name: str, org: str = "acme") -> sqlite3.Row:
    [row] = _rows(
        db_path,
        "SELECT k.* FROM api_keys k JOIN organizations o ON o.id = k.org_id "
        "WHERE k.name = ? AND o.slug = ?",
        name,
        org,
    )
    return row


def _revoke(*args: str) -> Result:
    return _admin("revoke-key", *args)


def _api(
    db_path: Path, method: str, path: str, key: str, body: dict[str, Any] | None = None
) -> httpx.Response:
    async def call() -> httpx.Response:
        settings = Settings(
            driver="fake", database_url=f"sqlite+aiosqlite:///{db_path}", api_key_pepper=PEPPER
        )
        app = create_app(settings)
        try:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
                headers = {"Authorization": f"Bearer {key}"}
                return await http.request(method, path, headers=headers, json=body)
        finally:
            await app.state.engine.dispose()

    return asyncio.run(call())


def _create_child_via_api(db_path: Path, key: str) -> str:
    body = {"name": "child", "scopes": ["sandboxes:read"]}
    response = _api(db_path, "POST", KEYS_URL, key, body)
    assert response.status_code == 201, response.text
    return "child"


def test_revoke_by_id_revokes_the_platform_admin_bootstrap_key(db_path: Path) -> None:
    bootstrap = _provision()
    _new_key("replacement")
    old = _key_row(db_path, "bootstrap-admin")
    assert old["is_platform_admin"] == 1

    result = _revoke("--org-slug", "acme", "--key-id", old["id"])

    assert result.exit_code == 0, result.output
    assert result.stdout.strip().splitlines() == [
        f"revoked {old['id']} name=bootstrap-admin prefix={old['prefix']}"
    ]
    assert _key_row(db_path, "bootstrap-admin")["revoked_at"] is not None
    assert _api(db_path, "GET", KEYS_URL, bootstrap).status_code == 401
    assert _key_row(db_path, "replacement")["revoked_at"] is None


def test_org_id_selects_the_org(db_path: Path) -> None:
    _provision()
    _new_key("other-key", "other")
    row = _key_row(db_path, "other-key", "other")

    result = _revoke("--org-id", row["org_id"], "--key-id", row["id"])

    assert result.exit_code == 0, result.output
    assert _key_row(db_path, "other-key", "other")["revoked_at"] is not None


def test_revoke_by_prefix(db_path: Path) -> None:
    _provision()
    _new_key("by-prefix")
    row = _key_row(db_path, "by-prefix")

    result = _revoke("--org-slug", "acme", "--prefix", row["prefix"])

    assert result.exit_code == 0, result.output
    assert row["id"] in result.stdout
    assert _key_row(db_path, "by-prefix")["revoked_at"] is not None


def test_ambiguous_prefix_refuses_and_lists_candidates(db_path: Path) -> None:
    _provision()
    _new_key("first")
    _new_key("second")
    first, second = _key_row(db_path, "first"), _key_row(db_path, "second")

    result = _revoke("--org-slug", "acme", "--prefix", "sf_live_")

    assert result.exit_code == 1
    assert "error:" in result.stderr
    for row in (first, second):
        assert row["id"] in result.stderr
        assert row["created_at"][:10] in result.stderr
    assert "first" in result.stderr and "second" in result.stderr
    assert _rows(db_path, "SELECT id FROM api_keys WHERE revoked_at IS NOT NULL") == []
    assert _rows(db_path, "SELECT id FROM audit_events WHERE action = ?", REVOKED) == []


def test_already_revoked_is_a_noop_with_exit_0(db_path: Path) -> None:
    _provision()
    _new_key("twice")
    row = _key_row(db_path, "twice")
    assert _revoke("--org-slug", "acme", "--key-id", row["id"]).exit_code == 0
    recorded = _key_row(db_path, "twice")["revoked_at"]

    result = _revoke("--org-slug", "acme", "--key-id", row["id"])

    assert result.exit_code == 0, result.output
    assert "already revoked" in result.stdout
    assert row["id"] in result.stdout
    assert _key_row(db_path, "twice")["revoked_at"] == recorded
    assert len(_rows(db_path, "SELECT id FROM audit_events WHERE action = ?", REVOKED)) == 1


def test_unknown_org_exits_1_and_writes_nothing(db_path: Path) -> None:
    _provision()
    row = _key_row(db_path, "bootstrap-admin")

    result = _revoke("--org-slug", "ghost", "--key-id", row["id"])

    assert result.exit_code == 1
    assert "error: unknown organisation ghost" in result.stderr
    assert _key_row(db_path, "bootstrap-admin")["revoked_at"] is None
    assert _rows(db_path, "SELECT id FROM audit_events WHERE action = ?", REVOKED) == []


@pytest.mark.parametrize("selector", [["--key-id", "key_missing"], ["--prefix", "sf_live_zzzz"]])
def test_unknown_key_exits_1_and_writes_nothing(db_path: Path, selector: list[str]) -> None:
    _provision()

    result = _revoke("--org-slug", "acme", *selector)

    assert result.exit_code == 1
    assert result.stderr.startswith("error: ")
    assert _rows(db_path, "SELECT id FROM api_keys WHERE revoked_at IS NOT NULL") == []
    assert _rows(db_path, "SELECT id FROM audit_events WHERE action = ?", REVOKED) == []


def test_key_of_another_org_is_unknown(db_path: Path) -> None:
    _provision()
    other = _key_row(db_path, "bootstrap-admin", "other")

    result = _revoke("--org-slug", "acme", "--key-id", other["id"])

    assert result.exit_code == 1
    assert result.stderr.startswith("error: ")
    assert _key_row(db_path, "bootstrap-admin", "other")["revoked_at"] is None


@pytest.mark.parametrize(
    "args",
    [
        ["--key-id", "key_x"],
        ["--org-slug", "acme", "--org-id", "org_x", "--key-id", "key_x"],
        ["--org-slug", "acme"],
        ["--org-slug", "acme", "--key-id", "key_x", "--prefix", "sf_live_"],
    ],
)
def test_exactly_one_selector_per_side_is_required(db_path: Path, args: list[str]) -> None:
    result = _revoke(*args)

    assert result.exit_code == 1
    assert "exactly one of" in result.stderr


def test_requires_pepper(db_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SANDFORT_API_KEY_PEPPER")

    result = _revoke("--org-slug", "acme", "--key-id", "key_x")

    assert result.exit_code == 1
    assert "SANDFORT_API_KEY_PEPPER" in result.stderr


def test_audit_event_matches_create_key_actor(db_path: Path) -> None:
    _provision()
    _new_key("audited")
    row = _key_row(db_path, "audited")

    assert _revoke("--org-slug", "acme", "--key-id", row["id"]).exit_code == 0

    [event] = _rows(db_path, "SELECT * FROM audit_events WHERE action = ?", REVOKED)
    assert event["org_id"] == row["org_id"]
    assert event["actor_type"] == "platform_admin"
    assert event["actor_id"] == "sandfort-admin"
    assert event["target_type"] == "api_key"
    assert event["target_id"] == row["id"]
    details = json.loads(event["details"])
    assert details["name"] == "audited"
    assert details["prefix"] == row["prefix"]
    assert details["cascade"] is False


def test_without_cascade_children_stay_alive(db_path: Path) -> None:
    bootstrap = _provision()
    child = _create_child_via_api(db_path, bootstrap)
    parent = _key_row(db_path, "bootstrap-admin")

    assert _revoke("--org-slug", "acme", "--key-id", parent["id"]).exit_code == 0

    assert _key_row(db_path, child)["revoked_at"] is None


def test_cascade_revokes_live_descendants_with_their_own_events(db_path: Path) -> None:
    bootstrap = _provision()
    child = _create_child_via_api(db_path, bootstrap)
    parent = _key_row(db_path, "bootstrap-admin")

    result = _revoke("--org-slug", "acme", "--key-id", parent["id"], "--cascade")

    assert result.exit_code == 0, result.output
    assert len(result.stdout.strip().splitlines()) == 1
    assert _key_row(db_path, child)["revoked_at"] is not None
    events = _rows(db_path, "SELECT * FROM audit_events WHERE action = ?", REVOKED)
    assert len(events) == 2
    assert {event["actor_type"] for event in events} == {"platform_admin"}
    assert {event["actor_id"] for event in events} == {"sandfort-admin"}
    own = next(e for e in events if e["target_id"] == parent["id"])
    assert json.loads(own["details"])["cascade"] is True


def test_plain_replacement_403_message_names_the_fix(db_path: Path) -> None:
    bootstrap = _provision()
    plain = _new_key("plain-replacement")
    old = _key_row(db_path, "bootstrap-admin")

    response = _api(db_path, "DELETE", f"{KEYS_URL}/{old['id']}", plain)

    assert response.status_code == 403, response.text
    message = response.json()["error"]["message"]
    assert "only a platform-admin key can revoke a platform-admin key" in message
    assert "create-key --platform-admin" in message
    assert "revoke-key" in message
    assert _api(db_path, "GET", KEYS_URL, bootstrap).status_code == 200


def test_platform_admin_replacement_can_revoke_over_the_api(db_path: Path) -> None:
    bootstrap = _provision()
    root = _new_key("root", "acme", "--platform-admin")
    old = _key_row(db_path, "bootstrap-admin")

    response = _api(db_path, "DELETE", f"{KEYS_URL}/{old['id']}", root)

    assert response.status_code == 200, response.text
    assert _api(db_path, "GET", KEYS_URL, bootstrap).status_code == 401


def test_create_key_and_revoke_key_help_name_the_bootstrap_case() -> None:
    create = _admin("create-key", "--help")
    revoke = _admin("revoke-key", "--help")

    assert create.exit_code == 0 and revoke.exit_code == 0
    flat = " ".join(create.stdout.split())
    assert "bootstrap" in flat and "revoke-key" in flat
    assert "--cascade" in revoke.stdout
