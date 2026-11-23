"""CLI r34: `key list` shows the expiry date again and its --json rows carry the status."""

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
PROFILE_KEY = "sf_test_key_do_not_print"
KEYS_URL = "/v1/api-keys"
KEY_ACTIVE = "key_01HZZZZZZZZZZZZZZZZZZZZZZA"
KEY_EXPIRED = "key_01HZZZZZZZZZZZZZZZZZZZZZZB"
KEY_REVOKED = "key_01HZZZZZZZZZZZZZZZZZZZZZZC"
KEY_NEVER = "key_01HZZZZZZZZZZZZZZZZZZZZZZD"
CREATED_AT = "2026-11-06T10:00:00+00:00"
EXPIRY_FORMAT = "%Y-%m-%d %H:%M"
RUNNER = CliRunner()


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def key_json(key_id, **extra):
    base = {
        "id": key_id,
        "name": "ci",
        "prefix": "sf_abcd",
        "scopes": ["sandboxes:read"],
        "sandbox_labels": None,
        "max_sandboxes": None,
        "created_at": CREATED_AT,
        "last_used_at": None,
        "expires_at": None,
        "revoked_at": None,
        "created_by": None,
    }
    return {**base, **extra}


def invoke(args, *, as_json=False):
    return RUNNER.invoke(create_app(), (["--json"] if as_json else []) + args)


def table_line(stdout, needle):
    return next(line for line in stdout.splitlines() if needle in line)


@pytest.fixture(autouse=True)
def profile(monkeypatch, tmp_path):
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, PROFILE_KEY)


@pytest.fixture
def router():
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


@pytest.fixture
def expiries():
    now = datetime.now(UTC)
    return {"active": now + timedelta(days=30), "expired": now - timedelta(days=1)}


@pytest.fixture
def keys(router, expiries):
    router.get(KEYS_URL).respond(
        200,
        json=envelope(
            [
                key_json(KEY_ACTIVE, expires_at=expiries["active"].isoformat()),
                key_json(KEY_EXPIRED, expires_at=expiries["expired"].isoformat()),
                key_json(KEY_REVOKED, revoked_at=CREATED_AT),
                key_json(KEY_NEVER),
            ]
        ),
    )


def test_table_has_an_expires_column_after_status_and_no_old_columns(keys):
    result = invoke(["key", "list", "--all"])

    header = table_line(result.stdout, "SCOPES")
    assert result.exit_code == 0, result.output
    assert header.index("STATUS") < header.index("EXPIRES") < header.index("SCOPES")
    assert "EXPIRES AT" not in result.stdout and "REVOKED AT" not in result.stdout


def test_table_shows_the_expiry_as_a_short_utc_date_and_time(keys, expiries):
    result = invoke(["key", "list"])

    assert result.exit_code == 0, result.output
    active = table_line(result.stdout, KEY_ACTIVE)
    assert expiries["active"].strftime(EXPIRY_FORMAT) in active
    assert expiries["active"].strftime("%Y-%m-%dT") not in active
    assert expiries["expired"].strftime(EXPIRY_FORMAT) in table_line(result.stdout, KEY_EXPIRED)


def test_table_shows_a_dash_for_a_key_that_never_expires(keys):
    result = invoke(["key", "list"])

    cells = [cell.strip() for cell in table_line(result.stdout, KEY_NEVER).split("│")]
    assert cells[cells.index("active") + 1] == "-"


def test_table_converts_an_offset_expiry_to_utc(router):
    expires_at = "2030-05-01T01:30:00+02:00"
    router.get(KEYS_URL).respond(200, json=envelope([key_json(KEY_ACTIVE, expires_at=expires_at)]))

    result = invoke(["key", "list"])

    assert "2030-04-30 23:30" in table_line(result.stdout, KEY_ACTIVE)


def test_json_rows_carry_the_status_the_table_shows(keys):
    table = invoke(["key", "list", "--all"]).stdout

    rows = json.loads(invoke(["key", "list", "--all"], as_json=True).stdout)

    statuses = {row["id"]: row["status"] for row in rows}
    assert statuses == {
        KEY_ACTIVE: "active",
        KEY_EXPIRED: "expired",
        KEY_REVOKED: "revoked",
        KEY_NEVER: "active",
    }
    for key_id, status in statuses.items():
        assert f" {status} " in table_line(table, key_id)


def test_json_keeps_the_iso_expiry_next_to_the_status(keys, expiries):
    rows = json.loads(invoke(["key", "list"], as_json=True).stdout)

    active = next(row for row in rows if row["id"] == KEY_ACTIVE)
    assert datetime.fromisoformat(active["expires_at"]) == expiries["active"]
    assert active["status"] == "active"
