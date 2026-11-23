"""CLI r33d: compact key table with STATUS, CREATED in the sandbox table, `sandbox delete`
alias, and structured details for a create timeout."""

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config, output  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import Client, SandboxTimeoutError  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
PROFILE_KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
OTHER_SID = "sbx_01HYYYYYYYYYYYYYYYYYYYYYYY"
SANDBOXES_URL = "/v1/sandboxes"
KEYS_URL = "/v1/api-keys"
KEY_ACTIVE = "key_01HZZZZZZZZZZZZZZZZZZZZZZA"
KEY_EXPIRED = "key_01HZZZZZZZZZZZZZZZZZZZZZZB"
KEY_REVOKED = "key_01HZZZZZZZZZZZZZZZZZZZZZZC"
ADMIN_SCOPES = ["sandboxes:read", "sandboxes:write", "sandboxes:exec", "api_keys:admin"]
CREATED_AT = "2026-11-06T10:00:00+00:00"
DELETED_MESSAGE = (
    f"creating sandbox 'demo' did not finish within 1 s; the sandbox it made ({SID}) "
    "was deleted, so nothing is left behind"
)
RUNNER = CliRunner()


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def iso(delta):
    return (datetime.now(UTC) + delta).isoformat()


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


def sandbox_json(state="started", *, sandbox_id=SID, name="demo", **extra):
    base = {
        "id": sandbox_id,
        "name": name,
        "state": state,
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
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


def route_keys(router):
    keys = [
        key_json(KEY_ACTIVE, scopes=ADMIN_SCOPES, expires_at=iso(timedelta(days=30))),
        key_json(KEY_EXPIRED, expires_at=iso(timedelta(days=-1))),
        key_json(KEY_REVOKED, revoked_at=iso(timedelta(hours=-1))),
    ]
    router.get(KEYS_URL).respond(200, json=envelope(keys))
    return keys


# --- key list -------------------------------------------------------------------------------


def test_key_list_shows_two_scopes_then_a_count(router):
    route_keys(router)

    result = invoke(["key", "list"])

    assert result.exit_code == 0, result.output
    assert "sandboxes:read,sandboxes:write +2 more" in table_line(result.stdout, KEY_ACTIVE)
    assert "sandboxes:exec" not in result.stdout and "api_keys:admin" not in result.stdout


def test_key_list_status_is_active_expired_and_revoked(router):
    route_keys(router)

    result = invoke(["key", "list", "--all"])

    assert result.exit_code == 0, result.output
    assert " active " in table_line(result.stdout, KEY_ACTIVE)
    assert " expired " in table_line(result.stdout, KEY_EXPIRED)
    assert " revoked " in table_line(result.stdout, KEY_REVOKED)


def test_key_list_has_the_compact_columns_and_hides_revoked_by_default(router):
    route_keys(router)

    result = invoke(["key", "list"])

    header = table_line(result.stdout, "SCOPES")
    names = ("ID", "NAME", "STATUS", "EXPIRES", "SCOPES", "LABELS", "MAX SANDB")
    positions = [header.index(name) for name in names]
    assert positions == sorted(positions)
    assert "EXPIRES AT" not in result.stdout and "REVOKED AT" not in result.stdout
    assert KEY_REVOKED not in result.stdout
    assert max(len(line) for line in result.stdout.splitlines()) < 140


def test_key_list_json_keeps_the_full_objects(router):
    keys = route_keys(router)

    payload = json.loads(invoke(["key", "list", "--all"], as_json=True).stdout)

    assert payload[0]["scopes"] == ADMIN_SCOPES
    assert [item["id"] for item in payload] == [key["id"] for key in keys]
    assert [item["status"] for item in payload] == ["active", "expired", "revoked"]


# --- sandbox list CREATED -------------------------------------------------------------------


def test_sandbox_list_shows_created_in_utc_and_blank_when_absent(router):
    sandboxes = [
        sandbox_json(created_at="2026-11-07T11:30:05+02:00"),
        sandbox_json(sandbox_id=OTHER_SID, name="other"),
    ]
    router.get(SANDBOXES_URL).respond(200, json=envelope(sandboxes))

    result = invoke(["sandbox", "list"])

    assert result.exit_code == 0, result.output
    header = table_line(result.stdout, "CREATED")
    assert header.index("DISK") < header.index("CREATED") < header.index("LABELS")
    assert "2026-11-07 09:30:05" in table_line(result.stdout, SID)
    assert "2026-" not in table_line(result.stdout, OTHER_SID)


def test_utc_cell_formats_aware_and_naive_values():
    aware = datetime(2026, 11, 7, 3, 2, 3, tzinfo=UTC).astimezone(UTC)

    assert output.utc_cell(aware) == "2026-11-07 03:02:03"
    assert output.utc_cell(datetime(2026, 11, 7, 1, 2, 3)) == "2026-11-07 01:02:03"
    assert output.utc_cell(None) == ""


# --- sandbox delete alias -------------------------------------------------------------------


def test_sandbox_delete_removes_like_rm(router):
    route = router.delete(f"{SANDBOXES_URL}/{SID}").respond(
        200, json=envelope(sandbox_json("destroying"))
    )

    text = invoke(["sandbox", "delete", SID])
    as_json = invoke(["sandbox", "delete", SID], as_json=True)

    assert text.exit_code == 0, text.output
    assert text.stdout.splitlines() == [SID]
    assert json.loads(as_json.stdout)["id"] == SID
    assert route.call_count == 2


def test_sandbox_delete_accepts_if_exists_and_is_hidden_from_help(router):
    router.get(SANDBOXES_URL).respond(200, json=envelope([]))

    result = invoke(["sandbox", "delete", "--if-exists", "ghost"])
    help_text = invoke(["sandbox", "--help"]).stdout

    assert result.exit_code == 0, result.output
    assert "ghost: not found, skipped" in result.stderr
    assert " rm " in help_text and " delete " not in help_text


# --- create timeout details -----------------------------------------------------------------


def test_json_create_wait_timeout_names_the_sandbox_in_details(router):
    router.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json("pending")))
    router.get(f"{SANDBOXES_URL}/{SID}").respond(200, json=envelope(sandbox_json("pending")))

    result = invoke(["sandbox", "create", "demo", "--wait", "--wait-timeout", "0.3"], as_json=True)

    assert result.exit_code == 1
    assert json.loads(result.stdout)["error"]["details"] == {"sandbox_id": SID, "deleted": False}


def test_create_timeout_reports_a_deleted_sandbox_in_json_and_keeps_the_text_line(monkeypatch):
    def timed_out(self, **kwargs):
        raise SandboxTimeoutError(DELETED_MESSAGE, sandbox_id=SID, deleted=True)

    monkeypatch.setattr(Client, "create_sandbox", timed_out)
    args = ["sandbox", "create", "demo", "--wait", "--wait-timeout", "1"]
    as_json = invoke(args, as_json=True)
    text = invoke(args)

    error = json.loads(as_json.stdout)["error"]
    assert as_json.exit_code == 1 and text.exit_code == 1
    assert error["details"] == {"sandbox_id": SID, "deleted": True}
    assert error["message"] == DELETED_MESSAGE
    assert text.stderr == f"error: {DELETED_MESSAGE}\n"


def test_timeout_details_fall_back_to_the_message_without_the_attribute():
    unknown = SandboxTimeoutError("creating a sandbox did not finish; it may still finish")
    legacy = SandboxTimeoutError(DELETED_MESSAGE)
    del legacy.deleted

    assert output.timeout_details(unknown) == {"deleted": False}
    assert output.timeout_details(legacy) == {"deleted": True}
