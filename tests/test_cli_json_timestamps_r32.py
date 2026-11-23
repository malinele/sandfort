"""CLI r32: --json sandbox output with server timestamps, key list ids, SDK updated_at."""

import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config, output  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import SandboxInfo  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
PROFILE_KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOXES_URL = "/v1/sandboxes"
KEYS_URL = "/v1/api-keys"
CREATED_AT = "2026-11-07T09:30:00+00:00"
UPDATED_AT = "2026-11-07T09:45:10+00:00"
LONG_KEY_ID = "key_01HZZZZZZZZZZZZZZZZZZZZZZA"
REVOKED_KEY_ID = "key_01HZZZZZZZZZZZZZZZZZZZZZZB"
NARROW_WIDTH = 60
RUNNER = CliRunner()


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def sandbox_json(state="started"):
    return {
        "id": SID,
        "name": "demo",
        "state": state,
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
        "created_at": CREATED_AT,
        "updated_at": UPDATED_AT,
    }


def key_json(key_id, **extra):
    base = {
        "id": key_id,
        "name": "student",
        "prefix": "sf_abcd",
        "scopes": ["sandboxes:read", "sandboxes:write"],
        "sandbox_labels": {"course": "intro"},
        "max_sandboxes": 2,
        "created_at": CREATED_AT,
        "last_used_at": None,
        "expires_at": None,
        "revoked_at": None,
        "created_by": None,
    }
    return {**base, **extra}


def invoke(args, *, as_json=True):
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


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


def assert_iso_timestamps(payload):
    assert payload["created_at"] == CREATED_AT
    assert payload["updated_at"] == UPDATED_AT
    assert datetime.fromisoformat(payload["created_at"]).utcoffset() is not None


def test_json_sandbox_list_prints_iso_timestamps(router):
    router.get(SANDBOXES_URL).respond(200, json=envelope([sandbox_json()]))

    result = invoke(["sandbox", "list"])

    assert result.exit_code == 0, result.output
    assert_iso_timestamps(json.loads(result.stdout)[0])


def test_json_sandbox_get_prints_iso_timestamps(router):
    router.get(f"{SANDBOXES_URL}/{SID}").respond(200, json=envelope(sandbox_json()))

    result = invoke(["sandbox", "get", SID])

    assert result.exit_code == 0, result.output
    assert_iso_timestamps(json.loads(result.stdout))


def test_text_sandbox_get_shows_both_timestamps(router):
    router.get(f"{SANDBOXES_URL}/{SID}").respond(200, json=envelope(sandbox_json()))

    result = invoke(["sandbox", "get", SID], as_json=False)

    assert result.exit_code == 0, result.output
    assert CREATED_AT in result.stdout and UPDATED_AT in result.stdout


def test_json_sandbox_create_wait_exits_0_with_valid_json(router):
    router.post(SANDBOXES_URL).respond(202, json=envelope(sandbox_json("creating")))
    router.get(f"{SANDBOXES_URL}/{SID}").respond(200, json=envelope(sandbox_json("started")))

    result = invoke(["sandbox", "create", "demo", "--wait"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["state"] == "started"
    assert_iso_timestamps(payload)


def test_json_sandbox_rm_exits_0_with_valid_json(router):
    router.delete(f"{SANDBOXES_URL}/{SID}").respond(200, json=envelope(sandbox_json("destroying")))

    result = invoke(["sandbox", "rm", SID])

    assert result.exit_code == 0, result.output
    assert_iso_timestamps(json.loads(result.stdout))


def test_print_json_serializes_any_datetime_and_still_rejects_other_types(capsys):
    output.print_json({"at": datetime.fromisoformat(CREATED_AT)})

    assert json.loads(capsys.readouterr().out) == {"at": CREATED_AT}
    with pytest.raises(TypeError):
        output.print_json({"unsupported": object()})


def test_key_list_prints_a_full_id_at_a_narrow_width(router, monkeypatch):
    monkeypatch.setattr(output, "PIPED_TABLE_WIDTH", NARROW_WIDTH)
    router.get(KEYS_URL).respond(200, json=envelope([key_json(LONG_KEY_ID)]))

    result = invoke(["key", "list"], as_json=False)

    assert result.exit_code == 0, result.output
    assert len(LONG_KEY_ID) == 30
    assert LONG_KEY_ID in result.stdout


def test_key_list_hides_revoked_keys_unless_all_is_given(router):
    keys = [key_json(LONG_KEY_ID), key_json(REVOKED_KEY_ID, revoked_at=UPDATED_AT)]
    router.get(KEYS_URL).respond(200, json=envelope(keys))

    default_text = invoke(["key", "list"], as_json=False)
    all_text = invoke(["key", "list", "--all"], as_json=False)
    default_json = json.loads(invoke(["key", "list"]).stdout)
    all_json = json.loads(invoke(["key", "list", "--all"]).stdout)

    assert REVOKED_KEY_ID not in default_text.stdout and LONG_KEY_ID in default_text.stdout
    assert REVOKED_KEY_ID in all_text.stdout
    assert [item["id"] for item in default_json] == [LONG_KEY_ID]
    assert [item["id"] for item in all_json] == [LONG_KEY_ID, REVOKED_KEY_ID]


def test_sdk_parses_updated_at_and_defaults_to_none():
    with_stamp = SandboxInfo.from_payload(sandbox_json())
    without = SandboxInfo.from_payload({"id": SID, "name": "demo", "state": "started"})

    assert with_stamp.updated_at == datetime.fromisoformat(UPDATED_AT)
    assert with_stamp.created_at == datetime.fromisoformat(CREATED_AT)
    assert without.updated_at is None
