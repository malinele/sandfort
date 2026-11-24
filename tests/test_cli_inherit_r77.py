"""CLI r77: ``sandbox create --inherit-resources`` and recorded snapshot resources (respx)."""

import json
import re
import sys
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
KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SNAP_ID = "snap_01HZZZZZZZZZZZZZZZZZZZZZZ"
CREATED = "2026-10-30T19:26:00Z"
SANDBOXES_URL = "/v1/sandboxes"
SNAPSHOT_URL = f"/v1/snapshots/{SNAP_ID}"
RECORDED = {"cpu_millicores": 500, "memory_mib": 256, "disk_gib": 1}

RUNNER = CliRunner()


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def snapshot_json(**extra):
    data = {
        "id": SNAP_ID,
        "name": "py",
        "state": "ready",
        "image_ref": "python:3.12-slim",
        "digest": "sha256:abc",
        "layer_count": 3,
        "source_sandbox_id": None,
        "created_at": CREATED,
    }
    return {**data, **extra}


def sandbox_json():
    return {
        "id": SID,
        "name": "demo",
        "state": "creating",
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
    }


def invoke(args, *, as_json=False):
    return RUNNER.invoke(create_app(), (["--json"] if as_json else []) + args)


def field_row(stdout, name):
    """The FIELD / VALUE row for ``name`` (None when the table has no such field)."""
    match = re.search(rf"^\W*{name}\W+(.*?)\W*$", stdout, re.MULTILINE)
    return None if match is None else match.group(1)


@pytest.fixture(autouse=True)
def profile_env(monkeypatch, tmp_path):
    """Keep every test away from the real home directory and any ambient credentials."""
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    return tmp_path / "cfg"


@pytest.fixture
def api():
    config.save_profile(BASE, KEY)
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        yield router
        for recorded in router.calls:
            assert recorded.request.headers["authorization"] == f"Bearer {KEY}"


# --- sandbox create --inherit-resources ----------------------------------------------------


def test_sandbox_create_inherit_resources_flag_is_sent(api):
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json()))

    result = invoke(["sandbox", "create", "demo", "--inherit-resources"])

    assert result.exit_code == 0, result.output
    body = json.loads(route.calls.last.request.content)
    assert body["inherit_resources"] is True


def test_sandbox_create_without_the_flag_sends_no_inherit_resources(api):
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json()))

    result = invoke(["sandbox", "create", "demo"])

    assert result.exit_code == 0, result.output
    body = json.loads(route.calls.last.request.content)
    assert "inherit_resources" not in body


# --- snapshot get: recorded resources ------------------------------------------------------


def test_snapshot_get_prints_recorded_resources(api):
    api.get(SNAPSHOT_URL).respond(200, json=envelope(snapshot_json(resources=RECORDED)))

    result = invoke(["snapshot", "get", SNAP_ID])

    assert result.exit_code == 0, result.output
    assert field_row(result.stdout, "cpu_millicores") == "500"
    assert field_row(result.stdout, "memory_mib") == "256"
    assert field_row(result.stdout, "disk_gib") == "1"


def test_snapshot_get_without_resources_prints_no_resource_fields(api):
    api.get(SNAPSHOT_URL).respond(200, json=envelope(snapshot_json()))

    result = invoke(["snapshot", "get", SNAP_ID])

    assert result.exit_code == 0, result.output
    assert SNAP_ID in result.stdout
    for name in ("cpu_millicores", "memory_mib", "disk_gib"):
        assert name not in result.stdout


def test_snapshot_get_json_carries_recorded_resources(api):
    api.get(SNAPSHOT_URL).respond(200, json=envelope(snapshot_json(resources=RECORDED)))

    result = invoke(["snapshot", "get", SNAP_ID], as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["resources"] == RECORDED
