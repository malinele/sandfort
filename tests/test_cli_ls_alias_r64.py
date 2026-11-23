"""``ls`` is a hidden alias of ``list`` in the sandbox, volume and snapshot groups."""

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
VOL_ID = "vol_01HZZZZZZZZZZZZZZZZZZZZZZ"
CREATED = "2026-11-08T10:00:00Z"
RUNNER = CliRunner()
GROUPS = ("sandbox", "volume", "snapshot")
ROWS = {
    "sandbox": (
        "/v1/sandboxes",
        {
            "id": SID,
            "name": "demo",
            "state": "started",
            "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
            "network": {"block_all": False},
        },
    ),
    "volume": (
        "/v1/volumes",
        {"id": VOL_ID, "name": "data", "state": "ready", "size_bytes": 4096, "created_at": CREATED},
    ),
    "snapshot": (
        "/v1/snapshots",
        {
            "id": SNAP_ID,
            "name": "py",
            "state": "ready",
            "image_ref": "python:3.12-slim",
            "digest": None,
            "layer_count": 3,
            "source_sandbox_id": None,
            "created_at": CREATED,
        },
    ),
}


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def invoke(args):
    return RUNNER.invoke(create_app(None), args)


@pytest.fixture(autouse=True)
def profile(monkeypatch, tmp_path):
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, KEY)


@pytest.fixture
def router():
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


@pytest.mark.parametrize("group", GROUPS)
def test_cli_ls_alias_prints_what_list_prints(router, group):
    path, row = ROWS[group]
    route = router.get(path).respond(200, json=envelope([row]))

    listed = invoke([group, "list"])
    aliased = invoke([group, "ls"])

    assert listed.exit_code == 0, listed.output
    assert aliased.exit_code == 0, aliased.output
    assert aliased.stdout == listed.stdout
    assert row["id"] in aliased.stdout
    assert route.call_count == 2


@pytest.mark.parametrize("group", GROUPS)
def test_cli_ls_alias_is_hidden_from_group_help(group):
    result = invoke([group, "--help"])

    assert result.exit_code == 0, result.output
    assert " list " in result.stdout
    assert " ls " not in result.stdout
