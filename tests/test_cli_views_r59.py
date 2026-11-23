"""CLI r59 review fixes: volume limit columns, sandbox image mounts, atomic audit export."""

import json
import os
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.output import AppState  # noqa: E402
from sandfort_cli.sandboxes import render_sandbox  # noqa: E402
from sandfort_cli.volume import render_volume, render_volumes  # noqa: E402
from sandfort_sdk import SandboxInfo, VolumeInfo  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
PROFILE_KEY = "sf_test_key_do_not_print"
VOLUMES_URL = "/v1/volumes"
EXPORT_URL = "/v1/audit-events/export"
RUNNER = CliRunner()
CREATED = datetime(2026, 11, 1, 10, 30, tzinfo=UTC)
# Exports end with a trailer line; without one `audit export` exits 3 (round 64).
NDJSON = '{"id":"aud_001"}\n{"id":"aud_002"}\n{"type":"export_summary","row_count":2}\n'
OLD_EXPORT = b"previous export\n"


def volume(volume_id="vol_1", **extra):
    """A real ``VolumeInfo`` parsed from a payload, like the CLI gets from the SDK."""
    payload = {"id": volume_id, "name": "data", "state": "ready", "created_at": CREATED.isoformat()}
    return VolumeInfo.from_payload({**payload, **extra})


def sandbox(**extra):
    """A real ``SandboxInfo`` parsed from a payload (``image_mounts`` as a list)."""
    payload = {
        "id": "sbx_1",
        "name": "box",
        "state": "started",
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
    }
    return SandboxInfo.from_payload({**payload, **extra})


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
def out_dir(tmp_path):
    """A directory apart from the profile, so listing it shows only export files."""
    path = tmp_path / "out"
    path.mkdir()
    return path


def invoke(args, *, as_json=False):
    return RUNNER.invoke(create_app(), (["--json"] if as_json else []) + args)


def printed_json(capsys):
    return json.loads(capsys.readouterr().out)


def row_of(text, needle):
    return next(line for line in text.splitlines() if needle in line)


# --- volumes: limit and over -------------------------------------------------------------------


def test_volume_list_text_shows_the_limit_and_an_over_marker(capsys):
    infos = [
        volume("vol_a", size_bytes=10, max_bytes=100),
        volume("vol_b", size_bytes=300, max_bytes=200, over_limit=True),
    ]

    render_volumes(AppState(), infos)

    out = capsys.readouterr().out
    assert "LIMIT" in out
    assert "OVER" in out
    assert "100" in row_of(out, "vol_a")
    assert "over" not in row_of(out, "vol_a")
    assert "200" in row_of(out, "vol_b")
    assert "over" in row_of(out, "vol_b")


def test_volume_list_text_shows_none_without_a_limit(capsys):
    render_volumes(AppState(), [volume("vol_a")])

    assert "none" in row_of(capsys.readouterr().out, "vol_a")


def test_volume_get_text_shows_limit_and_over(capsys):
    render_volume(AppState(), volume(size_bytes=300, max_bytes=200, over_limit=True))

    out = capsys.readouterr().out
    assert "200" in row_of(out, "limit")
    assert "true" in row_of(out, "over")


def test_volume_get_text_shows_none_and_not_over_without_a_limit(capsys):
    render_volume(AppState(), volume())

    out = capsys.readouterr().out
    assert "none" in row_of(out, "limit")
    assert "false" in row_of(out, "over")


def test_volume_json_carries_both_fields(capsys):
    render_volumes(AppState(json_output=True), [volume(max_bytes=5, over_limit=True), volume()])

    first, second = printed_json(capsys)
    assert (first["max_bytes"], first["over_limit"]) == (5, True)
    assert (second["max_bytes"], second["over_limit"]) == (None, False)


def test_volume_get_json_carries_both_fields(capsys):
    render_volume(AppState(json_output=True), volume(max_bytes=7))

    payload = printed_json(capsys)
    assert payload["max_bytes"] == 7
    assert payload["over_limit"] is False


def test_volume_commands_work_with_a_server_that_omits_the_fields(router):
    body = {"id": "vol_1", "name": "data", "state": "ready", "created_at": CREATED.isoformat()}
    router.get(VOLUMES_URL).respond(200, json={"success": True, "data": [body], "error": None})

    text = invoke(["volume", "list"])
    as_json = invoke(["volume", "list"], as_json=True)

    assert text.exit_code == 0, text.output
    assert "none" in row_of(text.stdout, "vol_1")
    assert as_json.exit_code == 0, as_json.output
    entry = json.loads(as_json.stdout)[0]
    assert entry["max_bytes"] is None
    assert entry["over_limit"] is False


# --- sandbox: image mounts ---------------------------------------------------------------------


def test_sandbox_text_shows_the_image_mounts_line(capsys):
    render_sandbox(AppState(), sandbox(image_mounts=["/a", "/b"]))

    row = row_of(capsys.readouterr().out, "image mounts")
    assert "/a, /b" in row


def test_sandbox_text_has_no_image_mounts_line_when_empty(capsys):
    render_sandbox(AppState(), sandbox())

    assert "image mounts" not in capsys.readouterr().out


def test_sandbox_json_carries_the_image_mounts_list(capsys):
    render_sandbox(AppState(json_output=True), sandbox(image_mounts=["/a", "/b"]))

    assert printed_json(capsys)["image_mounts"] == ["/a", "/b"]


def test_sandbox_json_carries_an_empty_list_without_image_mounts(capsys):
    render_sandbox(AppState(json_output=True), sandbox())

    assert printed_json(capsys)["image_mounts"] == []


def test_sandbox_image_mounts_are_sanitised(capsys):
    render_sandbox(AppState(), sandbox(image_mounts=["/a\x1b[31m"]))

    assert "\x1b" not in capsys.readouterr().out


# --- audit export: write beside, rename after the stream ---------------------------------------


class BrokenStream(httpx.SyncByteStream):
    def __init__(self, first: bytes):
        self.first = first

    def __iter__(self):
        yield self.first
        raise httpx.ReadError("connection lost")


def broken_response():
    return httpx.Response(200, stream=BrokenStream(NDJSON.encode()[:20]))


def old_export(out_dir):
    target = out_dir / "audit.ndjson"
    target.write_bytes(OLD_EXPORT)
    target.chmod(0o644)
    return target


def test_export_force_success_replaces_the_old_file_with_mode_600(router, out_dir):
    router.get(EXPORT_URL).respond(200, text=NDJSON)
    target = old_export(out_dir)

    result = invoke(["audit", "export", "--output", str(target), "--force"])

    assert result.exit_code == 0, result.output
    assert target.read_text() == NDJSON
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert os.listdir(out_dir) == ["audit.ndjson"]


def test_export_force_failure_keeps_the_old_file_and_leaves_no_temporary(router, out_dir):
    router.get(EXPORT_URL).mock(return_value=broken_response())
    target = old_export(out_dir)

    result = invoke(["audit", "export", "--output", str(target), "--force"])

    assert result.exit_code == 1
    assert "error:" in result.output
    assert target.read_bytes() == OLD_EXPORT
    assert os.listdir(out_dir) == ["audit.ndjson"]


def test_export_force_refused_request_keeps_the_old_file(router, out_dir):
    router.get(EXPORT_URL).respond(
        403,
        json={"success": False, "data": None, "error": {"code": "FORBIDDEN", "message": "no"}},
    )
    target = old_export(out_dir)

    result = invoke(["audit", "export", "--output", str(target), "--force"])

    assert result.exit_code == 1
    assert target.read_bytes() == OLD_EXPORT
    assert os.listdir(out_dir) == ["audit.ndjson"]


def test_export_force_to_a_new_path_fails_cleanly(router, out_dir):
    router.get(EXPORT_URL).mock(return_value=broken_response())
    target = out_dir / "fresh.ndjson"

    result = invoke(["audit", "export", "--output", str(target), "--force"])

    assert result.exit_code == 1
    assert os.listdir(out_dir) == []


def test_export_without_force_still_refuses_an_existing_file(router, out_dir):
    route = router.get(EXPORT_URL).respond(200, text=NDJSON)
    target = old_export(out_dir)

    result = invoke(["audit", "export", "--output", str(target)])

    assert result.exit_code == 1
    assert "--force" in result.output
    assert target.read_bytes() == OLD_EXPORT
    assert not route.called
    assert os.listdir(out_dir) == ["audit.ndjson"]


def test_export_without_force_failure_leaves_no_file(router, out_dir):
    router.get(EXPORT_URL).mock(return_value=broken_response())
    target = out_dir / "audit.ndjson"

    result = invoke(["audit", "export", "--output", str(target)])

    assert result.exit_code == 1
    assert os.listdir(out_dir) == []
