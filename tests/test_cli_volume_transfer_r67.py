"""CLI r67: `volume export` streams a volume to a .tar.gz file and `volume restore` uploads one."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
EXPORT_URL = "/v1/volumes/vol_1/export"
RESTORE_URL = "/v1/volumes/vol_1/restore"
RUNNER = CliRunner()


def invoke(args, *, as_json=False):
    return RUNNER.invoke(create_app(), (["--json"] if as_json else []) + args)


def error_envelope(code, message, details=None):
    error = {"code": code, "message": message, "details": details or {}, "request_id": "req_1"}
    return {"success": False, "data": None, "error": error, "meta": None}


def restored_envelope(size=2048):
    data = {"volume_id": "vol_1", "name": "data", "restored_bytes": size}
    return {"success": True, "data": data, "error": None, "meta": None}


@pytest.fixture(autouse=True)
def profile_env(monkeypatch, tmp_path):
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, KEY)


@pytest.fixture
def api():
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        yield router


@pytest.fixture
def archive(tmp_path):
    path = tmp_path / "data.tar.gz"
    path.write_bytes(b"\x1f\x8b" + b"x" * 3000)
    return path


# --- export ------------------------------------------------------------------------------------


def test_volume_export_writes_the_file_and_prints_the_byte_count(api, tmp_path):
    headers = {"Content-Type": "application/gzip"}
    route = api.get(EXPORT_URL).respond(200, content=b"gz" * 500, headers=headers)
    target = tmp_path / "out.tar.gz"

    result = invoke(["volume", "export", "vol_1", "-o", str(target)])

    assert result.exit_code == 0, result.output
    assert target.read_bytes() == b"gz" * 500
    assert "exported vol_1 to" in result.stdout and "1000 bytes" in result.stdout
    assert route.calls.last.request.headers["authorization"] == f"Bearer {KEY}"


def test_volume_export_json_prints_id_path_and_bytes(api, tmp_path):
    api.get(EXPORT_URL).respond(200, content=b"abc")
    target = tmp_path / "out.tar.gz"

    result = invoke(["volume", "export", "vol_1", "--output", str(target)], as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {"id": "vol_1", "path": str(target), "bytes": 3}


def test_volume_export_requires_an_output_file(api):
    assert invoke(["volume", "export", "vol_1"]).exit_code != 0


def test_volume_export_refused_by_the_server_fails_and_writes_nothing(api, tmp_path):
    body = error_envelope("CONFLICT", "this driver cannot export", {"reason": "unsupported_mode"})
    api.get(EXPORT_URL).respond(409, json=body)
    target = tmp_path / "out.tar.gz"

    result = invoke(["volume", "export", "vol_1", "-o", str(target)])

    assert result.exit_code == 1
    assert "CONFLICT" in result.stderr
    assert not target.exists()


def test_volume_export_into_a_missing_directory_is_a_cli_error(api, tmp_path):
    api.get(EXPORT_URL).respond(200, content=b"abc")
    target = tmp_path / "missing-dir" / "out.tar.gz"

    result = invoke(["volume", "export", "vol_1", "-o", str(target)])

    assert result.exit_code == 1
    assert f"cannot write {target}" in result.stderr


def test_volume_export_dropped_connection_leaves_no_file(api, tmp_path):
    api.get(EXPORT_URL).mock(side_effect=httpx.ReadError("connection lost"))
    target = tmp_path / "out.tar.gz"

    result = invoke(["volume", "export", "vol_1", "-o", str(target)])

    assert result.exit_code == 1
    assert not target.exists()


# --- restore -----------------------------------------------------------------------------------


def test_volume_restore_uploads_the_file_and_prints_the_byte_count(api, archive):
    route = api.post(RESTORE_URL).respond(200, json=restored_envelope(2048))

    result = invoke(["volume", "restore", "vol_1", str(archive)])

    assert result.exit_code == 0, result.output
    assert "restored vol_1 from" in result.stdout and "2048 bytes" in result.stdout
    request = route.calls.last.request
    assert request.content == archive.read_bytes()
    assert request.headers["content-type"] == "application/gzip"


def test_volume_restore_json_prints_the_result(api, archive):
    api.post(RESTORE_URL).respond(200, json=restored_envelope(5))

    result = invoke(["volume", "restore", "vol_1", str(archive)], as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {"volume_id": "vol_1", "name": "data", "restored_bytes": 5}


def test_volume_restore_of_a_missing_file_is_a_usage_error_and_sends_nothing(api, tmp_path):
    route = api.post(RESTORE_URL).respond(200, json=restored_envelope())

    result = invoke(["volume", "restore", "vol_1", str(tmp_path / "nope.tar.gz")])

    assert result.exit_code == 2
    assert not route.called


def test_volume_restore_refused_while_mounted_fails_with_the_server_error(api, archive):
    body = error_envelope("CONFLICT", "volume is mounted", {"reason": "in_use"})
    api.post(RESTORE_URL).respond(409, json=body)

    result = invoke(["volume", "restore", "vol_1", str(archive)])

    assert result.exit_code == 1
    assert "CONFLICT" in result.stderr and "volume is mounted" in result.stderr


def test_volume_restore_that_emptied_the_volume_says_so(api, archive):
    message = "the archive is not a readable tar; the volume was emptied"
    body = error_envelope("UNPROCESSABLE", message, {"volume_emptied": True})
    api.post(RESTORE_URL).respond(422, json=body)

    result = invoke(["volume", "restore", "vol_1", str(archive)])

    assert result.exit_code == 1
    assert "the volume was emptied" in result.stderr


def test_volume_restore_resolves_a_volume_name(api, archive):
    page = {"id": "vol_1", "name": "data", "state": "ready", "labels": {},
            "created_at": "2026-11-13T10:00:00Z"}  # fmt: skip
    api.get("/v1/volumes").respond(
        200, json={"success": True, "data": [page], "error": None, "meta": {"next_cursor": None}}
    )
    route = api.post(RESTORE_URL).respond(200, json=restored_envelope())

    result = invoke(["volume", "restore", "data", str(archive)])

    assert result.exit_code == 0, result.output
    assert route.called
