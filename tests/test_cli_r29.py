"""CLI r29: `sandbox list --all` asks the server for tombstones, names resolve through the SDK,
and `snapshot export` streams a ready snapshot to a file."""

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
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
OTHER_SID = "sbx_01HYYYYYYYYYYYYYYYYYYYYYYY"
SANDBOXES_URL = "/v1/sandboxes"
SANDBOX_URL = f"{SANDBOXES_URL}/{SID}"
EXPORT_URL = "/v1/snapshots/snap_1/export"

RUNNER = CliRunner()


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def error_envelope(code, message):
    error = {"code": code, "message": message, "details": {}, "request_id": "req_1"}
    return {"success": False, "data": None, "error": error, "meta": None}


def sandbox_json(state="started", *, sandbox_id=SID, name="demo"):
    return {"id": sandbox_id, "name": name, "state": state}


def invoke(args, *, as_json=False):
    return RUNNER.invoke(create_app(), (["--json"] if as_json else []) + args)


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


# --- sandbox list --all ------------------------------------------------------------------------


@pytest.mark.parametrize("show_all", [False, True])
def test_sandbox_list_sends_include_destroyed_only_with_all(api, show_all):
    gone = sandbox_json("destroyed", sandbox_id=OTHER_SID, name="gone")
    route = api.get(SANDBOXES_URL).respond(200, json=envelope([sandbox_json(), gone]))

    result = invoke(["sandbox", "list"] + (["--all"] if show_all else []), as_json=True)

    params = route.calls.last.request.url.params
    assert result.exit_code == 0, result.output
    assert ("include_destroyed" in params) is show_all
    assert [row["id"] for row in json.loads(result.stdout)] == [SID, OTHER_SID]


def test_sandbox_list_all_with_a_state_filter_passes_both(api):
    route = api.get(SANDBOXES_URL).respond(200, json=envelope([]))

    result = invoke(["sandbox", "list", "--all", "--state", "stopped"])

    params = route.calls.last.request.url.params
    assert result.exit_code == 0, result.output
    assert (params["include_destroyed"], params["state"]) == ("true", "stopped")


# --- name resolution through the SDK -----------------------------------------------------------


def test_a_name_resolves_to_the_live_sandbox_and_is_fetched_by_id(api):
    rows = [
        sandbox_json("destroyed", sandbox_id=OTHER_SID, name="marek"),
        sandbox_json(name="marek"),
    ]
    api.get(SANDBOXES_URL).respond(200, json=envelope(rows))
    route = api.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json(name="marek")))

    result = invoke(["sandbox", "get", "marek"], as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["id"] == SID
    assert route.called


def test_an_unknown_name_keeps_the_cli_error_message(api):
    api.get(SANDBOXES_URL).respond(200, json=envelope([sandbox_json(name="other")]))

    result = invoke(["sandbox", "get", "ghost"])

    assert result.exit_code == 1
    assert (
        "no sandbox named 'ghost'; pass an id (sbx_...) or the name of an existing sandbox"
        in result.stderr
    )


def test_an_ambiguous_name_lists_the_candidates_in_the_cli_message(api):
    rows = [sandbox_json(name="twin"), sandbox_json("stopped", sandbox_id=OTHER_SID, name="twin")]
    api.get(SANDBOXES_URL).respond(200, json=envelope(rows))

    result = invoke(["sandbox", "get", "twin"])

    assert result.exit_code == 1
    expected = f"several sandboxes are named 'twin': {SID} (started), {OTHER_SID} (stopped)"
    assert expected in result.stderr
    assert "pass an id (sbx_...)" in result.stderr


def test_an_id_is_used_without_listing(api):
    list_route = api.get(SANDBOXES_URL).respond(200, json=envelope([]))
    api.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json()))

    result = invoke(["sandbox", "get", SID])

    assert result.exit_code == 0, result.output
    assert not list_route.called


# --- snapshot export ---------------------------------------------------------------------------


def tar_route(api, content=b"image-tar-bytes" * 100):
    headers = {"Content-Type": "application/x-tar"}
    return api.get(EXPORT_URL).respond(200, content=content, headers=headers)


def test_snapshot_export_writes_the_file_and_prints_the_byte_count(api, tmp_path):
    route = tar_route(api)
    target = tmp_path / "image.tar"

    result = invoke(["snapshot", "export", "snap_1", "-o", str(target)])

    assert result.exit_code == 0, result.output
    assert target.read_bytes() == b"image-tar-bytes" * 100
    assert "1500 bytes" in result.stdout
    assert route.calls.last.request.headers["authorization"] == f"Bearer {KEY}"


def test_snapshot_export_json_prints_id_path_and_bytes(api, tmp_path):
    tar_route(api, b"abc")
    target = tmp_path / "out.tar"

    result = invoke(["snapshot", "export", "snap_1", "--output", str(target)], as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {"id": "snap_1", "path": str(target), "bytes": 3}


def test_snapshot_export_requires_an_output_file(api):
    result = invoke(["snapshot", "export", "snap_1"])

    assert result.exit_code != 0


def test_snapshot_export_of_a_snapshot_not_ready_fails_and_writes_nothing(api, tmp_path):
    body = error_envelope("INVALID_STATE", "snapshot snap_1 is pending, not ready")
    api.get(EXPORT_URL).respond(409, json=body)
    target = tmp_path / "image.tar"

    result = invoke(["snapshot", "export", "snap_1", "-o", str(target)])

    assert result.exit_code == 1
    assert "INVALID_STATE" in result.stderr
    assert not target.exists()


def test_snapshot_export_into_a_missing_directory_is_a_cli_error(api, tmp_path):
    tar_route(api)
    target = tmp_path / "missing-dir" / "image.tar"

    result = invoke(["snapshot", "export", "snap_1", "-o", str(target)])

    assert result.exit_code == 1
    assert f"cannot write {target}" in result.stderr


def test_snapshot_export_dropped_connection_leaves_no_file(api, tmp_path):
    api.get(EXPORT_URL).mock(side_effect=httpx.ReadError("connection lost"))
    target = tmp_path / "image.tar"

    result = invoke(["snapshot", "export", "snap_1", "-o", str(target)])

    assert result.exit_code == 1
    assert not target.exists()
