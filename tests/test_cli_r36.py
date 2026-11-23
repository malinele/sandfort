"""CLI round 36: ``delete`` is a hidden alias of ``rm``; an error-state create gives a hint."""

import json
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
VOL_ID = "vol_01HZZZZZZZZZZZZZZZZZZZZZZZ"
CREATED = "2026-11-08T10:00:00Z"
SANDBOXES_URL = "/v1/sandboxes"
RUNNER = CliRunner()


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def sandbox_json(state="started", **extra):
    data = {
        "id": SID,
        "name": "demo",
        "state": state,
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
    }
    return {**data, **extra}


def snapshot_json():
    return {
        "id": SNAP_ID,
        "name": "py",
        "state": "deleting",
        "image_ref": "python:3.12-slim",
        "digest": None,
        "layer_count": 3,
        "source_sandbox_id": None,
        "created_at": CREATED,
    }


def hidden_snapshot_json():
    """What a label-scoped key gets: image_ref and digest are null."""
    return {**snapshot_json(), "state": "ready", "image_ref": None}


def volume_json():
    return {
        "id": VOL_ID,
        "name": "data",
        "state": "deleting",
        "size_bytes": 4096,
        "created_at": CREATED,
    }


def invoke(args, *, as_json=False):
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


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


def test_sandbox_delete_works_like_rm(router):
    route = router.delete(f"{SANDBOXES_URL}/{SID}").respond(
        200, json=envelope(sandbox_json("destroying"))
    )

    result = invoke(["sandbox", "delete", SID])

    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == SID
    assert route.call_count == 1


def test_snapshot_delete_works_like_rm(router):
    route = router.delete(f"/v1/snapshots/{SNAP_ID}").respond(200, json=envelope(snapshot_json()))

    result = invoke(["snapshot", "delete", SNAP_ID])

    assert result.exit_code == 0, result.output
    assert SNAP_ID in result.stdout
    assert route.call_count == 1


def test_snapshot_list_with_a_null_image_ref_renders_a_dash(router):
    router.get("/v1/snapshots").respond(200, json=envelope([hidden_snapshot_json()]))

    result = invoke(["snapshot", "list"])

    assert result.exit_code == 0, result.output
    row = next(line for line in result.stdout.splitlines() if SNAP_ID in line)
    assert row.split("│")[-3].strip() == "-"  # IMAGE, followed by the LABELS column


def test_snapshot_get_with_a_null_image_ref_and_digest_renders_dashes(router):
    router.get(f"/v1/snapshots/{SNAP_ID}").respond(200, json=envelope(hidden_snapshot_json()))

    result = invoke(["snapshot", "get", SNAP_ID])

    assert result.exit_code == 0, result.output
    split_lines = (line.split("│") for line in result.stdout.splitlines())
    stripped = ([cell.strip() for cell in cells if cell.strip()] for cells in split_lines)
    rows = {cells[0]: cells[1] for cells in stripped if len(cells) == 2}
    assert (rows["image_ref"], rows["digest"]) == ("-", "-")


def test_snapshot_list_json_keeps_the_null_image_ref(router):
    router.get("/v1/snapshots").respond(200, json=envelope([hidden_snapshot_json()]))

    result = invoke(["snapshot", "list"], as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)[0]["image_ref"] is None


def test_volume_delete_works_like_rm(router):
    route = router.delete(f"/v1/volumes/{VOL_ID}").respond(200, json=envelope(volume_json()))

    result = invoke(["volume", "delete", VOL_ID])

    assert result.exit_code == 0, result.output
    assert VOL_ID in result.stdout
    assert route.call_count == 1


@pytest.mark.parametrize("group", ["sandbox", "snapshot", "volume"])
def test_help_lists_rm_and_hides_delete(group):
    result = invoke([group, "--help"])

    assert result.exit_code == 0
    words = result.stdout.replace("│", " ").split()
    assert "rm" in words
    assert "delete" not in words


def route_create(router, state="started", **sandbox_fields):
    return router.post(SANDBOXES_URL).respond(
        201, json=envelope(sandbox_json(state, **sandbox_fields))
    )


def test_create_already_in_error_exits_1_with_a_hint(router):
    route_create(router, "error", error_code="image_not_found", error_reason="no such image")

    result = invoke(["sandbox", "create", "demo", "--snapshot", "nope"])

    assert result.exit_code == 1
    assert f"error: sandbox {SID} is error [image_not_found]: no such image" in result.stderr
    assert "--wait" in result.stderr
    assert f"sandfort sandbox rm {SID}" in result.stderr


def test_create_already_in_error_json_prints_the_error_object(router):
    route_create(router, "error", error_code="image_not_found", error_reason="no such image")

    result = invoke(["sandbox", "create", "demo"], as_json=True)

    assert result.exit_code == 1
    error = json.loads(result.stdout)["error"]
    assert error["sandbox_id"] == SID
    assert error["state"] == "error"
    assert error["error_code"] == "image_not_found"
    assert "--wait" in error["hint"]
    assert f"sandbox rm {SID}" in error["hint"]


def test_create_in_a_non_terminal_state_exits_0(router):
    route_create(router, "pending")

    result = invoke(["sandbox", "create", "demo"])

    assert result.exit_code == 0, result.output
    assert "pending" in result.stdout
    assert result.stderr == ""


def test_normal_create_exits_0(router):
    route_create(router)

    result = invoke(["sandbox", "create", "demo"])

    assert result.exit_code == 0, result.output
    assert SID in result.stdout
    assert result.stderr == ""


# --- the failure line never strips the sandbox's own text ----------------------------------

BUILDS_URL = "/v1/images/builds"


def test_error_reason_ending_in_the_code_token_keeps_its_text(router):
    reason = "gave up waiting [timeout]"
    route_create(router, "error", error_code="timeout", error_reason=reason)

    text = invoke(["sandbox", "create", "demo"])
    as_json = invoke(["sandbox", "create", "demo"], as_json=True)

    assert f"error: sandbox {SID} is error [timeout]: {reason}" in text.stderr
    assert json.loads(as_json.stdout)["error"]["message"] == f"sandbox {SID} is error: {reason}"


def test_text_line_shows_the_error_code_exactly_once(router):
    route_create(router, "error", error_code="image_not_found", error_reason="no such image")

    result = invoke(["sandbox", "create", "demo"])
    as_json = invoke(["sandbox", "create", "demo"], as_json=True)

    assert result.stderr.count("[image_not_found]") == 1
    assert "[image_not_found]" not in json.loads(as_json.stdout)["error"]["message"]


REQUEST_ID = "req_wait_0001"


def fail_the_wait(router):
    router.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json("creating")))
    router.get(f"{SANDBOXES_URL}/{SID}").respond(
        200,
        json=envelope(sandbox_json("error", error_reason="image pull failed")),
        headers={"x-request-id": REQUEST_ID},
    )
    router.delete(f"{SANDBOXES_URL}/{SID}").respond(200, json=envelope(sandbox_json("destroying")))


def test_json_failure_message_has_no_request_id_tail_but_the_field_is_set(router):
    fail_the_wait(router)

    result = invoke(["sandbox", "create", "demo", "--wait"], as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == 1
    assert "(request id" not in error["message"]
    assert error["message"].startswith(f"sandbox {SID} is error: image pull failed")
    assert REQUEST_ID not in error["message"]
    assert error["request_id"] == REQUEST_ID


def test_text_failure_line_still_ends_with_the_request_id(router):
    fail_the_wait(router)

    result = invoke(["sandbox", "create", "demo", "--wait"])

    lines = result.stderr.strip().splitlines()
    assert result.exit_code == 1
    assert len(lines) == 1
    assert lines[0].endswith(f"(request id {REQUEST_ID})")


def test_scoped_build_summary_names_the_snapshot_id(router, tmp_path):
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"base": "python:3.12"}))
    ready = {**hidden_snapshot_json(), "spec_hash": "h1", "reused": True, "digest": None}
    router.post(BUILDS_URL).respond(200, json=envelope(ready))

    result = invoke(["snapshot", "build", str(spec)])

    assert result.exit_code == 0, result.output
    assert f"build {SNAP_ID} ready (reused): {SNAP_ID}" in result.stdout
    assert "ready (reused): -" not in result.stdout
