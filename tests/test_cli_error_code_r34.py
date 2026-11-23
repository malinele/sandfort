"""CLI r34: the machine-readable error_code shows in sandbox output; SDK field order."""

import dataclasses
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config, output  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import SandboxFailedError, SandboxInfo  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
PROFILE_KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOXES_URL = "/v1/sandboxes"
ERROR_CODE = "image_not_found"
ERROR_REASON = "image alpine:nope was not found"
RUNNER = CliRunner()


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def failed_sandbox_json(**extra):
    base = {
        "id": SID,
        "name": "demo",
        "state": "error",
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
        "error_reason": ERROR_REASON,
        "error_code": ERROR_CODE,
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


def test_detail_view_shows_error_code_next_to_error_reason(router):
    router.get(f"{SANDBOXES_URL}/{SID}").respond(200, json=envelope(failed_sandbox_json()))

    result = invoke(["sandbox", "get", SID], as_json=False)

    assert result.exit_code == 0, result.output
    assert "error_code" in result.stdout and ERROR_CODE in result.stdout
    assert "error_reason" in result.stdout


def test_detail_view_omits_error_code_when_unset():
    info = SandboxInfo.from_payload(failed_sandbox_json(error_code=None))

    fields = output.sandbox_fields(info)

    assert "error_code" not in fields
    assert fields["error_reason"] == ERROR_REASON


def test_json_sandbox_get_carries_error_code(router):
    router.get(f"{SANDBOXES_URL}/{SID}").respond(200, json=envelope(failed_sandbox_json()))

    result = invoke(["sandbox", "get", SID])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["error_code"] == ERROR_CODE
    assert payload["error_reason"] == ERROR_REASON


def test_list_cell_shows_code_and_reason_for_a_failed_sandbox(router):
    router.get(SANDBOXES_URL).respond(200, json=envelope([failed_sandbox_json()]))

    result = invoke(["sandbox", "list"], as_json=False)

    assert result.exit_code == 0, result.output
    assert f"{ERROR_CODE}: " in result.stdout
    assert "ERROR_CODE" not in result.stdout  # no new column


def test_list_cell_without_a_code_is_the_reason_alone():
    info = SandboxInfo.from_payload(failed_sandbox_json(error_code=None))

    assert output.error_cell(info) == output.truncate_cell(ERROR_REASON)


def test_list_cell_with_a_code_and_no_reason_is_the_code():
    info = SandboxInfo.from_payload(failed_sandbox_json(error_reason=None))

    assert output.error_cell(info) == ERROR_CODE


def test_failed_create_json_has_error_code_next_to_error_reason():
    failure = SandboxFailedError(
        "sandbox failed",
        sandbox_id=SID,
        state="error",
        error_reason=ERROR_REASON,
        error_code=ERROR_CODE,
    )

    error = output.error_payload(failure)["error"]

    assert error["code"] == "SANDBOX_FAILED"
    assert error["error_reason"] == ERROR_REASON
    assert error["error_code"] == ERROR_CODE


def test_failed_create_json_through_the_cli_has_error_code(router):
    creating = failed_sandbox_json(state="creating", error_reason=None, error_code=None)
    router.post(SANDBOXES_URL).respond(202, json=envelope(creating))
    router.get(f"{SANDBOXES_URL}/{SID}").respond(200, json=envelope(failed_sandbox_json()))
    router.delete(f"{SANDBOXES_URL}/{SID}").respond(
        200, json=envelope(failed_sandbox_json(state="destroying"))
    )

    result = invoke(["sandbox", "create", "demo", "--wait"])

    assert result.exit_code != 0
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "SANDBOX_FAILED"
    assert error["error_code"] == ERROR_CODE
    assert error["error_reason"] == ERROR_REASON


def test_sandbox_info_field_order_keeps_error_code_before_the_stop_fields():
    names = [item.name for item in dataclasses.fields(SandboxInfo)]

    assert names[: names.index("error_code") + 1] == [
        "id",
        "name",
        "state",
        "resources",
        "env",
        "labels",
        "block_network",
        "public",
        "auto_stop_minutes",
        "auto_delete_minutes",
        "error_reason",
        "job_id",
        "isolation",
        "snapshot",
        "created_at",
        "updated_at",
        "error_code",
    ]
    # later fields (volumes, image_mounts) may follow; only the relative order is pinned
    assert names.index("error_code") < names.index("stopped_at") < names.index("stop_cause")
