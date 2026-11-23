"""CLI r54: the stop cause and stop time of a sandbox show in the field view and REASON cell."""

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
from sandfort_sdk import SandboxInfo  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
PROFILE_KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOXES_URL = "/v1/sandboxes"
STOPPED_AT = "2026-11-10T15:04:05+00:00"
RUNNER = CliRunner()


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def sandbox_json(**extra):
    base = {
        "id": SID,
        "name": "demo",
        "state": "stopped",
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
    }
    return {**base, **extra}


def stopped_json(cause="auto_stop", **extra):
    return sandbox_json(stop_cause=cause, stopped_at=STOPPED_AT, **extra)


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


def test_get_stopped_sandbox_shows_both_rows_in_text(router):
    router.get(f"{SANDBOXES_URL}/{SID}").respond(200, json=envelope(stopped_json()))

    result = invoke(["sandbox", "get", SID], as_json=False)

    assert result.exit_code == 0, result.output
    assert "stop_cause" in result.stdout and "auto_stop" in result.stdout
    assert "stopped_at" in result.stdout and STOPPED_AT in result.stdout


def test_get_stopped_sandbox_json_has_both_keys(router):
    router.get(f"{SANDBOXES_URL}/{SID}").respond(200, json=envelope(stopped_json()))

    result = invoke(["sandbox", "get", SID])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["stop_cause"] == "auto_stop"
    assert payload["stopped_at"] == STOPPED_AT


def test_get_started_sandbox_shows_neither_row(router):
    router.get(f"{SANDBOXES_URL}/{SID}").respond(200, json=envelope(sandbox_json(state="started")))

    result = invoke(["sandbox", "get", SID], as_json=False)

    assert result.exit_code == 0, result.output
    assert "stop_cause" not in result.stdout
    assert "stopped_at" not in result.stdout


def test_rows_follow_error_code_and_are_sanitised():
    info = SandboxInfo.from_payload(
        stopped_json(cause="oom\x1b]0;x\x07_killed", error_reason="boom", error_code="timeout")
    )

    fields = output.sandbox_fields(info)
    names = list(fields)

    assert names.index("stop_cause") == names.index("error_code") + 1
    assert names.index("stopped_at") == names.index("stop_cause") + 1
    assert "\x1b" not in fields["stop_cause"] and "\x07" not in fields["stop_cause"]
    assert fields["stopped_at"] == STOPPED_AT


def test_render_sandbox_for_stop_and_start_carries_the_rows(capsys):
    info = SandboxInfo.from_payload(stopped_json(cause="requested"))

    output.render_sandbox(output.AppState(), info)

    shown = capsys.readouterr().out
    assert "stop_cause" in shown and "requested" in shown
    assert "stopped_at" in shown and STOPPED_AT in shown


def test_list_shows_the_cause_for_an_auto_stopped_sandbox(router):
    router.get(SANDBOXES_URL).respond(200, json=envelope([stopped_json()]))

    result = invoke(["sandbox", "list"], as_json=False)

    assert result.exit_code == 0, result.output
    assert "auto_stop" in result.stdout
    assert "STOP" not in result.stdout  # no new column


def test_list_keeps_the_code_form_for_container_exited(router):
    payload = stopped_json(cause="container_exited", error_code="exited", error_reason="exit 3")
    router.get(SANDBOXES_URL).respond(200, json=envelope([payload]))

    result = invoke(["sandbox", "list"], as_json=False)

    assert result.exit_code == 0, result.output
    assert "exited: exit 3" in result.stdout
    assert "container_exited" not in result.stdout


def test_cause_is_the_cell_only_without_code_and_reason():
    stopped = SandboxInfo.from_payload(stopped_json(cause="container_exited"))
    with_reason = SandboxInfo.from_payload(stopped_json(error_reason="disk full"))
    with_code = SandboxInfo.from_payload(stopped_json(error_code="timeout"))

    assert output.error_cell(stopped) == "container_exited"
    assert output.error_cell(with_reason) == "disk full"
    assert output.error_cell(with_code) == "timeout"


def test_list_cell_is_empty_for_a_started_sandbox(router):
    router.get(SANDBOXES_URL).respond(200, json=envelope([sandbox_json(state="started")]))

    result = invoke(["sandbox", "list"], as_json=False)

    assert result.exit_code == 0, result.output
    assert "STOP" not in result.stdout
    assert output.error_cell(SandboxInfo.from_payload(sandbox_json(state="started"))) == ""


def test_list_json_carries_both_fields(router):
    router.get(SANDBOXES_URL).respond(200, json=envelope([stopped_json()]))

    result = invoke(["sandbox", "list"])

    assert result.exit_code == 0, result.output
    row = json.loads(result.stdout)[0]
    assert row["stop_cause"] == "auto_stop"
    assert row["stopped_at"] == STOPPED_AT


def test_payload_without_the_fields_renders_as_before(router):
    router.get(f"{SANDBOXES_URL}/{SID}").respond(200, json=envelope(sandbox_json()))
    router.get(SANDBOXES_URL).respond(200, json=envelope([sandbox_json()]))

    detail = invoke(["sandbox", "get", SID], as_json=False)
    listing = invoke(["sandbox", "list"], as_json=False)
    as_json = invoke(["sandbox", "get", SID])

    assert detail.exit_code == 0 and listing.exit_code == 0, detail.output + listing.output
    assert "stop_cause" not in detail.stdout and "stopped_at" not in detail.stdout
    assert "STOP" not in listing.stdout
    payload = json.loads(as_json.stdout)
    assert payload["stop_cause"] is None and payload["stopped_at"] is None
