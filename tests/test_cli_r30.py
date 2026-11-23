"""CLI r30: `sandbox list` shows labels and the error reason; the SANDBOX_FAILED json error
carries the reason, the state and whether the sandbox was deleted."""

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
from sandfort_cli.output import ELLIPSIS, TABLE_CELL_MAX  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
OTHER_SID = "sbx_01HYYYYYYYYYYYYYYYYYYYYYYY"
SANDBOXES_URL = "/v1/sandboxes"
SANDBOX_URL = f"{SANDBOXES_URL}/{SID}"

RUNNER = CliRunner()


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def sandbox_json(state="started", *, sandbox_id=SID, name="demo", **extra):
    return {"id": sandbox_id, "name": name, "state": state, **extra}


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


def row_with(output, needle):
    return next(line for line in output.splitlines() if needle in line)


# --- sandbox list: LABELS and REASON -----------------------------------------------------------


def test_list_table_shows_labels_and_the_reason_of_an_error_row(api):
    broken = sandbox_json(
        "error", name="broken", labels={"team": "ml", "env": "ci"}, error_reason="image pull failed"
    )
    fine = sandbox_json(sandbox_id=OTHER_SID, name="fine", labels={"env": "dev"})
    api.get(SANDBOXES_URL).respond(200, json=envelope([broken, fine]))

    result = invoke(["sandbox", "list"])

    header = row_with(result.stdout, "LABELS")
    assert header.index("DISK") < header.index("LABELS") < header.index("REASON")
    broken_row = row_with(result.stdout, "broken")
    assert "team=ml,env=ci" in broken_row
    assert "image pull failed" in broken_row
    fine_row = row_with(result.stdout, "fine")
    assert "env=dev" in fine_row
    assert "image pull failed" not in fine_row


def test_list_table_truncates_long_labels_and_reasons(api):
    long_reason = "container start failed: " + "x" * 80
    long_label = "owner=" + "o" * 60
    broken = sandbox_json("error", labels={"owner": "o" * 60}, error_reason=long_reason)
    api.get(SANDBOXES_URL).respond(200, json=envelope([broken]))

    result = invoke(["sandbox", "list"])

    kept = TABLE_CELL_MAX - len(ELLIPSIS)
    assert long_reason[:kept] + ELLIPSIS in result.stdout
    assert long_reason not in result.stdout
    assert long_label[:kept] + ELLIPSIS in result.stdout
    assert long_label not in result.stdout


def test_list_json_keeps_the_full_objects(api):
    long_reason = "reason " * 30
    broken = sandbox_json("error", labels={"k": "v" * 80}, error_reason=long_reason)
    api.get(SANDBOXES_URL).respond(200, json=envelope([broken]))

    result = invoke(["sandbox", "list"], as_json=True)

    item = json.loads(result.stdout)[0]
    # Json success values flatten whitespace (the trailing space goes), but nothing is cut.
    assert item["error_reason"] == long_reason.rstrip()
    assert item["error_reason"].count("reason") == 30
    assert item["labels"] == {"k": "v" * 80}


# --- SANDBOX_FAILED json error -----------------------------------------------------------------


@pytest.mark.parametrize("keep", [False, True])
def test_failed_create_json_error_carries_reason_state_and_deleted(api, keep):
    failed = sandbox_json("error", error_reason="image pull failed")
    api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json("creating")))
    api.get(SANDBOX_URL).respond(200, json=envelope(failed))
    api.delete(SANDBOX_URL).respond(200, json=envelope(sandbox_json("destroying")))

    args = ["sandbox", "create", "demo", "--wait"] + (["--keep-on-failure"] if keep else [])
    result = invoke(args, as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == 1
    assert error["code"] == "SANDBOX_FAILED"
    assert (error["sandbox_id"], error["state"]) == (SID, "error")
    assert error["error_reason"] == "image pull failed"
    assert error["deleted"] is (not keep)
    assert "image pull failed" in error["message"]


def test_failed_create_text_error_stays_one_line(api):
    failed = sandbox_json("error", error_reason="image pull failed")
    api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json("creating")))
    api.get(SANDBOX_URL).respond(200, json=envelope(failed))
    api.delete(SANDBOX_URL).respond(200, json=envelope(sandbox_json("destroying")))

    result = invoke(["sandbox", "create", "demo", "--wait"])

    lines = result.stderr.strip().splitlines()
    assert result.exit_code == 1
    assert len(lines) == 1 and lines[0].startswith("error: ")
    assert "image pull failed" in lines[0]
