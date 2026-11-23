"""CLI r31f: the SANDBOX_FAILED error of `sandbox create --wait` carries the request id of the
reply that showed the failure (json: `error.request_id`; text: the one `error:` line)."""

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
SANDBOXES_URL = "/v1/sandboxes"
SANDBOX_URL = f"{SANDBOXES_URL}/{SID}"
POLL_REQUEST_ID = "req_poll_0001"

RUNNER = CliRunner()


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def sandbox_json(state="started", **extra):
    return {"id": SID, "name": "demo", "state": state, **extra}


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


def fail_the_create(api, *, request_id=POLL_REQUEST_ID):
    headers = {} if request_id is None else {"x-request-id": request_id}
    failed = sandbox_json("error", error_reason="image pull failed")
    api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json("creating")))
    api.get(SANDBOX_URL).respond(200, json=envelope(failed), headers=headers)
    api.delete(SANDBOX_URL).respond(200, json=envelope(sandbox_json("destroying")))


def test_failed_create_json_error_shows_the_request_id(api):
    fail_the_create(api)

    result = invoke(["sandbox", "create", "demo", "--wait"], as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == 1
    assert error["code"] == "SANDBOX_FAILED"
    assert error["request_id"] == POLL_REQUEST_ID
    assert error["deleted"] is True


def test_failed_create_text_error_names_the_request_id_on_one_line(api):
    fail_the_create(api)

    result = invoke(["sandbox", "create", "demo", "--wait"])

    lines = result.stderr.strip().splitlines()
    assert result.exit_code == 1
    assert len(lines) == 1 and lines[0].startswith("error: ")
    assert "image pull failed" in lines[0]
    assert f"request id {POLL_REQUEST_ID}" in lines[0]


def test_failed_create_without_a_request_id_keeps_null_and_the_plain_text_line(api):
    fail_the_create(api, request_id=None)

    as_json = invoke(["sandbox", "create", "demo", "--wait"], as_json=True)
    as_text = invoke(["sandbox", "create", "demo", "--wait"])

    assert json.loads(as_json.stdout)["error"]["request_id"] is None
    assert "request id" not in as_text.stderr
