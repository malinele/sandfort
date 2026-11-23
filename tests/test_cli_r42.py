"""CLI round 42: ``sandbox start`` takes ``--wait`` and ``--wait-timeout`` like ``create``.

Without ``--wait`` start is unchanged (one POST, the reply rendered). With ``--wait`` it blocks
until the sandbox reports ``started`` and renders the refreshed record. ``--wait-timeout``
requires ``--wait`` and must be > 0 (usage error, exit 2, the create wording); a wait that runs
out is a one-line error naming the sandbox, exit 1.
"""

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import Client  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOX_URL = f"/v1/sandboxes/{SID}"
START_URL = f"{SANDBOX_URL}/start"
RUNNER = CliRunner()


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def sandbox_json(state):
    return {
        "id": SID,
        "name": "demo",
        "state": state,
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
    }


def reply(state):
    return httpx.Response(200, json=envelope(sandbox_json(state)))


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


def route_start(router, state="starting"):
    return router.post(START_URL).respond(200, json=envelope(sandbox_json(state)))


def route_polls(router, *states):
    return router.get(SANDBOX_URL).mock(side_effect=[reply(state) for state in states])


# --- without --wait ---------------------------------------------------------------------------


def test_start_without_wait_is_unchanged(router):
    start_route = route_start(router)
    get_route = route_polls(router, "started")

    result = invoke(["sandbox", "start", SID])

    assert result.exit_code == 0, result.output
    assert start_route.call_count == 1
    assert get_route.call_count == 0
    assert "starting" in result.stdout and "started" not in result.stdout


def test_json_start_without_wait_prints_the_start_reply(router):
    route_start(router)

    result = invoke(["sandbox", "start", SID], as_json=True)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["id"] == SID and payload["state"] == "starting"


# --- with --wait ------------------------------------------------------------------------------


def test_start_wait_returns_once_started_and_shows_it(router):
    start_route = route_start(router)
    get_route = route_polls(router, "starting", "started")

    result = invoke(["sandbox", "start", SID, "--wait"])

    assert result.exit_code == 0, result.output
    assert start_route.call_count == 1
    assert get_route.call_count == 2
    assert "started" in result.stdout and "starting" not in result.stdout


def test_start_wait_goes_through_the_public_sdk_start(router, monkeypatch):
    calls = []
    original = Client.start

    def recording_start(self, sandbox_id, **kwargs):
        calls.append((sandbox_id, kwargs))
        return original(self, sandbox_id, **kwargs)

    monkeypatch.setattr(Client, "start", recording_start)
    route_start(router, "started")

    result = invoke(["sandbox", "start", SID, "--wait", "--wait-timeout", "7"])

    assert result.exit_code == 0, result.output
    assert calls == [(SID, {"wait": True, "wait_timeout_s": 7.0})]


def test_start_wait_on_an_already_started_reply_sends_no_further_request(router):
    start_route = route_start(router, "started")
    get_route = route_polls(router, "started")

    result = invoke(["sandbox", "start", SID, "--wait"])

    assert result.exit_code == 0, result.output
    assert start_route.call_count == 1
    assert get_route.call_count == 0
    assert "started" in result.stdout


def test_start_wait_timeout_covers_a_slow_start_request(router):
    def slow_start(request):
        time.sleep(1.0)
        raise httpx.ReadTimeout("the start is still running", request=request)

    router.post(START_URL).mock(side_effect=slow_start)
    get_route = route_polls(router, "started")

    began = time.monotonic()
    result = invoke(["sandbox", "start", SID, "--wait", "--wait-timeout", "0.3"])

    assert result.exit_code == 1
    assert time.monotonic() - began < 10
    assert get_route.call_count == 0
    assert result.stderr.startswith("error: ")
    assert len(result.stderr.strip().splitlines()) == 1
    assert SID in result.stderr


def test_json_start_wait_parses_and_shows_started(router):
    route_start(router)
    route_polls(router, "started")

    result = invoke(["sandbox", "start", SID, "--wait", "--wait-timeout", "5"], as_json=True)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["id"] == SID and payload["state"] == "started"


def test_start_wait_timeout_stops_the_polling_with_one_error_line(router):
    route_start(router)
    get_route = router.get(SANDBOX_URL).mock(side_effect=lambda request: reply("starting"))

    began = time.monotonic()
    result = invoke(["sandbox", "start", SID, "--wait", "--wait-timeout", "0.3"])

    assert result.exit_code == 1
    assert time.monotonic() - began < 10
    assert get_route.call_count >= 1
    assert result.stderr.startswith("error: ")
    assert len(result.stderr.strip().splitlines()) == 1
    assert SID in result.stderr


def test_json_start_wait_timeout_names_the_sandbox(router):
    route_start(router)
    router.get(SANDBOX_URL).mock(side_effect=lambda request: reply("starting"))

    result = invoke(["sandbox", "start", SID, "--wait", "--wait-timeout", "0.3"], as_json=True)

    assert result.exit_code == 1
    assert json.loads(result.stdout)["error"]["details"]["sandbox_id"] == SID


def test_start_wait_into_error_state_fails(router):
    route_start(router)
    route_polls(router, "error")

    result = invoke(["sandbox", "start", SID, "--wait"])

    assert result.exit_code == 1
    assert result.stderr.startswith("error: ") and SID in result.stderr


# --- --wait-timeout validation ----------------------------------------------------------------


@pytest.mark.parametrize("command", [["start", SID], ["create", "demo"]])
def test_wait_timeout_without_wait_is_the_same_usage_error(router, command):
    start_route = route_start(router)
    create_route = router.post("/v1/sandboxes").respond(201, json=envelope(sandbox_json("started")))

    result = invoke(["sandbox", *command, "--wait-timeout", "5"])

    assert result.exit_code == 2
    assert "--wait-timeout" in result.output and "requires --wait" in result.output
    assert start_route.call_count == 0 and create_route.call_count == 0


@pytest.mark.parametrize("value", ["0", "-1"])
def test_start_wait_timeout_must_be_positive(router, value):
    start_route = route_start(router)

    result = invoke(["sandbox", "start", SID, "--wait", "--wait-timeout", value])

    assert result.exit_code == 2
    assert "greater than 0" in result.output
    assert start_route.call_count == 0


def test_start_help_lists_the_wait_options():
    result = invoke(["sandbox", "start", "--help"])

    assert result.exit_code == 0
    assert "--wait" in result.stdout and "--wait-timeout" in result.stdout
