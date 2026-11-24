"""CLI ``sandbox resize``: GET, then POST /resize; the reply's resources are what is shown."""

import json
import re
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
RESIZE_URL = f"{SANDBOXES_URL}/{SID}/resize"
RUNNER = CliRunner()
NOTHING_TO_RESIZE = "nothing to resize"
# The resources GET returns (before the resize); the resize reply overrides some of them.
BEFORE = {"cpu_millicores": 1000, "memory_mib": 2048, "disk_gib": 3}


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def error_envelope(code, message):
    error = {"code": code, "message": message, "details": {}, "request_id": "req_1"}
    return {"success": False, "data": None, "error": error, "meta": None}


def sandbox_json(state="stopped", *, name="demo", **resources):
    """A sandbox record; ``resources`` override the nested ``resources`` object."""
    return {
        "id": SID,
        "name": name,
        "state": state,
        "resources": {**BEFORE, **resources},
        "network": {"block_all": False},
    }


def invoke(args, *, as_json=False):
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def field(output, name):
    """The VALUE cell of the FIELD ``name`` in a printed table (``None`` when absent)."""
    match = re.search(rf"^\W*{re.escape(name)}\W+(\S+)", output, re.MULTILINE)
    return match.group(1) if match else None


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


def route_get(router):
    return router.get(f"{SANDBOXES_URL}/{SID}").respond(200, json=envelope(sandbox_json()))


def route_list(router, *sandboxes):
    return router.get(SANDBOXES_URL).respond(200, json=envelope(list(sandboxes)))


def route_resize(router, **overrides):
    """The resize route: replies with a sandbox whose nested resources carry ``overrides``."""
    return router.post(RESIZE_URL).respond(200, json=envelope(sandbox_json(**overrides)))


def sent_body(route):
    return json.loads(route.calls.last.request.content)


# --- success ---------------------------------------------------------------------------


def test_resize_gets_then_posts_and_shows_the_reply_resources(router):
    get_route = route_get(router)
    resize_route = route_resize(router, memory_mib=1024)

    result = invoke(["sandbox", "resize", SID, "--memory-mib", "1024"])

    assert result.exit_code == 0, result.output
    assert [call.request.method for call in router.calls] == ["GET", "POST"]
    assert get_route.call_count == 1
    assert resize_route.call_count == 1
    assert sent_body(resize_route) == {"memory_mib": 1024}
    assert field(result.stdout, "memory_mib") == "1024"  # the reply, not the GET's 2048
    assert "2048" not in result.stdout
    assert result.stderr == ""


def test_resize_json_prints_the_sandbox_object_of_the_reply(router):
    route_get(router)
    route_resize(router, memory_mib=1024)

    result = invoke(["sandbox", "resize", SID, "--memory-mib", "1024"], as_json=True)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["id"] == SID
    assert payload["resources"]["memory_mib"] == 1024
    assert payload["resources"]["cpu_millicores"] == 1000


def test_resize_with_all_three_options_sends_all_three_keys(router):
    route_get(router)
    route = route_resize(router, cpu_millicores=2000, memory_mib=4096, disk_gib=10)

    result = invoke(
        ["sandbox", "resize", SID, "--cpu-millicores", "2000", "--memory-mib", "4096"]
        + ["--disk-gib", "10"]
    )

    assert result.exit_code == 0, result.output
    assert sent_body(route) == {"cpu_millicores": 2000, "memory_mib": 4096, "disk_gib": 10}
    assert field(result.stdout, "cpu_millicores") == "2000"
    assert field(result.stdout, "memory_mib") == "4096"
    assert field(result.stdout, "disk_gib") == "10"


def test_resize_resolves_a_name_through_the_list_route(router):
    list_route = route_list(router, sandbox_json(name="demo"))
    router.get(f"{SANDBOXES_URL}/{SID}").respond(200, json=envelope(sandbox_json()))
    resize_route = route_resize(router, disk_gib=7)

    result = invoke(["sandbox", "resize", "demo", "--disk-gib", "7"])

    assert result.exit_code == 0, result.output
    assert list_route.call_count >= 1
    assert resize_route.call_count == 1
    assert sent_body(resize_route) == {"disk_gib": 7}
    assert field(result.stdout, "disk_gib") == "7"


# --- usage errors (exit 2, no HTTP call) -----------------------------------------------


@pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
def test_resize_without_an_option_is_a_usage_error(router, as_json):
    result = invoke(["sandbox", "resize", SID], as_json=as_json)

    assert result.exit_code == 2
    assert NOTHING_TO_RESIZE in result.output
    assert len(router.calls) == 0


@pytest.mark.parametrize("option", ["--cpu-millicores", "--memory-mib", "--disk-gib"])
@pytest.mark.parametrize("value", ["abc", "1.5", "1_000", " 5", ""])
def test_resize_rejects_non_integer_values(router, option, value):
    result = invoke(["sandbox", "resize", SID, option, value])

    assert result.exit_code == 2, result.output
    assert len(router.calls) == 0


@pytest.mark.parametrize("blank", ["", "   "])
@pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
def test_resize_rejects_a_blank_sandbox_argument(router, blank, as_json):
    result = invoke(["sandbox", "resize", blank, "--memory-mib", "1024"], as_json=as_json)

    assert result.exit_code == 2, result.output
    assert len(router.calls) == 0


# --- server errors (exit 1) ------------------------------------------------------------


def test_resize_of_a_started_sandbox_exits_1_in_text(router):
    route_get(router)
    router.post(RESIZE_URL).respond(
        409, json=error_envelope("INVALID_STATE", "sandbox must be stopped")
    )

    result = invoke(["sandbox", "resize", SID, "--memory-mib", "1024"])

    assert result.exit_code == 1
    assert "sandbox must be stopped" in result.stderr
    assert result.stdout == ""


def test_resize_of_a_started_sandbox_exits_1_under_json(router):
    route_get(router)
    router.post(RESIZE_URL).respond(
        409, json=error_envelope("INVALID_STATE", "sandbox must be stopped")
    )

    result = invoke(["sandbox", "resize", SID, "--memory-mib", "1024"], as_json=True)

    assert result.exit_code == 1
    assert json.loads(result.stdout)["error"]["code"] == "INVALID_STATE"


# --- help ------------------------------------------------------------------------------


def test_resize_help_lists_the_three_options():
    result = invoke(["sandbox", "resize", "--help"])

    assert result.exit_code == 0, result.output
    for option in ("--cpu-millicores", "--memory-mib", "--disk-gib"):
        assert option in result.stdout
    assert "stopped sandbox" in result.stdout


def test_sandbox_help_lists_resize():
    result = invoke(["sandbox", "--help"])

    assert result.exit_code == 0, result.output
    assert "resize" in result.stdout
