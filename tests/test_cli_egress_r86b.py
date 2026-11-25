"""CLI ``sandbox egress set`` (PATCH the allowlist) and ``sandbox egress show`` (GET)."""

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
SANDBOX_URL = f"/v1/sandboxes/{SID}"
RUNNER = CliRunner()
EXACTLY_ONE = "exactly one of --allow and --deny-all"
RESET_HINT = "reset the sandbox to upgrade its egress credential"


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def error_envelope(code, message):
    error = {"code": code, "message": message, "details": {}, "request_id": "req_1"}
    return {"success": False, "data": None, "error": error, "meta": None}


def sandbox_json(allowlist=("a.example.com",), generation=2, **extra):
    return {
        "id": SID,
        "name": "demo",
        "state": "started",
        "resources": {"cpu_millicores": 1000, "memory_mib": 2048, "disk_gib": 3},
        "network": {"block_all": False},
        "egress_allowlist": None if allowlist is None else list(allowlist),
        "egress_policy_generation": generation,
        "future_server_field": {"ignored": True},
        **extra,
    }


def invoke(args, *, as_json=False):
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def sent_body(route):
    return json.loads(route.calls.last.request.content)


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


def route_patch(router, **kwargs):
    return router.patch(SANDBOX_URL).respond(200, json=envelope(sandbox_json(**kwargs)))


def route_get(router, **kwargs):
    return router.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json(**kwargs)))


# --- set -------------------------------------------------------------------------------


def test_set_with_repeated_allow_sends_the_list_in_order(router):
    route = route_patch(router, allowlist=("b.example.com", "a.example.com"))

    result = invoke(
        ["sandbox", "egress", "set", SID, "--allow", "b.example.com", "--allow", "a.example.com"]
    )

    assert result.exit_code == 0, result.output
    assert [call.request.method for call in router.calls] == ["PATCH"]
    assert sent_body(route) == {"egress_allowlist": ["b.example.com", "a.example.com"]}
    assert "b.example.com" in result.stdout
    assert "a.example.com" in result.stdout
    assert result.stderr == ""


def test_set_deny_all_sends_an_empty_list(router):
    route = route_patch(router, allowlist=(), generation=3)

    result = invoke(["sandbox", "egress", "set", SID, "--deny-all"])

    assert result.exit_code == 0, result.output
    assert sent_body(route) == {"egress_allowlist": []}


def test_set_json_prints_id_allowlist_and_generation(router):
    route_patch(router, allowlist=("a.example.com",), generation=5)

    result = invoke(["sandbox", "egress", "set", SID, "--allow", "a.example.com"], as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "id": SID,
        "egress_allowlist": ["a.example.com"],
        "egress_policy_generation": 5,
    }


def test_set_resolves_a_name_before_patching(router):
    router.get("/v1/sandboxes").respond(200, json=envelope([sandbox_json()]))
    route_get(router)
    patch_route = route_patch(router)

    result = invoke(["sandbox", "egress", "set", "demo", "--allow", "a.example.com"])

    assert result.exit_code == 0, result.output
    assert patch_route.call_count == 1


@pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
def test_set_without_allow_or_deny_all_is_a_usage_error(router, as_json):
    result = invoke(["sandbox", "egress", "set", SID], as_json=as_json)

    assert result.exit_code == 2
    assert EXACTLY_ONE in result.output
    assert len(router.calls) == 0


def test_set_with_allow_and_deny_all_is_a_usage_error(router):
    result = invoke(["sandbox", "egress", "set", SID, "--allow", "a.example.com", "--deny-all"])

    assert result.exit_code == 2
    assert EXACTLY_ONE in result.output
    assert len(router.calls) == 0


@pytest.mark.parametrize("blank", ["", "   "])
def test_set_rejects_a_blank_allow_entry(router, blank):
    result = invoke(["sandbox", "egress", "set", SID, "--allow", blank])

    assert result.exit_code == 2, result.output
    assert len(router.calls) == 0


@pytest.mark.parametrize("blank", ["", "   "])
def test_set_rejects_a_blank_sandbox_argument(router, blank):
    result = invoke(["sandbox", "egress", "set", blank, "--deny-all"])

    assert result.exit_code == 2, result.output
    assert len(router.calls) == 0


@pytest.mark.parametrize(
    ("status", "code", "message"),
    [
        (409, "INVALID_STATE", RESET_HINT),
        (403, "FORBIDDEN", "network egress is disabled by operator policy"),
        (422, "VALIDATION_FAILED", "invalid egress entry 'A.EXAMPLE.COM'"),
    ],
)
def test_set_renders_a_4xx_in_text_on_stderr(router, status, code, message):
    router.patch(SANDBOX_URL).respond(status, json=error_envelope(code, message))

    result = invoke(["sandbox", "egress", "set", SID, "--allow", "a.example.com"])

    assert result.exit_code == 1
    assert message in result.stderr
    assert result.stdout == ""


def test_set_renders_a_4xx_as_one_json_object_under_json(router):
    router.patch(SANDBOX_URL).respond(409, json=error_envelope("INVALID_STATE", RESET_HINT))

    result = invoke(["sandbox", "egress", "set", SID, "--deny-all"], as_json=True)

    assert result.exit_code == 1
    assert json.loads(result.stdout)["error"]["message"] == RESET_HINT


# --- show ------------------------------------------------------------------------------


def test_show_prints_the_allowlist_and_the_generation(router):
    route = route_get(router, allowlist=("a.example.com", "10.0.0.0/8"), generation=4)

    result = invoke(["sandbox", "egress", "show", SID])

    assert result.exit_code == 0, result.output
    assert [call.request.method for call in router.calls] == ["GET"]
    assert route.call_count == 1
    assert "a.example.com" in result.stdout
    assert "10.0.0.0/8" in result.stdout
    assert re.search(r"egress_policy_generation\W+4\b", result.stdout)


def test_show_json_matches_the_set_shape(router):
    route_get(router, allowlist=("a.example.com",), generation=4)

    result = invoke(["sandbox", "egress", "show", SID], as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "id": SID,
        "egress_allowlist": ["a.example.com"],
        "egress_policy_generation": 4,
    }


def test_show_json_keeps_a_missing_allowlist_null(router):
    route_get(router, allowlist=None, generation=0)

    result = invoke(["sandbox", "egress", "show", SID], as_json=True)

    assert json.loads(result.stdout)["egress_allowlist"] is None


def test_show_an_empty_allowlist_says_all_connections_are_blocked(router):
    route_get(router, allowlist=(), generation=2)

    result = invoke(["sandbox", "egress", "show", SID])

    assert result.exit_code == 0, result.output
    assert "blocked" in result.stdout


def test_show_without_an_allowlist_says_there_is_none(router):
    route_get(router, allowlist=None, generation=0)

    result = invoke(["sandbox", "egress", "show", SID])

    assert result.exit_code == 0, result.output
    assert "no allowlist" in result.stdout


def test_show_of_an_unknown_sandbox_exits_1(router):
    router.get(SANDBOX_URL).respond(404, json=error_envelope("NOT_FOUND", "sandbox not found"))

    result = invoke(["sandbox", "egress", "show", SID])

    assert result.exit_code == 1
    assert "not found" in result.stderr


# --- help ------------------------------------------------------------------------------


def test_egress_group_help_lists_set_and_show():
    result = invoke(["sandbox", "egress", "--help"])

    assert result.exit_code == 0, result.output
    assert "Replace the egress allowlist." in result.stdout
    assert "Show the egress allowlist." in result.stdout


def test_set_help_lists_both_options():
    result = invoke(["sandbox", "egress", "set", "--help"])

    assert result.exit_code == 0, result.output
    assert "--allow" in result.stdout
    assert "--deny-all" in result.stdout


def test_sandbox_help_lists_egress():
    result = invoke(["sandbox", "--help"])

    assert result.exit_code == 0, result.output
    assert "egress" in result.stdout
