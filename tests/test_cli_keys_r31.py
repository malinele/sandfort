"""CLI r31: the `key` group (create, list, revoke) over the SDK API key methods."""

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
PROFILE_KEY = "sf_test_key_do_not_print"
SECRET = "sf_new_secret_shown_once"
KEYS_URL = "/v1/api-keys"
KEY_A = "key_01HZZZZZZZZZZZZZZZZZZZZZZA"
KEY_B = "key_01HZZZZZZZZZZZZZZZZZZZZZZB"
CREATED_AT = "2026-11-06T10:00:00+00:00"
REVOKED_AT = "2026-11-06T11:00:00+00:00"
CREATED_SCOPES = ["sandboxes:read", "sandboxes:write"]

RUNNER = CliRunner()


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def error_envelope(code, message):
    error = {"code": code, "message": message, "details": {}, "request_id": "req_keys_1"}
    return {"success": False, "data": None, "error": error, "meta": None}


def key_json(key_id=KEY_A, **extra):
    base = {
        "id": key_id,
        "name": "ci",
        "prefix": "sf_abcd",
        "scopes": ["sandboxes:read"],
        "sandbox_labels": None,
        "max_sandboxes": None,
        "created_at": CREATED_AT,
        "last_used_at": None,
        "expires_at": None,
        "revoked_at": None,
        "created_by": None,
    }
    return {**base, **extra}


def invoke(args, *, as_json=False):
    return RUNNER.invoke(create_app(), (["--json"] if as_json else []) + args)


@pytest.fixture(autouse=True)
def profile_env(monkeypatch, tmp_path):
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, PROFILE_KEY)


@pytest.fixture
def api():
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        yield router


def route_create(api, **extra):
    body = key_json(key=SECRET, scopes=CREATED_SCOPES, **extra)
    return api.post(KEYS_URL).respond(201, json=envelope(body))


def route_revoke(api, key_id):
    return api.delete(f"{KEYS_URL}/{key_id}").respond(
        200, json=envelope(key_json(key_id, revoked_at=REVOKED_AT))
    )


def route_missing(api, key_id):
    return api.delete(f"{KEYS_URL}/{key_id}").respond(
        404, json=error_envelope("NOT_FOUND", "no such api key")
    )


def test_create_prints_the_secret_once_and_the_warning_on_stderr(api):
    route = route_create(api)

    result = invoke(["key", "create", "ci", "--scope", "sandboxes:read", "-s", "sandboxes:write"])

    assert result.exit_code == 0
    assert result.stdout == f"{SECRET}\n"
    assert result.stderr.count("shown only once") == 1
    assert len(result.stderr.strip().splitlines()) == 1
    assert json.loads(route.calls.last.request.content)["scopes"] == CREATED_SCOPES


def test_create_sends_labels_cap_and_expiry(api):
    route = route_create(api, sandbox_labels={"team": "a"}, max_sandboxes=3)

    result = invoke(
        [
            "key", "create", "ci", "-s", "sandboxes:read", "--label", "team=a",
            "--max-sandboxes", "3", "--expires-at", "2027-01-01T00:00:00Z",
        ]
    )  # fmt: skip

    body = json.loads(route.calls.last.request.content)
    assert result.exit_code == 0
    assert body["sandbox_labels"] == {"team": "a"}
    assert body["max_sandboxes"] == 3
    assert body["expires_at"].startswith("2027-01-01T00:00:00")


def test_create_json_returns_the_object_with_the_secret(api):
    route_create(api)

    result = invoke(["key", "create", "ci", "-s", "sandboxes:read"], as_json=True)

    payload = json.loads(result.stdout)
    assert result.exit_code == 0
    assert payload["key"] == SECRET
    assert payload["id"] == KEY_A
    assert payload["scopes"] == CREATED_SCOPES


def test_create_rejects_a_naive_expiry_and_a_cap_without_labels(api):
    route = route_create(api)

    naive = invoke(["key", "create", "ci", "-s", "x", "--expires-at", "2027-01-01T00:00:00"])
    capped = invoke(["key", "create", "ci", "-s", "x", "--max-sandboxes", "2"])

    assert naive.exit_code == 2 and "timezone" in naive.stderr
    assert capped.exit_code == 2 and "--label" in capped.stderr

    naive_json = invoke(
        ["key", "create", "ci", "-s", "x", "--expires-at", "2027-01-01T00:00:00"], as_json=True
    )
    error = json.loads(naive_json.stdout)["error"]
    assert naive_json.exit_code == 2 and naive_json.stderr == ""
    assert error["code"] == "USAGE_ERROR" and error["source"] == "client"
    assert "timezone" in error["message"]
    assert route.call_count == 0


def test_create_api_error_is_a_json_error_with_code_and_request_id(api):
    api.post(KEYS_URL).respond(403, json=error_envelope("FORBIDDEN", "scope not held"))

    result = invoke(["key", "create", "ci", "-s", "api_keys:admin"], as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == 1
    assert error["code"] == "FORBIDDEN"
    assert error["request_id"] == "req_keys_1"


def test_list_table_hides_secrets_and_shows_the_columns(api):
    keys = [
        key_json(KEY_A, sandbox_labels={"team": "a"}, max_sandboxes=2),
        key_json(KEY_B, name="old", revoked_at=REVOKED_AT),
    ]
    api.get(KEYS_URL).respond(200, json=envelope(keys))

    result = invoke(["key", "list", "--all"])

    assert result.exit_code == 0
    for text in (KEY_A, KEY_B, "ci", "sandboxes:read", "team=a", "revoked", "MAX SANDBOXES"):
        assert text in result.stdout
    assert "STATUS" in result.stdout and "REVOKED AT" not in result.stdout
    assert SECRET not in result.stdout and PROFILE_KEY not in result.stdout


def test_list_hides_revoked_keys_by_default(api):
    keys = [key_json(KEY_A), key_json(KEY_B, name="old", revoked_at=REVOKED_AT)]
    api.get(KEYS_URL).respond(200, json=envelope(keys))

    result = invoke(["key", "list"])

    assert result.exit_code == 0
    assert KEY_A in result.stdout and KEY_B not in result.stdout


def test_list_json_lists_the_objects_without_a_secret(api):
    api.get(KEYS_URL).respond(200, json=envelope([key_json(KEY_A), key_json(KEY_B)]))

    result = invoke(["key", "list"], as_json=True)

    payload = json.loads(result.stdout)
    assert [item["id"] for item in payload] == [KEY_A, KEY_B]
    assert all("key" not in item for item in payload)


def test_label_with_rich_markup_and_control_characters_renders_literally(api):
    labels = {"[bold]x[/bold]": "[red]y[/]\x1b[2J"}
    key = key_json(KEY_A, name="[b]n[/b]\x07", sandbox_labels=labels)
    api.get(KEYS_URL).respond(200, json=envelope([key]))

    result = invoke(["key", "list"])

    assert result.exit_code == 0
    assert "[bold]x[/bold]=[red]y[/]" in result.stdout
    assert "[b]n[/b]" in result.stdout
    assert "\x1b" not in result.stdout and "\x07" not in result.stdout


def test_revoke_several_ids_confirms_each_key(api):
    route_revoke(api, KEY_A)
    route_revoke(api, KEY_B)

    result = invoke(["key", "revoke", KEY_A, KEY_B])

    assert result.exit_code == 0
    assert result.stdout.splitlines() == [f"revoked {KEY_A} (ci)", f"revoked {KEY_B} (ci)"]


def test_revoke_json_lists_every_processed_key(api):
    route_revoke(api, KEY_A)
    route_revoke(api, KEY_B)

    result = invoke(["key", "revoke", KEY_A, KEY_B], as_json=True)

    payload = json.loads(result.stdout)
    assert [item["id"] for item in payload] == [KEY_A, KEY_B]
    assert all(item["revoked_at"] == REVOKED_AT for item in payload)


def test_revoke_missing_id_exits_1(api):
    route_revoke(api, KEY_A)
    route_missing(api, KEY_B)

    result = invoke(["key", "revoke", KEY_A, KEY_B])

    assert result.exit_code == 1
    assert result.stdout.splitlines() == [f"revoked {KEY_A} (ci)"]
    assert "NOT_FOUND" in result.stderr


def test_revoke_missing_id_with_if_exists_skips_and_exits_0(api):
    route_missing(api, KEY_A)
    route_revoke(api, KEY_B)

    result = invoke(["key", "revoke", "--if-exists", KEY_A, KEY_B])

    assert result.exit_code == 0
    assert result.stdout.splitlines() == [f"revoked {KEY_B} (ci)"]
    assert f"{KEY_A}: not found, skipped" in result.stderr


def test_revoke_if_exists_still_fails_on_other_errors(api):
    api.delete(f"{KEYS_URL}/{KEY_A}").respond(403, json=error_envelope("FORBIDDEN", "no"))

    result = invoke(["key", "revoke", "--if-exists", KEY_A])

    assert result.exit_code == 1
    assert "FORBIDDEN" in result.stderr
