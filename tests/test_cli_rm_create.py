"""CLI ``sandbox rm`` (several refs, --if-exists, id-only output) and the create wait options."""

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import Client, Sandbox, SandboxInfo  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
OTHER_SID = "sbx_01HYYYYYYYYYYYYYYYYYYYYYYY"
THIRD_SID = "sbx_01HXXXXXXXXXXXXXXXXXXXXXXX"
SANDBOXES_URL = "/v1/sandboxes"
RUNNER = CliRunner()


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def error_envelope(code, message):
    error = {"code": code, "message": message, "details": {}, "request_id": "req_1"}
    return {"success": False, "data": None, "error": error, "meta": None}


def sandbox_json(state="started", *, sandbox_id=SID, name="demo"):
    return {
        "id": sandbox_id,
        "name": name,
        "state": state,
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
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


def route_delete(router, sandbox_id, state="destroying"):
    return router.delete(f"{SANDBOXES_URL}/{sandbox_id}").respond(
        200, json=envelope(sandbox_json(state, sandbox_id=sandbox_id))
    )


def route_not_found(router, sandbox_id):
    return router.delete(f"{SANDBOXES_URL}/{sandbox_id}").respond(
        404, json=error_envelope("NOT_FOUND", "no such sandbox")
    )


def route_get(router, sandbox_id, state="started"):
    return router.get(f"{SANDBOXES_URL}/{sandbox_id}").respond(
        200, json=envelope(sandbox_json(state, sandbox_id=sandbox_id))
    )


def route_get_not_found(router, sandbox_id):
    return router.get(f"{SANDBOXES_URL}/{sandbox_id}").respond(
        404, json=error_envelope("NOT_FOUND", "no such sandbox")
    )


def route_list(router, *sandboxes):
    return router.get(SANDBOXES_URL).respond(200, json=envelope(list(sandboxes)))


def deleted_ids(router):
    return [
        call.request.url.path.rsplit("/", 1)[-1]
        for call in router.calls
        if call.request.method == "DELETE"
    ]


# --- rm ------------------------------------------------------------------------------------


def test_rm_prints_the_id_only(router):
    route = route_delete(router, SID)

    result = invoke(["sandbox", "rm", SID])

    assert result.exit_code == 0, result.output
    assert route.call_count == 1
    assert result.stdout == f"{SID}\n"
    assert result.stderr == ""


def test_rm_by_name_resolves_then_deletes(router):
    route_list(router, sandbox_json(name="demo"))
    route = route_delete(router, SID)

    result = invoke(["sandbox", "rm", "demo"])

    assert result.exit_code == 0, result.output
    assert route.call_count == 1
    assert result.stdout == f"{SID}\n"


def test_rm_several_refs_delete_in_order(router):
    route_list(router, sandbox_json(sandbox_id=OTHER_SID, name="second"))
    route_delete(router, SID)
    route_delete(router, OTHER_SID)
    route_delete(router, THIRD_SID)

    result = invoke(["sandbox", "rm", SID, "second", THIRD_SID])

    assert result.exit_code == 0, result.output
    assert result.stdout == f"{SID}\n{OTHER_SID}\n{THIRD_SID}\n"
    assert deleted_ids(router) == [SID, OTHER_SID, THIRD_SID]


def test_rm_json_with_one_ref_keeps_the_object(router):
    route_delete(router, SID)

    result = invoke(["sandbox", "rm", SID], as_json=True)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert (payload["id"], payload["state"]) == (SID, "destroying")


def test_rm_json_with_several_refs_prints_a_list(router):
    route_delete(router, SID)
    route_delete(router, OTHER_SID)

    result = invoke(["sandbox", "rm", SID, OTHER_SID], as_json=True)

    assert result.exit_code == 0, result.output
    assert [item["id"] for item in json.loads(result.stdout)] == [SID, OTHER_SID]


def test_rm_if_exists_skips_an_unknown_name(router):
    route_list(router)

    result = invoke(["sandbox", "rm", "--if-exists", "ghost"])

    assert result.exit_code == 0, result.output
    assert result.stdout == ""
    assert "ghost: not found, skipped" in result.stderr


def test_rm_if_exists_skips_an_id_answering_not_found(router):
    route_get_not_found(router, SID)
    delete_gone = route_not_found(router, SID)
    route_get(router, OTHER_SID)
    route_delete(router, OTHER_SID)

    result = invoke(["sandbox", "rm", "--if-exists", SID, OTHER_SID])

    assert result.exit_code == 0, result.output
    assert result.stdout == f"{OTHER_SID}\n"
    assert f"{SID}: not found, skipped" in result.stderr
    assert delete_gone.call_count == 0


def test_rm_if_exists_skips_an_id_whose_get_answers_destroyed(router):
    route_get(router, SID, state="destroyed")
    delete_route = route_delete(router, SID, state="destroyed")

    result = invoke(["sandbox", "rm", "--if-exists", SID])

    assert result.exit_code == 0, result.output
    assert result.stdout == ""
    assert f"{SID}: not found, skipped" in result.stderr
    assert delete_route.call_count == 0


def test_rm_if_exists_prints_the_id_when_the_delete_answers_destroyed_inline(router):
    route_get(router, SID)
    delete_route = route_delete(router, SID, state="destroyed")

    result = invoke(["sandbox", "rm", "--if-exists", SID])

    assert result.exit_code == 0, result.output
    assert delete_route.call_count == 1
    assert result.stdout == f"{SID}\n"
    assert "skipped" not in result.stderr


def test_rm_if_exists_by_name_deletes_a_live_sandbox_answering_destroyed(router):
    route_list(router, sandbox_json(name="demo"))
    delete_route = route_delete(router, SID, state="destroyed")

    result = invoke(["sandbox", "rm", "--if-exists", "demo"])

    assert result.exit_code == 0, result.output
    assert delete_route.call_count == 1
    assert result.stdout == f"{SID}\n"
    assert "skipped" not in result.stderr


def test_rm_json_with_one_skipped_ref_prints_the_skipped_object(router):
    route_list(router)

    result = invoke(["sandbox", "rm", "--if-exists", "ghost"], as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {"ref": "ghost", "skipped": "not_found"}


def test_rm_json_with_several_refs_mixes_deleted_and_skipped(router):
    route_get(router, SID)
    route_delete(router, SID)
    route_get_not_found(router, OTHER_SID)

    result = invoke(["sandbox", "rm", "--if-exists", SID, OTHER_SID], as_json=True)

    assert result.exit_code == 0, result.output
    items = json.loads(result.stdout)
    assert items[0]["id"] == SID
    assert items[1] == {"ref": OTHER_SID, "skipped": "not_found"}


def test_rm_json_reports_processed_refs_before_a_later_failure(router):
    route_delete(router, SID)
    route_not_found(router, OTHER_SID)

    result = invoke(["sandbox", "rm", SID, OTHER_SID], as_json=True)

    assert result.exit_code == 1
    document = json.loads(result.stdout)  # ONE document: the error with the processed refs
    assert [item["id"] for item in document["processed"]] == [SID]
    assert document["error"]["code"] == "NOT_FOUND"


def test_rm_without_the_flag_fails_on_an_unknown_name_after_earlier_refs(router):
    route_list(router)
    first = route_delete(router, SID)

    result = invoke(["sandbox", "rm", SID, "ghost"])

    assert result.exit_code == 1
    assert first.call_count == 1
    assert result.stdout == f"{SID}\n"
    assert "error: NOT_FOUND: no sandbox named 'ghost'; pass an id (sbx_...)" in result.stderr


def test_rm_without_the_flag_fails_on_an_id_answering_not_found(router):
    route_not_found(router, SID)

    result = invoke(["sandbox", "rm", SID])

    assert result.exit_code == 1
    assert "NOT_FOUND: no such sandbox" in result.stderr


def test_rm_if_exists_still_fails_on_an_ambiguous_name(router):
    route_list(
        router,
        sandbox_json(sandbox_id=SID, name="dup"),
        sandbox_json(sandbox_id=OTHER_SID, name="dup"),
    )

    result = invoke(["sandbox", "rm", "--if-exists", "dup"])

    assert result.exit_code == 1
    assert "several sandboxes are named 'dup'" in result.stderr
    assert "skipped" not in result.stderr


def test_rm_if_exists_still_fails_on_other_api_errors(router):
    route_get(router, SID)
    router.delete(f"{SANDBOXES_URL}/{SID}").respond(
        500, json=error_envelope("INTERNAL_ERROR", "boom")
    )

    result = invoke(["sandbox", "rm", "--if-exists", SID])

    assert result.exit_code == 1
    assert "boom" in result.stderr


# --- create --wait-timeout / --keep-on-failure ---------------------------------------------


def route_create(router, state="started"):
    return router.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json(state)))


def test_wait_timeout_without_wait_is_a_usage_error(router):
    route = route_create(router)

    result = invoke(["sandbox", "create", "demo", "--wait-timeout", "5"])

    assert result.exit_code == 2
    assert "--wait-timeout" in result.output and "requires --wait" in result.output
    assert route.call_count == 0


def test_wait_timeout_must_be_positive(router):
    route = route_create(router)

    result = invoke(["sandbox", "create", "demo", "--wait", "--wait-timeout", "0"])

    assert result.exit_code == 2
    assert "greater than 0" in result.output
    assert route.call_count == 0


def test_wait_timeout_reaches_the_sdk_and_stops_the_polling(router):
    route_create(router, state="pending")
    get_route = router.get(f"{SANDBOXES_URL}/{SID}").respond(
        200, json=envelope(sandbox_json("pending"))
    )

    started = time.monotonic()
    result = invoke(["sandbox", "create", "demo", "--wait", "--wait-timeout", "0.3"])

    assert result.exit_code == 1
    assert time.monotonic() - started < 10
    assert get_route.call_count >= 1
    assert result.stderr.startswith("error: ")
    assert len(result.stderr.strip().splitlines()) == 1
    assert SID in result.stderr


def create_kwargs(monkeypatch, extra):
    """Run ``sandbox create`` with the SDK call patched; the keyword arguments it received."""
    seen = {}

    def fake_create(self, **kwargs):
        seen.update(kwargs)
        return Sandbox(SandboxInfo.from_payload(sandbox_json()), self._transport)

    monkeypatch.setattr(Client, "create_sandbox", fake_create)
    result = invoke(["sandbox", "create", "demo", *extra])
    assert result.exit_code == 0, result.output
    return seen


def test_wait_timeout_is_passed_as_wait_timeout_s(monkeypatch):
    seen = create_kwargs(monkeypatch, ["--wait", "--wait-timeout", "2.5"])

    assert seen["wait_timeout_s"] == 2.5


def test_keep_on_failure_passes_delete_on_failure_false(monkeypatch):
    seen = create_kwargs(monkeypatch, ["--wait", "--keep-on-failure"])

    assert seen["delete_on_failure"] is False


def test_default_create_passes_delete_on_failure_true(monkeypatch):
    seen = create_kwargs(monkeypatch, ["--wait"])

    assert seen["delete_on_failure"] is True
    assert "wait_timeout_s" not in seen


def test_keep_on_failure_leaves_an_errored_sandbox_undeleted(router):
    route_create(router, state="error")
    delete_route = route_delete(router, SID)

    result = invoke(["sandbox", "create", "demo", "--wait", "--keep-on-failure"])

    assert result.exit_code == 1
    assert delete_route.call_count == 0


def test_default_create_deletes_an_errored_sandbox(router):
    route_create(router, state="error")
    delete_route = route_delete(router, SID)

    result = invoke(["sandbox", "create", "demo", "--wait"])

    assert result.exit_code == 1
    assert delete_route.call_count == 1
