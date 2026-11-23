"""CLI r35: snapshot in the detail view, error_code in the failure line, exec timeout text."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config, exec_cmd, output  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import SandboxFailedError, SandboxInfo  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
PROFILE_KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOXES_URL = "/v1/sandboxes"
SANDBOX_URL = f"{SANDBOXES_URL}/{SID}"
EXEC_URL = f"{SANDBOX_URL}/toolbox/process/execute"
ERROR_CODE = "image_not_found"
ERROR_REASON = "image alpine:nope was not found"
SNAPSHOT = "snap_alpine"
SPACED_NAME = "my box"
SERVER_STDERR = "killed after 5s; pass a larger timeout_s (up to 3600) to allow more time"
RUNNER = CliRunner()


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def sandbox_json(**extra):
    base = {
        "id": SID,
        "name": "demo",
        "state": "started",
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
    }
    return {**base, **extra}


def failed_json(**extra):
    failure = {"state": "error", "error_reason": ERROR_REASON, "error_code": ERROR_CODE}
    return sandbox_json(**{**failure, **extra})


def timed_out_json(stderr):
    return {
        "exit_code": 0,
        "stdout": "",
        "stderr": stderr,
        "timed_out": True,
        "truncated": False,
        "duration_ms": 5000,
    }


def invoke(args, *, as_json=False):
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


def test_detail_view_shows_the_snapshot(router):
    router.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json(snapshot=SNAPSHOT)))

    result = invoke(["sandbox", "get", SID])

    assert result.exit_code == 0, result.output
    assert "snapshot" in result.stdout and SNAPSHOT in result.stdout


def test_detail_view_shows_a_dash_without_a_snapshot():
    info = SandboxInfo.from_payload(sandbox_json())

    assert output.sandbox_fields(info)["snapshot"] == "-"


def test_failed_create_line_shows_the_code_after_the_state(router):
    router.post(SANDBOXES_URL).respond(202, json=envelope(sandbox_json(state="creating")))
    router.get(SANDBOX_URL).respond(200, json=envelope(failed_json()))
    router.delete(SANDBOX_URL).respond(200, json=envelope(failed_json(state="destroying")))

    result = invoke(["sandbox", "create", "demo", "--wait"])

    assert result.exit_code != 0
    assert f"is error [{ERROR_CODE}]: {ERROR_REASON}" in result.stderr


def test_failure_text_without_a_code_is_unchanged():
    failure = SandboxFailedError(
        f"sandbox {SID} is error: {ERROR_REASON}", sandbox_id=SID, state="error"
    )

    assert output.describe_error(failure) == f"sandbox {SID} is error: {ERROR_REASON}"


def test_failed_create_json_message_is_unchanged():
    failure = SandboxFailedError(
        f"sandbox {SID} is error: {ERROR_REASON}",
        sandbox_id=SID,
        state="error",
        error_code=ERROR_CODE,
    )

    error = output.error_payload(failure)["error"]

    assert error["message"] == f"sandbox {SID} is error: {ERROR_REASON}"
    assert error["error_code"] == ERROR_CODE


def test_failure_text_output_shows_the_code_exactly_once():
    failure = SandboxFailedError(
        f"sandbox {SID} is error: {ERROR_REASON}",
        sandbox_id=SID,
        state="error",
        error_code=ERROR_CODE,
    )

    text = output.describe_error(failure)

    assert text == f"sandbox {SID} is error [{ERROR_CODE}]: {ERROR_REASON}"
    assert text.count(f"[{ERROR_CODE}]") == 1


def test_failure_text_shows_the_code_once_when_the_message_already_embeds_it():
    failure = SandboxFailedError(
        f"sandbox {SID} is error: {ERROR_REASON}",
        sandbox_id=SID,
        state="error",
        error_code=ERROR_CODE,
    )
    failure.args = (f"{failure} (request id req_1)",)

    text = output.describe_error(failure)

    assert text.count(f"[{ERROR_CODE}]") == 1
    assert output.error_payload(failure)["error"]["message"].count(ERROR_CODE) == 0


def test_exec_timeout_message_names_the_flag_and_its_position(router):
    router.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json()))
    router.post(EXEC_URL).respond(200, json=envelope(timed_out_json("")))

    result = invoke(["exec", SID, "sleep", "99"])

    assert result.exit_code == 124
    assert "-t/--timeout" in result.stderr
    assert "timeout_s" not in result.stderr
    assert "before the sandbox reference" in result.stderr
    assert f"sandfort exec -t 120 {SID} -- <command>" in result.stderr
    assert result.stderr.endswith("\n")


def test_exec_timeout_example_without_t_is_above_the_default():
    message = exec_cmd.timeout_message(SID, None)

    assert f"sandfort exec -t 120 {SID} -- <command>" in message
    assert 120 > exec_cmd.DEFAULT_TIMEOUT_S


@pytest.mark.parametrize(
    ("passed", "suggested"), [(5, 10), (300, 600), (1800, 3600), (2000, 3600), (3599, 3600)]
)
def test_exec_timeout_example_doubles_the_passed_t_capped_at_the_maximum(passed, suggested):
    message = exec_cmd.timeout_message(SID, passed)

    assert f"sandfort exec -t {suggested} {SID} -- <command>" in message


def test_exec_timeout_example_uses_the_t_that_was_passed(router):
    router.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json()))
    router.post(EXEC_URL).respond(200, json=envelope(timed_out_json("")))

    result = invoke(["exec", "-t", "300", SID, "sleep", "999"])

    assert result.exit_code == 124
    assert f"sandfort exec -t 600 {SID} -- <command>" in result.stderr
    assert "-t 60 " not in result.stderr


def test_exec_timeout_message_quotes_a_reference_with_a_space(router):
    router.get(SANDBOXES_URL).respond(200, json=envelope([sandbox_json(name=SPACED_NAME)]))
    router.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json(name=SPACED_NAME)))
    router.post(EXEC_URL).respond(200, json=envelope(timed_out_json("")))

    result = invoke(["exec", SPACED_NAME, "sleep", "99"])

    assert result.exit_code == 124, result.output
    assert f"sandfort exec -t 120 '{SPACED_NAME}' -- <command>" in result.stderr


def test_exec_timeout_message_quotes_shell_metacharacters():
    message = exec_cmd.timeout_message("a;rm -rf x", None)

    assert "'a;rm -rf x'" in message


def test_exec_timeout_at_the_maximum_suggests_a_session_not_an_example(router):
    router.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json()))
    router.post(EXEC_URL).respond(200, json=envelope(timed_out_json("")))

    result = invoke(["exec", "-t", str(exec_cmd.MAX_TIMEOUT_S), SID, "sleep", "9999"])

    assert result.exit_code == 124
    assert "did not finish within the maximum of 3600 s" in result.stderr
    assert "session" in result.stderr
    assert f"sandfort cmd start {SID} -- <command>" in result.stderr
    assert "sandfort exec -t" not in result.stderr
    assert result.stderr.endswith("\n")


def test_exec_timeout_at_the_maximum_quotes_the_reference():
    message = exec_cmd.timeout_message(SPACED_NAME, exec_cmd.MAX_TIMEOUT_S)

    assert f"sandfort cmd start '{SPACED_NAME}' -- <command>" in message


def test_exec_timeout_message_starts_on_its_own_line(router):
    router.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json()))
    router.post(EXEC_URL).respond(200, json=envelope(timed_out_json(SERVER_STDERR)))

    result = invoke(["exec", SID, "sleep", "99"])

    lines = result.stderr.splitlines()
    assert lines[0] == SERVER_STDERR
    assert lines[1].startswith("error: command timed out")
    assert result.stderr.endswith("\n")
