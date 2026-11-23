"""CLI round 37: request ids everywhere a failure is shown.

An error-state create without ``--wait`` carries the create reply's request id (json field and
text line); a text line names the request id once (the SDK's ``str()`` tail, not the CLI's own);
a json error for which no request of the step reached the server (a connect failure, bad local
input) is marked ``"source": "client"``; one raised on or after a server reply (an ambiguous
name, a failed build, an extract that failed in the sandbox) is not. A CliError is a client
error only when raised with ``client=True``. Every group's ``--help`` explains the marker. A
transport error's text line ends with its request id; ``mention_request_id`` is gone.
"""

import contextlib
import io
import json
import os
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
import typer  # noqa: E402
from sandfort_cli import (  # noqa: E402
    cmd_cmd,
    config,
    cp_cmd,
    output,
    sandboxes,
    shell_cmd,
    snapshot,
)
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import (  # noqa: E402
    AmbiguousSandboxName,
    InvalidResponseError,
    NotFound,
    RequestTimedOut,
    SandboxFailedError,
    TransportError,
)
from sandfort_sdk.models import ExecResult  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOXES_URL = "/v1/sandboxes"
CREATE_REQUEST_ID = "req_create_0037"
POLL_REQUEST_ID = "req_poll_0037"
ERROR_REQUEST_ID = "req_err_0037"
RUNNER = CliRunner()


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def error_envelope(code, message, details=None, request_id=ERROR_REQUEST_ID):
    error = {"code": code, "message": message, "details": details or {}, "request_id": request_id}
    return {"success": False, "data": None, "error": error, "meta": None}


def sandbox_json(state="started", **extra):
    data = {
        "id": SID,
        "name": "demo",
        "state": state,
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
    }
    return {**data, **extra}


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


def create_in_error(router, request_id=CREATE_REQUEST_ID):
    headers = {"x-request-id": request_id} if request_id else {}
    sandbox = sandbox_json("error", error_code="image_not_found", error_reason="no such image")
    router.post(SANDBOXES_URL).respond(201, json=envelope(sandbox), headers=headers)


def fail_the_wait(router):
    router.post(SANDBOXES_URL).respond(
        201, json=envelope(sandbox_json("creating")), headers={"x-request-id": CREATE_REQUEST_ID}
    )
    router.get(f"{SANDBOXES_URL}/{SID}").respond(
        200,
        json=envelope(sandbox_json("error", error_reason="image pull failed")),
        headers={"x-request-id": POLL_REQUEST_ID},
    )
    router.delete(f"{SANDBOXES_URL}/{SID}").respond(200, json=envelope(sandbox_json("destroying")))


def first_line(result):
    return result.stderr.strip().splitlines()[0]


# --- an error-state create without --wait carries the create reply's request id ---------------


def test_immediate_error_json_carries_the_create_reply_request_id(router):
    create_in_error(router)

    result = invoke(["sandbox", "create", "demo"], as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == 1
    assert error["code"] == "SANDBOX_FAILED"
    assert error["request_id"] == CREATE_REQUEST_ID
    assert CREATE_REQUEST_ID not in error["message"]
    assert "source" not in error
    assert error["hint"].startswith("the sandbox was kept")


def test_immediate_error_text_line_names_the_create_request_id_once(router):
    create_in_error(router)

    result = invoke(["sandbox", "create", "demo"])

    line = first_line(result)
    assert result.exit_code == 1
    assert line == (
        f"error: sandbox {SID} is error [image_not_found]: no such image "
        f"(request id {CREATE_REQUEST_ID})"
    )
    assert result.stderr.count(CREATE_REQUEST_ID) == 1


def test_immediate_error_without_a_request_id_header_keeps_null_and_no_tail(router):
    create_in_error(router, request_id=None)

    as_json = invoke(["sandbox", "create", "demo"], as_json=True)
    as_text = invoke(["sandbox", "create", "demo"])

    assert json.loads(as_json.stdout)["error"]["request_id"] is None
    assert "request id" not in as_text.stderr


# --- the --wait failure line names the request id once -------------------------------------


def test_wait_failure_text_line_has_no_duplicated_request_id(router):
    fail_the_wait(router)

    result = invoke(["sandbox", "create", "demo", "--wait"])

    lines = result.stderr.strip().splitlines()
    assert result.exit_code == 1
    assert len(lines) == 1
    assert lines[0].endswith(f"(request id {POLL_REQUEST_ID})")
    assert lines[0].count("request id") == 1
    assert CREATE_REQUEST_ID not in lines[0]


def test_wait_failure_json_message_has_no_tail_and_the_field_is_set(router):
    fail_the_wait(router)

    error = json.loads(invoke(["sandbox", "create", "demo", "--wait"], as_json=True).stdout)

    assert error["error"]["request_id"] == POLL_REQUEST_ID
    assert "request id" not in error["error"]["message"]


# --- an ApiError text line names the request id once ---------------------------------------


def test_api_error_text_line_ends_with_the_request_id(router):
    router.get(f"{SANDBOXES_URL}/{SID}").respond(
        404, json=error_envelope("NOT_FOUND", "no such sandbox")
    )

    result = invoke(["sandbox", "get", SID])

    assert result.exit_code == 1
    assert result.stderr == f"error: NOT_FOUND: no such sandbox (request id {ERROR_REQUEST_ID})\n"


def test_api_error_text_line_puts_the_request_id_after_the_details(router):
    details = {"field": "name"}
    router.post(SANDBOXES_URL).respond(
        422, json=error_envelope("VALIDATION_ERROR", "bad name", details)
    )

    result = invoke(["sandbox", "create", "demo"])

    assert first_line(result) == (
        f"error: VALIDATION_ERROR: bad name (field=name) (request id {ERROR_REQUEST_ID})"
    )
    assert result.stderr.count(ERROR_REQUEST_ID) == 1


def test_api_error_text_line_without_a_request_id_has_no_tail(router):
    router.get(f"{SANDBOXES_URL}/{SID}").respond(
        404, json=error_envelope("NOT_FOUND", "no such sandbox", request_id=None)
    )

    result = invoke(["sandbox", "get", SID])

    assert result.stderr == "error: NOT_FOUND: no such sandbox\n"


def test_api_error_json_keeps_the_request_id_and_has_no_source(router):
    router.get(f"{SANDBOXES_URL}/{SID}").respond(
        404, json=error_envelope("NOT_FOUND", "no such sandbox")
    )

    error = json.loads(invoke(["sandbox", "get", SID], as_json=True).stdout)["error"]

    assert error["request_id"] == ERROR_REQUEST_ID
    assert error["message"] == "no such sandbox"
    assert "source" not in error


def test_describe_error_names_an_id_already_in_the_message_once():
    failure = SandboxFailedError(
        f"sandbox {SID} is error: oom (request id req_x)",
        sandbox_id=SID,
        state="error",
        request_id="req_x",
        error_code="oom_killed",
    )

    text = output.describe_error(failure)

    assert text == f"sandbox {SID} is error [oom_killed]: oom (request id req_x)"
    assert text.count("req_x") == 1


def test_describe_error_of_an_api_error_with_the_id_in_its_message_names_it_once():
    error = NotFound("gone (request id req_y)", request_id="req_y")

    assert output.describe_error(error).count("req_y") == 1


# --- "source": "client" means no request reached the server --------------------------------


def connect_failure():
    """A ``TransportError`` as the SDK raises it for a refused connection."""
    try:
        raise TransportError("GET /v1/x failed: ConnectError: refused") from httpx.ConnectError(
            "refused"
        )
    except TransportError as exc:
        return exc


def test_get_on_a_missing_name_found_after_the_list_call_is_not_found_with_no_source(router):
    router.get(SANDBOXES_URL).respond(200, json=envelope([]))

    result = invoke(["sandbox", "get", "missing"], as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == 1
    assert error["code"] == "NOT_FOUND"
    assert "source" not in error
    assert error["request_id"] is None


def test_rm_on_a_missing_name_found_after_the_list_call_is_not_found_with_no_source(router):
    router.get(SANDBOXES_URL).respond(200, json=envelope([]))

    result = invoke(["sandbox", "rm", "missing"], as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == 1
    assert error["code"] == "NOT_FOUND"
    assert "source" not in error
    assert error["request_id"] is None


def test_a_connect_failure_is_a_client_error_in_json():
    error = output.error_payload(connect_failure())["error"]

    assert error["source"] == "client"
    assert error["request_id"] is None


def test_a_refused_connection_from_the_cli_is_a_client_error(router):
    router.get(f"{SANDBOXES_URL}/{SID}").mock(side_effect=httpx.ConnectError("refused"))

    result = invoke(["sandbox", "get", SID], as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == 1
    assert error["source"] == "client"


def test_an_ambiguous_name_found_after_the_list_call_has_no_source(router):
    twins = [sandbox_json(id=f"{SID[:-1]}{n}", name="twin") for n in (1, 2)]
    list_route = router.get(SANDBOXES_URL).respond(200, json=envelope(twins))

    result = invoke(["sandbox", "get", "twin"], as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == 1
    assert list_route.called
    assert error["message"].startswith("several sandboxes are named 'twin'")
    assert "source" not in error


def test_the_sdk_ambiguous_name_error_has_no_source():
    exc = AmbiguousSandboxName("twin", (("sbx_1", "started"), ("sbx_2", "started")))

    assert "source" not in output.error_payload(exc)["error"]


def test_a_transport_error_that_is_not_a_connect_failure_has_no_source():
    try:
        raise TransportError("GET /v1/x failed: ReadError") from httpx.ReadError("reset")
    except TransportError as exc:
        error = output.error_payload(exc)["error"]

    assert "source" not in error


def test_a_cli_error_raised_on_a_server_reply_has_no_source():
    try:
        try:
            raise NotFound("no sandbox named 'x'", request_id="req_l")
        except NotFound:
            raise output.CliError("no sandbox named 'x'") from None
    except output.CliError as exc:
        error = output.error_payload(exc)["error"]

    assert "source" not in error


def test_a_bad_option_value_is_a_client_error_in_json(router):
    result = invoke(["sandbox", "create", "demo", "--env", "NOEQUALS"], as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == 2
    assert error["code"] == "USAGE_ERROR"
    assert error["source"] == "client"
    assert error["request_id"] is None


def test_client_error_text_line_is_unchanged(router):
    router.get(SANDBOXES_URL).respond(200, json=envelope([]))

    result = invoke(["sandbox", "get", "missing"])

    assert first_line(result).startswith("error: NOT_FOUND: no sandbox named 'missing'")
    assert "request id" not in result.stderr
    assert "source" not in result.stderr


def test_a_timeout_before_the_request_left_is_a_client_error():
    error = output.error_payload(RequestTimedOut("GET /x failed", request_sent=False))["error"]

    assert error["source"] == "client"
    assert error["request_id"] is None


def test_a_timeout_after_the_request_may_have_left_has_no_source():
    error = output.error_payload(RequestTimedOut("GET /x failed", request_sent=True))["error"]

    assert "source" not in error


def test_a_transport_error_json_carries_its_stream_request_id():
    error = output.error_payload(TransportError("stream broke", request_id="req_s"))["error"]

    assert error["request_id"] == "req_s"
    assert "source" not in error


# --- the text line of a non-API error names its request id once ----------------------------


def test_a_transport_error_text_line_ends_with_its_request_id():
    text = output.describe_error(TransportError("stream broke", request_id="req_s"))

    assert text == "stream broke (request id req_s)"


def test_an_invalid_response_text_line_ends_with_its_request_id():
    text = output.describe_error(InvalidResponseError("bad event", request_id="req_e"))

    assert text == "bad event (request id req_e)"


def test_a_transport_error_text_line_names_an_id_already_in_the_message_once():
    exc = TransportError("stream broke (request id req_s)", request_id="req_s")

    assert output.describe_error(exc).count("req_s") == 1


def test_a_transport_error_without_a_request_id_has_no_tail():
    shown = output.describe_error(connect_failure())

    assert shown == "GET /v1/x failed: could not connect to the server: refused"


def test_cli_errors_prints_the_transport_request_id_on_stderr(capsys):
    output.set_json_errors(False)

    with pytest.raises(typer.Exit):
        with output.cli_errors():
            raise TransportError("stream broke", request_id="req_s")

    assert capsys.readouterr().err == "error: stream broke (request id req_s)\n"


# --- the dead helper is gone ----------------------------------------------------------------


def test_mention_request_id_is_gone():
    assert not hasattr(sandboxes, "mention_request_id")


# --- a CliError is "client" only when raised with client=True ------------------------------

SNAP_ID = "snap_01HZZZZZZZZZZZZZZZZZZZZZZZ"
BUILDS_URL = "/v1/images/builds"
SSE_HEADERS = {"content-type": "text/event-stream"}
PLATFORM_ERROR = 125
USAGE_ERROR_EXIT = 2


def use_client(monkeypatch, module, client):
    """Make ``module.open_client()`` hand out ``client`` (a fake SDK client)."""
    monkeypatch.setattr(module, "open_client", lambda: contextlib.nullcontext(client))


def last_error(stdout):
    """The ``error`` object of the last json document on stdout (a result may precede it)."""
    decoder, text, index, document = json.JSONDecoder(), stdout.strip(), 0, None
    while index < len(text):
        document, index = decoder.raw_decode(text, index)
        while index < len(text) and text[index].isspace():
            index += 1
    return document["error"]


def spec_path(tmp_path):
    path = tmp_path / "spec.json"
    path.write_text(json.dumps({"schema_version": "1", "base_image": "python:3.12-slim"}))
    return path


def test_a_cli_error_is_not_a_client_error_by_default():
    assert "source" not in output.error_payload(output.CliError("x"))["error"]


def test_a_cli_error_raised_with_client_true_is_a_client_error():
    assert output.error_payload(output.CliError("x", client=True))["error"]["source"] == "client"


def test_a_client_cli_error_chained_from_a_server_reply_has_no_source():
    try:
        try:
            raise NotFound("gone", request_id="req_n")
        except NotFound:
            raise output.CliError("gone", client=True) from None
    except output.CliError as exc:
        error = output.error_payload(exc)["error"]

    assert "source" not in error


def test_a_build_log_that_ends_without_a_final_state_has_no_source(monkeypatch, tmp_path):
    pending = SimpleNamespace(id=SNAP_ID, state="pending")
    snapshots = SimpleNamespace(
        build=lambda spec, name=None: pending,
        follow_build_logs=lambda snapshot_id: contextlib.nullcontext(iter(())),
    )
    use_client(monkeypatch, snapshot, SimpleNamespace(snapshots=snapshots))

    result = invoke(["snapshot", "build", str(spec_path(tmp_path))], as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == 1
    assert error["message"] == f"build log of {SNAP_ID} ended without a final state"
    assert "source" not in error


def test_a_build_the_server_reports_failed_has_no_source(router, tmp_path):
    pending = {
        "id": SNAP_ID,
        "name": "py",
        "state": "pending",
        "image_ref": None,
        "digest": None,
        "layer_count": 0,
        "source_sandbox_id": None,
        "created_at": "2026-11-08T10:00:00Z",
        "spec_hash": "h1",
        "reused": False,
    }
    final = {"state": "error", "snapshot_id": SNAP_ID, "digest": None, "reason": "pip failed"}
    router.post(BUILDS_URL).respond(202, json=envelope(pending))
    router.get(f"{BUILDS_URL}/{SNAP_ID}/logs").respond(
        200, content=f"event: state\ndata: {json.dumps(final)}\n\n".encode(), headers=SSE_HEADERS
    )

    result = invoke(["snapshot", "build", str(spec_path(tmp_path))], as_json=True)

    error = last_error(result.stdout)
    assert result.exit_code == 1
    assert error["message"] == f"build {SNAP_ID} ended error: pip failed"
    assert "source" not in error


def test_a_command_the_platform_did_not_report_has_no_source(monkeypatch):
    process = SimpleNamespace(
        create_session=lambda: SimpleNamespace(id="ses_1"),
        execute_session_command=lambda *args, **kwargs: SimpleNamespace(command=None),
    )
    sandbox = SimpleNamespace(id=SID, process=process)
    use_client(monkeypatch, cmd_cmd, SimpleNamespace(get=lambda ref: sandbox))

    result = invoke(["cmd", "start", SID, "--", "sleep", "1"], as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == PLATFORM_ERROR
    assert error["message"].startswith("the platform did not report a command")
    assert "source" not in error


def exec_result(exit_code, *, timed_out=False, stderr=""):
    return ExecResult(
        exit_code=exit_code,
        stdout="",
        stderr=stderr,
        timed_out=timed_out,
        truncated=False,
        duration_ms=1,
    )


def fake_sandbox(*, result=None, download=b""):
    """A sandbox: uploads succeed, exec answers ``result``, a dir download yields ``download``."""
    fs = SimpleNamespace(
        upload_file=lambda path, data, **kwargs: SimpleNamespace(size_bytes=0),
        delete=lambda path, **kwargs: None,
        download_dir=lambda path, **kwargs: contextlib.nullcontext(iter([download])),
    )
    return SimpleNamespace(id=SID, fs=fs, process_exec=lambda **kwargs: result)


@pytest.mark.parametrize(
    ("result", "message"),
    [
        (exec_result(124, timed_out=True), "extracting the archive in the sandbox timed out"),
        (exec_result(2, stderr="tar: boom"), "extracting the archive failed (exit 2): tar: boom"),
        # the missing tar is learned from the sandbox's exit status 127, i.e. after the exec ran
        (exec_result(127), cp_cmd.cp_dir.NO_TAR_MESSAGE),
    ],
)
def test_an_extract_that_failed_in_the_sandbox_has_no_source(
    monkeypatch, tmp_path, result, message
):
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "a").write_text("alpha")
    sandbox = fake_sandbox(result=result)
    use_client(monkeypatch, cp_cmd, SimpleNamespace(get=lambda ref: sandbox))

    outcome = invoke(["cp", "-r", str(tree), f"{SID}:/w"], as_json=True)

    error = json.loads(outcome.stdout)["error"]
    assert outcome.exit_code == PLATFORM_ERROR
    assert error["message"] == message
    assert "source" not in error


def test_an_unsafe_path_in_a_downloaded_archive_has_no_source(monkeypatch, tmp_path):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        member = tarfile.TarInfo("../evil")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    sandbox = fake_sandbox(download=buffer.getvalue())
    use_client(monkeypatch, cp_cmd, SimpleNamespace(get=lambda ref: sandbox))

    result = invoke(["cp", "-r", f"{SID}:/w/dir", str(tmp_path / "out")], as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == PLATFORM_ERROR
    assert error["message"] == "unsafe path in archive: '../evil'"
    assert "source" not in error


@pytest.mark.parametrize(
    ("source", "destination"), [("a.txt", "b.txt"), (f"{SID}:/a", f"{SID}:/b")]
)
def test_a_bad_cp_reference_is_a_client_error(router, source, destination):
    result = invoke(["cp", source, destination], as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == USAGE_ERROR_EXIT
    assert error["code"] == "USAGE_ERROR"
    assert error["message"].startswith("exactly one of source and destination")
    assert error["source"] == "client"
    assert router.calls.call_count == 0


@pytest.mark.parametrize("recursive", [False, True])
def test_a_missing_local_file_is_a_client_error_sent_before_any_request(
    router, tmp_path, recursive
):
    missing = tmp_path / "missing.txt"

    args = ["cp", *(["-r"] if recursive else []), str(missing), f"{SID}:/w/x"]
    result = invoke(args, as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == USAGE_ERROR_EXIT
    assert error["message"] == f"no such file: {missing}"
    assert error["source"] == "client"
    assert router.calls.call_count == 0


@pytest.mark.parametrize("recursive", [False, True])
def test_an_empty_remote_path_is_a_client_error_sent_before_any_request(
    router, tmp_path, recursive
):
    local = tmp_path / "tree"
    local.mkdir()
    (local / "a").write_text("alpha")
    source = local if recursive else local / "a"

    args = ["cp", *(["-r"] if recursive else []), str(source), f"{SID}:"]
    result = invoke(args, as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == USAGE_ERROR_EXIT
    assert error["code"] == "USAGE_ERROR"
    assert "must not be empty" in error["message"]
    assert error["source"] == "client"
    assert router.calls.call_count == 0


class RecordingClient:
    """A fake SDK client that records every call; any call counts as a request."""

    def __init__(self):
        self.calls = []

    def get(self, ref):
        self.calls.append(("get", ref))
        raise AssertionError("no request may be sent")

    def list(self, *args, **kwargs):
        self.calls.append(("list", args))
        raise AssertionError("no request may be sent")


@pytest.mark.parametrize("recursive", [False, True])
def test_an_empty_remote_path_is_rejected_before_the_mocked_client_is_used(
    monkeypatch, tmp_path, recursive
):
    local = tmp_path / "tree"
    local.mkdir()
    (local / "a").write_text("alpha")
    client = RecordingClient()
    use_client(monkeypatch, cp_cmd, client)

    source = local if recursive else local / "a"
    args = ["cp", *(["-r"] if recursive else []), str(source), f"{SID}:"]
    result = invoke(args, as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == USAGE_ERROR_EXIT
    assert error["code"] == "USAGE_ERROR"
    assert "must not be empty" in error["message"]
    assert error["source"] == "client"
    assert client.calls == []


def test_the_post_lookup_dir_upload_guard_raises_without_the_client_marker(tmp_path):
    local = tmp_path / "tree"
    local.mkdir()

    with pytest.raises(output.CliError) as caught:
        cp_cmd.cp_dir.upload_dir(fake_sandbox(), local, "")

    assert str(caught.value) == "remote path must not be empty"
    assert "source" not in output.error_payload(caught.value)["error"]


def test_the_post_lookup_file_upload_guard_raises_without_the_client_marker(tmp_path):
    local = tmp_path / "a"
    local.write_text("alpha")

    with pytest.raises(output.CliError) as caught:
        cp_cmd.upload(fake_sandbox(), local, "")

    assert str(caught.value) == "remote path must not be empty"
    assert "source" not in output.error_payload(caught.value)["error"]


def test_the_post_lookup_upload_guard_on_a_missing_file_has_no_client_marker(tmp_path):
    missing = tmp_path / "missing.txt"

    with pytest.raises(output.CliError) as caught:
        cp_cmd.upload(fake_sandbox(), missing, "/w/x")

    assert str(caught.value) == f"no such file: {missing}"
    assert "source" not in output.error_payload(caught.value)["error"]


def test_the_pre_request_upload_check_keeps_the_client_marker(tmp_path):
    with pytest.raises(output.CliError) as caught:
        cp_cmd.check_upload(tmp_path / "missing.txt", "/w/x")

    assert output.error_payload(caught.value)["error"]["source"] == "client"


def test_a_missing_spec_file_is_a_client_error(router, tmp_path):
    result = invoke(["snapshot", "build", str(tmp_path / "nope.json")], as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == 1
    assert error["message"].startswith("cannot read spec file")
    assert error["source"] == "client"
    assert router.calls.call_count == 0


def test_a_bad_mount_is_a_client_error(router):
    result = invoke(["sandbox", "create", "demo", "--mount", "nocolon"], as_json=True)

    error = json.loads(result.stdout)["error"]
    assert error["source"] == "client"
    assert router.calls.call_count == 0


@pytest.mark.parametrize("value", ["not-a-date", "2027-01-01T00:00:00"])
def test_a_bad_expires_at_is_a_client_error(router, value):
    result = invoke(
        ["key", "create", "ci", "--scope", "sandboxes:read", "--expires-at", value], as_json=True
    )

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == 2
    assert error["code"] == "USAGE_ERROR"
    assert error["source"] == "client"
    assert router.calls.call_count == 0


def test_a_key_create_cap_without_a_label_is_a_local_usage_error(router):
    args = ["key", "create", "ci", "--scope", "sandboxes:read", "--max-sandboxes", "2"]
    result = invoke(args, as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == 2
    assert error["code"] == "USAGE_ERROR"
    assert "--label" in error["message"]
    assert error["source"] == "client"
    assert router.calls.call_count == 0


# --- settings, stdin and terminal checks run before the first request ------------------------


def assert_client_error(result, message_start, exit_code=1):
    error = json.loads(result.stdout)["error"]
    assert result.exit_code == exit_code, result.output
    assert error["message"].startswith(message_start)
    assert error["source"] == "client"


def test_a_bad_base_url_in_the_environment_is_a_client_error(router, monkeypatch):
    monkeypatch.setenv(config.BASE_URL_ENV, "ftp://sandfort.test")

    result = invoke(["sandbox", "list"], as_json=True)

    assert_client_error(
        result,
        f"Invalid value for {config.BASE_URL_ENV}: base url ftp://sandfort.test is not a valid url",
        exit_code=2,
    )
    assert router.calls.call_count == 0


def test_a_bad_base_url_at_login_is_a_client_error(router):
    result = invoke(["login", "--base-url", "ftp://x", "--api-key", KEY], as_json=True)

    assert_client_error(
        result, "Invalid value for --base-url: base url ftp://x is not a valid url", exit_code=2
    )
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "USAGE_ERROR"
    assert "must start with http:// or https://" in error["message"]
    assert router.calls.call_count == 0


def test_an_empty_key_at_login_is_a_client_error(router):
    result = invoke(["login", "--base-url", BASE, "--api-key", "   "], as_json=True)

    assert_client_error(result, "Invalid value for --api-key: must not be empty", exit_code=2)
    assert json.loads(result.stdout)["error"]["code"] == "USAGE_ERROR"
    assert router.calls.call_count == 0


def test_not_being_logged_in_is_a_client_error(router, monkeypatch, tmp_path):
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "empty"))

    result = invoke(["sandbox", "list"], as_json=True)

    assert_client_error(result, "not logged in")
    assert router.calls.call_count == 0


@pytest.mark.parametrize(
    ("content", "message"), [("{not json", "is unreadable"), ("[1, 2]", "is malformed")]
)
def test_an_unusable_profile_is_a_client_error(router, content, message):
    path = config.profile_path()
    path.write_text(content)

    result = invoke(["sandbox", "list"], as_json=True)

    assert_client_error(result, f"profile {path} {message}")
    assert router.calls.call_count == 0


def test_stdin_that_is_not_utf8_is_a_client_error_sent_before_any_request(router):
    args = ["--json", "exec", "-i", SID, "cat"]
    result = RUNNER.invoke(create_app(None), args, input=b"\xff\xfe")

    assert_client_error(result, "stdin is not valid UTF-8 text", exit_code=PLATFORM_ERROR)
    assert router.calls.call_count == 0


@pytest.fixture
def pipe_fd():
    read_fd, write_fd = os.pipe()
    yield read_fd
    os.close(read_fd)
    os.close(write_fd)


@pytest.mark.parametrize("stdin", ["replaced", "pipe"])
def test_a_shell_without_a_terminal_is_a_client_error_sent_before_any_request(
    router, monkeypatch, pipe_fd, stdin
):
    if stdin == "pipe":
        monkeypatch.setattr(shell_cmd, "stdin_fileno", lambda: pipe_fd)

    result = invoke(["shell", SID], as_json=True)

    assert_client_error(result, shell_cmd.NO_TERMINAL, exit_code=PLATFORM_ERROR)
    assert router.calls.call_count == 0


def test_the_late_terminal_check_after_the_requests_is_not_a_client_error(monkeypatch, pipe_fd):
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(fileno=lambda: pipe_fd))

    with pytest.raises(output.CliError) as caught:
        shell_cmd.PosixTerminal().enter_raw()

    assert str(caught.value) == shell_cmd.NO_TERMINAL
    assert "source" not in output.error_payload(caught.value)["error"]


# --- every group's --help explains "source" ------------------------------------------------


def flat(text):
    return " ".join(text.split())


def test_the_epilog_is_one_shared_constant():
    assert output.CLIENT_SOURCE in sandboxes.JSON_ERROR_EPILOG
    assert "ambiguous" not in sandboxes.JSON_ERROR_EPILOG


@pytest.mark.parametrize(
    "group",
    [
        [],
        ["sandbox"],
        ["snapshot"],
        ["key"],
        ["members"],
        ["volume"],
        ["cmd"],
        ["cp"],
        ["exec"],
        ["shell"],
        ["preview"],
        ["login"],
    ],
)
def test_help_shows_the_json_error_epilog(group):
    result = RUNNER.invoke(create_app(None), [*group, "--help"], terminal_width=200)

    assert result.exit_code == 0, result.output
    assert flat(sandboxes.JSON_ERROR_EPILOG) in flat(result.stdout)
