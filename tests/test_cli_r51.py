"""CLI round 51, batch 1: the traceback tail.

Ordinary client-side input no longer ends in a traceback (which also broke the one-object
promise of ``--json``):

* an exec timeout above the server cap of 3600 s is the unified usage error, and the socket
  timeout conversion is guarded anyway;
* a copy download into a missing or unwritable local directory is a clean client error;
* an empty volume or snapshot name is a usage error;
* a configured api key that cannot go into a header is a malformed-key usage error that never
  echoes the key;
* a server ``details`` that is a string or a list is kept as sanitised text;
* a deeply nested body on any command is handled as a non-envelope answer.
"""

import json
import os
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config, cp_cmd, exec_cmd  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.output import describe_error, details_text  # noqa: E402
from sandfort_sdk import Conflict, InternalError  # noqa: E402
from sandfort_sdk import _requests as sdk_requests  # noqa: E402
from sandfort_sdk import _transport as sdk_transport  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SANDBOX_URL = "/v1/sandboxes/sbx_1"
SANDBOXES_URL = "/v1/sandboxes"
VOLUMES_URL = "/v1/volumes"
PLATFORM_ERROR = 125
USAGE = 2
RUNNER = CliRunner()
BOTH_MODES = pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
TRACEBACK_MARKERS = (
    "Traceback",
    'File "',
    "RecursionError",
    "OverflowError",
    "AttributeError",
    "UnicodeEncodeError",
    "FileNotFoundError",
    "PermissionError",
    "ValueError",
    "httpx.",
)
DEEP_DEPTH = 100_000
DEEP_BODY = b"[" * DEEP_DEPTH + b"]" * DEEP_DEPTH
JSON_HEADERS = {"content-type": "application/json"}


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def flat(text: str) -> str:
    """Text without the box-drawing frame, whitespace collapsed."""
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


def assert_clean(result: Any) -> None:
    """No uncaught exception and no traceback text on either stream."""
    assert result.exception is None or isinstance(result.exception, SystemExit), repr(
        result.exception
    )
    for stream in (result.stdout, result.stderr):
        assert not any(marker in stream for marker in TRACEBACK_MARKERS), stream


def json_error(result: Any) -> dict[str, Any]:
    """The one ``{"error": {...}}`` object on stdout, with nothing on stderr."""
    payload = json.loads(result.stdout)
    assert list(payload) == ["error"]
    assert result.stderr.strip() == ""
    error: dict[str, Any] = payload["error"]
    return error


def report(result: Any, as_json: bool) -> str:
    """The error as one line: the json message, or the text report on stderr."""
    if as_json:
        return str(json_error(result)["message"])
    assert result.stdout.strip() == ""
    return flat(result.stderr)


def envelope(code: str, message: str, details: Any) -> dict[str, Any]:
    error = {"code": code, "message": message, "details": details, "request_id": "req_1"}
    return {"success": False, "data": None, "error": error, "meta": None}


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    return config.save_profile(BASE, KEY)


@pytest.fixture
def router() -> Iterator[Any]:
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


class FakeClient:
    """Stands in for ``Client`` as a context manager whose ``get`` returns ``sandbox``."""

    def __init__(self, sandbox: Any) -> None:
        self._sandbox = sandbox

    def __enter__(self) -> "FakeClient":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def get(self, ref: str) -> Any:
        return self._sandbox


class FakeStream:
    def __enter__(self) -> Iterator[bytes]:
        return iter([b"data"])

    def __exit__(self, *exc: object) -> None:
        return None


def fake_exec_client(monkeypatch: pytest.MonkeyPatch, process_exec: Any) -> None:
    sandbox = SimpleNamespace(process_exec=process_exec)
    monkeypatch.setattr(exec_cmd, "open_client", lambda: FakeClient(sandbox))


# 1) exec timeout ------------------------------------------------------------------------------

OVER_CAP_TIMEOUTS = {"over-cap": "3601", "trillion": str(10**12), "enormous": "9" * 40}


@BOTH_MODES
@pytest.mark.parametrize("value", list(OVER_CAP_TIMEOUTS.values()), ids=list(OVER_CAP_TIMEOUTS))
def test_an_exec_timeout_over_the_cap_is_a_usage_error(
    router: Any, as_json: bool, value: str
) -> None:
    result = invoke(["exec", "-t", value, "sbx_1", "--", "ls"], as_json=as_json)

    assert_clean(result)
    assert result.exit_code == USAGE
    assert router.calls.call_count == 0
    assert "must be a whole number from 1 to 3600" in report(result, as_json)
    if as_json:
        error = json_error(result)
        assert error["code"] == "USAGE_ERROR" and error["source"] == "client"


def test_the_cap_itself_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def process_exec(**kwargs: Any) -> Any:
        seen.update(kwargs)
        return SimpleNamespace(
            stdout="",
            stderr="",
            exit_code=0,
            timed_out=False,
            sandbox_stopped=False,
            replayed=False,
            stop_reason=None,  # r65: exec reads ok, stop_reason and truncated
            truncated=False,
            ok=True,
        )

    fake_exec_client(monkeypatch, process_exec)

    result = invoke(["exec", "-t", "3600", "sbx_1", "--", "ls"])

    assert_clean(result)
    assert result.exit_code == 0
    assert seen["timeout_s"] == exec_cmd.MAX_TIMEOUT_S


@BOTH_MODES
def test_a_socket_timeout_overflow_is_a_clean_platform_error(
    monkeypatch: pytest.MonkeyPatch, as_json: bool
) -> None:
    def process_exec(**kwargs: Any) -> Any:
        raise OverflowError("timestamp too large to convert to C _PyTime_t")

    fake_exec_client(monkeypatch, process_exec)

    result = invoke(["exec", "-t", "60", "sbx_1", "--", "ls"], as_json=as_json)

    assert_clean(result)
    assert result.exit_code == PLATFORM_ERROR
    assert "timeout is too large" in report(result, as_json)


# 2) copy download destination -----------------------------------------------------------------


@BOTH_MODES
def test_a_download_into_a_missing_directory_is_a_client_error(
    router: Any, tmp_path: Path, as_json: bool
) -> None:
    target = tmp_path / "missing" / "out.txt"

    result = invoke(["cp", "sbx_1:/w/a.txt", str(target)], as_json=as_json)

    assert_clean(result)
    assert result.exit_code == USAGE
    assert router.calls.call_count == 0
    assert "does not exist" in report(result, as_json)
    assert not target.parent.exists()
    if as_json:
        assert json_error(result)["source"] == "client"


@pytest.fixture
def read_only_dir(tmp_path: Path) -> Iterator[Path]:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root can write into a read-only directory")
    directory = tmp_path / "ro"
    directory.mkdir()
    directory.chmod(0o500)
    try:
        yield directory
    finally:
        directory.chmod(0o700)


@BOTH_MODES
@pytest.mark.parametrize("into_dir", [False, True], ids=["file-path", "directory"])
def test_a_download_into_an_unwritable_directory_is_a_client_error(
    router: Any, read_only_dir: Path, as_json: bool, into_dir: bool
) -> None:
    target = read_only_dir if into_dir else read_only_dir / "out.txt"

    result = invoke(["cp", "sbx_1:/w/a.txt", str(target)], as_json=as_json)

    assert_clean(result)
    assert result.exit_code == USAGE
    assert router.calls.call_count == 0
    assert "is not writable" in report(result, as_json)
    assert list(read_only_dir.iterdir()) == []
    if as_json:
        assert json_error(result)["source"] == "client"


@BOTH_MODES
def test_a_local_write_failure_after_the_download_started_is_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, as_json: bool
) -> None:
    def refuse(self: Path, *args: Any, **kwargs: Any) -> Any:
        raise PermissionError(13, "Permission denied")

    sandbox = SimpleNamespace(
        fs=SimpleNamespace(download_file=lambda remote, chunk_size: FakeStream())
    )
    monkeypatch.setattr(cp_cmd, "open_client", lambda: FakeClient(sandbox))
    monkeypatch.setattr(Path, "open", refuse)

    result = invoke(["cp", "sbx_1:/w/a.txt", str(tmp_path / "out.txt")], as_json=as_json)

    assert_clean(result)
    assert result.exit_code == PLATFORM_ERROR
    shown = report(result, as_json)
    assert "cannot write" in shown and "Permission denied" in shown
    if as_json:
        assert "source" not in json_error(result)


# 3) empty volume and snapshot names -----------------------------------------------------------

EMPTY_NAME_COMMANDS = {
    "volume-empty": ["volume", "create", ""],
    "volume-blank": ["volume", "create", "   "],
    "snapshot-empty": ["snapshot", "create", "sbx_1", ""],
    "snapshot-blank": ["snapshot", "create", "sbx_1", " "],
}


@BOTH_MODES
@pytest.mark.parametrize("args", list(EMPTY_NAME_COMMANDS.values()), ids=list(EMPTY_NAME_COMMANDS))
def test_an_empty_name_is_a_usage_error(router: Any, as_json: bool, args: list[str]) -> None:
    result = invoke(args, as_json=as_json)

    assert_clean(result)
    assert result.exit_code == USAGE
    assert router.calls.call_count == 0
    assert "must not be empty" in report(result, as_json)
    if as_json:
        error = json_error(result)
        assert error["code"] == "USAGE_ERROR" and error["source"] == "client"


# 4) malformed configured api key --------------------------------------------------------------

SECRET_PART = "Zq7SECRETPART"
BAD_KEYS = {
    "tab": f"sf_bad\t{SECRET_PART}",
    "space": f"sf_bad {SECRET_PART}",
    "non-ascii": f"sf_badé{SECRET_PART}",
}


def configure_key(monkeypatch: pytest.MonkeyPatch, profile: Path, source: str, key: str) -> None:
    if source == "env":
        monkeypatch.setenv(config.API_KEY_ENV, key)
        return
    profile.write_text(json.dumps({"base_url": BASE, "api_key": key}), encoding="utf-8")


@BOTH_MODES
@pytest.mark.parametrize("source", ["env", "profile"])
@pytest.mark.parametrize("key", list(BAD_KEYS.values()), ids=list(BAD_KEYS))
def test_a_malformed_configured_key_is_reported_without_echoing_it(
    monkeypatch: pytest.MonkeyPatch,
    profile: Path,
    router: Any,
    as_json: bool,
    source: str,
    key: str,
) -> None:
    configure_key(monkeypatch, profile, source, key)

    result = invoke(["sandbox", "list"], as_json=as_json)

    assert_clean(result)
    assert result.exit_code == USAGE
    assert router.calls.call_count == 0
    assert SECRET_PART not in result.stdout + result.stderr
    shown = report(result, as_json)
    assert "is malformed" in shown
    assert (config.API_KEY_ENV if source == "env" else "api_key in") in shown
    if as_json:
        error = json_error(result)
        assert error["code"] == "USAGE_ERROR" and error["source"] == "client"


def test_a_key_with_outer_whitespace_only_is_still_accepted(
    monkeypatch: pytest.MonkeyPatch, router: Any
) -> None:
    route = router.get(SANDBOXES_URL).respond(
        200, json={"success": True, "data": [], "error": None, "meta": None}
    )
    monkeypatch.setenv(config.API_KEY_ENV, f"  {KEY}\n")

    result = invoke(["sandbox", "list"], as_json=True)

    assert_clean(result)
    assert result.exit_code == 0, result.output
    assert route.calls.last.request.headers["authorization"] == f"Bearer {KEY}"


# 5) non-object details ------------------------------------------------------------------------

NON_OBJECT_DETAILS: dict[str, Any] = {"string": "boom \x1b[31mred", "list": ["a", "b"]}
SHOWN_DETAILS = {"string": "details=boom", "list": 'details=["a","b"]'}
DETAIL_CODES = {
    "not-found": (404, "NOT_FOUND"),
    "conflict": (409, "CONFLICT"),
    "internal": (500, "INTERNAL_ERROR"),
}
# (command, code) pairs; a 404 on a name lookup is a name miss (round 50), so the name-reference
# cases use the other codes.
DETAIL_CASES = [
    (command, code_id)
    for command in ("exec", "cp", "name-ref")
    for code_id in DETAIL_CODES
    if not (command == "name-ref" and code_id == "not-found")
]


def details_command(
    router: Any, tmp_path: Path, command: str, status: int, code: str, details: Any
) -> list[str]:
    body = envelope(code, "refused", details)
    if command == "name-ref":
        router.get(SANDBOXES_URL).respond(status, json=body)
        return ["exec", "web", "--", "ls"]
    router.get(SANDBOX_URL).respond(status, json=body)
    if command == "cp":
        return ["cp", "sbx_1:/w/a.txt", str(tmp_path / "out.txt")]
    return ["exec", "sbx_1", "--", "ls"]


@BOTH_MODES
@pytest.mark.parametrize(
    ("command", "code_id"), DETAIL_CASES, ids=[f"{c}-{k}" for c, k in DETAIL_CASES]
)
@pytest.mark.parametrize("kind", list(NON_OBJECT_DETAILS))
def test_a_non_object_details_is_kept_as_sanitised_text(
    router: Any, tmp_path: Path, as_json: bool, command: str, code_id: str, kind: str
) -> None:
    status, code = DETAIL_CODES[code_id]
    args = details_command(router, tmp_path, command, status, code, NON_OBJECT_DETAILS[kind])

    result = invoke(args, as_json=as_json)

    assert_clean(result)
    assert result.exit_code == PLATFORM_ERROR
    assert "\x1b" not in result.stdout + result.stderr
    if as_json:
        error = json_error(result)
        assert error["code"] == code
        if kind == "list":
            assert error["details"] == ["a", "b"]
        else:
            assert isinstance(error["details"], str) and error["details"].startswith("boom")
    else:
        assert result.stderr.startswith(f"error: {code}: refused")
        assert SHOWN_DETAILS[kind] in result.stderr


def test_details_text_keeps_the_object_form_for_a_mapping() -> None:
    assert details_text({"reason": "busy"}, KEY) == "reason=busy"
    assert details_text("plain", KEY) == "details=plain"
    assert details_text(["x", 1], KEY) == 'details=["x",1]'


def test_describe_error_does_not_crash_on_a_string_details() -> None:
    exc = InternalError("boom", code="E", details="raw text")  # type: ignore[arg-type]

    assert describe_error(exc) == "E: boom (details=raw text)"


# 6) deeply nested bodies ----------------------------------------------------------------------


@BOTH_MODES
@pytest.mark.parametrize(
    "args",
    [["sandbox", "list"], ["volume", "list"], ["snapshot", "list"]],
    ids=["sandbox", "volume", "snapshot"],
)
def test_a_deeply_nested_error_body_is_a_non_envelope_error(
    router: Any, as_json: bool, args: list[str]
) -> None:
    router.get(re.compile(r".*/v1/(sandboxes|volumes|snapshots).*")).respond(
        500, content=DEEP_BODY, headers=JSON_HEADERS
    )

    result = invoke(args, as_json=as_json)

    assert_clean(result)
    assert result.exit_code == 1
    if as_json:
        error = json_error(result)
        assert error["code"] == "HTTP_500"
        assert error["message"] == "Internal Server Error"
    else:
        assert result.stderr.startswith("error: HTTP_500: Internal Server Error")


@BOTH_MODES
def test_a_deeply_nested_success_body_is_an_invalid_response(router: Any, as_json: bool) -> None:
    router.get(VOLUMES_URL).respond(200, content=DEEP_BODY, headers=JSON_HEADERS)

    result = invoke(["volume", "list"], as_json=as_json)

    assert_clean(result)
    assert result.exit_code == 1
    assert "response is not a Sandfort envelope" in report(result, as_json)


def test_the_retry_check_reads_no_fields_from_a_deeply_nested_body() -> None:
    response = httpx.Response(429, content=DEEP_BODY, headers=JSON_HEADERS)

    assert sdk_requests.error_fields(response) == ("", "")


def test_a_conflict_with_list_details_keeps_them() -> None:
    response = httpx.Response(409, json=envelope("CONFLICT", "busy", ["a"]))

    with pytest.raises(Conflict) as caught:
        sdk_transport.parse_response(response)

    assert caught.value.details == ["a"]  # type: ignore[comparison-overlap]
    assert caught.value.request_id == "req_1"


def test_installing_the_guards_twice_wraps_once() -> None:
    parse = sdk_transport.parse_response
    fields = sdk_requests.error_fields

    config.install_body_guards()

    assert sdk_transport.parse_response is parse
    assert sdk_requests.error_fields is fields
    assert getattr(parse, config.GUARD_MARK) is True
