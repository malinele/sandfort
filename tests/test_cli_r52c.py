"""CLI round 52, batch c: the empty-argument sweep.

A blank argument (empty or whitespace-only) is the shared usage error of round 51: exit 2,
``Invalid value for <placeholder>: must not be empty``, one ``USAGE_ERROR`` object with
``"source": "client"`` under ``--json``, and no request sent. This covers the tracebacks
(``snapshot register``, ``members add``), the empty ids that used to reach the server
(``snapshot export``, ``key revoke``, ``cmd logs``/``kill``, the sandbox reference of the
sandbox commands and of ``cmd start``/``preview``) and ``key create``.
"""

import json
import re
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
USAGE = 2
RUNNER = CliRunner()
BOTH_MODES = pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
BLANKS = pytest.mark.parametrize("blank", ["", "   "], ids=["empty", "whitespace"])
TRACEBACK_MARKERS = ("Traceback", 'File "', "ValueError", "httpx.", "not a Sandfort envelope")
NOT_FOUND = {
    "success": False,
    "data": None,
    "error": {"code": "NOT_FOUND", "message": "gone", "details": {}, "request_id": "req_1"},
    "meta": None,
}


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def flat(text: str) -> str:
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, KEY)


@pytest.fixture
def router() -> Iterator[Any]:
    """Every request is answered with a NOT_FOUND envelope and counted."""
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        mock.route().mock(return_value=httpx.Response(404, json=NOT_FOUND))
        yield mock


def assert_usage_error(result: Any, router: Any, placeholder: str, as_json: bool) -> None:
    assert result.exit_code == USAGE, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert router.calls.call_count == 0
    for stream in (result.stdout, result.stderr):
        assert not any(marker in stream for marker in TRACEBACK_MARKERS), stream
    expected = f"Invalid value for {placeholder}: must not be empty"
    if as_json:
        payload = json.loads(result.stdout)  # exactly one document
        assert list(payload) == ["error"]
        assert result.stderr.strip() == ""
        error = payload["error"]
        assert error["code"] == "USAGE_ERROR" and error["source"] == "client"
        assert expected in flat(str(error["message"]))
    else:
        assert result.stdout.strip() == ""
        assert expected in flat(result.stderr)


# blank value -> (args, placeholder) -----------------------------------------------------------

BLANK_CASES: dict[str, tuple[Callable[[str], list[str]], str]] = {
    "snapshot-register-image": (lambda b: ["snapshot", "register", b], "<image>"),
    "snapshot-register-name": (
        lambda b: ["snapshot", "register", "python:3.12", "--name", b],
        "--name",
    ),
    "members-add-display-name": (
        lambda b: ["members", "add", "a@example.test", b, "--role", "viewer"],
        "<display-name>",
    ),
    "snapshot-export": (lambda b: ["snapshot", "export", b, "-o", "out.tar"], "<snapshot-id>"),
    "key-revoke": (lambda b: ["key", "revoke", b], "<key-id>"),
    "key-revoke-second": (lambda b: ["key", "revoke", "key_1", b], "<key-id>"),
    "key-create": (lambda b: ["key", "create", b, "--scope", "sandboxes:read"], "<name>"),
    "cmd-logs-session": (lambda b: ["cmd", "logs", "sbx_1", b, "cmd_1"], "<session-id>"),
    "cmd-logs-command": (lambda b: ["cmd", "logs", "sbx_1", "ses_1", b], "<command-id>"),
    "cmd-logs-sandbox": (lambda b: ["cmd", "logs", b, "ses_1", "cmd_1"], "<sandbox>"),
    "cmd-kill-session": (lambda b: ["cmd", "kill", "sbx_1", b, "cmd_1"], "<session-id>"),
    "cmd-kill-command": (lambda b: ["cmd", "kill", "sbx_1", "ses_1", b], "<command-id>"),
    "cmd-kill-sandbox": (lambda b: ["cmd", "kill", b, "ses_1", "cmd_1"], "<sandbox>"),
    "cmd-start-sandbox": (lambda b: ["cmd", "start", b, "--", "ls"], "<sandbox>"),
    "preview": (lambda b: ["preview", b, "8080"], "<sandbox>"),
    "sandbox-create": (lambda b: ["sandbox", "create", b], "<name>"),
    "sandbox-get": (lambda b: ["sandbox", "get", b], "<sandbox>"),
    "sandbox-stop": (lambda b: ["sandbox", "stop", b], "<sandbox>"),
    "sandbox-start": (lambda b: ["sandbox", "start", b], "<sandbox>"),
    "sandbox-reset": (lambda b: ["sandbox", "reset", b], "<sandbox>"),
    "sandbox-rm": (lambda b: ["sandbox", "rm", b], "<sandbox>"),
    "sandbox-rm-second": (lambda b: ["sandbox", "rm", "sbx_1", b], "<sandbox>"),
}


@BOTH_MODES
@BLANKS
@pytest.mark.parametrize("case", list(BLANK_CASES))
def test_a_blank_argument_is_a_local_usage_error(
    router: Any, as_json: bool, blank: str, case: str
) -> None:
    build, placeholder = BLANK_CASES[case]

    result = invoke(build(blank), as_json=as_json)

    assert_usage_error(result, router, placeholder, as_json)


# control cases: one valid argument per command -----------------------------------------------

CONTROL_CASES: dict[str, list[str]] = {
    "snapshot-register": ["snapshot", "register", "python:3.12", "--name", "base"],
    "members-add": ["members", "add", "a@example.test", "Ada", "--role", "viewer"],
    "snapshot-export": ["snapshot", "export", "snap_1", "-o", "out.tar"],
    "key-revoke": ["key", "revoke", "key_1"],
    "key-create": ["key", "create", "ci", "--scope", "sandboxes:read"],
    "cmd-logs": ["cmd", "logs", "sbx_1", "ses_1", "cmd_1"],
    "cmd-kill": ["cmd", "kill", "sbx_1", "ses_1", "cmd_1"],
    "cmd-start": ["cmd", "start", "sbx_1", "--", "ls"],
    "preview": ["preview", "sbx_1", "8080"],
    "sandbox-create": ["sandbox", "create", "demo"],
    "sandbox-get": ["sandbox", "get", "sbx_1"],
    "sandbox-stop": ["sandbox", "stop", "sbx_1"],
    "sandbox-start": ["sandbox", "start", "sbx_1"],
    "sandbox-reset": ["sandbox", "reset", "sbx_1"],
    "sandbox-rm": ["sandbox", "rm", "sbx_1"],
}


@pytest.mark.parametrize("args", list(CONTROL_CASES.values()), ids=list(CONTROL_CASES))
def test_a_valid_argument_still_reaches_the_server(
    router: Any, args: list[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)

    result = invoke(args)

    assert result.exit_code != USAGE, result.output
    assert router.calls.call_count >= 1
    assert "must not be empty" not in result.output
