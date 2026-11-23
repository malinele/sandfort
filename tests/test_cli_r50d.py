"""CLI round 50, batch 4: parser-message style and usage-line placeholders.

The exec ``--timeout``, the preview port and ``key create --max-sandboxes`` are parsed by the
CLI, so a bad value gets the unified ``Invalid value for X: ...`` wording (exit 2, one json
object under ``--json``); positional arguments render in angle brackets on the usage line; a
sandbox name that matches nothing carries the not-found code (client source) under ``--json``.
"""

import json
import re
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli import cmd_cmd, exec_cmd, keys, sandboxes  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import NotFound  # noqa: E402
from sandfort_sdk.models import ExecResult, PreviewInfo  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
MISSING_NAME = "ghost"
SECRET = "sf_created_secret"
EXPIRES = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
RUNNER = CliRunner()
BOTH_MODES = pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
USAGE_EXIT = 2
PLATFORM_ERROR = 125
NAME_NOT_FOUND_MESSAGE = (
    f"no sandbox named '{MISSING_NAME}'; pass an id (sbx_...) or the name of an existing sandbox"
)


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def flat(text: str) -> str:
    """Text without the box-drawing frame, whitespace collapsed."""
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


class FakeSandbox:
    id = SID
    state = "started"

    def __init__(self) -> None:
        self.execs: list[dict[str, Any]] = []
        self.previews: list[tuple[int, int | None]] = []

    def process_exec(self, **kwargs: Any) -> ExecResult:
        self.execs.append(kwargs)
        return ExecResult(
            exit_code=0, stdout="ok\n", stderr="", timed_out=False, truncated=False, duration_ms=1
        )

    def preview(self, port: int, *, ttl_seconds: int | None = None) -> PreviewInfo:
        self.previews.append((port, ttl_seconds))
        url = f"http://{port}-x.preview.test"
        return PreviewInfo(url=url, token="t", port=port, expires_at=EXPIRES)


class FakeCreated:
    key = SECRET


class FakeClient:
    """A client whose name lookups find nothing and whose id lookup returns one sandbox."""

    def __init__(self) -> None:
        self.sandbox = FakeSandbox()
        self.opened = 0
        self.key_calls: list[dict[str, Any]] = []

    def get(self, ref: str) -> FakeSandbox:
        if ref != SID:
            raise NotFound(f"no sandbox named '{ref}'")
        return self.sandbox

    def stop(self, sandbox_id: str) -> FakeSandbox:  # looked up before the ref resolves
        raise AssertionError(f"stop must not be reached for {sandbox_id}")

    def create_api_key(self, name: str, scopes: list[str], **kwargs: Any) -> FakeCreated:
        self.key_calls.append({"name": name, "scopes": scopes, **kwargs})
        return FakeCreated()


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> FakeClient:
    fake = FakeClient()

    @contextmanager
    def opened() -> Iterator[FakeClient]:
        fake.opened += 1
        yield fake

    for module in (sandboxes, exec_cmd, cmd_cmd, keys):
        monkeypatch.setattr(module, "open_client", opened)
    return fake


def assert_unified_usage_error(result: Any, option: str, raw: str, *, as_json: bool) -> str:
    """Check the unified wording in either mode; return the message as shown."""
    assert result.exit_code == USAGE_EXIT, result.output
    if as_json:
        error = json.loads(result.stdout)["error"]
        assert error["code"] == "USAGE_ERROR"
        assert error["source"] == "client"
        shown = str(error["message"])
    else:
        shown = flat(result.stderr)
    assert f"Invalid value for {option}: must be a whole number" in shown
    assert f"got '{raw}'" in shown
    assert f"'{option}'" not in shown  # no quoted option name
    assert "range" not in shown and "x>=" not in shown and "<=x" not in shown
    return shown


# --- 1. parser-native errors in the unified wording ------------------------------------------


@BOTH_MODES
@pytest.mark.parametrize("raw", ["abc", "0"], ids=["non-numeric", "zero"])
def test_exec_timeout_bad_value_is_the_unified_usage_error(
    client: FakeClient, raw: str, as_json: bool
) -> None:
    result = invoke(["exec", "-t", raw, SID, "--", "true"], as_json=as_json)

    shown = assert_unified_usage_error(result, "--timeout", raw, as_json=as_json)
    assert "from 1 to 3600" in shown
    assert client.opened == 0


def test_exec_timeout_valid_value_still_runs(client: FakeClient) -> None:
    result = invoke(["exec", "--timeout", "5", SID, "--", "true"])

    assert result.exit_code == 0, result.output
    assert result.stdout == "ok\n"
    assert client.sandbox.execs[0]["timeout_s"] == 5


def test_exec_without_timeout_sends_none(client: FakeClient) -> None:
    result = invoke(["exec", SID, "--", "true"])

    assert result.exit_code == 0, result.output
    assert "timeout_s" not in client.sandbox.execs[0]


@BOTH_MODES
@pytest.mark.parametrize("raw", ["0", "65536", "http"], ids=["zero", "above", "non-numeric"])
def test_preview_port_bad_value_is_the_unified_usage_error(
    client: FakeClient, raw: str, as_json: bool
) -> None:
    result = invoke(["preview", SID, raw], as_json=as_json)

    shown = assert_unified_usage_error(result, "<port>", raw, as_json=as_json)
    assert "from 1024 to 65535" in shown
    assert client.sandbox.previews == []


@pytest.mark.parametrize("raw", ["1024", "65535"])
def test_preview_valid_port_still_works(client: FakeClient, raw: str) -> None:
    result = invoke(["preview", SID, raw])

    assert result.exit_code == 0, result.output
    assert client.sandbox.previews == [(int(raw), None)]


@BOTH_MODES
@pytest.mark.parametrize("raw", ["many", "0"], ids=["non-numeric", "zero"])
def test_max_sandboxes_bad_value_is_the_unified_usage_error(
    client: FakeClient, raw: str, as_json: bool
) -> None:
    args = ["key", "create", "ci", "-s", "sandboxes:read", "-l", "team=a", "--max-sandboxes", raw]

    result = invoke(args, as_json=as_json)

    shown = assert_unified_usage_error(result, "--max-sandboxes", raw, as_json=as_json)
    assert "greater than 0" in shown
    assert client.key_calls == []


def test_max_sandboxes_valid_value_still_creates_the_key(client: FakeClient) -> None:
    args = ["key", "create", "ci", "-s", "sandboxes:read", "-l", "team=a", "--max-sandboxes", "3"]

    result = invoke(args)

    assert result.exit_code == 0, result.output
    assert result.stdout == f"{SECRET}\n"
    assert client.key_calls[0]["max_sandboxes"] == 3
    assert client.key_calls[0]["sandbox_labels"] == {"team": "a"}


# --- 2. usage lines read with angle brackets -------------------------------------------------


def usage_block(output: str) -> str:
    """The usage line(s) of a help page: from ``Usage:`` up to the first blank line."""
    lines = output.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip().startswith("Usage:"))
    block = []
    for line in lines[start:]:
        if not line.strip():
            break
        block.append(line.strip())
    return " ".join(block)


@pytest.mark.parametrize(
    ("command", "placeholders"),
    [
        (["sandbox", "get"], ["<sandbox>"]),
        (["sandbox", "create"], ["<name>"]),
        (["sandbox", "rm"], ["<sandbox>..."]),
        (["key", "create"], ["<name>"]),
        (["key", "revoke"], ["<key-id>..."]),
        (["exec"], ["<sandbox>", "<argv>..."]),
        (["preview"], ["<sandbox>", "<port>"]),
        (["cmd", "start"], ["<sandbox>", "<argv>..."]),
        (["cmd", "logs"], ["<sandbox>", "<session-id>", "<command-id>"]),
    ],
    ids=[
        "sandbox-get",
        "sandbox-create",
        "sandbox-rm",
        "key-create",
        "key-revoke",
        "exec",
        "preview",
        "cmd-start",
        "cmd-logs",
    ],
)
def test_usage_lines_use_angle_bracket_placeholders(
    command: list[str], placeholders: list[str]
) -> None:
    result = invoke([*command, "--help"])

    usage = usage_block(result.stdout)
    assert result.exit_code == 0, result.output
    assert "{" not in usage and "}" not in usage
    for placeholder in placeholders:
        assert placeholder in usage


def test_option_metavars_are_unchanged() -> None:
    exec_help = flat(invoke(["exec", "--help"]).stdout)
    key_help = flat(invoke(["key", "create", "--help"]).stdout)

    assert "INTEGER" in exec_help
    assert "INTEGER" in key_help


def test_a_missing_argument_names_the_angle_placeholder() -> None:
    result = invoke(["sandbox", "get"])

    assert result.exit_code == USAGE_EXIT
    assert "<sandbox>" in flat(result.stderr)


# --- 3. the name-lookup failure carries the not-found code ------------------------------------


@pytest.mark.parametrize(
    ("args", "exit_code"),
    [
        (["sandbox", "get", MISSING_NAME], 1),
        (["sandbox", "stop", MISSING_NAME], 1),
        (["exec", MISSING_NAME, "--", "true"], PLATFORM_ERROR),
        (["preview", MISSING_NAME, "3000"], PLATFORM_ERROR),
        (["cmd", "kill", MISSING_NAME, "ses_1", "cmd_1"], PLATFORM_ERROR),
    ],
    ids=["get", "stop", "exec", "preview", "cmd-kill"],
)
def test_name_lookup_failure_has_the_not_found_code_in_json(
    client: FakeClient, args: list[str], exit_code: int
) -> None:
    result = invoke(args, as_json=True)

    assert result.stdout, (result.exit_code, result.output, repr(result.exception))
    error = json.loads(result.stdout)["error"]
    assert result.exit_code == exit_code
    assert error["code"] == "NOT_FOUND"
    assert "source" not in error
    assert error["message"] == NAME_NOT_FOUND_MESSAGE
    assert result.stderr == ""


@pytest.mark.parametrize(
    ("args", "exit_code"),
    [
        (["sandbox", "get", MISSING_NAME], 1),
        (["exec", MISSING_NAME, "--", "true"], PLATFORM_ERROR),
    ],
    ids=["get", "exec"],
)
def test_name_lookup_failure_keeps_its_text_line_and_exit_code(
    client: FakeClient, args: list[str], exit_code: int
) -> None:
    result = invoke(args)

    assert result.exit_code == exit_code
    assert result.stdout == ""
    assert result.stderr == f"error: NOT_FOUND: {NAME_NOT_FOUND_MESSAGE}\n"
