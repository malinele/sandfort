"""``sandfort cmd start|logs|kill`` and ``sandfort preview`` against fake SDK sandboxes."""

import json
import sys
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli import cmd_cmd  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import Conflict, NotFound, TransportError  # noqa: E402
from sandfort_sdk.models import (  # noqa: E402
    CommandInfo,
    LogEvent,
    LogPage,
    PreviewInfo,
    SessionExecResult,
    SessionInfo,
)
from typer.testing import CliRunner  # noqa: E402

SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SESSION = "ses_1"
COMMAND = "cmd_1"
NOW = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)
EXPIRES = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
PLATFORM_ERROR = 125
NOT_RUNNING = "toolbox operations require a started sandbox"
START_HINT = f"start it with: sandfort sandbox start {SID}"


def session_info(session_id=SESSION):
    return SessionInfo(session_id, SID, None, {}, "active", NOW)


def command_info(state="running", exit_code=None):
    return CommandInfo(COMMAND, SESSION, state, exit_code, 0, 0, NOW)


def out(line):
    return LogEvent(stream="stdout", offset=0, line=line)


def err(line):
    return LogEvent(stream="stderr", offset=0, line=line)


def exit_event(exit_code, state="exited"):
    return LogEvent(stream="exit", offset=0, exit_code=exit_code, state=state)


class FakeStream:
    def __init__(self, events, error=None):
        self._events = events
        self._error = error
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True

    def __iter__(self):
        yield from self._events
        if self._error is not None:
            raise self._error


class FakeProcess:
    def __init__(self):
        self.calls: list[tuple] = []
        self.sessions = {SESSION: session_info()}
        self.pages: list[LogPage] = []
        self.stream = FakeStream([])
        self.error: Exception | None = None

    def create_session(self, **kwargs):
        self.calls.append(("create_session", kwargs))
        if self.error is not None:
            raise self.error
        return session_info("ses_new")

    def get_session(self, session_id):
        self.calls.append(("get_session", session_id))
        if session_id not in self.sessions:
            raise NotFound("no such session")
        return self.sessions[session_id]

    def execute_session_command(self, session_id, command, *, run_async=False, timeout_s=60):
        self.calls.append(("execute", session_id, command, run_async, timeout_s))
        return SessionExecResult(mode="async", command=command_info())

    def get_command_logs(self, session_id, command_id, *, offset=0, limit=None):
        self.calls.append(("logs", session_id, command_id, offset))
        if self.error is not None:
            raise self.error
        return self.pages.pop(0)

    def follow_logs(self, session_id, command_id, *, offset=0):
        self.calls.append(("follow", session_id, command_id, offset))
        if self.error is not None:
            raise self.error
        return self.stream

    def kill_command(self, session_id, command_id):
        self.calls.append(("kill", session_id, command_id))
        if self.error is not None:
            raise self.error
        return command_info("killed", 137)


class FakeSandbox:
    id = SID

    def __init__(self):
        self.process = FakeProcess()
        self.previews: list[tuple] = []
        self.state = "started"
        self.preview_error: Exception | None = None

    def preview(self, port, *, ttl_seconds=None):
        self.previews.append((port, ttl_seconds))
        if self.preview_error is not None:
            raise self.preview_error
        return PreviewInfo(
            url=f"http://{port}-{SID}.preview.test?sandfort_preview_token=pvt_x",
            token="pvt_x",
            port=port,
            expires_at=EXPIRES,
        )


class FakeClient:
    def __init__(self, sandbox):
        self._sandbox = sandbox

    def get(self, sandbox_id):
        assert sandbox_id == SID
        return self._sandbox


@pytest.fixture
def sandbox(monkeypatch):
    fake = FakeSandbox()

    @contextmanager
    def opened():
        yield FakeClient(fake)

    monkeypatch.setattr(cmd_cmd, "open_client", opened)
    return fake


def run(*args, json_output=False):
    prefix = ["--json"] if json_output else []
    return CliRunner().invoke(create_app(), [*prefix, *args])


# --- cmd start ------------------------------------------------------------------------------


def test_start_creates_a_session_runs_async_and_prints_both_ids(sandbox):
    result = run("cmd", "start", SID, "--", "npm", "run", "dev")

    assert result.exit_code == 0, result.output
    assert result.stdout == f"session: ses_new\ncommand: {COMMAND}\n"
    assert sandbox.process.calls == [
        ("create_session", {}),
        ("execute", "ses_new", "npm run dev", True, 3600),
    ]


def test_start_json_prints_the_ids(sandbox):
    result = run("cmd", "start", SID, "--", "sleep", "1", json_output=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "sandbox_id": SID,
        "session_id": "ses_new",
        "command_id": COMMAND,
    }


def test_start_quotes_arguments_so_the_shell_sees_the_same_argv(sandbox):
    result = run("cmd", "start", SID, "--", "sh", "-c", "echo hi; sleep 1")

    assert result.exit_code == 0, result.output
    assert sandbox.process.calls[-1][2] == "sh -c 'echo hi; sleep 1'"


def test_start_reuses_an_existing_session(sandbox):
    result = run("cmd", "start", SID, "--session", SESSION, "--", "make", "watch")

    assert result.exit_code == 0, result.output
    assert result.stdout.startswith(f"session: {SESSION}\n")
    assert sandbox.process.calls == [
        ("get_session", SESSION),
        ("execute", SESSION, "make watch", True, 3600),
    ]


def test_start_passes_the_timeout(sandbox):
    result = run("cmd", "start", SID, "-t", "120", "--", "true")

    assert result.exit_code == 0, result.output
    assert sandbox.process.calls[-1] == ("execute", "ses_new", "true", True, 120)


def test_start_with_an_unknown_session_fails_clearly_and_runs_nothing(sandbox):
    result = run("cmd", "start", SID, "--session", "ses_missing", "--", "true")

    assert result.exit_code == PLATFORM_ERROR
    assert "no session 'ses_missing'" in result.stderr
    assert "omit --session" in result.stderr
    assert [call[0] for call in sandbox.process.calls] == ["get_session"]


def test_start_without_a_command_is_a_usage_error(sandbox):
    result = run("cmd", "start", SID)

    assert result.exit_code == 2
    assert sandbox.process.calls == []


def test_start_hints_how_to_start_a_sandbox_that_is_not_running(sandbox):
    sandbox.process.error = Conflict(NOT_RUNNING, status_code=409)

    result = run("cmd", "start", SID, "--", "true")

    assert result.exit_code == PLATFORM_ERROR
    assert result.stderr.startswith(f"error: CONFLICT: {NOT_RUNNING}")
    assert result.stderr.endswith(f"\n{START_HINT}\n")


def test_start_not_running_adds_a_hint_field_in_json_mode(sandbox):
    sandbox.process.error = Conflict(NOT_RUNNING, status_code=409)

    result = run("cmd", "start", SID, "--", "true", json_output=True)

    assert result.exit_code == PLATFORM_ERROR
    error = json.loads(result.stdout)["error"]
    assert error["message"] == NOT_RUNNING
    assert error["hint"] == START_HINT


def test_start_adds_no_hint_to_an_unrelated_conflict(sandbox):
    sandbox.process.error = Conflict("modified concurrently", status_code=409)

    result = run("cmd", "start", SID, "--", "true", json_output=True)

    assert result.exit_code == PLATFORM_ERROR
    assert "hint" not in json.loads(result.stdout)["error"]


def test_start_help_has_one_sentence_per_line_without_wrap_artifacts():
    result = run("cmd", "start", "--help")

    assert result.exit_code == 0, result.output
    assert "The command runs through the session shell." in result.stdout
    assert "It is killed after --timeout seconds (default and maximum: 3600)." in result.stdout
    assert "COMMAND... The" not in result.stdout


# --- cmd logs -------------------------------------------------------------------------------


def page(events, next_offset, complete=False):
    return LogPage(tuple(events), next_offset, False, complete)


def test_logs_prints_every_page_and_routes_stderr(sandbox):
    sandbox.process.pages = [
        page([out("one\n"), err("warn\n")], 10),
        page([out("two\n")], 14, complete=True),
    ]

    result = run("cmd", "logs", SID, SESSION, COMMAND)

    assert result.exit_code == 0, result.output
    assert result.stdout == "one\ntwo\n"
    assert result.stderr == "warn\n"
    assert sandbox.process.calls == [
        ("logs", SESSION, COMMAND, 0),
        ("logs", SESSION, COMMAND, 10),
    ]


def test_logs_of_a_running_command_stops_when_nothing_new_arrived(sandbox):
    sandbox.process.pages = [page([out("tick\n")], 5), page([], 5)]

    result = run("cmd", "logs", SID, SESSION, COMMAND)

    assert result.exit_code == 0, result.output
    assert result.stdout == "tick\n"
    assert len(sandbox.process.calls) == 2


def test_logs_follow_streams_events_and_exits_with_the_command_status(sandbox):
    sandbox.process.stream = FakeStream([out("ready\n"), err("oops\n"), exit_event(3)])

    result = run("cmd", "logs", SID, SESSION, COMMAND, "--follow")

    assert result.exit_code == 3, result.output
    assert result.stdout == "ready\n"
    assert result.stderr == "oops\n"
    assert sandbox.process.calls == [("follow", SESSION, COMMAND, 0)]
    assert sandbox.process.stream.closed


@pytest.mark.parametrize(
    "final", [exit_event(None, "killed"), exit_event(None), exit_event(137, "killed")]
)
def test_logs_follow_of_a_killed_command_exits_137_with_a_message(sandbox, final):
    sandbox.process.stream = FakeStream([out("bye\n"), final])

    result = run("cmd", "logs", SID, SESSION, COMMAND, "-f")

    assert result.exit_code == 137, result.output
    assert result.stdout == "bye\n"
    assert result.stderr == "sandfort: the command was killed\n"


def test_logs_follow_of_a_timed_out_command_exits_124_with_a_message(sandbox):
    sandbox.process.stream = FakeStream([out("slow\n"), exit_event(124)])

    result = run("cmd", "logs", SID, SESSION, COMMAND, "-f")

    assert result.exit_code == 124, result.output
    assert result.stdout == "slow\n"
    assert result.stderr == "sandfort: the command timed out\n"


def test_logs_follow_of_a_successful_command_prints_no_message(sandbox):
    sandbox.process.stream = FakeStream([out("ok\n"), exit_event(0)])

    result = run("cmd", "logs", SID, SESSION, COMMAND, "-f")

    assert result.exit_code == 0, result.output
    assert result.stderr == ""


def test_logs_hints_how_to_start_a_sandbox_that_is_not_running(sandbox):
    sandbox.process.error = Conflict(NOT_RUNNING, status_code=409)

    result = run("cmd", "logs", SID, SESSION, COMMAND, "--follow")

    assert result.exit_code == PLATFORM_ERROR
    assert result.stderr.endswith(f"\n{START_HINT}\n")


def test_kill_hints_how_to_start_a_sandbox_that_is_not_running(sandbox):
    sandbox.process.error = Conflict(NOT_RUNNING, status_code=409)

    result = run("cmd", "kill", SID, SESSION, COMMAND, json_output=True)

    assert result.exit_code == PLATFORM_ERROR
    assert json.loads(result.stdout)["error"]["hint"] == START_HINT


def test_logs_follow_reports_a_broken_stream_as_a_platform_error(sandbox):
    sandbox.process.stream = FakeStream([out("partial\n")], error=TransportError("stream cut"))

    result = run("cmd", "logs", SID, SESSION, COMMAND, "--follow")

    assert result.exit_code == PLATFORM_ERROR
    assert "stream cut" in result.stderr
    assert sandbox.process.stream.closed


# --- cmd kill -------------------------------------------------------------------------------


def test_kill_calls_the_sdk_and_reports_the_state(sandbox):
    result = run("cmd", "kill", SID, SESSION, COMMAND)

    assert result.exit_code == 0, result.output
    assert result.stdout == f"command {COMMAND}: killed\n"
    assert sandbox.process.calls == [("kill", SESSION, COMMAND)]


def test_kill_json_prints_state_and_exit_code(sandbox):
    result = run("cmd", "kill", SID, SESSION, COMMAND, json_output=True)

    assert json.loads(result.stdout) == {
        "sandbox_id": SID,
        "session_id": SESSION,
        "command_id": COMMAND,
        "state": "killed",
        "exit_code": 137,
    }


# --- preview --------------------------------------------------------------------------------


def test_preview_prints_the_url_only(sandbox):
    result = run("preview", SID, "3000")

    assert result.exit_code == 0, result.output
    assert result.stdout == f"http://3000-{SID}.preview.test?sandfort_preview_token=pvt_x\n"
    assert sandbox.previews == [(3000, None)]


def test_preview_json_includes_token_and_expiry(sandbox):
    result = run("preview", SID, "8080", "--ttl", "600", json_output=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "url": f"http://8080-{SID}.preview.test?sandfort_preview_token=pvt_x",
        "token": "pvt_x",
        "port": 8080,
        "expires_at": "2026-11-05T12:00:00+00:00",
    }
    assert sandbox.previews == [(8080, 600)]


@pytest.mark.parametrize("state", ["stopped", "creating"])
def test_preview_of_a_sandbox_that_is_not_started_prints_the_url_and_warns(sandbox, state):
    sandbox.state = state

    result = run("preview", SID, "3000")

    assert result.exit_code == 0, result.output
    assert result.stdout == f"http://3000-{SID}.preview.test?sandfort_preview_token=pvt_x\n"
    assert result.stderr == f"sandfort: the sandbox is {state}; the URL works after it is started\n"


def test_preview_of_a_started_sandbox_prints_no_warning(sandbox):
    result = run("preview", SID, "3000")

    assert result.stderr == ""


def test_preview_json_of_a_stopped_sandbox_keeps_stdout_pure_json(sandbox):
    sandbox.state = "stopped"

    result = run("preview", SID, "3000", json_output=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["port"] == 3000
    assert "the sandbox is stopped" in result.stderr


def test_preview_conflict_hints_how_to_start_the_sandbox(sandbox):
    sandbox.preview_error = Conflict(NOT_RUNNING, status_code=409)

    text = run("preview", SID, "3000")
    as_json = run("preview", SID, "3000", json_output=True)

    assert text.exit_code == PLATFORM_ERROR
    assert text.stderr.endswith(f"\n{START_HINT}\n")
    assert as_json.exit_code == PLATFORM_ERROR
    assert json.loads(as_json.stdout)["error"]["hint"] == START_HINT


@pytest.mark.parametrize("args", [["0"], ["65536"], ["3000", "--ttl", "59"]])
def test_preview_rejects_out_of_range_values(sandbox, args):
    result = run("preview", SID, *args)

    assert result.exit_code == 2
    assert sandbox.previews == []
