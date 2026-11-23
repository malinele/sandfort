"""Round 64 CLI polish from a teacher persona.

* ``cmd sessions`` / ``cmd rm-session`` and ``cmd start --follow --close`` manage sessions.
* The exec exit 127 hint appears only when stderr says a command was missing, and its ``sh -c``
  example keeps the original quoting.
* Server validation errors for a mount name ``--mount <value>``, not ``body.volumes.N...``.
* ``volume list`` gives the labels column the width the layout leaves.
* ``cp`` of a path that does not exist says ``no such file``.
"""

import json
import os
import re
import shlex
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import cmd_cmd, cmd_sessions, config, cp_cmd, exec_cmd, main  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import NotFound  # noqa: E402
from sandfort_sdk.models import (  # noqa: E402
    CommandInfo,
    ExecResult,
    LogEvent,
    SessionExecResult,
    SessionInfo,
)
from typer.testing import CliRunner  # noqa: E402

SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
USAGE_ERROR = 2
PLATFORM_ERROR = 125
RUNNER = CliRunner()


def run(*args: str, json_output: bool = False) -> Any:
    prefix = ["--json"] if json_output else []
    return RUNNER.invoke(create_app(), [*prefix, *args])


def flat(text: str) -> str:
    return " ".join(re.sub(r"[│┃╭╮╰╯─━┏┓┗┛┡┩╇╈┳┻]", " ", text).split())


# --- cmd sessions, rm-session, start --close ------------------------------------------------


def session_info(session_id: str, state: str = "active", cwd: str | None = None) -> SessionInfo:
    return SessionInfo(session_id, SID, cwd, {"SECRET_ENV": "hunter2"}, state, NOW)


class FakeStream:
    def __init__(self, events: list[LogEvent]):
        self._events = events

    def __enter__(self) -> "FakeStream":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def __iter__(self) -> Iterator[LogEvent]:
        yield from self._events


class FakeProcess:
    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.sessions = {
            "ses_a": session_info("ses_a", cwd="/work"),
            "ses_b": session_info("ses_b"),
        }
        self.events = [
            LogEvent(stream="stdout", offset=0, line="hi\n"),
            LogEvent(stream="exit", offset=3, exit_code=3, state="exited"),
        ]
        self.delete_error: Exception | None = None

    def list_sessions(self) -> tuple[SessionInfo, ...]:
        self.calls.append(("list",))
        return tuple(self.sessions.values())

    def delete_session(self, session_id: str) -> SessionInfo:
        self.calls.append(("delete", session_id))
        if self.delete_error is not None:
            raise self.delete_error
        if session_id not in self.sessions:
            raise NotFound("session not found", status_code=404)
        return session_info(session_id, state="closed")

    def create_session(self, **_: Any) -> SessionInfo:
        self.calls.append(("create",))
        self.sessions["ses_new"] = session_info("ses_new")
        return self.sessions["ses_new"]

    def get_session(self, session_id: str) -> SessionInfo:
        if session_id not in self.sessions:
            raise NotFound("no such session")
        return self.sessions[session_id]

    def execute_session_command(
        self, session_id: str, command: str, *, run_async: bool = False, timeout_s: int = 60
    ) -> SessionExecResult:
        self.calls.append(("execute", session_id, command))
        info = CommandInfo("cmd_1", session_id, "running", None, 0, 0, NOW)
        return SessionExecResult(mode="async", command=info)

    def follow_logs(self, session_id: str, command_id: str, *, offset: int = 0) -> FakeStream:
        self.calls.append(("follow", session_id, command_id))
        return FakeStream(self.events)


class FakeSandbox:
    id = SID

    def __init__(self) -> None:
        self.process = FakeProcess()


class FakeClient:
    def __init__(self, sandbox: Any):
        self._sandbox = sandbox

    def get(self, sandbox_id: str) -> Any:
        assert sandbox_id == SID
        return self._sandbox


@pytest.fixture
def sandbox(monkeypatch: pytest.MonkeyPatch) -> FakeSandbox:
    fake = FakeSandbox()

    @contextmanager
    def opened() -> Iterator[FakeClient]:
        yield FakeClient(fake)

    monkeypatch.setattr(cmd_cmd, "open_client", opened)
    monkeypatch.setattr(cmd_sessions, "open_client", opened)
    monkeypatch.setattr(exec_cmd, "open_client", opened)
    monkeypatch.setattr(cp_cmd, "open_client", opened)
    return fake


def test_sessions_lists_every_session_in_a_table(sandbox):
    result = run("cmd", "sessions", SID)

    assert result.exit_code == 0, result.output
    text = flat(result.output)
    assert "ses_a" in text and "ses_b" in text
    assert "active" in text
    assert "/work" in text
    assert "hunter2" not in result.output


def test_sessions_json_lists_ids_states_and_no_environment(sandbox):
    result = run("cmd", "sessions", SID, json_output=True)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert [item["id"] for item in payload] == ["ses_a", "ses_b"]
    assert payload[0]["state"] == "active"
    assert payload[0]["cwd"] == "/work"
    assert "hunter2" not in result.output


def test_rm_session_deletes_through_the_sdk(sandbox):
    result = run("cmd", "rm-session", SID, "ses_a")

    assert result.exit_code == 0, result.output
    assert ("delete", "ses_a") in sandbox.process.calls
    assert "ses_a" in result.output
    assert "closed" in result.output


def test_rm_session_json_reports_the_closed_state(sandbox):
    result = run("cmd", "rm-session", SID, "ses_a", json_output=True)

    assert json.loads(result.output) == {
        "sandbox_id": SID,
        "session_id": "ses_a",
        "state": "closed",
    }


def test_rm_session_of_an_unknown_session_fails_with_exit_1(sandbox):
    # r65: a missing session exits 1 like a missing sandbox; 125 stays for platform errors.
    result = run("cmd", "rm-session", SID, "ses_nope")

    assert result.exit_code == 1
    assert "not found" in result.output


def test_rm_session_rejects_a_blank_session_id(sandbox):
    result = run("cmd", "rm-session", SID, " ")

    assert result.exit_code == USAGE_ERROR
    assert sandbox.process.calls == []


def test_start_follow_streams_output_and_exits_with_the_command_status(sandbox):
    result = run("cmd", "start", "--follow", SID, "--", "echo", "hi")

    assert result.exit_code == 3
    assert "hi" in result.output
    assert not any(call[0] == "delete" for call in sandbox.process.calls)


def test_start_follow_close_deletes_the_new_session_after_the_command_ends(sandbox):
    result = run("cmd", "start", "--follow", "--close", SID, "--", "echo", "hi")

    assert result.exit_code == 3
    kinds = [call[0] for call in sandbox.process.calls]
    assert kinds.index("follow") < kinds.index("delete")
    assert ("delete", "ses_new") in sandbox.process.calls


def test_start_close_deletes_the_session_even_when_the_stream_breaks(sandbox, monkeypatch):
    def broken(*_: Any, **__: Any) -> int:
        raise RuntimeError("stream broke")

    monkeypatch.setattr(cmd_cmd, "follow_to_exit_code", broken)

    result = run("cmd", "start", "--follow", "--close", SID, "--", "true")

    assert result.exit_code != 0
    assert ("delete", "ses_new") in sandbox.process.calls


def test_start_close_without_follow_is_a_usage_error_and_runs_nothing(sandbox):
    result = run("cmd", "start", "--close", SID, "--", "echo", "hi")

    assert result.exit_code == USAGE_ERROR
    assert "--follow" in result.output
    assert sandbox.process.calls == []


def test_start_close_with_an_existing_session_is_a_usage_error(sandbox):
    result = run("cmd", "start", "--follow", "--close", "--session", "ses_a", SID, "--", "ls")

    assert result.exit_code == USAGE_ERROR
    assert "--session" in result.output
    assert sandbox.process.calls == []


def test_start_close_keeps_the_command_status_when_the_delete_fails(sandbox):
    sandbox.process.delete_error = NotFound("gone", status_code=404)

    result = run("cmd", "start", "--follow", "--close", SID, "--", "echo", "hi")

    assert result.exit_code == 3
    assert "ses_new" in result.output


def test_start_without_follow_still_prints_ids_and_returns_at_once(sandbox):
    result = run("cmd", "start", SID, "--", "echo", "hi")

    assert result.exit_code == 0
    assert "session: ses_new" in result.output
    assert "command: cmd_1" in result.output


# --- exec 127 hints -------------------------------------------------------------------------


class ExecSandbox:
    def __init__(self, exit_code: int, stderr: str = "") -> None:
        self.exit_code = exit_code
        self.stderr = stderr

    def process_exec(self, command: Any = None, *, argv: Any = None, **_: Any) -> ExecResult:
        return ExecResult(
            exit_code=self.exit_code,
            stdout="",
            stderr=self.stderr,
            timed_out=False,
            truncated=False,
            duration_ms=1,
        )


def exec_127(monkeypatch: pytest.MonkeyPatch, stderr: str, *argv: str, json_output: bool = False):
    fake = ExecSandbox(127, stderr)

    @contextmanager
    def opened() -> Iterator[FakeClient]:
        yield FakeClient(fake)

    monkeypatch.setattr(exec_cmd, "open_client", opened)
    return run("exec", SID, "--", *argv, json_output=json_output)


def test_a_program_that_exits_127_on_purpose_gets_no_not_found_hint(monkeypatch):
    result = exec_127(monkeypatch, "", "python", "-c", "import sys; sys.exit(127)")

    assert result.exit_code == 127
    assert "hint:" not in result.stderr


def test_a_program_that_exits_127_on_purpose_has_no_hint_key_in_json(monkeypatch):
    result = exec_127(
        monkeypatch, "", "python", "-c", "import sys; sys.exit(127)", json_output=True
    )

    assert "hint" not in json.loads(result.stdout)


def test_the_runner_not_found_text_still_triggers_the_hint(monkeypatch):
    result = exec_127(monkeypatch, "command not found: nosuchtool\n", "nosuchtool")

    assert "hint: exit 127 means command not found" in result.stderr


def test_a_shell_not_found_line_for_the_first_word_triggers_the_hint(monkeypatch):
    result = exec_127(monkeypatch, "sh: 1: nosuchtool: not found\n", "nosuchtool", "|", "wc")

    assert "hint: exit 127 means command not found" in result.stderr


def test_a_no_such_file_line_for_the_first_word_triggers_the_hint(monkeypatch):
    result = exec_127(monkeypatch, "env: ./run.sh: No such file or directory\n", "./run.sh")

    assert "hint: exit 127" in result.stderr


def test_unrelated_stderr_text_does_not_trigger_the_hint(monkeypatch):
    result = exec_127(monkeypatch, "my tool: all done\n", "mytool")

    assert "hint:" not in result.stderr


def test_sh_c_exit_127_gets_no_hint_when_the_shell_reported_nothing(monkeypatch):
    result = exec_127(monkeypatch, "", "sh", "-c", "exit 127")

    assert result.exit_code == 127
    assert "hint:" not in result.stderr


def test_sh_c_with_a_missing_command_still_says_the_shell_reported_it(monkeypatch):
    result = exec_127(monkeypatch, "sh: 1: nosuchtool: not found\n", "sh", "-c", "nosuchtool")

    assert "the shell reported a missing command" in result.stderr


def sh_c_argument(stderr: str) -> str:
    (line,) = [line for line in stderr.splitlines() if line.startswith("hint: exit 127")]
    tail = line.split(" -- sh -c ", 1)[1].split(". The default working directory")[0]
    return shlex.split(tail)[0]


@pytest.mark.parametrize(
    "argv",
    [
        ["python", "-c", "print(1); print(2)", "|", "wc"],
        ["echo", "two words", "&&", "echo", "it's"],
        ["python3", "-c", 'print("a b")', ">", "out.txt"],
    ],
)
def test_the_sh_c_example_keeps_the_original_quoting(monkeypatch, argv):
    result = exec_127(monkeypatch, f"command not found: {argv[0]}\n", *argv)

    line = sh_c_argument(result.stderr)
    assert shlex.split(line) == argv


def test_a_whole_command_line_in_one_word_is_passed_as_is(monkeypatch):
    result = exec_127(monkeypatch, "command not found: ls -la /tmp\n", "ls -la /tmp")

    assert sh_c_argument(result.stderr) == "ls -la /tmp"


# --- --mount in server validation errors ----------------------------------------------------

MOUNT_MESSAGE = "String should match pattern '^/[^:,\\\\]+$'"


def validation_failure(*issues: tuple[list[str], str]) -> httpx.Response:
    errors = [{"loc": loc, "msg": msg, "type": "string_pattern_mismatch"} for loc, msg in issues]
    first_loc, first_msg = issues[0]
    message = f"request validation failed: {'.'.join(first_loc)}: {first_msg}"
    if len(issues) > 1:
        message += f" (and {len(issues) - 1} more)"
    error = {
        "code": "VALIDATION_ERROR",
        "message": message,
        "details": {"errors": errors},
        "request_id": "req_1",
    }
    return httpx.Response(422, json={"success": False, "data": None, "error": error, "meta": None})


@pytest.fixture
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    monkeypatch.delenv("COLUMNS", raising=False)
    monkeypatch.chdir(tmp_path)
    config.save_profile(BASE, KEY)


@pytest.fixture
def router(profile: None) -> Iterator[Any]:
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


def create_with(*mounts: str, json_output: bool = False) -> Any:
    args = ["sandbox", "create", "demo"]
    for mount in mounts:
        args += ["-m", mount]
    return run(*args, json_output=json_output)


def test_a_mount_path_validation_error_names_the_option_and_the_typed_value(router):
    router.post("/v1/sandboxes").mock(
        return_value=validation_failure((["body", "volumes", "0", "mount_path"], MOUNT_MESSAGE))
    )

    result = create_with("vol_1:/bad")

    assert result.exit_code == 1
    text = flat(result.output)
    assert f"--mount vol_1:/bad: {MOUNT_MESSAGE}" in text
    assert "body.volumes" not in text


def test_the_second_mount_is_matched_by_its_index(router):
    router.post("/v1/sandboxes").mock(
        return_value=validation_failure(
            (["body", "volumes", "1", "mount_path"], "Mount path is reserved")
        )
    )

    result = create_with("vol_1:/ok", "vol_2:/proc:ro".replace(":ro", ""))

    text = flat(result.output)
    assert "--mount vol_2:/proc: Mount path is reserved" in text
    assert "vol_1:/ok" not in text


def test_a_volume_id_validation_error_also_names_the_option(router):
    router.post("/v1/sandboxes").mock(
        return_value=validation_failure((["body", "volumes", "0", "volume_id"], "Bad volume id"))
    )

    result = create_with("vol_9:/data")

    assert "--mount vol_9:/data: Bad volume id" in flat(result.output)
    assert "body.volumes" not in result.output


def test_json_error_carries_the_option_in_message_and_location(router):
    router.post("/v1/sandboxes").mock(
        return_value=validation_failure((["body", "volumes", "0", "mount_path"], "too odd"))
    )

    result = create_with("vol_1:/odd", json_output=True)

    error = json.loads(result.output)["error"]
    assert "body.volumes" not in json.dumps(error)
    assert "--mount vol_1:/odd" in error["message"]


def test_other_validation_errors_are_left_alone(router):
    router.post("/v1/sandboxes").mock(
        return_value=validation_failure((["body", "name"], "Name is too long"))
    )

    result = create_with("vol_1:/data")

    text = flat(result.output)
    assert "body.name: Name is too long" in text
    assert "--mount" not in text


# --- volume list labels ---------------------------------------------------------------------

LONG_LABELS = {
    "env": "production",
    "team": "platform-engineering",
    "owner": "someone@example.com",
    "tier": "backend",
}
LABELS_TEXT = ",".join(f"{k}={v}" for k, v in LONG_LABELS.items())


def test_volume_list_labels_use_the_free_width(router, monkeypatch):
    monkeypatch.setenv("COLUMNS", "170")
    volume = {
        "id": "vol_1",
        "name": "data",
        "state": "ready",
        "created_at": "2026-11-10T19:26:00Z",
        "labels": LONG_LABELS,
        "size_bytes": 0,
        "max_bytes": 1024**3,
        "over_limit": False,
    }
    body = {"success": True, "data": [volume], "error": None, "meta": None}
    router.get("/v1/volumes").mock(return_value=httpx.Response(200, json=body))
    assert len(LABELS_TEXT) > 32

    result = run("volume", "list")

    assert result.exit_code == 0, result.output
    assert LABELS_TEXT in result.output
    assert "…" not in result.output


# --- cp of a missing file -------------------------------------------------------------------


def test_cp_of_a_missing_relative_file_says_no_such_file_with_the_typed_path(
    sandbox, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)

    result = run("cp", "./nonexistent", f"{SID}:/x")

    assert result.exit_code == USAGE_ERROR
    assert "no such file: ./nonexistent" in result.output
    assert "not a regular file" not in result.output


def test_cp_of_a_missing_file_with_r_says_no_such_file(sandbox, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = run("cp", "-r", "nodir", f"{SID}:/x")

    assert result.exit_code == USAGE_ERROR
    assert "no such file: nodir" in result.output


def test_cp_of_a_missing_file_in_json_keeps_the_client_source(sandbox, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = run("cp", "./nonexistent", f"{SID}:/x", json_output=True)

    error = json.loads(result.output)["error"]
    assert error["message"] == "no such file: ./nonexistent"
    assert error["source"] == "client"


def test_cp_of_a_directory_without_r_keeps_the_regular_file_message(sandbox, tmp_path):
    result = run("cp", str(tmp_path), f"{SID}:/x")

    assert result.exit_code == USAGE_ERROR
    assert "is not a regular file; use -r for directories" in flat(result.output)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_cp_of_a_special_file_keeps_the_regular_file_message(sandbox, tmp_path):
    pipe = tmp_path / "pipe"
    os.mkfifo(pipe)

    result = run("cp", str(pipe), f"{SID}:/x")

    assert result.exit_code == USAGE_ERROR
    assert "is not a regular file" in flat(result.output)
    assert "no such file" not in result.output


def test_module_imports_are_wired():
    assert main.create_app is create_app
