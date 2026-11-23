"""Round 65 CLI findings: a stopped command never reads as success, consistent missing-item exits,
the 127 hint and the newline before our sentences on the followed path, outward symlinks on
upload, and plain ids from ``volume rm``."""

import dataclasses
import json
import sys
import tarfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli import cmd_cmd, cmd_sessions, cp_cmd, cp_dir, exec_cmd, volume  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import NotFound, VolumeInfo  # noqa: E402
from sandfort_sdk.models import (  # noqa: E402
    CommandInfo,
    ExecResult,
    LogEvent,
    SessionExecResult,
    SessionInfo,
)
from typer.testing import CliRunner  # noqa: E402

SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
RUNNER = CliRunner()
NOT_OK_EXIT = 120


def run(*args: str, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + list(args))


# --- fakes -----------------------------------------------------------------------------------


def exec_result(exit_code=0, *, stderr="", stdout="", stop_reason=None, truncated=False):
    return ExecResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=False,
        truncated=truncated,
        duration_ms=1,
        stop_reason=stop_reason,
    )


class ExecSandbox:
    id = SID

    def __init__(self, result):
        self.result = dataclasses.replace(result, request_id="req_1")

    def process_exec(self, command=None, *, argv=None, **kwargs):
        return self.result


class Stream:
    def __init__(self, events):
        self._events = events

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def __iter__(self) -> Iterator[LogEvent]:
        yield from self._events


def session(session_id="ses_a"):
    return SessionInfo(session_id, SID, None, {}, "active", NOW)


class Process:
    def __init__(self):
        self.events: list[LogEvent] = []
        self.deleted: list[str] = []

    def create_session(self, **_):
        return session("ses_new")

    def execute_session_command(self, session_id, command, *, run_async=False, timeout_s=60):
        info = CommandInfo("cmd_1", session_id, "running", None, 0, 0, NOW)
        return SessionExecResult(mode="async", command=info)

    def follow_logs(self, session_id, command_id, *, offset=0):
        return Stream(self.events)

    def delete_session(self, session_id):
        self.deleted.append(session_id)
        if session_id != "ses_a":
            raise NotFound("session not found", status_code=404)
        return dataclasses.replace(session(session_id), state="closed")


class ProcessSandbox:
    id = SID

    def __init__(self, result=None):
        self.process = Process()
        self.result = result


@pytest.fixture
def install(monkeypatch):
    def apply(sandbox):
        @contextmanager
        def opened():
            yield SimpleNamespace(get=lambda sandbox_id: sandbox)

        for module in (cmd_cmd, cmd_sessions, exec_cmd, cp_cmd):
            monkeypatch.setattr(module, "open_client", opened)
        return sandbox

    return apply


def out(line):
    return LogEvent(stream="stdout", offset=0, line=line)


def err(line):
    return LogEvent(stream="stderr", offset=0, line=line)


def exit_event(exit_code, state="exited", *, truncated=False, stop_cause=None):
    return LogEvent(
        stream="exit",
        offset=0,
        exit_code=exit_code,
        state=state,
        truncated=truncated,
        stop_cause=stop_cause,
    )


# --- 1. exec: a stopped or truncated command with exit 0 is not a success ---------------------


def test_exec_output_limit_with_exit_0_exits_with_the_not_ok_code(install):
    install(ExecSandbox(exec_result(0, stop_reason="output_limit", truncated=True)))

    result = run("exec", SID, "--", "sh", "-c", "yes | head -c 2000000")

    assert result.exit_code == NOT_OK_EXIT
    assert result.stderr == "sandfort: the command was stopped: output_limit; output truncated\n"


def test_exec_truncated_alone_with_exit_0_is_not_ok(install):
    install(ExecSandbox(exec_result(0, truncated=True)))

    result = run("exec", SID, "--", "cat", "/big")

    assert result.exit_code == NOT_OK_EXIT
    assert result.stderr == "sandfort: the command was stopped: output truncated\n"


def test_exec_stop_reason_alone_with_exit_0_is_not_ok(install):
    install(ExecSandbox(exec_result(0, stop_reason="killed")))

    result = run("exec", SID, "--", "true")

    assert result.exit_code == NOT_OK_EXIT
    assert result.stderr == "sandfort: the command was stopped: killed\n"


def test_exec_not_ok_sentence_starts_on_its_own_line(install):
    install(ExecSandbox(exec_result(0, stderr="partial", stop_reason="output_limit")))

    result = run("exec", SID, "--", "true")

    assert result.exit_code == NOT_OK_EXIT
    assert result.stderr == "partial\nsandfort: the command was stopped: output_limit\n"


def test_exec_keeps_the_commands_own_non_zero_exit_code(install):
    install(ExecSandbox(exec_result(7, stop_reason="output_limit", truncated=True)))

    result = run("exec", SID, "--", "false")

    assert result.exit_code == 7
    assert "the command was stopped:" not in result.stderr


def test_exec_unterminated_server_sentence_ends_with_a_newline(install):
    sentence = "the command was stopped because its output exceeded the limit of 65536 bytes"
    install(ExecSandbox(exec_result(137, stderr=sentence, stop_reason="output_limit")))

    result = run("exec", SID, "--", "yes")

    assert result.exit_code == 137
    assert result.stderr == sentence + "\n"


def test_exec_ok_run_exits_0_and_prints_nothing_extra(install):
    install(ExecSandbox(exec_result(0, stdout="hi\n")))

    result = run("exec", SID, "--", "echo", "hi")

    assert result.exit_code == 0
    assert result.stderr == ""


def test_exec_json_carries_ok_and_the_not_ok_exit_code(install):
    install(ExecSandbox(exec_result(0, stop_reason="output_limit", truncated=True)))

    result = run("exec", SID, "--", "true", as_json=True)

    assert result.exit_code == NOT_OK_EXIT
    assert json.loads(result.stdout)["ok"] is False


def test_exec_json_ok_is_true_for_a_clean_run(install):
    install(ExecSandbox(exec_result(0)))

    result = run("exec", SID, "--", "true", as_json=True)

    assert result.exit_code == 0
    assert json.loads(result.stdout)["ok"] is True


# --- 1b. followed commands -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("final", "reason"),
    [
        (exit_event(0, truncated=True), "output truncated"),
        (exit_event(0, stop_cause="sandbox_stopped"), "sandbox_stopped"),
    ],
)
def test_follow_with_exit_0_but_a_stopped_command_exits_with_the_not_ok_code(
    install, final, reason
):
    box = install(ProcessSandbox())
    box.process.events = [out("x\n"), final]

    result = run("cmd", "start", "-f", SID, "--", "true")

    assert result.exit_code == NOT_OK_EXIT
    assert f"sandfort: the command was stopped: {reason}\n" in result.stderr


def test_follow_passes_a_non_zero_exit_code_through(install):
    box = install(ProcessSandbox())
    box.process.events = [exit_event(4, truncated=True)]

    result = run("cmd", "start", "-f", SID, "--", "false")

    assert result.exit_code == 4


def test_follow_with_close_also_reports_the_not_ok_code_and_deletes_the_session(install):
    box = install(ProcessSandbox())
    box.process.events = [exit_event(0, truncated=True)]

    result = run("cmd", "start", "-f", "--close", SID, "--", "true")

    assert result.exit_code == NOT_OK_EXIT
    assert box.process.deleted == ["ses_new"]


def test_follow_clean_exit_stays_0(install):
    box = install(ProcessSandbox())
    box.process.events = [out("x\n"), exit_event(0)]

    result = run("cmd", "start", "-f", SID, "--", "true")

    assert result.exit_code == 0


# --- 2. rm-session: a missing session exits 1 -------------------------------------------------


def test_rm_session_of_a_missing_session_exits_1_with_the_not_found_message(install):
    install(ProcessSandbox())

    result = run("cmd", "rm-session", SID, "ses_nope")

    assert result.exit_code == 1
    assert "not found" in result.stderr


def test_rm_session_missing_session_json_error_exits_1(install):
    install(ProcessSandbox())

    result = run("cmd", "rm-session", SID, "ses_nope", as_json=True)

    assert result.exit_code == 1
    assert "not found" in json.loads(result.stdout)["error"]["message"]


def test_rm_session_if_exists_skips_a_missing_session_with_one_note(install):
    install(ProcessSandbox())

    result = run("cmd", "rm-session", "--if-exists", SID, "ses_nope")

    assert result.exit_code == 0, result.output
    assert result.stdout == ""
    assert result.stderr == "ses_nope: not found, skipped\n"


def test_rm_session_if_exists_json_reports_the_skip(install):
    install(ProcessSandbox())

    result = run("cmd", "rm-session", "--if-exists", SID, "ses_nope", as_json=True)

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {
        "sandbox_id": SID,
        "session_id": "ses_nope",
        "skipped": "not_found",
    }


def test_rm_session_if_exists_still_deletes_an_existing_session(install):
    box = install(ProcessSandbox())

    result = run("cmd", "rm-session", "--if-exists", SID, "ses_a")

    assert result.exit_code == 0
    assert box.process.deleted == ["ses_a"]


# --- 3. cmd start -f: the 127 hint -------------------------------------------------------------


def test_follow_adds_the_127_hint_when_stderr_says_the_command_is_missing(install):
    box = install(ProcessSandbox())
    box.process.events = [err("sh: 1: nosuchtool: not found\n"), exit_event(127)]

    result = run("cmd", "start", "-f", SID, "--", "nosuchtool")

    assert result.exit_code == 127
    assert "hint: exit 127 means command not found" in result.stderr
    assert "--cwd" not in result.stderr


def test_follow_gives_no_hint_to_a_program_that_exits_127_on_its_own(install):
    box = install(ProcessSandbox())
    box.process.events = [err("custom failure\n"), exit_event(127)]

    result = run("cmd", "start", "-f", SID, "--", "mytool")

    assert result.exit_code == 127
    assert "hint:" not in result.stderr


# --- 4. newline before our sentences on the followed path --------------------------------------


def test_follow_timeout_sentence_starts_on_its_own_line(install):
    box = install(ProcessSandbox())
    box.process.events = [
        err("the command was stopped after 3600 s (timeout); allow more time, up to 3600 s"),
        exit_event(124),
    ]

    result = run("cmd", "start", "-f", SID, "--", "sleep", "9999")

    assert result.exit_code == 124
    assert result.stderr.endswith("up to 3600 s\nsandfort: the command timed out\n")


def test_follow_killed_sentence_starts_on_its_own_line(install):
    box = install(ProcessSandbox())
    box.process.events = [err("partial"), exit_event(None, "killed")]

    result = run("cmd", "start", "-f", SID, "--", "x")

    assert result.exit_code == 137
    assert result.stderr.endswith("partial\nsandfort: the command was killed\n")


# --- 5. cp -r upload skips symlinks that point outside the tree --------------------------------


class UploadFs:
    def __init__(self):
        self.uploads: dict[str, bytes] = {}

    def upload_file(self, path, data, *, size_bytes=None, chunk_size=0, **_):
        self.uploads[path] = data.read()
        return SimpleNamespace(size_bytes=len(self.uploads[path]))

    def delete(self, path, *, recursive=False):
        return None


class CopySandbox:
    def __init__(self):
        self.fs = UploadFs()

    def process_exec(self, command=None, *, argv=None, **kwargs):
        return exec_result(0)


def uploaded_names(sandbox):
    import io

    (body,) = sandbox.fs.uploads.values()
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
        return sorted(archive.getnames())


def test_upload_skips_symlinks_that_point_outside_the_tree(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("s")
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "a").write_text("alpha")
    (tree / "inside").symlink_to("a")
    (tree / "up").symlink_to("../secret.txt")
    (tree / "abs").symlink_to(secret)
    (tree / "dir").symlink_to(tmp_path)
    sandbox = CopySandbox()

    stats = cp_dir.upload_dir(sandbox, tree, "/x")

    assert uploaded_names(sandbox) == ["a", "inside"]
    assert stats.symlinks == 1
    assert sorted(stats.skipped) == sorted(
        [
            f"skipped symlink abs -> {secret} (points outside the copied tree)",
            f"skipped symlink dir -> {tmp_path} (points outside the copied tree)",
            "skipped symlink up -> ../secret.txt (points outside the copied tree)",
        ]
    )


def test_upload_keeps_a_symlink_that_stays_inside_a_subdirectory(tmp_path):
    tree = tmp_path / "tree"
    (tree / "sub").mkdir(parents=True)
    (tree / "sub" / "b").write_text("beta")
    (tree / "sub" / "back").symlink_to("../sub/b")
    sandbox = CopySandbox()

    stats = cp_dir.upload_dir(sandbox, tree, "/x")

    assert uploaded_names(sandbox) == ["sub", "sub/b", "sub/back"]
    assert stats.skipped == ()


def test_cp_r_upload_prints_the_warning_on_stderr(install, tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "up").symlink_to("../elsewhere")
    install(CopySandbox())

    result = run("cp", "-r", str(tree), f"{SID}:/x")

    assert result.exit_code == 0, result.output
    assert "skipped symlink up -> ../elsewhere (points outside the copied tree)" in result.stderr


# --- 6. volume rm prints the id ----------------------------------------------------------------


def volume_info(volume_id="vol_1"):
    return VolumeInfo(
        id=volume_id,
        name="data",
        state="deleting",
        created_at=NOW,
    )


class Volumes:
    def delete(self, volume_id):
        return volume_info(volume_id)


@pytest.fixture
def volumes(monkeypatch):
    @contextmanager
    def opened():
        yield SimpleNamespace(volumes=Volumes())

    monkeypatch.setattr(volume, "open_client", opened)
    monkeypatch.setattr(volume, "volume_id_for_ref", lambda client, ref, metavar: ref)


def test_volume_rm_prints_one_plain_id(volumes):
    result = run("volume", "rm", "vol_1")

    assert result.exit_code == 0, result.output
    assert result.stdout == "vol_1\n"


def test_volume_rm_json_is_unchanged(volumes):
    result = run("volume", "rm", "vol_1", as_json=True)

    assert json.loads(result.stdout)["id"] == "vol_1"
    assert json.loads(result.stdout)["state"] == "deleting"
