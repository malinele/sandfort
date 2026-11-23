"""Round 61: ``sandfort exec`` builtin note and exit 126 hint; ``sandfort cp`` usage exit code
and the honest read-only message of ``cp -r`` with the request id of the refusing call."""

import dataclasses
import json
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli import cp_cmd, exec_cmd  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import ApiError  # noqa: E402
from sandfort_sdk.models import ExecResult  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
RUNNER = CliRunner()
USAGE_ERROR = 2
PLATFORM_FAILURE = 125
REQUEST_ID = "req_refused_01"
DEST = "/data/ro"
NOTHING_WRITTEN = f"{DEST} is on a read-only mount; nothing was written"
EARLIER_ENTRIES = "earlier entries may have been written"
HINT_126 = "exit 126: the file exists but cannot be executed (permissions, or not a binary/script)"


def note_for(word):
    return (
        f"'{word}' only changes this one call; use --cwd, a session (sandfort shell), "
        "or chain with sh -c"
    )


def exec_result(exit_code=0, stderr="", stdout=""):
    return ExecResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=False,
        truncated=False,
        duration_ms=1,
    )


class FakeFs:
    def __init__(self, upload_error=None):
        self.upload_error = upload_error
        self.uploads = {}

    def upload_file(self, path, data, *, size_bytes=None, chunk_size=0, **_):
        if self.upload_error is not None:
            raise self.upload_error
        body = data.read()
        self.uploads[path] = body
        return SimpleNamespace(size_bytes=len(body))

    def delete(self, path, *, recursive=False):
        return None


class FakeSandbox:
    def __init__(self, result=None, fs=None, request_id=REQUEST_ID):
        self.result = dataclasses.replace(result or exec_result(), request_id=request_id)
        self.fs = fs or FakeFs()
        self.calls = []

    def process_exec(self, command=None, *, argv=None, **kwargs):
        self.calls.append(argv)
        return self.result


@pytest.fixture
def install(monkeypatch):
    def apply(sandbox):
        @contextmanager
        def opened():
            yield SimpleNamespace(get=lambda sandbox_id: sandbox)

        monkeypatch.setattr(exec_cmd, "open_client", opened)
        monkeypatch.setattr(cp_cmd, "open_client", opened)
        return sandbox

    return apply


def run(*args, as_json=False):
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + list(args))


# --- exec: builtins that cannot outlive the call ------------------------------------------------


@pytest.mark.parametrize("word", ["cd", "export", "alias", "source", "set", "ulimit", "umask"])
def test_exec_of_a_shell_builtin_prints_one_note_and_keeps_the_exit_code(install, word):
    install(FakeSandbox(exec_result(0)))

    result = run("exec", SID, "--", word, "/tmp")

    assert result.exit_code == 0
    assert result.stderr.count(note_for(word)) == 1


def test_exec_builtin_note_keeps_a_failing_exit_code(install):
    install(FakeSandbox(exec_result(3)))

    result = run("exec", SID, "--", "cd", "/nope")

    assert result.exit_code == 3
    assert note_for("cd") in result.stderr


def test_exec_builtin_note_starts_on_its_own_line_after_unterminated_stderr(install):
    install(FakeSandbox(exec_result(0, stderr="partial")))

    result = run("exec", SID, "--", "cd", "/tmp")

    assert result.stderr == f"partial\n{note_for('cd')}\n"


def test_exec_builtin_note_also_appears_with_json_on_stderr_only(install):
    install(FakeSandbox(exec_result(0)))

    result = run("exec", SID, "--", "export", "A=1", as_json=True)

    assert result.exit_code == 0
    assert note_for("export") in result.stderr
    assert json.loads(result.stdout)["exit_code"] == 0


@pytest.mark.parametrize(
    "argv",
    [["ls", "/tmp"], ["sh", "-c", "cd /tmp"], ["/bin/cd", "/tmp"], ["echo", "cd"]],
    ids=["plain-program", "inside-sh-c", "path-to-program", "word-as-argument"],
)
def test_exec_prints_no_builtin_note_for_other_commands(install, argv):
    install(FakeSandbox(exec_result(0)))

    result = run("exec", SID, "--", *argv)

    assert result.exit_code == 0
    assert "only changes this one call" not in result.stderr


# --- exec: exit 126 ---------------------------------------------------------------------------


def test_exec_126_prints_the_not_executable_hint_and_keeps_the_exit_code(install):
    install(FakeSandbox(exec_result(126)))

    result = run("exec", SID, "--", "/tmp/script.sh")

    assert result.exit_code == 126
    assert HINT_126 in result.stderr
    assert result.stderr.count("hint:") == 1
    assert "command not found" not in result.stderr


def test_exec_126_json_puts_the_hint_in_the_result_object(install):
    install(FakeSandbox(exec_result(126)))

    result = run("exec", SID, "--", "/tmp/script.sh", as_json=True)

    assert result.exit_code == 126
    assert HINT_126 in json.loads(result.stdout)["hint"]
    assert "hint:" not in result.stderr


@pytest.mark.parametrize("code", [0, 1, 2, 125])
def test_exec_other_exit_codes_carry_no_126_hint(install, code):
    install(FakeSandbox(exec_result(code)))

    result = run("exec", SID, "--", "ls")

    assert HINT_126 not in result.stderr
    assert "hint" not in json.loads(run("--json", "exec", SID, "--", "ls").stdout)


def test_exec_127_still_prints_its_own_hint(install):
    install(FakeSandbox(exec_result(127, stderr="command not found: nosuchtool\n")))

    result = run("exec", SID, "--", "nosuchtool")

    assert result.exit_code == 127
    assert "hint: exit 127 means command not found" in result.stderr
    assert HINT_126 not in result.stderr


# --- cp: client-side usage errors exit 2 ------------------------------------------------------


def test_cp_relative_remote_path_is_a_usage_error_with_exit_2(install, tmp_path):
    sandbox = install(FakeSandbox())
    source = tmp_path / "one.txt"
    source.write_text("x")

    result = run("cp", str(source), f"{SID}:relative/path")

    assert result.exit_code == USAGE_ERROR
    assert "remote path must be absolute" in result.stderr
    assert sandbox.fs.uploads == {}


def test_cp_missing_local_source_exits_2(install, tmp_path):
    install(FakeSandbox())

    result = run("cp", str(tmp_path / "missing.txt"), f"{SID}:/w/x")

    assert result.exit_code == USAGE_ERROR
    assert "no such file:" in result.stderr


def test_cp_directory_without_r_exits_2_with_the_hint(install, tmp_path):
    install(FakeSandbox())

    result = run("cp", str(tmp_path), f"{SID}:/w/x")

    assert result.exit_code == USAGE_ERROR
    assert "use -r for directories" in result.stderr


def test_cp_download_into_a_missing_directory_exits_2(install, tmp_path):
    install(FakeSandbox())

    result = run("cp", f"{SID}:/w/x", str(tmp_path / "nodir" / "x"))

    assert result.exit_code == USAGE_ERROR
    assert "does not exist" in result.stderr


def test_cp_client_error_in_json_keeps_the_client_source_and_exits_2(install, tmp_path):
    install(FakeSandbox())

    result = run("cp", str(tmp_path / "missing.txt"), f"{SID}:/w/x", as_json=True)

    assert result.exit_code == USAGE_ERROR
    error = json.loads(result.stdout)["error"]
    assert error["source"] == "client"
    assert "no such file:" in error["message"]


def test_cp_two_local_paths_still_exit_2(install, tmp_path):
    install(FakeSandbox())

    result = run("cp", str(tmp_path), str(tmp_path))

    assert result.exit_code == USAGE_ERROR


def test_cp_failure_after_a_request_was_sent_still_exits_125(install, tmp_path):
    error = ApiError("boom", code="DRIVER_ERROR", status_code=502)
    install(FakeSandbox(fs=FakeFs(upload_error=error)))
    source = tmp_path / "one.txt"
    source.write_text("x")

    result = run("cp", str(source), f"{SID}:/w/x")

    assert result.exit_code == PLATFORM_FAILURE


# --- cp -r into a read-only mount -------------------------------------------------------------


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "tree"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_bytes(b"alpha")
    (root / "sub" / "b.txt").write_bytes(b"beta")
    return root


def read_only_put_error():
    return ApiError(
        NOTHING_WRITTEN,
        code="READ_ONLY_PATH",
        status_code=409,
        details={"path": DEST},
        request_id=REQUEST_ID,
    )


def tar_stderr_for(entry):
    return f"tar: {entry}: Cannot open: Read-only file system\n"


def test_cp_single_file_read_only_message_carries_the_request_id(install, tmp_path):
    install(FakeSandbox(fs=FakeFs(upload_error=read_only_put_error())))
    source = tmp_path / "one.txt"
    source.write_text("x")

    result = run("cp", str(source), f"{SID}:{DEST}")

    assert NOTHING_WRITTEN in result.stderr
    assert f"(request id {REQUEST_ID})" in result.stderr


def test_cp_r_refused_at_the_first_entry_says_nothing_was_written(install, tree):
    install(FakeSandbox(exec_result(2, stderr=tar_stderr_for("./sub"))))

    result = run("cp", "-r", str(tree), f"{SID}:{DEST}")

    assert result.exit_code == PLATFORM_FAILURE
    assert f"error: READ_ONLY_PATH: {NOTHING_WRITTEN}" in result.stderr
    assert EARLIER_ENTRIES not in result.stderr
    assert f"(request id {REQUEST_ID})" in result.stderr


def test_cp_r_refused_after_earlier_entries_keeps_the_partial_note_and_the_id(install, tree):
    install(FakeSandbox(exec_result(2, stderr=tar_stderr_for("sub/b.txt"))))

    result = run("cp", "-r", str(tree), f"{SID}:{DEST}")

    assert "nothing was written" not in result.stderr
    assert EARLIER_ENTRIES in result.stderr
    assert f"(request id {REQUEST_ID})" in result.stderr


def test_cp_r_mkdir_refusal_says_nothing_was_written(install, tree):
    stderr = f"mkdir: cannot create directory '{DEST}': Read-only file system\n"
    install(FakeSandbox(exec_result(1, stderr=stderr)))

    result = run("cp", "-r", str(tree), f"{SID}:{DEST}")

    assert NOTHING_WRITTEN in result.stderr
    assert f"(request id {REQUEST_ID})" in result.stderr


def test_cp_r_an_unrecognised_refused_entry_keeps_the_partial_note(install, tree):
    install(FakeSandbox(exec_result(2, stderr=tar_stderr_for("elsewhere/c.txt"))))

    result = run("cp", "-r", str(tree), f"{SID}:{DEST}")

    assert EARLIER_ENTRIES in result.stderr
    assert "nothing was written" not in result.stderr


def test_cp_r_an_earlier_other_error_line_keeps_the_partial_note(install, tree):
    stderr = "tar: ./sub: Cannot open: File exists\n" + tar_stderr_for("./sub")
    install(FakeSandbox(exec_result(2, stderr=stderr)))

    result = run("cp", "-r", str(tree), f"{SID}:{DEST}")

    assert EARLIER_ENTRIES in result.stderr


def test_cp_r_read_only_json_error_has_the_request_id(install, tree):
    install(FakeSandbox(exec_result(2, stderr=tar_stderr_for("./sub"))))

    result = run("cp", "-r", str(tree), f"{SID}:{DEST}", as_json=True)

    error = json.loads(result.stdout)["error"]
    assert error["code"] == "READ_ONLY_PATH"
    assert error["request_id"] == REQUEST_ID
    assert error["message"] == NOTHING_WRITTEN


def test_cp_r_without_a_known_request_id_still_reports_honestly(install, tree):
    install(FakeSandbox(exec_result(2, stderr=tar_stderr_for("./sub")), request_id=None))

    result = run("cp", "-r", str(tree), f"{SID}:{DEST}", as_json=True)

    error = json.loads(result.stdout)["error"]
    assert error["message"] == NOTHING_WRITTEN
    assert error["request_id"] is None


def test_cp_r_server_refusal_of_the_archive_put_keeps_its_own_request_id(install, tree):
    install(FakeSandbox(fs=FakeFs(upload_error=read_only_put_error())))

    result = run("cp", "-r", str(tree), f"{SID}:{DEST}")

    assert f"error: READ_ONLY_PATH: {NOTHING_WRITTEN}" in result.stderr
    assert result.stderr.count(f"(request id {REQUEST_ID})") == 1
