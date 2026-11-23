"""Round 59: first-use hints in ``sandfort exec`` (exit 127) and ``sandfort cp`` (paths)."""

import json
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import typer.main  # noqa: E402
from sandfort_cli import cp_cmd, exec_cmd  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import NotFound  # noqa: E402
from sandfort_sdk.models import ExecResult  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
COMMAND_NOT_FOUND = 127
PLATFORM_FAILURE = 125
USAGE_ERROR = 2  # round 61: a client-side cp check exits 2, like every usage error


class FakeFs:
    def __init__(self, missing: NotFound | None = None):
        self.missing = missing
        self.uploads: dict[str, bytes] = {}

    def download_file(self, path, *, chunk_size=0):
        assert self.missing is not None
        raise self.missing

    def upload_file(self, path, data, *, size_bytes=None, chunk_size=0, **_):
        body = data.read()
        self.uploads[path] = body
        return SimpleNamespace(size_bytes=len(body))


class FakeSandbox:
    def __init__(self, exit_code: int = 0, fs: FakeFs | None = None):
        self.exit_code = exit_code
        self.fs = fs or FakeFs()
        self.calls: list[dict] = []

    def process_exec(self, command=None, *, argv=None, **kwargs):
        self.calls.append({"argv": argv, **kwargs})
        # Round 64: exit 127 gets its hint only when stderr reports a missing command.
        missing = f"command not found: {argv[0]}\n" if self.exit_code == COMMAND_NOT_FOUND else ""
        return ExecResult(
            exit_code=self.exit_code,
            stdout="",
            stderr=missing,
            timed_out=False,
            truncated=False,
            duration_ms=1,
        )


class FakeClient:
    def __init__(self, sandbox: FakeSandbox):
        self._sandbox = sandbox

    def get(self, sandbox_id):
        assert sandbox_id == SID
        return self._sandbox


@pytest.fixture
def install(monkeypatch):
    def apply(sandbox: FakeSandbox) -> FakeSandbox:
        @contextmanager
        def opened():
            yield FakeClient(sandbox)

        monkeypatch.setattr(exec_cmd, "open_client", opened)
        monkeypatch.setattr(cp_cmd, "open_client", opened)
        return sandbox

    return apply


def run(*args: str):
    return CliRunner().invoke(create_app(), list(args))


def hint_lines(stderr: str) -> list[str]:
    return [line for line in stderr.splitlines() if "without a shell" in line]


def exec_option_names(param_name: str) -> list[str]:
    """The option names the real ``exec`` command declares for the parameter ``param_name``."""
    group = typer.main.get_command(create_app())
    return [
        name
        for param in group.commands["exec"].params  # type: ignore[attr-defined]
        if param.name == param_name
        for name in param.opts
    ]


# --- exec exit 127 ---------------------------------------------------------------------------


def test_exec_127_with_plain_argv_prints_one_hint_without_the_sh_c_part(install):
    install(FakeSandbox(exit_code=COMMAND_NOT_FOUND))

    result = run("exec", SID, "--", "nosuchtool", "arg")

    assert result.exit_code == COMMAND_NOT_FOUND
    (line,) = hint_lines(result.stderr)
    assert "sh -c" not in line
    assert result.stdout == ""


def test_exec_127_names_the_working_directory_and_the_real_cwd_option(install):
    install(FakeSandbox(exit_code=COMMAND_NOT_FOUND))
    cwd_names = exec_option_names("cwd")
    assert cwd_names == ["--cwd"]

    result = run("exec", SID, "--", "nosuchtool")

    (line,) = hint_lines(result.stderr)
    assert "working directory" in line
    assert "root directory" in line
    assert cwd_names[0] in line


@pytest.mark.parametrize(
    "argv",
    [
        ["echo", "hi", "&&", "ls"],
        ["ls", "|", "wc"],
        ["ls", ";", "pwd"],
        ["cat", "x", ">", "out"],
        ["cat", "<", "in"],
        ["echo", "$HOME"],
        ["echo", "`id`"],
        ["ls", "*.txt"],
        ["ls", "file?"],
        ["echo", "'quoted'"],
        ["echo", '"quoted"'],
        ["ls -la /tmp"],
    ],
)
def test_exec_127_with_shell_syntax_shows_the_sh_c_example_with_the_typed_ref(install, argv):
    install(FakeSandbox(exit_code=COMMAND_NOT_FOUND))

    result = run("exec", SID, "--", *argv)

    assert result.exit_code == COMMAND_NOT_FOUND
    (line,) = hint_lines(result.stderr)
    assert f"sandfort exec {SID} -- sh -c '" in line


def test_exec_127_sh_c_example_carries_the_whole_command_as_one_quoted_argument(install):
    install(FakeSandbox(exit_code=COMMAND_NOT_FOUND))

    result = run("exec", SID, "--", "ls", "|", "wc", "-l")

    (line,) = hint_lines(result.stderr)
    assert f"sandfort exec {SID} -- sh -c 'ls | wc -l'" in line


@pytest.mark.parametrize("code", [0, 1, 2, 124, 128])
def test_exec_other_exit_codes_print_no_hint(install, code):
    install(FakeSandbox(exit_code=code))

    result = run("exec", SID, "--", "echo", "$HOME")

    assert result.exit_code == code
    assert hint_lines(result.stderr) == []
    assert "hint" not in result.stderr


def test_exec_127_json_puts_the_hint_in_the_result_object_not_on_stderr(install):
    install(FakeSandbox(exit_code=COMMAND_NOT_FOUND))

    result = run("--json", "exec", SID, "--", "ls", "|", "wc")

    assert result.exit_code == COMMAND_NOT_FOUND
    payload = json.loads(result.stdout)
    assert payload["exit_code"] == COMMAND_NOT_FOUND
    assert "without a shell" in payload["hint"]
    assert f"sandfort exec {SID} -- sh -c 'ls | wc'" in payload["hint"]
    assert "--cwd" in payload["hint"]
    assert result.stderr == ""


def test_exec_json_other_exit_codes_have_no_hint_field(install):
    install(FakeSandbox(exit_code=0))

    result = run("--json", "exec", SID, "--", "true")

    assert result.exit_code == 0
    assert "hint" not in json.loads(result.stdout)


def test_exec_127_hint_text_is_sanitised(install):
    install(FakeSandbox(exit_code=COMMAND_NOT_FOUND))

    result = run("exec", SID, "--", "echo", "\x1b]52;c;AAAA\x07 $HOME")

    (line,) = hint_lines(result.stderr)
    assert "\x1b" not in line
    assert "\x07" not in line


# --- cp download of a missing remote file ----------------------------------------------------


def missing_file_error() -> NotFound:
    return NotFound(
        "the object does not exist",
        status_code=404,
        details={"foo": "bar"},
        request_id="req_1",
    )


def test_cp_download_missing_file_error_names_the_remote_reference(install, tmp_path):
    install(FakeSandbox(fs=FakeFs(missing=missing_file_error())))

    result = run("cp", f"{SID}:/etc/nope.txt", str(tmp_path / "out.txt"))

    assert result.exit_code == PLATFORM_FAILURE
    assert f"error: NOT_FOUND: {SID}:/etc/nope.txt: the object does not exist" in result.stderr
    assert "path=/etc/nope.txt" in result.stderr


def test_cp_download_missing_file_json_keeps_shape_and_adds_the_remote_path(install, tmp_path):
    install(FakeSandbox(fs=FakeFs(missing=missing_file_error())))

    result = run("--json", "cp", f"{SID}:/etc/nope.txt", str(tmp_path / "out.txt"))

    assert result.exit_code == PLATFORM_FAILURE
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "NOT_FOUND"
    assert error["message"] == f"{SID}:/etc/nope.txt: the object does not exist"
    assert error["details"] == {"foo": "bar", "path": "/etc/nope.txt"}
    assert error["request_id"] == "req_1"


def test_cp_download_other_not_found_errors_are_left_alone(install, tmp_path):
    gone = NotFound(f"sandbox {SID} not found", status_code=404)
    install(FakeSandbox(fs=FakeFs(missing=gone)))

    result = run("cp", f"{SID}:/etc/x", str(tmp_path / "out.txt"))

    assert result.exit_code == PLATFORM_FAILURE
    assert f"error: NOT_FOUND: sandbox {SID} not found" in result.stderr
    assert f"{SID}:/etc/x:" not in result.stderr


# --- cp with a relative remote path ----------------------------------------------------------


def test_cp_download_relative_remote_path_suggests_the_rewritten_argument(install, tmp_path):
    sandbox = install(FakeSandbox())

    result = run("cp", f"{SID}:notes/a.txt", str(tmp_path / "out.txt"))

    assert result.exit_code == USAGE_ERROR
    assert "must be absolute" in result.stderr
    assert f"{SID}:/notes/a.txt" in result.stderr
    assert "root directory" in result.stderr
    assert sandbox.calls == []


def test_cp_upload_relative_remote_path_suggests_the_rewritten_argument(install, tmp_path):
    source = tmp_path / "a.txt"
    source.write_text("x")
    sandbox = install(FakeSandbox())

    result = run("cp", str(source), f"{SID}:work/a.txt")

    assert result.exit_code == USAGE_ERROR
    assert "must be absolute" in result.stderr
    assert f"{SID}:/work/a.txt" in result.stderr
    assert sandbox.fs.uploads == {}


def test_cp_relative_remote_path_json_error_carries_the_same_message(install, tmp_path):
    install(FakeSandbox())

    result = run("--json", "cp", f"{SID}:notes/a.txt", str(tmp_path / "out.txt"))

    assert result.exit_code == USAGE_ERROR
    message = json.loads(result.stdout)["error"]["message"]
    assert "must be absolute" in message
    assert f"{SID}:/notes/a.txt" in message


def test_cp_absolute_remote_path_is_not_touched_by_the_new_check(install, tmp_path):
    install(FakeSandbox(fs=FakeFs(missing=missing_file_error())))

    result = run("cp", f"{SID}:/abs/file", str(tmp_path / "out.txt"))

    assert "must be absolute" not in result.stderr


# --- review fixes: exec 127 when a shell already ran -----------------------------------------

USAGE_LIMIT = 600  # sandfort_cli.sanitise.USAGE_MESSAGE_CHARS


def stderr_hint(stderr: str) -> str:
    (line,) = [line for line in stderr.splitlines() if line.startswith("hint: exit 127")]
    return line


@pytest.mark.parametrize(
    "argv",
    [
        ["sh", "-c", "nosuchtool | wc"],
        ["bash", "-c", "nosuchtool"],
        ["dash", "script.sh"],
        ["zsh", "-c", "nosuchtool && ls"],
        ["/bin/sh", "-c", "nosuchtool"],
        ["/usr/bin/bash", "-lc", "nosuchtool"],
    ],
)
def test_exec_127_after_a_shell_says_the_shell_reported_a_missing_command(install, argv):
    install(FakeSandbox(exit_code=COMMAND_NOT_FOUND))

    result = run("exec", SID, "--", *argv)

    assert result.exit_code == COMMAND_NOT_FOUND
    line = stderr_hint(result.stderr)
    assert "the shell reported a missing command" in line
    assert "without a shell" not in line
    assert "sh -c" not in line


def test_exec_127_with_a_program_named_like_a_shell_prefix_keeps_the_no_shell_hint(install):
    install(FakeSandbox(exit_code=COMMAND_NOT_FOUND))

    result = run("exec", SID, "--", "shellcheck", "x")

    line = stderr_hint(result.stderr)
    assert "without a shell" in line
    assert "the shell reported" not in line


def test_exec_127_json_hint_after_a_shell_has_no_sh_c_advice(install):
    install(FakeSandbox(exit_code=COMMAND_NOT_FOUND))

    result = run("--json", "exec", SID, "--", "sh", "-c", "nosuchtool | wc")

    hint = json.loads(result.stdout)["hint"]
    assert "the shell reported a missing command" in hint
    assert "sh -c" not in hint


# --- review fixes: exec 127 and --cwd --------------------------------------------------------


def test_exec_127_does_not_advise_cwd_when_cwd_was_passed(install):
    install(FakeSandbox(exit_code=COMMAND_NOT_FOUND))

    result = run("exec", "--cwd", "/work", SID, "--", "nosuchtool")

    line = stderr_hint(result.stderr)
    assert "--cwd" not in line
    assert "root directory" not in line


def test_exec_127_after_a_shell_with_cwd_gives_neither_cwd_nor_sh_c_advice(install):
    install(FakeSandbox(exit_code=COMMAND_NOT_FOUND))

    result = run("exec", "--cwd", "/work", SID, "--", "bash", "-c", "nosuchtool")

    line = stderr_hint(result.stderr)
    assert "--cwd" not in line
    assert "sh -c" not in line


# --- review fixes: exec 127 hint length ------------------------------------------------------


def test_exec_127_long_command_is_truncated_and_the_cwd_sentence_survives(install):
    install(FakeSandbox(exit_code=COMMAND_NOT_FOUND))
    long_word = "x" * 2000

    result = run("exec", SID, "--", "echo", long_word, "|", "wc")

    line = stderr_hint(result.stderr)
    assert len(line) <= USAGE_LIMIT
    assert f"sandfort exec {SID} -- sh -c 'echo xxx" in line
    assert "working directory" in line
    assert line.rstrip().endswith("which goes before the sandbox reference")
    assert long_word not in line


def test_exec_127_long_command_json_hint_keeps_the_cwd_sentence(install):
    install(FakeSandbox(exit_code=COMMAND_NOT_FOUND))

    result = run("--json", "exec", SID, "--", "echo", "y" * 3000, ";", "true")

    hint = json.loads(result.stdout)["hint"]
    assert len(hint) <= USAGE_LIMIT
    assert "sh -c 'echo yyy" in hint
    assert hint.endswith("which goes before the sandbox reference")


def test_exec_127_command_with_many_quotes_still_fits(install):
    install(FakeSandbox(exit_code=COMMAND_NOT_FOUND))

    result = run("exec", SID, "--", "echo", "'" * 900)

    line = stderr_hint(result.stderr)
    assert len(line) <= USAGE_LIMIT
    assert line.rstrip().endswith("which goes before the sandbox reference")


def test_exec_help_documents_the_hint_key_of_the_json_result():
    result = run("exec", "--help")

    assert result.exit_code == 0
    flat = " ".join(result.stdout.split())
    assert "hint" in flat
    assert "127" in flat


# --- review fixes: cp with a tilde remote path -----------------------------------------------


def test_cp_download_tilde_path_suggests_the_absolute_home_path(install, tmp_path):
    sandbox = install(FakeSandbox())

    result = run("cp", f"{SID}:~/notes/a.txt", str(tmp_path / "out.txt"))

    assert result.exit_code == USAGE_ERROR
    assert "must be absolute" in result.stderr
    assert "/~" not in result.stderr
    assert "not expanded" in result.stderr
    assert f"{SID}:/root/notes/a.txt" in result.stderr
    assert sandbox.calls == []


def test_cp_upload_tilde_path_suggests_the_absolute_home_path(install, tmp_path):
    source = tmp_path / "a.txt"
    source.write_text("x")
    sandbox = install(FakeSandbox())

    result = run("cp", str(source), f"{SID}:~/a.txt")

    assert result.exit_code == USAGE_ERROR
    assert "/~" not in result.stderr
    assert "home directory" in result.stderr
    assert f"{SID}:/root/a.txt" in result.stderr
    assert sandbox.fs.uploads == {}


@pytest.mark.parametrize("path", ["~", "~bob/x"])
def test_cp_other_tilde_forms_never_suggest_slash_tilde(install, tmp_path, path):
    install(FakeSandbox())

    result = run("--json", "cp", f"{SID}:{path}", str(tmp_path / "out.txt"))

    assert result.exit_code == USAGE_ERROR
    message = json.loads(result.stdout)["error"]["message"]
    assert "/~" not in message
    assert "not expanded" in message
    assert "/root" in message


def test_cp_relative_path_without_tilde_keeps_the_leading_slash_rewrite(install, tmp_path):
    install(FakeSandbox())

    result = run("cp", f"{SID}:notes/a.txt", str(tmp_path / "out.txt"))

    assert f"{SID}:/notes/a.txt" in result.stderr
    assert "not expanded" not in result.stderr
