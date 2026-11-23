"""Round 60: ``create --wait`` cleans up a failed start; ``cp -r`` into a read-only mount.

The CLI mirrors the SDK: a sandbox that ends in ``error`` (``start_failed``) while ``--wait``
blocks is deleted unless ``--keep-on-failure`` is given, and the error says what happened to it.
``cp -r`` into a read-only mount shows the ``READ_ONLY_PATH`` message the single-file ``cp``
shows, not the raw ``tar`` error.
"""

import json
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli import config, cp_cmd, sandboxes  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import ApiError, SandboxDestroyedError, SandboxFailedError  # noqa: E402
from sandfort_sdk.models import ExecResult  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
REASON = "the container could not be started"
READ_ONLY_DEST = "/data/ro"
READ_ONLY_MESSAGE = f"{READ_ONLY_DEST} is on a read-only mount; nothing was written"
STOPPED_NOTE = (
    "the transfer stopped at the first read-only path; earlier entries may have been written"
)
TAR_STDERR = "tar: ./a.txt: Cannot open: Read-only file system\n"
RUNNER = CliRunner()


@pytest.fixture(autouse=True)
def profile(monkeypatch, tmp_path):
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, KEY)


# --- create --wait: a failed start -----------------------------------------------------------


def failure(state="error", *, deleted=False, cls=SandboxFailedError):
    text = f"sandbox {SID} is {state}: {REASON}"
    return cls(
        text,
        sandbox_id=SID,
        state=state,
        request_id="req_create",
        error_reason=REASON,
        error_code="start_failed",
        deleted=deleted,
    )


class StubClient:
    """What the CLI sees of the SDK client: a create that fails, and a recording delete."""

    def __init__(self, error, delete_error=None):
        self.error = error
        self.delete_error = delete_error
        self.created = []
        self.deleted = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def create_sandbox(self, **kwargs):
        self.created.append(kwargs)
        raise self.error

    def delete(self, sandbox_id):
        self.deleted.append(sandbox_id)
        if self.delete_error is not None:
            raise self.delete_error


def create(monkeypatch, client, *extra, as_json=False):
    monkeypatch.setattr(sandboxes, "open_client", lambda: client)
    args = (["--json"] if as_json else []) + ["sandbox", "create", "demo", "--wait", *extra]
    return RUNNER.invoke(create_app(None), args)


def delete_refused():
    return ApiError("the runtime is busy", code="DRIVER_ERROR", status_code=502)


def test_failed_start_deletes_the_sandbox_by_default(monkeypatch):
    client = StubClient(failure())

    result = create(monkeypatch, client)

    assert result.exit_code == 1
    assert client.deleted == [SID]
    assert result.stderr.startswith("error: ")
    assert "was deleted" in result.stderr
    assert SID in result.stderr and REASON in result.stderr
    assert len(result.stderr.strip().splitlines()) == 1


def test_failed_start_state_start_failed_is_cleaned_up_too(monkeypatch):
    client = StubClient(failure("start_failed"))

    result = create(monkeypatch, client)

    assert result.exit_code == 1
    assert client.deleted == [SID]
    assert "was deleted" in result.stderr


def test_keep_on_failure_keeps_the_sandbox_and_says_so(monkeypatch):
    client = StubClient(failure())

    result = create(monkeypatch, client, "--keep-on-failure")

    assert result.exit_code == 1
    assert client.deleted == []
    assert client.created[0]["delete_on_failure"] is False
    assert "was kept" in result.stderr and "--keep-on-failure" in result.stderr
    assert f"sandfort sandbox rm {SID}" in result.stderr
    assert "was deleted" not in result.stderr


def test_failed_delete_keeps_the_sandbox_and_says_why(monkeypatch):
    client = StubClient(failure(), delete_error=delete_refused())

    result = create(monkeypatch, client)

    assert result.exit_code == 1
    assert client.deleted == [SID]
    assert "was kept" in result.stderr
    assert "could not be deleted" in result.stderr
    assert "the runtime is busy" in result.stderr
    assert f"sandfort sandbox rm {SID}" in result.stderr
    assert "was deleted" not in result.stderr


def test_a_sandbox_the_sdk_already_deleted_is_not_deleted_again(monkeypatch):
    client = StubClient(failure().as_deleted())  # what the SDK raises after its own cleanup

    result = create(monkeypatch, client)

    assert result.exit_code == 1
    assert client.deleted == []
    assert result.stderr.count("was deleted") == 1


def test_a_destroyed_sandbox_is_left_alone(monkeypatch):
    client = StubClient(failure("destroyed", cls=SandboxDestroyedError))

    result = create(monkeypatch, client)

    assert result.exit_code == 1
    assert client.deleted == []


def test_json_error_carries_the_sandbox_id_and_reason_after_a_delete(monkeypatch):
    client = StubClient(failure())

    result = create(monkeypatch, client, as_json=True)

    assert result.exit_code == 1
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "SANDBOX_FAILED"
    assert error["sandbox_id"] == SID
    assert error["error_reason"] == REASON
    assert error["error_code"] == "start_failed"
    assert error["state"] == "error"
    assert error["deleted"] is True
    assert "was deleted" in error["message"]


def test_json_error_says_not_deleted_when_the_delete_fails(monkeypatch):
    client = StubClient(failure(), delete_error=delete_refused())

    result = create(monkeypatch, client, as_json=True)

    assert result.exit_code == 1
    error = json.loads(result.stdout)["error"]
    assert error["sandbox_id"] == SID
    assert error["error_reason"] == REASON
    assert error["deleted"] is False
    assert "was kept" in error["message"]


def test_json_error_with_keep_on_failure_has_the_fields(monkeypatch):
    client = StubClient(failure())

    result = create(monkeypatch, client, "--keep-on-failure", as_json=True)

    assert result.exit_code == 1
    error = json.loads(result.stdout)["error"]
    assert error["sandbox_id"] == SID
    assert error["error_reason"] == REASON
    assert error["deleted"] is False


# --- cp -r into a read-only mount ------------------------------------------------------------


class FakeFs:
    def __init__(self, upload_error=None):
        self.upload_error = upload_error
        self.uploads = []

    def upload_file(self, path, data, *, size_bytes=None, chunk_size=0, **_):
        if self.upload_error is not None:
            raise self.upload_error
        body = data.read()
        self.uploads.append(path)
        return SimpleNamespace(size_bytes=len(body))

    def delete(self, path, *, recursive=False):
        return None


class FakeSandbox:
    def __init__(self, fs, exec_result=None):
        self.fs = fs
        self.exec_result = exec_result

    def process_exec(self, command=None, *, argv=None, **_):
        assert self.exec_result is not None
        return self.exec_result


def tar_failure(stderr=TAR_STDERR):
    return ExecResult(
        exit_code=2, stdout="", stderr=stderr, timed_out=False, truncated=False, duration_ms=1
    )


def read_only_error():
    return ApiError(
        READ_ONLY_MESSAGE,
        code="READ_ONLY_PATH",
        status_code=409,
        details={"path": READ_ONLY_DEST},
    )


@pytest.fixture
def fake_sandbox(monkeypatch):
    def install(sandbox):
        @contextmanager
        def opened():
            yield SimpleNamespace(get=lambda sandbox_id: sandbox)

        monkeypatch.setattr(cp_cmd, "open_client", opened)

    return install


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "a.txt").write_bytes(b"alpha")
    return root


def run_cp(*args, as_json=False):
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + ["cp", *args])


def test_cp_r_into_a_read_only_mount_shows_the_read_only_code_and_a_partial_note(
    tree, fake_sandbox
):
    fake_sandbox(FakeSandbox(FakeFs(upload_error=read_only_error())))
    single = run_cp(str(tree / "a.txt"), f"{SID}:{READ_ONLY_DEST}")
    fake_sandbox(FakeSandbox(FakeFs(), tar_failure()))

    recursive = run_cp("-r", str(tree), f"{SID}:{READ_ONLY_DEST}")

    assert single.exit_code != 0
    assert "READ_ONLY_PATH" in single.stderr
    assert recursive.exit_code == single.exit_code
    # Round 61: the first (only) entry was refused, so nothing was written, as for one file.
    assert f"error: READ_ONLY_PATH: {READ_ONLY_MESSAGE}" in recursive.stderr
    assert "tar" not in recursive.stderr and "Read-only file system" not in recursive.stderr


def test_cp_r_does_not_claim_nothing_was_written_after_a_partial_extract(tree, fake_sandbox):
    stderr = "tar: ./ok.txt: Cannot open: File exists\ntar: ./sub/b.txt: Read-only file system\n"
    fake_sandbox(FakeSandbox(FakeFs(), tar_failure(stderr)))

    result = run_cp("-r", str(tree), f"{SID}:{READ_ONLY_DEST}")

    assert result.exit_code != 0
    assert "nothing was written" not in result.stderr
    assert STOPPED_NOTE in result.stderr


def test_cp_r_read_only_json_error_has_the_code(tree, fake_sandbox):
    stderr = "mkdir: cannot create directory '/data/ro': Read-only file system\n"
    fake_sandbox(FakeSandbox(FakeFs(), tar_failure(stderr)))

    result = run_cp("-r", str(tree), f"{SID}:{READ_ONLY_DEST}", as_json=True)

    assert result.exit_code != 0
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "READ_ONLY_PATH"
    assert error["message"] == READ_ONLY_MESSAGE  # round 61: mkdir refused, nothing written


@pytest.mark.parametrize(
    "stderr",
    [
        "tar: ./read-only file system.txt: Permission denied\n",
        "tar: ./notes marked read-only.txt: Cannot open: Permission denied\n",
        "Read-only file system is what the docs call it\n",
    ],
    ids=["name-in-path", "marker-mid-line", "no-error-prefix"],
)
def test_cp_r_marker_text_inside_other_tar_output_is_not_read_only(tree, fake_sandbox, stderr):
    fake_sandbox(FakeSandbox(FakeFs(), tar_failure(stderr)))

    result = run_cp("-r", str(tree), f"{SID}:{READ_ONLY_DEST}")

    assert result.exit_code != 0
    assert "READ_ONLY_PATH" not in result.stderr
    assert "extracting the archive failed (exit 2)" in result.stderr


def test_cp_r_marker_on_stdout_only_is_not_read_only(tree, fake_sandbox):
    out = ExecResult(
        exit_code=2,
        stdout="tar: ./a.txt: Read-only file system\n",
        stderr="tar: ./a.txt: Permission denied\n",
        timed_out=False,
        truncated=False,
        duration_ms=1,
    )
    fake_sandbox(FakeSandbox(FakeFs(), out))

    result = run_cp("-r", str(tree), f"{SID}:{READ_ONLY_DEST}")

    assert result.exit_code != 0
    assert "READ_ONLY_PATH" not in result.stderr


def test_cp_r_server_409_on_the_archive_put_is_rendered_the_same(tree, fake_sandbox):
    fake_sandbox(FakeSandbox(FakeFs(upload_error=read_only_error())))

    result = run_cp("-r", str(tree), f"{SID}:{READ_ONLY_DEST}")

    assert result.exit_code != 0
    assert f"error: READ_ONLY_PATH: {READ_ONLY_MESSAGE}" in result.stderr


def test_cp_r_other_extract_failures_keep_their_text(tree, fake_sandbox):
    fake_sandbox(FakeSandbox(FakeFs(), tar_failure("tar: ./a.txt: Permission denied\n")))

    result = run_cp("-r", str(tree), f"{SID}:{READ_ONLY_DEST}")

    assert result.exit_code != 0
    assert "extracting the archive failed (exit 2)" in result.stderr
    assert "Permission denied" in result.stderr
    assert "READ_ONLY_PATH" not in result.stderr
