"""``sandfort cp -r``: directory upload and download against fake SDK sandboxes (no network)."""

import io
import json
import sys
import tarfile
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli import cp_cmd, cp_dir  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.output import CliError  # noqa: E402
from sandfort_sdk import Conflict, NotFound, PayloadTooLarge  # noqa: E402
from sandfort_sdk.models import ExecResult  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
EXPECTED_SCRIPT = 'mkdir -p "$1" && tar -xzf "$2" -C "$1"'
NO_TAR = "the sandbox image has no tar; install it or copy files one by one"


def exec_result(exit_code=0, stderr=""):
    return ExecResult(
        exit_code=exit_code,
        stdout="",
        stderr=stderr,
        timed_out=False,
        truncated=False,
        duration_ms=1,
    )


class FakeStream:
    def __init__(self, data: bytes):
        self._data = data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def __iter__(self):
        for start in range(0, len(self._data), 1000):
            yield self._data[start : start + 1000]


class FakeFs:
    def __init__(self, *, download_tar=b"", upload_error=None, delete_error=None):
        self.uploads: dict[str, bytes] = {}
        self.deleted: list[str] = []
        self.download_tar = download_tar
        self.downloaded: list[str] = []
        self.upload_error = upload_error
        self.delete_error = delete_error

    def upload_file(self, path, data, *, size_bytes=None, chunk_size=0, **_):
        if self.upload_error is not None:
            raise self.upload_error
        body = data.read()
        assert size_bytes in (None, len(body))
        self.uploads[path] = body
        return SimpleNamespace(size_bytes=len(body))

    def delete(self, path, *, recursive=False):
        self.deleted.append(path)
        if self.delete_error is not None:
            raise self.delete_error

    def download_dir(self, path, *, chunk_size=0):
        self.downloaded.append(path)
        return FakeStream(self.download_tar)


class FakeSandbox:
    def __init__(self, fs: FakeFs, result: ExecResult | None = None):
        self.fs = fs
        self.result = result or exec_result()
        self.calls: list[list[str]] = []

    def process_exec(self, command=None, *, argv=None, **_):
        assert command is None
        self.calls.append(list(argv))
        return self.result


def make_tree(root: Path) -> Path:
    tree = root / "mydir"
    (tree / "sub").mkdir(parents=True)
    (tree / "a").write_text("alpha")
    (tree / "sub" / "b.txt").write_text("beta")
    (tree / "link").symlink_to("a")
    return tree


def tar_bytes(members: dict[str, bytes | None]) -> bytes:
    """An uncompressed tar; a ``None`` value is a directory entry."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            if content is None:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            else:
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def open_gz(body: bytes) -> tarfile.TarFile:
    return tarfile.open(fileobj=io.BytesIO(body), mode="r:gz")


# --- upload --------------------------------------------------------------------------------


def test_upload_packs_contents_uploads_under_tmp_and_extracts(tmp_path):
    tree = make_tree(tmp_path)
    fs = FakeFs()
    sandbox = FakeSandbox(fs)

    stats = cp_dir.upload_dir(sandbox, tree, "/x")

    (remote_tar,) = fs.uploads
    assert remote_tar.startswith("/tmp/.sandfort-cp-")
    assert remote_tar.endswith(".tar.gz")
    assert sandbox.calls == [["sh", "-c", EXPECTED_SCRIPT, "sh", "/x", remote_tar]]
    assert fs.deleted == [remote_tar]
    with open_gz(fs.uploads[remote_tar]) as archive:
        assert sorted(archive.getnames()) == ["a", "link", "sub", "sub/b.txt"]
        assert archive.getmember("link").issym()
        assert archive.getmember("link").linkname == "a"
        assert archive.extractfile("sub/b.txt").read() == b"beta"
    assert stats.bytes == 9  # alpha 5 + beta 4: regular files only, not the archive
    assert stats.files == 2


def test_upload_stores_a_symlinked_directory_as_a_link(tmp_path):
    # r65: only links that stay inside the tree are stored; outward ones are skipped.
    tree = make_tree(tmp_path)
    (tree / "outside").symlink_to("sub")
    fs = FakeFs()

    cp_dir.upload_dir(FakeSandbox(fs), tree, "/x")

    (body,) = fs.uploads.values()
    with open_gz(body) as archive:
        assert archive.getmember("outside").issym()
        assert not any(name.startswith("outside/") for name in archive.getnames())


def test_upload_deletes_the_temporary_tar_even_when_extract_fails(tmp_path):
    fs = FakeFs()
    sandbox = FakeSandbox(fs, exec_result(2, "tar: boom"))

    with pytest.raises(CliError, match="exit 2.*tar: boom"):
        cp_dir.upload_dir(sandbox, make_tree(tmp_path), "/x")

    (remote_tar,) = fs.uploads
    assert fs.deleted == [remote_tar]


def test_upload_ignores_a_failing_cleanup_delete(tmp_path):
    fs = FakeFs(delete_error=NotFound("gone"))

    stats = cp_dir.upload_dir(FakeSandbox(fs), make_tree(tmp_path), "/x")

    assert stats.files == 2
    assert len(fs.deleted) == 1


def test_upload_reports_a_missing_tar(tmp_path):
    fs = FakeFs()
    sandbox = FakeSandbox(fs, exec_result(127))

    with pytest.raises(CliError) as caught:
        cp_dir.upload_dir(sandbox, make_tree(tmp_path), "/x")

    assert str(caught.value) == NO_TAR
    assert len(fs.deleted) == 1


def test_upload_too_large_adds_the_directory_hint(tmp_path):
    fs = FakeFs(upload_error=PayloadTooLarge("upload exceeds 256 MiB"))

    with pytest.raises(CliError) as caught:
        cp_dir.upload_dir(FakeSandbox(fs), make_tree(tmp_path), "/x")

    assert str(caught.value) == (
        "upload exceeds 256 MiB (directory archive too large; copy subdirectories separately)"
    )
    assert len(fs.deleted) == 1


def test_upload_rejects_an_empty_remote_path(tmp_path):
    fs = FakeFs()
    sandbox = FakeSandbox(fs)

    with pytest.raises(CliError, match="must not be empty") as caught:
        cp_dir.upload_dir(sandbox, make_tree(tmp_path), "")

    # runs after the sandbox lookup, so it is not a client error; nothing reached the sandbox
    assert caught.value.client is False
    assert fs.uploads == {}
    assert sandbox.calls == []


# --- download ------------------------------------------------------------------------------


def test_download_extracts_into_a_new_local_directory(tmp_path):
    tar = tar_bytes({"sub": None, "a": b"alpha", "sub/b.txt": b"beta"})
    sandbox = FakeSandbox(FakeFs(download_tar=tar))
    target = tmp_path / "new" / "out"

    stats = cp_dir.download_dir(sandbox, "/x", target)

    assert (target / "a").read_bytes() == b"alpha"
    assert (target / "sub" / "b.txt").read_bytes() == b"beta"
    assert stats.bytes == 9  # alpha 5 + beta 4: regular files only, not the archive
    assert stats.files == 2


def test_download_strips_the_top_level_directory(tmp_path):
    tar = tar_bytes({"x": None, "x/a": b"alpha", "x/sub": None, "x/sub/b.txt": b"beta"})
    sandbox = FakeSandbox(FakeFs(download_tar=tar))
    target = tmp_path / "out"

    stats = cp_dir.download_dir(sandbox, "/w/x", target)

    assert (target / "a").read_bytes() == b"alpha"
    assert (target / "sub" / "b.txt").read_bytes() == b"beta"
    assert not (target / "x").exists()
    assert stats.files == 2


def test_download_strips_a_root_that_repeats_inside_the_directory(tmp_path):
    tar = tar_bytes({"x": None, "x/x": None, "x/x/a": b"alpha"})
    sandbox = FakeSandbox(FakeFs(download_tar=tar))

    cp_dir.download_dir(sandbox, "/x", tmp_path / "out")

    assert (tmp_path / "out" / "x" / "a").read_bytes() == b"alpha"
    assert not (tmp_path / "out" / "a").exists()


@pytest.mark.parametrize(
    "members",
    [
        {"other": None, "other/a": b"1"},
        {"x": None, "x/a": b"1", "stray": b"2"},
        {"a": b"1"},
    ],
)
def test_download_keeps_names_unless_every_member_is_under_the_directory_name(tmp_path, members):
    sandbox = FakeSandbox(FakeFs(download_tar=tar_bytes(members)))
    target = tmp_path / "out"

    cp_dir.download_dir(sandbox, "/x", target)

    assert sorted(p.name for p in target.iterdir()) == sorted(
        name for name in members if "/" not in name
    )


@pytest.mark.parametrize("remote", ["/w/x/", "/w/x//"])
def test_download_accepts_a_trailing_slash(tmp_path, remote):
    fs = FakeFs(download_tar=tar_bytes({"x": None, "x/a": b"alpha"}))

    cp_dir.download_dir(FakeSandbox(fs), remote, tmp_path / "out")

    assert fs.downloaded == ["/w/x"]
    assert (tmp_path / "out" / "a").read_bytes() == b"alpha"


@pytest.mark.parametrize("name", ["../evil", "sub/../../evil", "/abs/evil"])
def test_download_rejects_unsafe_member_names(tmp_path, name):
    sandbox = FakeSandbox(FakeFs(download_tar=tar_bytes({"ok": b"1", name: b"x"})))
    target = tmp_path / "out"

    with pytest.raises(CliError, match="unsafe path"):
        cp_dir.download_dir(sandbox, "/x", target)

    assert not (tmp_path / "evil").exists()
    assert not (target / "ok").exists()


def test_download_skips_links_pointing_outside(tmp_path):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo("escape")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../etc/passwd"
        archive.addfile(info)
    sandbox = FakeSandbox(FakeFs(download_tar=buffer.getvalue()))

    stats = cp_dir.download_dir(sandbox, "/x", tmp_path / "out")

    assert not (tmp_path / "out" / "escape").is_symlink()
    assert stats.skipped == (
        "skipped symlink escape -> ../../etc/passwd (points outside the copied tree)",
    )


def test_download_reports_a_corrupt_archive(tmp_path):
    sandbox = FakeSandbox(FakeFs(download_tar=b"this is not a tar archive" * 50))

    with pytest.raises(CliError, match="cannot extract"):
        cp_dir.download_dir(sandbox, "/x", tmp_path / "out")


# --- command -------------------------------------------------------------------------------


class FakeClient:
    def __init__(self, sandbox):
        self._sandbox = sandbox

    def get(self, sandbox_id):
        assert sandbox_id == SID
        return self._sandbox


@pytest.fixture
def fake_client(monkeypatch):
    def install(sandbox):
        @contextmanager
        def opened():
            yield FakeClient(sandbox)

        monkeypatch.setattr(cp_cmd, "open_client", opened)

    return install


def run_cp(*args):
    return CliRunner().invoke(create_app(), ["--json", "cp", *args])


def test_cp_r_upload_prints_bytes_and_files(tmp_path, fake_client):
    fs = FakeFs()
    fake_client(FakeSandbox(fs))

    result = run_cp("-r", str(make_tree(tmp_path)), f"{SID}:/x")

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["files"] == 2
    assert payload["bytes"] == 9  # alpha 5 + beta 4
    assert payload["destination"] == f"{SID}:/x"


def test_cp_r_download_prints_bytes_and_files(tmp_path, fake_client):
    fake_client(FakeSandbox(FakeFs(download_tar=tar_bytes({"a": b"alpha"}))))
    target = tmp_path / "out"

    result = run_cp("--recursive", f"{SID}:/x", str(target))

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["files"] == 1
    assert (target / "a").read_bytes() == b"alpha"


def test_cp_r_with_a_plain_file_still_copies_one_file(tmp_path, fake_client):
    fs = FakeFs()
    fake_client(FakeSandbox(fs))
    source = tmp_path / "one.txt"
    source.write_text("x")

    result = run_cp("-r", str(source), f"{SID}:/w/one")

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["files"] == 1
    assert list(fs.uploads) == ["/w/one"]


def test_cp_without_r_rejects_a_directory_with_the_hint(tmp_path, fake_client):
    fake_client(FakeSandbox(FakeFs()))
    tree = make_tree(tmp_path)

    result = CliRunner().invoke(create_app(), ["cp", str(tree), f"{SID}:/x"])

    assert result.exit_code == 2
    assert f"{tree} is not a regular file; use -r for directories" in result.stderr


def test_cp_missing_tar_exits_1_with_the_message(tmp_path, fake_client):
    fake_client(FakeSandbox(FakeFs(), exec_result(127)))

    result = CliRunner().invoke(create_app(), ["cp", "-r", str(make_tree(tmp_path)), f"{SID}:/x"])

    assert result.exit_code == 125
    assert NO_TAR in result.stderr


NOT_RUNNING = "toolbox operations require a started sandbox"


def test_cp_download_with_a_trailing_slash_puts_the_contents_in_the_local_directory(
    tmp_path, fake_client
):
    fs = FakeFs(download_tar=tar_bytes({"x": None, "x/a": b"alpha"}))
    fake_client(FakeSandbox(fs))
    target = tmp_path / "out"

    result = run_cp("-r", f"{SID}:/w/x/", str(target))

    assert result.exit_code == 0, result.output
    assert fs.downloaded == ["/w/x"]
    assert (target / "a").read_bytes() == b"alpha"


def test_cp_hints_how_to_start_a_sandbox_that_is_not_running(tmp_path, fake_client):
    fake_client(FakeSandbox(FakeFs(upload_error=Conflict(NOT_RUNNING, status_code=409))))
    source = tmp_path / "one.txt"
    source.write_text("x")

    result = CliRunner().invoke(create_app(), ["cp", str(source), f"{SID}:/w/one"])

    assert result.exit_code == 125
    assert result.stderr.startswith(f"error: CONFLICT: {NOT_RUNNING}")
    assert result.stderr.endswith(f"\nstart it with: sandfort sandbox start {SID}\n")


def test_cp_not_running_adds_a_hint_field_in_json_mode(tmp_path, fake_client):
    fake_client(FakeSandbox(FakeFs(upload_error=Conflict(NOT_RUNNING, status_code=409))))
    source = tmp_path / "one.txt"
    source.write_text("x")

    result = run_cp(str(source), f"{SID}:/w/one")

    assert result.exit_code == 125
    error = json.loads(result.stdout)["error"]
    assert error["message"] == NOT_RUNNING
    assert error["hint"] == f"start it with: sandfort sandbox start {SID}"


def test_cp_adds_no_hint_to_an_unrelated_conflict(tmp_path, fake_client):
    fake_client(FakeSandbox(FakeFs(upload_error=Conflict("modified", status_code=409))))
    source = tmp_path / "one.txt"
    source.write_text("x")

    result = CliRunner().invoke(create_app(), ["cp", str(source), f"{SID}:/w/one"])

    assert result.exit_code == 125
    assert "start it with" not in result.stderr
