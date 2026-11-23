"""Round 56: ``sandfort cp -r`` reports the sum of the file sizes, not the archive size."""

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
from sandfort_cli import cp_cmd  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk.models import ExecResult  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
FIRST = b"alpha"  # 5 bytes
SECOND = b"sixteen bytes!!!"  # 16 bytes
TOTAL_BYTES = len(FIRST) + len(SECOND)


class FakeStream:
    def __init__(self, data: bytes):
        self._data = data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def __iter__(self):
        yield self._data


class FakeFs:
    def __init__(self, download_tar: bytes = b""):
        self.uploads: dict[str, bytes] = {}
        self.download_tar = download_tar

    def upload_file(self, path, data, *, size_bytes=None, chunk_size=0, **_):
        body = data.read()
        self.uploads[path] = body
        return SimpleNamespace(size_bytes=len(body))

    def delete(self, path, *, recursive=False):
        return None

    def download_dir(self, path, *, chunk_size=0):
        return FakeStream(self.download_tar)


class FakeSandbox:
    def __init__(self, fs: FakeFs):
        self.fs = fs

    def process_exec(self, command=None, *, argv=None, **_):
        return ExecResult(
            exit_code=0,
            stdout="",
            stderr="",
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
def fake_client(monkeypatch):
    def install(sandbox: FakeSandbox) -> None:
        @contextmanager
        def opened():
            yield FakeClient(sandbox)

        monkeypatch.setattr(cp_cmd, "open_client", opened)

    return install


def run_cp(*args: str):
    return CliRunner().invoke(create_app(), ["--json", "cp", *args])


def tar_of_two_files() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, content in (("one.txt", FIRST), ("two.txt", SECOND)):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def test_upload_dir_reports_the_sum_of_the_file_sizes(tmp_path, fake_client):
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "one.txt").write_bytes(FIRST)
    (tree / "two.txt").write_bytes(SECOND)
    fs = FakeFs()
    fake_client(FakeSandbox(fs))

    result = run_cp("-r", str(tree), f"{SID}:/x")

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["bytes"] == TOTAL_BYTES
    assert payload["files"] == 2
    (archive_body,) = fs.uploads.values()
    assert len(archive_body) != TOTAL_BYTES  # the archive size is no longer what is reported


def test_download_dir_reports_the_sum_of_the_extracted_file_sizes(tmp_path, fake_client):
    archive_bytes = tar_of_two_files()
    assert len(archive_bytes) != TOTAL_BYTES
    fake_client(FakeSandbox(FakeFs(download_tar=archive_bytes)))
    target = tmp_path / "out"

    result = run_cp("-r", f"{SID}:/x", str(target))

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["bytes"] == TOTAL_BYTES
    assert payload["files"] == 2
    assert (target / "one.txt").read_bytes() == FIRST
    assert (target / "two.txt").read_bytes() == SECOND
