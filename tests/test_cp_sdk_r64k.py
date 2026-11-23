"""Round 64k: cp -r skips links that leave the tree, uploads are owned by root, volume get takes
a name, and the SDK raises ReadOnlyPath for a read-only mount."""

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
import respx  # noqa: E402
import sandfort_sdk  # noqa: E402
from sandfort_cli import config, cp_cmd, cp_dir  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import ApiError, Conflict, ReadOnlyPath  # noqa: E402
from sandfort_sdk.exceptions import error_for  # noqa: E402
from sandfort_sdk.models import ExecResult  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
VOL_ID = "vol_01HZZZZZZZZZZZZZZZZZZZZZZZ"
CREATED = "2026-11-10T19:26:00Z"
RUNNER = CliRunner()


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
    def __init__(self, download_tar=b""):
        self.uploads: dict[str, bytes] = {}
        self.download_tar = download_tar

    def upload_file(self, path, data, *, size_bytes=None, chunk_size=0, **_):
        self.uploads[path] = data.read()
        return SimpleNamespace(size_bytes=len(self.uploads[path]))

    def delete(self, path, *, recursive=False):
        return None

    def download_dir(self, path, *, chunk_size=0):
        return FakeStream(self.download_tar)


class FakeSandbox:
    def __init__(self, fs: FakeFs):
        self.fs = fs

    def process_exec(self, command=None, *, argv=None, **_):
        return ExecResult(
            exit_code=0, stdout="", stderr="", timed_out=False, truncated=False, duration_ms=1
        )


def tar_with(entries: list[tuple[str, str, bytes | str]]) -> bytes:
    """A tar from ``(kind, name, payload)``: kind is dir, file or sym (payload = link target)."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for kind, name, payload in entries:
            info = tarfile.TarInfo(name)
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif kind == "sym":
                info.type = tarfile.SYMTYPE
                info.linkname = str(payload)
                archive.addfile(info)
            else:
                data = payload if isinstance(payload, bytes) else payload.encode()
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


TREE_WITH_LINKS = tar_with(
    [
        ("dir", "d", b""),
        ("file", "d/a", b"alpha"),
        ("dir", "d/sub", b""),
        ("file", "d/sub/b", b"beta"),
        ("sym", "d/link_rel", "a"),
        ("sym", "d/sub/up_in_tree", "../a"),
        ("sym", "d/link_abs", "/etc/passwd"),
        ("sym", "d/sub/link_escape", "../../outside"),
        ("file", "d/z_after", b"zz"),
    ]
)


@pytest.fixture
def fake_client(monkeypatch):
    def install(sandbox):
        @contextmanager
        def opened():
            yield SimpleNamespace(get=lambda sandbox_id: sandbox)

        monkeypatch.setattr(cp_cmd, "open_client", opened)

    return install


# --- cp -r download: links that leave the tree ---------------------------------------------


def test_download_skips_absolute_and_escaping_symlinks_and_keeps_the_rest(tmp_path):
    out = tmp_path / "out"
    stats = cp_dir.download_dir(FakeSandbox(FakeFs(TREE_WITH_LINKS)), "/w/d", out)

    assert (out / "a").read_text() == "alpha"
    assert (out / "z_after").read_text() == "zz"  # extraction went on after the skipped links
    assert (out / "link_rel").is_symlink() and (out / "link_rel").readlink() == Path("a")
    assert (out / "sub" / "up_in_tree").is_symlink()
    assert not (out / "link_abs").is_symlink() and not (out / "link_abs").exists()
    assert not (out / "sub" / "link_escape").is_symlink()
    assert not (tmp_path / "outside").exists()
    assert stats.files == 3
    assert stats.directories == 1  # sub (the root directory itself is not counted)
    assert stats.symlinks == 2
    assert stats.skipped == (
        "skipped symlink d/link_abs -> /etc/passwd (points outside the copied tree)",
        "skipped symlink d/sub/link_escape -> ../../outside (points outside the copied tree)",
    )


def test_download_never_writes_through_an_extracted_link(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    sneaky = tar_with(
        [
            ("dir", "d", b""),
            ("sym", "d/hop", "sub"),
            ("sym", "d/sub", str(outside)),
            ("file", "d/sub/pwned", b"x"),
        ]
    )
    out = tmp_path / "out"

    cp_dir.download_dir(FakeSandbox(FakeFs(sneaky)), "/w/d", out)

    assert list(outside.iterdir()) == []


def test_cp_r_download_warns_per_skipped_entry_and_summarises(tmp_path, fake_client):
    fake_client(FakeSandbox(FakeFs(TREE_WITH_LINKS)))
    out = tmp_path / "out"

    result = RUNNER.invoke(create_app(), ["cp", "-r", f"{SID}:/w/d", str(out)])

    assert result.exit_code == 0, result.output
    warnings = [line for line in result.stderr.splitlines() if line.startswith("skipped")]
    assert warnings == [
        "skipped symlink d/link_abs -> /etc/passwd (points outside the copied tree)",
        "skipped symlink d/sub/link_escape -> ../../outside (points outside the copied tree)",
    ]
    assert "copied 11 bytes (3 files, 1 directory, 2 symlinks; skipped 2 symlinks)" in result.stdout


def test_cp_r_download_json_counts_each_kind(tmp_path, fake_client):
    fake_client(FakeSandbox(FakeFs(TREE_WITH_LINKS)))

    result = RUNNER.invoke(create_app(), ["--json", "cp", "-r", f"{SID}:/w/d", str(tmp_path / "o")])

    payload = json.loads(result.stdout)
    assert (payload["files"], payload["directories"], payload["symlinks"]) == (3, 1, 2)
    assert len(payload["skipped"]) == 2


def test_a_plain_tree_keeps_the_short_summary(tmp_path, fake_client):
    fake_client(FakeSandbox(FakeFs(tar_with([("file", "a", b"alpha")]))))

    result = RUNNER.invoke(create_app(), ["cp", "-r", f"{SID}:/x", str(tmp_path / "o")])

    assert "copied 5 bytes (1 file):" in result.stdout
    assert "skipped" not in result.output


# --- upload ownership ----------------------------------------------------------------------


def test_uploaded_archive_is_owned_by_root_and_keeps_modes(tmp_path):
    tree = tmp_path / "t"
    (tree / "sub").mkdir(parents=True)
    script = tree / "run.sh"
    script.write_text("echo")
    script.chmod(0o750)
    (tree / "link").symlink_to("run.sh")
    fs = FakeFs()

    cp_dir.upload_dir(FakeSandbox(fs), tree, "/x")

    (body,) = fs.uploads.values()
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
        members = archive.getmembers()
        assert {m.name for m in members} == {"run.sh", "link", "sub"}
        for member in members:
            assert (member.uid, member.gid) == (0, 0), member.name
            assert (member.uname, member.gname) == ("root", "root"), member.name
        assert archive.getmember("run.sh").mode & 0o777 == 0o750


def test_server_single_file_upload_header_is_root_owned():
    from sandfort.toolbox.fs_transfer import _header

    info = tarfile.TarInfo.frombuf(_header("f", 3, 0o644, 0), "utf-8", "surrogateescape")

    assert (info.uid, info.gid) == (0, 0)


# --- volume get by name --------------------------------------------------------------------


@pytest.fixture
def profile(monkeypatch, tmp_path):
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, KEY)


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def volume_json(**extra):
    return {"id": VOL_ID, "name": "data", "state": "ready", "created_at": CREATED, **extra}


def test_volume_get_resolves_a_name(profile):
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        router.get("/v1/volumes").respond(200, json=envelope([volume_json()]))
        route = router.get(f"/v1/volumes/{VOL_ID}").respond(200, json=envelope(volume_json()))

        result = RUNNER.invoke(create_app(), ["--json", "volume", "get", "data"])

    assert result.exit_code == 0, result.output
    assert route.call_count == 1
    assert json.loads(result.stdout)["id"] == VOL_ID


def test_volume_get_still_takes_an_id_without_a_listing(profile):
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        listing = router.get("/v1/volumes").respond(200, json=envelope([]))
        router.get(f"/v1/volumes/{VOL_ID}").respond(200, json=envelope(volume_json()))

        result = RUNNER.invoke(create_app(), ["volume", "get", VOL_ID])

    assert result.exit_code == 0, result.output
    assert listing.call_count == 0


def test_volume_get_unknown_name_is_a_usage_error(profile):
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        router.get("/v1/volumes").respond(200, json=envelope([]))

        result = RUNNER.invoke(create_app(), ["volume", "get", "nope"])

    assert result.exit_code == 2
    assert "no volume named nope" in result.output


# --- ReadOnlyPath --------------------------------------------------------------------------


def test_read_only_path_is_a_typed_conflict_exported_by_the_package():
    exc = error_for(
        "READ_ONLY_PATH", "/data is read-only", status_code=409, details={"path": "/data"}
    )

    assert type(exc) is ReadOnlyPath
    assert isinstance(exc, Conflict) and isinstance(exc, ApiError)
    assert exc.code == "READ_ONLY_PATH"
    assert "ReadOnlyPath" in sandfort_sdk.__all__


def test_generic_conflict_is_unchanged():
    assert type(error_for("CONFLICT", "x", status_code=409)) is Conflict


def test_cp_r_into_a_read_only_mount_raises_read_only_path(tmp_path):
    from sandfort_cli.cp_dir import read_only_error

    assert isinstance(read_only_error("/data"), ReadOnlyPath)
    assert cp_dir.CopyStats(bytes=1, files=1).skipped == ()
