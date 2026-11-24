"""MCP filesystem tools: called directly against stub fs/client objects (no protocol/network)."""

import base64
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "mcp_server"))

import pytest  # noqa: E402

pytest.importorskip("mcp.server.mcpserver")

import sandfort_mcp  # noqa: E402
from sandfort_sdk import ApiError  # noqa: E402

MODIFIED = datetime(2026, 11, 23, 12, 30, 15, tzinfo=UTC)
MODIFIED_ISO = "2026-11-23T12:30:15+00:00"


def entry(
    name: str = "a.txt",
    kind: str = "file",
    modified_at: datetime | None = MODIFIED,
) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        path=f"/work/{name}",
        kind=kind,
        size_bytes=5,
        mode="644",
        modified_at=modified_at,
    )


class StubFs:
    def __init__(self, calls: list[tuple[str, Any]]) -> None:
        self._calls = calls
        self.entries: tuple[SimpleNamespace, ...] = ()
        self.stat_entry: SimpleNamespace = entry()
        self.data = b""

    def list_dir(self, path: str = "/") -> SimpleNamespace:
        self._calls.append(("list_dir", path))
        return SimpleNamespace(path=path, entries=self.entries)

    def stat(self, path: str) -> SimpleNamespace:
        self._calls.append(("stat", path))
        return self.stat_entry

    def mkdir(self, path: str, *, mode: str = "755", parents: bool = True) -> SimpleNamespace:
        self._calls.append(("mkdir", (path, parents)))
        return SimpleNamespace(path=path, created=True)

    def delete(self, path: str, *, recursive: bool = False) -> SimpleNamespace:
        self._calls.append(("delete", (path, recursive)))
        return SimpleNamespace(path=path, deleted=True)

    def upload_file(self, path: str, data: bytes, *, overwrite: bool = True) -> SimpleNamespace:
        self._calls.append(("upload", (path, data, overwrite)))
        return SimpleNamespace(path=path, size_bytes=len(data))

    def read_bytes(self, path: str) -> bytes:
        self._calls.append(("read", path))
        return self.data


class StubClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []
        self.fs = StubFs(self.calls)
        self.error: Exception | None = None

    def get(self, sandbox_id: str) -> SimpleNamespace:
        if self.error is not None:
            raise self.error
        self.calls.append(("get", sandbox_id))
        return SimpleNamespace(fs=self.fs)


@pytest.fixture
def stub(monkeypatch: pytest.MonkeyPatch) -> StubClient:
    client = StubClient()
    monkeypatch.setattr(sandfort_mcp, "HOLDER", SimpleNamespace(get=lambda: client))
    return client


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def test_list_directory_returns_entries_json(stub: StubClient) -> None:
    stub.fs.entries = (entry("a.txt"), entry("sub", kind="dir"))

    out = json.loads(sandfort_mcp.list_directory("sbx_1", "/work"))

    assert ("list_dir", "/work") in stub.calls
    assert out["path"] == "/work"
    assert out["truncated"] is False
    assert [e["name"] for e in out["entries"]] == ["a.txt", "sub"]
    assert out["entries"][0] == {
        "name": "a.txt",
        "path": "/work/a.txt",
        "kind": "file",
        "size_bytes": 5,
        "mode": "644",
        "modified_at": MODIFIED_ISO,
    }


def test_list_directory_defaults_to_root(stub: StubClient) -> None:
    out = json.loads(sandfort_mcp.list_directory("sbx_1"))

    assert ("list_dir", "/") in stub.calls
    assert out == {"path": "/", "entries": [], "truncated": False}


def test_list_directory_truncates_at_the_cap(stub: StubClient) -> None:
    cap = sandfort_mcp.MAX_LIST_ENTRIES
    stub.fs.entries = tuple(entry(f"f{i}") for i in range(cap + 1))

    out = json.loads(sandfort_mcp.list_directory("sbx_1", "/big"))

    assert len(out["entries"]) == cap
    assert out["truncated"] is True
    assert out["entries"][-1]["name"] == f"f{cap - 1}"


def test_list_directory_exactly_at_the_cap_is_not_truncated(stub: StubClient) -> None:
    cap = sandfort_mcp.MAX_LIST_ENTRIES
    stub.fs.entries = tuple(entry(f"f{i}") for i in range(cap))

    out = json.loads(sandfort_mcp.list_directory("sbx_1", "/big"))

    assert len(out["entries"]) == cap
    assert out["truncated"] is False


def test_stat_path_returns_entry_json(stub: StubClient) -> None:
    stub.fs.stat_entry = entry("link", kind="symlink")

    out = json.loads(sandfort_mcp.stat_path("sbx_1", "/work/link"))

    assert ("stat", "/work/link") in stub.calls
    assert out["name"] == "link"
    assert out["kind"] == "symlink"
    assert out["modified_at"] == MODIFIED_ISO


def test_stat_path_serializes_missing_modified_at_as_null(stub: StubClient) -> None:
    stub.fs.stat_entry = entry(modified_at=None)

    out = json.loads(sandfort_mcp.stat_path("sbx_1", "/work/a.txt"))

    assert out["modified_at"] is None


def test_make_directory_defaults_to_parents(stub: StubClient) -> None:
    out = json.loads(sandfort_mcp.make_directory("sbx_1", "/work/a/b"))

    assert ("mkdir", ("/work/a/b", True)) in stub.calls
    assert out == {"path": "/work/a/b", "created": True}


def test_make_directory_passes_parents_false(stub: StubClient) -> None:
    sandfort_mcp.make_directory("sbx_1", "/work/c", parents=False)

    assert ("mkdir", ("/work/c", False)) in stub.calls


def test_delete_path_is_not_recursive_by_default(stub: StubClient) -> None:
    out = json.loads(sandfort_mcp.delete_path("sbx_1", "/work/a.txt"))

    assert ("delete", ("/work/a.txt", False)) in stub.calls
    assert out == {"path": "/work/a.txt", "deleted": True}


def test_delete_path_passes_recursive_flag(stub: StubClient) -> None:
    sandfort_mcp.delete_path("sbx_1", "/work/tree", recursive=True)

    assert ("delete", ("/work/tree", True)) in stub.calls


def test_delete_path_docstring_warns_about_whole_trees() -> None:
    doc = sandfort_mcp.delete_path.__doc__ or ""

    assert "recursive=True" in doc
    assert "tree" in doc


def test_upload_binary_file_decodes_and_writes(stub: StubClient) -> None:
    payload = bytes(range(256))

    out = sandfort_mcp.upload_binary_file("sbx_1", "/bin.dat", b64(payload))

    assert out == "uploaded 256 bytes to /bin.dat"
    assert ("upload", ("/bin.dat", payload, True)) in stub.calls


def test_upload_binary_file_passes_overwrite_false(stub: StubClient) -> None:
    sandfort_mcp.upload_binary_file("sbx_1", "/bin.dat", b64(b"x"), overwrite=False)

    assert ("upload", ("/bin.dat", b"x", False)) in stub.calls


def test_upload_binary_file_refuses_oversized_base64_before_decoding(
    stub: StubClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    decoded: list[object] = []
    monkeypatch.setattr(sandfort_mcp.base64, "b64decode", lambda *a, **k: decoded.append(a) or b"")
    limit = 4 * ((sandfort_mcp.MAX_BINARY_BYTES + 2) // 3)

    out = sandfort_mcp.upload_binary_file("sbx_1", "/big", "A" * (limit + 1))

    assert out == "error: content is over the 1 MiB limit; not uploaded"
    assert decoded == []
    assert stub.calls == []


def test_upload_binary_file_refuses_decoded_content_over_limit(stub: StubClient) -> None:
    out = sandfort_mcp.upload_binary_file(
        "sbx_1", "/big", b64(b"x" * (sandfort_mcp.MAX_BINARY_BYTES + 1))
    )

    assert out == "error: content is over the 1 MiB limit; not uploaded"
    assert not any(name == "upload" for name, _ in stub.calls)


def test_upload_binary_file_accepts_content_at_the_limit(stub: StubClient) -> None:
    data = b"x" * sandfort_mcp.MAX_BINARY_BYTES

    out = sandfort_mcp.upload_binary_file("sbx_1", "/max", b64(data))

    assert out == f"uploaded {len(data)} bytes to /max"


def test_upload_binary_file_rejects_invalid_base64(stub: StubClient) -> None:
    out = sandfort_mcp.upload_binary_file("sbx_1", "/bad", "not*base64!")

    assert out == "error: content_base64 is not valid base64"
    assert not any(name == "upload" for name, _ in stub.calls)


def test_download_binary_file_returns_base64_json(stub: StubClient) -> None:
    stub.fs.data = b"hello\x00\xff"

    out = json.loads(sandfort_mcp.download_binary_file("sbx_1", "/bin.dat"))

    assert ("read", "/bin.dat") in stub.calls
    assert out == {"path": "/bin.dat", "size_bytes": 7, "content_base64": "aGVsbG8A/w=="}


def test_download_binary_file_refuses_over_one_mebibyte(stub: StubClient) -> None:
    stub.fs.data = b"x" * (sandfort_mcp.MAX_DOWNLOAD_BYTES + 1)

    out = sandfort_mcp.download_binary_file("sbx_1", "/big")

    assert out.startswith("error:")
    assert "1 MiB" in out
    assert out == (
        f"error: /big is {sandfort_mcp.MAX_DOWNLOAD_BYTES + 1} bytes, "
        "over the 1 MiB limit; not returned"
    )


def test_download_binary_file_docstring_notes_base64_inflation() -> None:
    doc = sandfort_mcp.download_binary_file.__doc__ or ""

    assert "base64" in doc
    assert "third" in doc


@pytest.mark.parametrize(
    "call",
    [
        lambda: sandfort_mcp.list_directory("sbx_x"),
        lambda: sandfort_mcp.stat_path("sbx_x", "/a"),
        lambda: sandfort_mcp.make_directory("sbx_x", "/a"),
        lambda: sandfort_mcp.delete_path("sbx_x", "/a"),
        lambda: sandfort_mcp.upload_binary_file("sbx_x", "/a", b64(b"x")),
        lambda: sandfort_mcp.download_binary_file("sbx_x", "/a"),
    ],
)
def test_sdk_errors_surface_as_readable_strings(stub: StubClient, call: Any) -> None:
    stub.error = ApiError("sandbox not found", code="NOT_FOUND", status_code=404)

    assert call() == "error: sandbox not found"
