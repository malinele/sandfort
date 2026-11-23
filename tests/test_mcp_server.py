"""MCP server tools: called directly against a stub client holder (no protocol, no network)."""

import json
import sys
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


class StubFs:
    def __init__(self, calls: list[tuple[str, Any]], data: bytes) -> None:
        self._calls = calls
        self._data = data

    def upload_file(self, path: str, data: bytes) -> None:
        self._calls.append(("upload", (path, data)))

    def read_bytes(self, path: str) -> bytes:
        self._calls.append(("read", path))
        return self._data


class StubSandbox:
    id = "sbx_1"
    state = "started"

    def __init__(self, calls: list[tuple[str, Any]], data: bytes) -> None:
        self._calls = calls
        self.info = SimpleNamespace(name="demo")
        self.fs = StubFs(calls, data)

    def _result(self) -> SimpleNamespace:
        return SimpleNamespace(exit_code=0, stdout="42\n", stderr="", timed_out=False)

    def code_run(self, language: str, code: str, *, timeout_s: int) -> SimpleNamespace:
        self._calls.append(("code_run", (language, code, timeout_s)))
        return self._result()

    def process_exec(self, command: str, *, cwd: str | None, timeout_s: int) -> SimpleNamespace:
        self._calls.append(("exec", (command, cwd, timeout_s)))
        return self._result()


class StubClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []
        self.data = b"hello"
        self.error: Exception | None = None
        self.snapshots = SimpleNamespace(create_from_sandbox=self._snapshot)

    def _maybe_fail(self) -> None:
        if self.error is not None:
            raise self.error

    def _snapshot(self, sandbox_id: str, name: str) -> SimpleNamespace:
        self.calls.append(("snapshot", (sandbox_id, name)))
        return SimpleNamespace(id="snap_1", state="pending")

    def create_sandbox(self, *, name: str | None, snapshot: str | None) -> StubSandbox:
        self._maybe_fail()
        self.calls.append(("create", (name, snapshot)))
        return StubSandbox(self.calls, self.data)

    def get(self, sandbox_id: str) -> StubSandbox:
        self._maybe_fail()
        self.calls.append(("get", sandbox_id))
        return StubSandbox(self.calls, self.data)

    def list_sandboxes(self) -> SimpleNamespace:
        return SimpleNamespace(items=(StubSandbox(self.calls, self.data),))

    def delete(self, sandbox_id: str) -> None:
        self.calls.append(("delete", sandbox_id))


@pytest.fixture
def stub(monkeypatch: pytest.MonkeyPatch) -> StubClient:
    client = StubClient()
    monkeypatch.setattr(sandfort_mcp, "HOLDER", SimpleNamespace(get=lambda: client))
    return client


def test_create_sandbox_returns_id_and_state(stub: StubClient) -> None:
    out = json.loads(sandfort_mcp.create_sandbox(name="n", snapshot="s"))

    assert out == {"id": "sbx_1", "state": "started"}
    assert ("create", ("n", "s")) in stub.calls


def test_run_code_maps_arguments_and_returns_exec_fields(stub: StubClient) -> None:
    out = json.loads(sandfort_mcp.run_code("sbx_1", "python", "print(42)", timeout_seconds=7))

    assert ("code_run", ("python", "print(42)", 7)) in stub.calls
    assert out["exit_code"] == 0
    assert out["stdout"] == "42\n"
    assert out["stderr"] == ""


def test_run_command_maps_cwd_and_timeout(stub: StubClient) -> None:
    out = json.loads(sandfort_mcp.run_command("sbx_1", "ls", cwd="/tmp", timeout_seconds=5))

    assert ("exec", ("ls", "/tmp", 5)) in stub.calls
    assert out["exit_code"] == 0


def test_upload_then_download_text_file(stub: StubClient) -> None:
    sandfort_mcp.upload_text_file("sbx_1", "/a.txt", "héllo")

    assert ("upload", ("/a.txt", "héllo".encode())) in stub.calls
    assert sandfort_mcp.download_text_file("sbx_1", "/a.txt") == "hello"


def test_download_refuses_content_over_one_mebibyte(stub: StubClient) -> None:
    stub.data = b"x" * (sandfort_mcp.MAX_DOWNLOAD_BYTES + 1)

    out = sandfort_mcp.download_text_file("sbx_1", "/big")

    assert out.startswith("error:")
    assert "1 MiB" in out


def test_list_delete_and_snapshot(stub: StubClient) -> None:
    assert json.loads(sandfort_mcp.list_sandboxes()) == [
        {"id": "sbx_1", "name": "demo", "state": "started"}
    ]
    assert sandfort_mcp.delete_sandbox("sbx_1") == "deleted sbx_1"
    assert json.loads(sandfort_mcp.create_snapshot("sbx_1", "snap")) == {
        "id": "snap_1",
        "state": "pending",
    }


def test_list_sandboxes_returns_live_rows_only(
    stub: StubClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def row(sandbox_id: str, state: str) -> SimpleNamespace:
        return SimpleNamespace(id=sandbox_id, info=SimpleNamespace(name="n"), state=state)

    page = SimpleNamespace(
        items=(row("sbx_gone", "destroyed"), row("sbx_live", "started"), row("sbx_del", "deleting"))
    )
    monkeypatch.setattr(stub, "list_sandboxes", lambda: page)

    assert json.loads(sandfort_mcp.list_sandboxes()) == [
        {"id": "sbx_live", "name": "n", "state": "started"}
    ]


def test_sdk_errors_surface_as_readable_strings(stub: StubClient) -> None:
    stub.error = ApiError("sandbox not found", code="NOT_FOUND", status_code=404)

    assert sandfort_mcp.run_command("sbx_x", "ls") == "error: sandbox not found"
    assert sandfort_mcp.create_sandbox() == "error: sandbox not found"


def test_missing_environment_raises_clear_error() -> None:
    with pytest.raises(sandfort_mcp.ConfigError, match="SANDFORT_API_KEY"):
        sandfort_mcp.load_config({"SANDFORT_BASE_URL": "http://x"})


def test_config_reads_both_variables() -> None:
    env = {"SANDFORT_BASE_URL": "http://x", "SANDFORT_API_KEY": "sf_k"}

    assert sandfort_mcp.load_config(env) == ("http://x", "sf_k")
