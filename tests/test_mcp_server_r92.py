"""MCP round 92: text upload limit, create options, start and stop tools, 0.1.1 metadata."""

import asyncio
import base64
import json
import sys
import tomllib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "mcp_server"))

import pytest  # noqa: E402

pytest.importorskip("mcp.server.mcpserver")

import sandfort_mcp  # noqa: E402
from sandfort_sdk import ApiError, SandboxTimeoutError  # noqa: E402

TOO_LARGE = "error: content is over the 1 MiB limit; not uploaded"
BAD_TIMEOUT = "error: wait_timeout_seconds must be greater than 0"
LIMIT = 1024 * 1024
EXPECTED_TOOLS = frozenset(
    {
        "create_sandbox",
        "create_snapshot",
        "delete_path",
        "delete_sandbox",
        "download_binary_file",
        "download_text_file",
        "list_directory",
        "list_sandboxes",
        "make_directory",
        "run_code",
        "run_command",
        "stat_path",
        "upload_binary_file",
        "upload_text_file",
        "start_sandbox",
        "stop_sandbox",
    }
)
CREATE_OPTIONS = (
    "auto_stop_minutes",
    "auto_delete_minutes",
    "labels",
    "block_network",
    "egress_allowlist",
    "isolation",
)
FULL_OPTIONS: dict[str, Any] = {
    "auto_stop_minutes": 30,
    "auto_delete_minutes": 120,
    "labels": {"team": "a"},
    "block_network": True,
    "egress_allowlist": ["pypi.org", ".github.com"],
    "isolation": "gvisor",
}


class StubFs:
    def __init__(self, calls: list[tuple[str, Any]]) -> None:
        self._calls = calls

    def upload_file(self, path: str, data: bytes) -> None:
        self._calls.append(("upload", (path, data)))


class StubClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []
        self.error: Exception | None = None
        self.fs = StubFs(self.calls)

    def _maybe_fail(self) -> None:
        if self.error is not None:
            raise self.error

    def _sandbox(self, state: str) -> SimpleNamespace:
        return SimpleNamespace(id="sbx_1", state=state, fs=self.fs)

    def get(self, sandbox_id: str) -> SimpleNamespace:
        self._maybe_fail()
        self.calls.append(("get", sandbox_id))
        return self._sandbox("started")

    def create_sandbox(self, **kwargs: Any) -> SimpleNamespace:
        self._maybe_fail()
        self.calls.append(("create", kwargs))
        return self._sandbox("started")

    def start(self, sandbox_id: str, *, wait: bool, wait_timeout_s: float) -> SimpleNamespace:
        self._maybe_fail()
        self.calls.append(("start", (sandbox_id, wait, wait_timeout_s)))
        return self._sandbox("started")

    def stop(self, sandbox_id: str) -> SimpleNamespace:
        self._maybe_fail()
        self.calls.append(("stop", sandbox_id))
        return self._sandbox("stopping")


@pytest.fixture
def stub(monkeypatch: pytest.MonkeyPatch) -> StubClient:
    client = StubClient()

    def holder_get() -> StubClient:
        client.calls.append(("holder", None))
        return client

    monkeypatch.setattr(sandfort_mcp, "HOLDER", SimpleNamespace(get=holder_get))
    return client


def tools() -> dict[str, Any]:
    return {t.name: t for t in asyncio.run(sandfort_mcp.mcp.list_tools())}


# Text upload


def test_text_upload_over_the_limit_makes_no_request(stub: StubClient) -> None:
    result = sandfort_mcp.upload_text_file("sbx_1", "/big", "x" * (LIMIT + 1))

    assert result == TOO_LARGE
    assert stub.calls == []


def test_text_upload_counts_bytes_not_characters(stub: StubClient) -> None:
    content = "é" * (LIMIT // 2 + 1)
    assert len(content) <= LIMIT

    result = sandfort_mcp.upload_text_file("sbx_1", "/big", content)

    assert result == TOO_LARGE
    assert stub.calls == []


def test_text_upload_at_the_limit_is_sent(stub: StubClient) -> None:
    result = sandfort_mcp.upload_text_file("sbx_1", "/max", "x" * LIMIT)

    assert result == "uploaded 1048576 bytes to /max"
    assert ("get", "sbx_1") in stub.calls
    assert ("upload", ("/max", b"x" * LIMIT)) in stub.calls


def test_text_upload_multibyte_at_the_limit_is_sent(stub: StubClient) -> None:
    content = "é" * (LIMIT // 2)

    result = sandfort_mcp.upload_text_file("sbx_1", "/m", content)

    assert result == "uploaded 1048576 bytes to /m"
    assert ("upload", ("/m", content.encode("utf-8"))) in stub.calls


def test_text_upload_docstring_names_the_limit() -> None:
    doc = sandfort_mcp.upload_text_file.__doc__ or ""

    assert "1 MiB" in doc
    assert "bytes" in doc


def test_binary_upload_message_is_unchanged(stub: StubClient) -> None:
    encoded = base64.b64encode(b"x" * (LIMIT + 1)).decode("ascii")

    result = sandfort_mcp.upload_binary_file("sbx_1", "/big", encoded)

    assert result == TOO_LARGE
    assert not [name for name, _ in stub.calls if name == "upload"]


# create_sandbox


def test_create_sandbox_default_call_sends_only_name_and_snapshot(stub: StubClient) -> None:
    result = sandfort_mcp.create_sandbox()

    assert json.loads(result) == {"id": "sbx_1", "state": "started"}
    assert stub.calls == [("holder", None), ("create", {"name": None, "snapshot": None})]


def test_create_sandbox_maps_every_option(stub: StubClient) -> None:
    sandfort_mcp.create_sandbox(name="n", snapshot="s", **FULL_OPTIONS)

    expected = {"name": "n", "snapshot": "s", **FULL_OPTIONS}
    assert stub.calls[-1] == ("create", expected)


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("auto_stop_minutes", 0),
        ("auto_stop_minutes", -1),
        ("auto_delete_minutes", 0),
        ("auto_delete_minutes", -1),
        ("block_network", False),
        ("egress_allowlist", []),
        ("labels", {}),
    ],
)
def test_create_sandbox_passes_falsy_values_that_are_not_none(
    stub: StubClient, option: str, value: Any
) -> None:
    sandfort_mcp.create_sandbox(**{option: value})

    assert stub.calls[-1] == ("create", {"name": None, "snapshot": None, option: value})


@pytest.mark.parametrize("option", CREATE_OPTIONS)
def test_create_sandbox_leaves_out_options_that_are_none(stub: StubClient, option: str) -> None:
    kwargs = {**FULL_OPTIONS, option: None}

    sandfort_mcp.create_sandbox(**kwargs)

    recorded = stub.calls[-1][1]
    assert option not in recorded
    assert all(other in recorded for other in CREATE_OPTIONS if other != option)


def test_create_sandbox_docstring_documents_timers_and_image() -> None:
    doc = sandfort_mcp.create_sandbox.__doc__ or ""

    for phrase in (
        "python:3.12-slim",
        "pip",
        "no git",
        "-1",
        "525600",
        "0 deletes",
        "auto_stop_minutes",
        "auto_delete_minutes",
        "labels",
        "block_network",
        "egress_allowlist",
        "isolation",
    ):
        assert phrase in doc, phrase


# start_sandbox and stop_sandbox


def test_start_sandbox_waits_with_the_default_timeout(stub: StubClient) -> None:
    result = sandfort_mcp.start_sandbox("sbx_1")

    assert json.loads(result) == {"id": "sbx_1", "state": "started"}
    assert stub.calls == [("holder", None), ("start", ("sbx_1", True, 60))]


def test_start_sandbox_passes_the_timeout(stub: StubClient) -> None:
    sandfort_mcp.start_sandbox("sbx_1", wait_timeout_seconds=5)

    assert stub.calls[-1] == ("start", ("sbx_1", True, 5))


@pytest.mark.parametrize("value", [0, -1, -60])
def test_start_sandbox_rejects_a_timeout_that_is_not_positive(
    stub: StubClient, value: int
) -> None:
    result = sandfort_mcp.start_sandbox("sbx_1", wait_timeout_seconds=value)

    assert result == BAD_TIMEOUT
    assert stub.calls == []


def test_start_sandbox_turns_a_wait_timeout_into_an_error_string(stub: StubClient) -> None:
    stub.error = SandboxTimeoutError("start timed out", sandbox_id="sbx_1", state="starting")

    assert sandfort_mcp.start_sandbox("sbx_1") == "error: start timed out"


def test_stop_sandbox_returns_without_waiting(stub: StubClient) -> None:
    result = sandfort_mcp.stop_sandbox("sbx_1")

    assert json.loads(result) == {"id": "sbx_1", "state": "stopping"}
    assert stub.calls == [("holder", None), ("stop", "sbx_1")]


def test_stop_sandbox_docstring_says_it_does_not_wait() -> None:
    doc = sandfort_mcp.stop_sandbox.__doc__ or ""

    assert "does not wait" in doc
    assert "stopping" in doc


CALLS = [
    pytest.param(lambda: sandfort_mcp.create_sandbox(isolation="gvisor"), id="create"),
    pytest.param(lambda: sandfort_mcp.start_sandbox("sbx_x"), id="start"),
    pytest.param(lambda: sandfort_mcp.stop_sandbox("sbx_x"), id="stop"),
    pytest.param(lambda: sandfort_mcp.upload_text_file("sbx_x", "/a", "hi"), id="upload"),
]


@pytest.mark.parametrize("call", CALLS)
def test_sdk_errors_surface_as_readable_strings(stub: StubClient, call: Any) -> None:
    stub.error = ApiError("sandbox not found", code="NOT_FOUND", status_code=404)

    assert call() == "error: sandbox not found"


@pytest.mark.parametrize("call", CALLS)
def test_missing_config_is_a_readable_string(monkeypatch: pytest.MonkeyPatch, call: Any) -> None:
    def raise_config() -> Any:
        msg = "missing required environment variable(s): SANDFORT_API_KEY"
        raise sandfort_mcp.ConfigError(msg)

    monkeypatch.setattr(sandfort_mcp, "HOLDER", SimpleNamespace(get=raise_config))

    result = call()

    assert result.startswith("error: missing required")
    assert "SANDFORT_API_KEY" in result


# Tool list and schemas


def test_tool_list_has_sixteen_tools() -> None:
    assert set(tools()) == EXPECTED_TOOLS
    assert len(tools()) == 16


def test_create_sandbox_schema_lists_the_options() -> None:
    schema = tools()["create_sandbox"].input_schema

    assert set(schema["properties"]) == {"name", "snapshot", *CREATE_OPTIONS}
    assert schema.get("required", []) == []


def test_start_and_stop_schemas() -> None:
    listed = tools()
    start = listed["start_sandbox"].input_schema
    stop = listed["stop_sandbox"].input_schema

    assert set(start["properties"]) == {"sandbox_id", "wait_timeout_seconds"}
    assert start["required"] == ["sandbox_id"]
    assert start["properties"]["wait_timeout_seconds"]["default"] == 60
    assert set(stop["properties"]) == {"sandbox_id"}
    assert stop["required"] == ["sandbox_id"]


# Release and size


def test_version_is_0_1_1_everywhere() -> None:
    pyproject = tomllib.loads((ROOT / "mcp_server" / "pyproject.toml").read_text())
    server = json.loads((ROOT / "server.json").read_text())

    assert pyproject["project"]["version"] == "0.1.1"
    assert server["version"] == "0.1.1"
    assert server["packages"][0]["version"] == "0.1.1"


def test_readme_lists_the_new_tools_and_the_text_limit() -> None:
    text = (ROOT / "mcp_server" / "README.md").read_text()

    assert "- `start_sandbox`:" in text
    assert "- `stop_sandbox`:" in text
    assert "`python:3.12-slim`" in text
    assert "A text upload counts UTF-8 bytes, not characters." in text
    assert "File downloads and binary uploads are limited to 1 MiB." not in text


def test_module_and_this_file_stay_small() -> None:
    for path in (ROOT / "mcp_server" / "sandfort_mcp.py", Path(__file__)):
        lines = path.read_text().splitlines()
        assert len(lines) < 400, path
        assert max(len(line) for line in lines) <= 100, path
