"""Round 61: the SDK exec result carries the ``x-request-id`` of the reply that produced it, and
``sandfort cp -r`` names that id when the extract step hits a read-only mount.

The SDK runs over an ``httpx.MockTransport`` (no socket); the CLI uses the real process facade
with a stub for the file toolbox.
"""

import asyncio
import dataclasses
import json
import sys
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
from sandfort_cli import cp_cmd, cp_dir  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk._transport import AsyncTransport, SyncTransport, client_kwargs  # noqa: E402
from sandfort_sdk.code_contexts import CellResult  # noqa: E402
from sandfort_sdk.models import ExecResult  # noqa: E402
from sandfort_sdk.process import AsyncProcess, Process  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
TIMEOUT_S = 30.0
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
REQUEST_ID = "req_exec_r61_01"
DEST = "/data/ro"
RUNNER = CliRunner()
Handler = Callable[[httpx.Request], httpx.Response]


def payload(exit_code: int = 0, stderr: str = "") -> dict[str, object]:
    return {
        "exit_code": exit_code,
        "stdout": "",
        "stderr": stderr,
        "timed_out": False,
        "truncated": False,
        "duration_ms": 3,
    }


def reply_with(data: dict[str, object], request_id: str | None) -> Handler:
    headers = {"x-request-id": request_id} if request_id else {}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"success": True, "data": data, "error": None}, headers=headers
        )

    return handler


def sync_process(handler: Handler) -> Process:
    transport = SyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    transport._http.close()
    transport._http = httpx.Client(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return Process(SID, transport)


def async_process(handler: Handler) -> AsyncProcess:
    transport = AsyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return AsyncProcess(SID, transport)


# --- the model -------------------------------------------------------------------------------


def test_request_id_defaults_to_none_for_existing_constructions() -> None:
    result = ExecResult(0, "out", "", False, False, 1)
    assert result.request_id is None
    assert ExecResult.from_payload(payload()).request_id is None


def test_from_payload_takes_the_request_id() -> None:
    assert ExecResult.from_payload(payload(), request_id=REQUEST_ID).request_id == REQUEST_ID


def test_request_id_is_not_read_from_the_body() -> None:
    body = {**payload(), "request_id": "req_from_body"}
    assert ExecResult.from_payload(body).request_id is None


def test_the_result_stays_frozen_and_comparable() -> None:
    result = ExecResult.from_payload(payload(), request_id=REQUEST_ID)
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.request_id = "other"  # type: ignore[misc]
    assert result == ExecResult.from_payload(payload(), request_id=REQUEST_ID)


def test_a_cell_result_carries_the_request_id_too() -> None:
    cell = CellResult.from_payload(payload(), request_id=REQUEST_ID)
    assert cell.request_id == REQUEST_ID
    assert CellResult.from_payload(payload()).request_id is None


# --- the SDK sets it from the reply header ---------------------------------------------------


@pytest.mark.parametrize("method", ["exec", "code_run"])
def test_sync_result_carries_the_reply_request_id(method: str) -> None:
    process = sync_process(reply_with(payload(), REQUEST_ID))
    if method == "exec":
        result = process.exec("true")
    else:
        result = process.code_run("python", "print(1)")
    assert result.request_id == REQUEST_ID


@pytest.mark.parametrize("method", ["exec", "code_run"])
def test_sync_result_has_no_request_id_without_the_header(method: str) -> None:
    process = sync_process(reply_with(payload(), None))
    if method == "exec":
        result = process.exec("true")
    else:
        result = process.code_run("python", "print(1)")
    assert result.request_id is None


@pytest.mark.parametrize("method", ["exec", "code_run"])
def test_async_result_carries_the_reply_request_id(method: str) -> None:
    process = async_process(reply_with(payload(), REQUEST_ID))
    if method == "exec":
        result = asyncio.run(process.exec("true"))
    else:
        result = asyncio.run(process.code_run("python", "print(1)"))
    assert result.request_id == REQUEST_ID


@pytest.mark.parametrize("method", ["exec", "code_run"])
def test_async_result_has_no_request_id_without_the_header(method: str) -> None:
    process = async_process(reply_with(payload(), None))
    if method == "exec":
        result = asyncio.run(process.exec("true"))
    else:
        result = asyncio.run(process.code_run("python", "print(1)"))
    assert result.request_id is None


def test_each_call_reports_its_own_request_id() -> None:
    ids = iter(["req_first", "req_second"])

    def handler(request: httpx.Request) -> httpx.Response:
        return reply_with(payload(), next(ids))(request)

    process = sync_process(handler)
    assert [process.exec("true").request_id, process.exec("true").request_id] == [
        "req_first",
        "req_second",
    ]


# --- cp -r names the id of the refusing call -------------------------------------------------


class StubFs:
    def upload_file(self, path, data, **_):  # type: ignore[no-untyped-def]
        return SimpleNamespace(size_bytes=len(data.read()))

    def delete(self, path, *, recursive=False):  # type: ignore[no-untyped-def]
        return None


class SdkBackedSandbox:
    """A sandbox whose exec goes through the real SDK process facade."""

    def __init__(self, process: Process) -> None:
        self.process = process
        self.fs = StubFs()

    def process_exec(self, command=None, **kwargs):  # type: ignore[no-untyped-def]
        return self.process.exec(command, **kwargs)


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "tree"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_bytes(b"alpha")
    return root


def install(monkeypatch: pytest.MonkeyPatch, sandbox: SdkBackedSandbox) -> None:
    @contextmanager
    def opened():  # type: ignore[no-untyped-def]
        yield SimpleNamespace(get=lambda sandbox_id: sandbox)

    monkeypatch.setattr(cp_cmd, "open_client", opened)


def refused_stderr() -> str:
    return "tar: ./sub: Cannot mkdir: Read-only file system\n"


@pytest.mark.parametrize("request_id", [REQUEST_ID, None])
def test_cp_r_read_only_refusal_shows_the_exec_reply_request_id(
    monkeypatch: pytest.MonkeyPatch, tree: Path, request_id: str | None
) -> None:
    body = payload(2, refused_stderr())
    install(monkeypatch, SdkBackedSandbox(sync_process(reply_with(body, request_id))))

    result = RUNNER.invoke(create_app(None), ["--json", "cp", "-r", str(tree), f"{SID}:{DEST}"])

    error = json.loads(result.stdout)["error"]
    assert error["code"] == "READ_ONLY_PATH"
    assert error["request_id"] == request_id


def test_cp_dir_no_longer_taps_the_transport() -> None:
    assert not hasattr(cp_dir, "RequestIdTap")
    assert "_transport" not in Path(cp_dir.__file__).read_text(encoding="utf-8")
