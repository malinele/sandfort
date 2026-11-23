"""SDK code contexts r30: interrupt, CellResult, stop reasons, context managers."""

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
import sandfort_sdk  # noqa: E402
from sandfort_sdk import (  # noqa: E402
    AsyncCodeContext,
    CellError,
    CellResult,
    CodeContext,
    ExecResult,
    InternalError,
    InvalidResponseError,
    NotFound,
    is_known_stop_reason,
)
from sandfort_sdk._transport import AsyncTransport, SyncTransport, client_kwargs  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
TIMEOUT_S = 30.0
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
CID = "ctx_0123456789abcdef"
CONTEXT = f"/v1/sandboxes/{SID}/toolbox/code-contexts/{CID}"

Handler = Callable[[httpx.Request], httpx.Response]


def envelope(data: Any, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json={"success": True, "data": data, "meta": None})


def failed(status: int, code: str) -> httpx.Response:
    error = {"code": code, "message": "boom", "details": {}, "request_id": "req_1"}
    body = {"success": False, "data": None, "error": error, "meta": None}
    return httpx.Response(status, json=body)


def run_payload(**over: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "exit_code": 0,
        "stdout": "",
        "stderr": "",
        "timed_out": False,
        "truncated": False,
        "duration_ms": 12,
        "sandbox_stopped": False,
        "stop_reason": None,
        "result": None,
        "error": None,
    }
    return {**data, **over}


class Recorder:
    """A handler that answers every request with ``answer`` and records the requests."""

    def __init__(self, answer: httpx.Response) -> None:
        self.answer = answer
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.answer

    def calls(self) -> list[tuple[str, str]]:
        return [(r.method, r.url.path) for r in self.requests]


def sync_context(handler: Handler) -> CodeContext:
    transport = SyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    transport._http.close()
    transport._http = httpx.Client(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return CodeContext(SID, CID, "/work", transport)


def async_context(handler: Handler) -> AsyncCodeContext:
    transport = AsyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return AsyncCodeContext(SID, CID, "/work", transport)


# --- interrupt ---------------------------------------------------------------------------


def test_interrupt_posts_to_the_interrupt_path_and_returns_the_flag() -> None:
    recorder = Recorder(envelope({"id": CID, "interrupted": True}))

    assert sync_context(recorder).interrupt() is True
    assert recorder.calls() == [("POST", f"{CONTEXT}/interrupt")]


def test_interrupt_returns_false_for_a_context_without_a_live_kernel() -> None:
    recorder = Recorder(envelope({"id": CID, "interrupted": False}))

    assert sync_context(recorder).interrupt() is False


@pytest.mark.parametrize("data", [{"id": CID}, {"id": CID, "interrupted": "yes"}, []])
def test_interrupt_rejects_a_malformed_answer(data: Any) -> None:
    with pytest.raises(InvalidResponseError):
        sync_context(Recorder(envelope(data))).interrupt()


def test_interrupt_of_a_missing_context_raises_not_found() -> None:
    with pytest.raises(NotFound):
        sync_context(Recorder(failed(404, "NOT_FOUND"))).interrupt()


async def test_async_interrupt_posts_to_the_interrupt_path() -> None:
    recorder = Recorder(envelope({"id": CID, "interrupted": True}))

    assert await async_context(recorder).interrupt() is True
    assert recorder.calls() == [("POST", f"{CONTEXT}/interrupt")]


# --- CellResult --------------------------------------------------------------------------


def test_run_returns_a_cell_result_with_the_trailing_expression() -> None:
    recorder = Recorder(envelope(run_payload(stdout="42\n", result="42")))

    cell = sync_context(recorder).run("40 + 2", timeout_s=20)

    assert isinstance(cell, CellResult)
    assert isinstance(cell, ExecResult)
    assert (cell.result, cell.error, cell.stdout, cell.ok) == ("42", None, "42\n", True)
    assert recorder.calls() == [("POST", f"{CONTEXT}/run")]
    assert json.loads(recorder.requests[0].content)["timeout_s"] == 20


def test_run_returns_the_error_the_cell_raised() -> None:
    error = {"type": "ZeroDivisionError", "message": "division by zero"}
    cell = sync_context(Recorder(envelope(run_payload(exit_code=1, error=error)))).run("1/0")

    assert cell.error == CellError("ZeroDivisionError", "division by zero")
    assert cell.result is None
    assert cell.exit_code == 1


def test_run_with_neither_result_nor_error_keeps_the_exec_fields() -> None:
    payload = run_payload(stdout="hi\n", duration_ms=7)
    cell = sync_context(Recorder(envelope(payload))).run("print('hi')")

    assert (cell.result, cell.error) == (None, None)
    assert (cell.exit_code, cell.stdout, cell.duration_ms) == (0, "hi\n", 7)
    assert (cell.timed_out, cell.truncated, cell.sandbox_stopped) == (False, False, False)


def test_an_older_server_without_result_and_error_still_parses() -> None:
    payload = run_payload()
    del payload["result"], payload["error"], payload["stop_reason"]

    cell = sync_context(Recorder(envelope(payload))).run("pass")

    assert (cell.result, cell.error, cell.stop_reason) == (None, None, None)


@pytest.mark.parametrize(
    "over",
    [
        {"result": 42},
        {"error": "boom"},
        {"error": {"type": "X"}},
        {"error": {"type": 1, "message": ""}},
    ],
)
def test_a_malformed_outcome_raises_invalid_response(over: dict[str, Any]) -> None:
    with pytest.raises(InvalidResponseError):
        sync_context(Recorder(envelope(run_payload(**over)))).run("pass")


async def test_async_run_returns_a_cell_result() -> None:
    error = {"type": "KeyboardInterrupt", "message": ""}
    reply = envelope(run_payload(exit_code=1, error=error))

    cell = await async_context(Recorder(reply)).run("while True: pass")

    assert cell.error == CellError("KeyboardInterrupt", "")


# --- stop reasons ------------------------------------------------------------------------


@pytest.mark.parametrize("reason", ["queue_timeout", "context_lost"])
def test_context_stop_reasons_are_kept_and_known(reason: str) -> None:
    payload = run_payload(exit_code=124, timed_out=True, stop_reason=reason)
    cell = sync_context(Recorder(envelope(payload))).run("pass")

    assert cell.stop_reason == reason
    assert is_known_stop_reason(cell.stop_reason)


def test_an_unknown_stop_reason_stays_a_string_and_fails_the_type_guard() -> None:
    cell = sync_context(Recorder(envelope(run_payload(stop_reason="quota_hit")))).run("pass")

    assert cell.stop_reason == "quota_hit"
    assert not is_known_stop_reason(cell.stop_reason)
    assert not is_known_stop_reason(None)


def test_the_constants_cover_every_stop_reason_the_server_sends() -> None:
    constants = {
        getattr(sandfort_sdk, name) for name in sandfort_sdk.__all__ if name.startswith("STOP_")
    }
    expected = {
        "timeout",
        "output_limit",
        "sandbox_stopped",
        "sandbox_deleted",
        "sandbox_reset",
        "oom_killed",
        "killed",
        "queue_timeout",
        "context_lost",
    }

    assert constants == expected
    assert all(is_known_stop_reason(value) for value in expected)


# --- context managers --------------------------------------------------------------------


def deleted() -> httpx.Response:
    return envelope({"id": CID, "deleted": True})


def test_the_context_manager_deletes_the_context_on_exit() -> None:
    recorder = Recorder(deleted())

    with sync_context(recorder) as ctx:
        assert recorder.calls() == []
        assert ctx.id == CID

    assert recorder.calls() == [("DELETE", CONTEXT)]


def test_the_context_manager_deletes_when_the_block_raises_and_keeps_the_error() -> None:
    recorder = Recorder(deleted())

    with pytest.raises(RuntimeError, match="cell failed"), sync_context(recorder):
        raise RuntimeError("cell failed")

    assert recorder.calls() == [("DELETE", CONTEXT)]


def test_a_missing_context_is_ignored_on_exit() -> None:
    recorder = Recorder(failed(404, "NOT_FOUND"))

    with sync_context(recorder):
        pass

    assert recorder.calls() == [("DELETE", CONTEXT)]


def test_another_delete_error_is_raised_on_exit() -> None:
    with pytest.raises(InternalError), sync_context(Recorder(failed(500, "INTERNAL"))):
        pass


def test_a_delete_error_does_not_mask_the_exception_in_the_block() -> None:
    context = sync_context(Recorder(failed(500, "INTERNAL")))

    with pytest.raises(RuntimeError, match="in block"), context:
        raise RuntimeError("in block")


async def test_the_async_context_manager_deletes_the_context_on_exit() -> None:
    recorder = Recorder(deleted())

    async with async_context(recorder) as ctx:
        assert recorder.calls() == []
        assert ctx.id == CID

    assert recorder.calls() == [("DELETE", CONTEXT)]


async def test_the_async_context_manager_ignores_a_missing_context() -> None:
    recorder = Recorder(failed(404, "NOT_FOUND"))

    async with async_context(recorder):
        pass

    assert recorder.calls() == [("DELETE", CONTEXT)]


async def test_the_async_context_manager_deletes_when_the_block_raises() -> None:
    recorder = Recorder(deleted())

    with pytest.raises(RuntimeError, match="cell failed"):
        async with async_context(recorder):
            raise RuntimeError("cell failed")

    assert recorder.calls() == [("DELETE", CONTEXT)]
