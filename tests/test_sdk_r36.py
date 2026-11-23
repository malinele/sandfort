"""SDK r36: a destroyed replay is ``SandboxDestroyedError``; ``ensure`` reports ``created``;
stream errors carry the request id and empty ``details`` (``has_details`` False);
``CONTEXT_GONE_ERRORS``; null snapshot ``image_ref``; ``str()`` of a rewritten failure."""

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
CLI_SRC = Path(__file__).resolve().parents[1] / "cli" / "src"
sys.path.insert(0, str(SDK_SRC))
sys.path.insert(0, str(CLI_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
import sandfort_sdk  # noqa: E402
from sandfort_cli.output import with_error_code  # noqa: E402
from sandfort_sdk import (  # noqa: E402
    CONTEXT_GONE_ERRORS,
    AsyncClient,
    CellResult,
    Client,
    InternalError,
    InvalidResponseError,
    NoContainer,
    NotFound,
    SandboxDestroyedError,
    SandboxFailedError,
    SnapshotInfo,
    TransportError,
)
from sandfort_sdk._transport import AsyncTransport, SyncTransport, client_kwargs  # noqa: E402
from sandfort_sdk.code_contexts import (  # noqa: E402
    AsyncCodeContext,
    AsyncCodeContexts,
    CodeContext,
    CodeContexts,
)
from sandfort_sdk.exceptions import error_for  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
TIMEOUT_S = 30.0
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
CID = "ctx_0123456789abcdef"
SANDBOXES = "/v1/sandboxes"
CONTEXTS = f"{SANDBOXES}/{SID}/toolbox/code-contexts"
STREAM = f"{CONTEXTS}/{CID}/run/stream"
NAME = "analysis"
REQUEST_ID = "req_stream_1"
SSE = {"content-type": "text/event-stream", "x-request-id": REQUEST_ID}
Handler = Callable[[httpx.Request], httpx.Response]


def envelope(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data, "error": None, "meta": None}


def sync_transport(handler: Handler) -> SyncTransport:
    transport = SyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    transport._http.close()
    transport._http = httpx.Client(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return transport


def async_transport(handler: Handler) -> AsyncTransport:
    transport = AsyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return transport


# --- SandboxDestroyedError -------------------------------------------------------------------


def destroyed_replay(request: httpx.Request) -> httpx.Response:
    """A keyed create replayed after the delete: the server returns the destroyed record."""
    assert (request.method, request.url.path) == ("POST", SANDBOXES)
    assert request.headers["Idempotency-Key"] == "key-1"
    data = {"id": SID, "name": "demo", "state": "destroyed", "error_reason": None}
    return httpx.Response(200, json=envelope(data), headers={"x-request-id": "req_replay"})


def test_a_destroyed_replay_raises_the_subclass_caught_by_the_base() -> None:
    client = Client(BASE, KEY)
    client._transport = sync_transport(destroyed_replay)

    with pytest.raises(SandboxFailedError) as raised:
        client.create_sandbox(idempotency_key="key-1", poll_interval_s=0)

    failure = raised.value
    assert isinstance(failure, SandboxDestroyedError)
    assert (failure.state, failure.error_code, failure.sandbox_id) == ("destroyed", None, SID)
    assert (failure.request_id, failure.deleted) == ("req_replay", False)


async def test_async_destroyed_replay_raises_the_subclass() -> None:
    client = AsyncClient(BASE, KEY)
    await client._transport._http.aclose()
    client._transport = async_transport(destroyed_replay)

    with pytest.raises(SandboxDestroyedError) as raised:
        await client.create_sandbox(idempotency_key="key-1", poll_interval_s=0)

    assert raised.value.state == "destroyed"
    assert raised.value.error_code is None


def test_an_error_state_stays_a_plain_sandbox_failed_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        data = {"id": SID, "name": "demo", "state": "error", "error_code": "timeout"}
        return httpx.Response(200, json=envelope(data))

    client = Client(BASE, KEY)
    client._transport = sync_transport(handler)

    with pytest.raises(SandboxFailedError) as raised:
        client.create_sandbox(poll_interval_s=0, delete_on_failure=False)

    assert type(raised.value) is SandboxFailedError
    assert (raised.value.state, raised.value.error_code) == ("error", "timeout")


def test_as_deleted_keeps_the_subclass() -> None:
    failure = SandboxDestroyedError("sandbox x is destroyed", sandbox_id=SID, state="destroyed")

    assert isinstance(failure.as_deleted(), SandboxDestroyedError)


# --- ensure reports created ----------------------------------------------------------------


class ContextServer:
    """The create route: a named create answers 200 with the live context, 201 with a new one."""

    def __init__(self) -> None:
        self.live: dict[str, dict[str, Any]] = {}
        self.counter = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert (request.method, request.url.path) == ("POST", CONTEXTS)
        name = json.loads(request.content).get("name")
        if name is not None and name in self.live:
            return httpx.Response(200, json=envelope(self.live[name]))
        self.counter += 1
        context = {"id": f"ctx_{self.counter:016x}", "cwd": "/work", "name": name}
        if name is not None:
            self.live[name] = context
        return httpx.Response(201, json=envelope(context))


def test_ensure_reports_created_then_found() -> None:
    server = ContextServer()
    contexts = CodeContexts(SID, sync_transport(server))

    first = contexts.ensure(NAME)
    again = contexts.ensure(NAME)
    server.live.clear()  # the sandbox was stopped and started: the kernel is gone
    after = contexts.ensure(NAME)

    assert (first.created, again.created, after.created) == (True, False, True)
    assert again.id == first.id
    assert after.id != first.id


async def test_async_ensure_reports_created_then_found() -> None:
    server = ContextServer()
    contexts = AsyncCodeContexts(SID, async_transport(server))

    first = await contexts.ensure(NAME)
    again = await contexts.ensure(NAME)

    assert (first.created, again.created) == (True, False)
    assert again.id == first.id


def test_create_without_a_name_is_created_and_the_flag_is_read_only() -> None:
    context = CodeContexts(SID, sync_transport(ContextServer())).create()

    assert context.created is True
    with pytest.raises(AttributeError):
        context.created = False  # type: ignore[misc]


async def test_async_create_without_a_name_is_created() -> None:
    context = await AsyncCodeContexts(SID, async_transport(ContextServer())).create()

    assert context.created is True


RATE_LIMITED_REPLY = {
    "success": False,
    "data": None,
    "error": {"code": "RATE_LIMITED", "message": "slow down", "details": {}, "request_id": "r"},
}


class RateLimitedOnce:
    """The create route answering 429 RATE_LIMITED first, then what ``ContextServer`` would."""

    def __init__(self, server: ContextServer) -> None:
        self.server = server
        self.calls = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        if self.calls == 1:
            return httpx.Response(429, json=RATE_LIMITED_REPLY, headers={"Retry-After": "1"})
        return self.server(request)


def retrying_sync(handler: Handler, pauses: list[float]) -> SyncTransport:
    transport = SyncTransport(BASE, KEY, TIMEOUT_S, max_retries=2, sleep=pauses.append)
    transport._http.close()
    transport._http = httpx.Client(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return transport


def retrying_async(handler: Handler, pauses: list[float]) -> AsyncTransport:
    async def sleep(seconds: float) -> None:
        pauses.append(seconds)

    transport = AsyncTransport(BASE, KEY, TIMEOUT_S, max_retries=2, sleep=sleep)
    transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return transport


def test_a_named_create_is_resent_after_429_and_reports_created() -> None:
    handler, pauses = RateLimitedOnce(ContextServer()), []
    contexts = CodeContexts(SID, retrying_sync(handler, pauses))

    context = contexts.ensure(NAME)

    assert (handler.calls, len(pauses)) == (2, 1)
    assert context.created is True


async def test_async_named_create_is_resent_after_429_and_reports_created() -> None:
    handler, pauses = RateLimitedOnce(ContextServer()), []
    contexts = AsyncCodeContexts(SID, retrying_async(handler, pauses))

    context = await contexts.ensure(NAME)

    assert (handler.calls, len(pauses)) == (2, 1)
    assert context.created is True


def test_a_named_create_answered_200_after_a_429_reports_found() -> None:
    server = ContextServer()
    server.live[NAME] = {"id": CID, "cwd": "/work", "name": NAME}
    handler, pauses = RateLimitedOnce(server), []

    context = CodeContexts(SID, retrying_sync(handler, pauses)).ensure(NAME)

    assert (handler.calls, context.created, context.id) == (2, False, CID)


async def test_async_named_create_answered_200_reports_found() -> None:
    server = ContextServer()
    server.live[NAME] = {"id": CID, "cwd": "/work", "name": NAME}
    handler, pauses = RateLimitedOnce(server), []

    context = await AsyncCodeContexts(SID, retrying_async(handler, pauses)).ensure(NAME)

    assert (handler.calls, context.created, context.id) == (2, False, CID)


def test_a_reply_carries_the_status_of_the_final_answer() -> None:
    reply = sync_transport(ContextServer()).request("POST", CONTEXTS, json={"name": NAME})

    assert reply.status_code == 201


def test_a_named_create_error_is_typed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        error = {"code": "NOT_FOUND", "message": "no sandbox", "details": {}, "request_id": "r"}
        return httpx.Response(404, json={"success": False, "data": None, "error": error})

    with pytest.raises(NotFound):
        CodeContexts(SID, sync_transport(handler)).ensure(NAME)


# --- stream errors -------------------------------------------------------------------------


def stream_context(body: bytes, headers: dict[str, str]) -> CodeContext:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == STREAM
        return httpx.Response(200, content=body, headers=headers)

    return CodeContext(SID, CID, "/work", sync_transport(handler))


class BrokenStream(httpx.SyncByteStream):
    """A body that yields one output event and then fails mid-read."""

    def __iter__(self) -> Any:
        yield b'event: stdout\ndata: {"data": "1\\n"}\n\n'
        raise httpx.ReadError("connection reset")


def test_a_broken_stream_transport_error_carries_the_request_id() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=BrokenStream(), headers=SSE)

    context = CodeContext(SID, CID, "/work", sync_transport(handler))

    with pytest.raises(TransportError) as raised:
        list(context.run_stream("print(1)"))

    assert raised.value.request_id == REQUEST_ID
    assert "connection reset" in str(raised.value)


def test_a_stream_that_ends_early_carries_the_request_id() -> None:
    context = stream_context(b'event: stdout\ndata: {"data": "x"}\n\n', SSE)

    with pytest.raises(TransportError) as raised:
        list(context.run_stream("print(1)"))

    assert raised.value.request_id == REQUEST_ID


def test_a_malformed_event_carries_the_request_id() -> None:
    context = stream_context(b"event: stdout\ndata: not json\n\n", SSE)

    with pytest.raises(InvalidResponseError) as raised:
        list(context.run_stream("print(1)"))

    assert raised.value.request_id == REQUEST_ID
    assert "stdout event" in str(raised.value)


def test_a_stream_error_without_the_header_has_no_request_id() -> None:
    context = stream_context(b"event: stdout\ndata: {}\n\n", {"content-type": "text/event-stream"})

    with pytest.raises(InvalidResponseError) as raised:
        list(context.run_stream("print(1)"))

    assert raised.value.request_id is None


async def test_async_stream_end_carries_the_request_id() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"", headers=SSE)

    context = AsyncCodeContext(SID, CID, "/work", async_transport(handler))

    with pytest.raises(TransportError) as raised:
        async with await context.run_stream("1") as events:
            [event async for event in events]

    assert raised.value.request_id == REQUEST_ID


def test_an_error_event_without_details_has_empty_details_and_no_has_details() -> None:
    event = b'event: error\ndata: {"code": "INTERNAL", "message": "kernel died"}\n\n'
    context = stream_context(event, SSE)

    with pytest.raises(InternalError) as raised:
        list(context.run_stream("1"))

    assert raised.value.details == {}
    assert raised.value.has_details is False
    assert (raised.value.request_id, raised.value.status_code) == (REQUEST_ID, 200)


def test_an_error_event_with_details_keeps_them() -> None:
    data = {"code": "CONFLICT", "message": "gone", "details": {"reason": "no_container"}}
    context = stream_context(f"event: error\ndata: {json.dumps(data)}\n\n".encode(), SSE)

    with pytest.raises(NoContainer) as raised:
        list(context.run_stream("1"))

    assert raised.value.details == {"reason": "no_container"}
    assert raised.value.has_details is True


def test_a_result_event_still_ends_the_stream() -> None:
    result = {
        "exit_code": 0,
        "stdout": "",
        "stderr": "",
        "timed_out": False,
        "truncated": False,
        "duration_ms": 1,
    }
    context = stream_context(f"event: result\ndata: {json.dumps(result)}\n\n".encode(), SSE)

    events = list(context.run_stream("1"))

    assert isinstance(events[-1], CellResult)


def test_a_reply_error_keeps_empty_details() -> None:
    error = error_for("INTERNAL", "boom")

    assert error.details == {}
    assert error.has_details is False
    assert error.details.get("reason") is None  # a dict for typed callers, never None


# --- CONTEXT_GONE_ERRORS -------------------------------------------------------------------


def test_context_gone_errors_is_exported_and_catches_both() -> None:
    assert CONTEXT_GONE_ERRORS == (NoContainer, NotFound)
    assert "CONTEXT_GONE_ERRORS" in sandfort_sdk.__all__
    assert "SandboxDestroyedError" in sandfort_sdk.__all__
    stopped = error_for("CONFLICT", "stopped", details={"reason": "no_container"})
    deleted = error_for("NOT_FOUND", "deleted")

    for error in (stopped, deleted):
        with pytest.raises(CONTEXT_GONE_ERRORS):
            raise error


FAILURE_MESSAGE = "sandbox sbx_x is error: image pull failed"
FAILURE_CODE = "image_not_found"


def failure(cls=SandboxFailedError, **extra):
    return cls(FAILURE_MESSAGE, sandbox_id="sbx_x", state="error", **extra)


@pytest.mark.parametrize("cls", [SandboxFailedError, SandboxDestroyedError])
def test_failure_str_names_the_error_code(cls):
    exc = failure(cls, error_code=FAILURE_CODE)

    assert str(exc) == f"{FAILURE_MESSAGE} [{FAILURE_CODE}]"
    assert exc.args[0] == FAILURE_MESSAGE
    assert exc.message == FAILURE_MESSAGE


@pytest.mark.parametrize("cls", [SandboxFailedError, SandboxDestroyedError])
def test_failure_str_without_a_code_is_the_message(cls):
    assert str(failure(cls)) == FAILURE_MESSAGE


def test_as_deleted_keeps_the_code_once_in_str():
    deleted = failure(error_code=FAILURE_CODE).as_deleted()

    assert str(deleted) == f"{FAILURE_MESSAGE} (the failed sandbox was deleted) [{FAILURE_CODE}]"
    assert deleted.error_code == FAILURE_CODE


# --- null image_ref / digest for a label-scoped key ---------------------------------------


def snapshot_payload(**extra):
    return {
        "id": "snap_1",
        "name": "py",
        "state": "ready",
        "layer_count": 2,
        "created_at": "2026-11-08T10:00:00Z",
        **extra,
    }


def test_snapshot_from_payload_accepts_a_null_image_ref_and_digest():
    info = SnapshotInfo.from_payload(snapshot_payload(image_ref=None, digest=None))

    assert info.image_ref is None
    assert info.digest is None


def test_snapshot_from_payload_keeps_a_string_image_ref():
    info = SnapshotInfo.from_payload(snapshot_payload(image_ref="python:3.12", digest="sha256:a"))

    assert (info.image_ref, info.digest) == ("python:3.12", "sha256:a")


# --- the message never carries the code; only str() composes it ------------------------------


def reason_failure(reason):
    return SandboxFailedError(
        f"sandbox sbx_x is error: {reason}",
        sandbox_id="sbx_x",
        state="error",
        error_code=FAILURE_CODE,
    )


def test_str_keeps_a_reason_that_ends_in_the_code_token():
    reason = f"gave up [{FAILURE_CODE}]"
    exc = reason_failure(reason)

    assert exc.message == f"sandbox sbx_x is error: {reason}"
    assert str(exc) == f"sandbox sbx_x is error: {reason} [{FAILURE_CODE}]"


def test_with_error_code_builds_from_the_message_without_stripping():
    reason = f"gave up [{FAILURE_CODE}]"

    line = with_error_code(reason_failure(reason))

    assert line == f"sandbox sbx_x is error [{FAILURE_CODE}]: {reason}"
