"""SDK r37: the streamed ``CellResult`` keeps the result event's ``stop_reason`` and
``timed_out``, exactly as the plain ``run`` result does (sync and async); failures pickle and
copy; request ids: the created handle exposes the create reply's, an immediate error-state
create fails with it, and ``str()`` of an ``ApiError`` or ``SandboxFailedError`` ends with it."""

import copy
import json
import pickle
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
from sandfort_sdk import ApiError, CellResult, NotFound, ValidationFailed  # noqa: E402
from sandfort_sdk._transport import AsyncTransport, SyncTransport, client_kwargs  # noqa: E402
from sandfort_sdk.code_contexts import AsyncCodeContext, CodeContext, OutputChunk  # noqa: E402
from sandfort_sdk.exceptions import SandboxDestroyedError, SandboxFailedError  # noqa: E402

from test_sdk_r30 import (  # noqa: E402
    ONE_SANDBOX,
    SANDBOXES,
    Router,
    async_client,
    ok,
    sandbox_json,
    sync_client,
)

BASE = "http://sandfort.test"
KEY = "sf_test_key"
TIMEOUT_S = 30.0
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
CID = "ctx_0123456789abcdef"
CONTEXTS = f"/v1/sandboxes/{SID}/toolbox/code-contexts"
RUN = f"{CONTEXTS}/{CID}/run"
STREAM = f"{RUN}/stream"
SSE = {"content-type": "text/event-stream"}
Handler = Callable[[httpx.Request], httpx.Response]

STOPPED: dict[str, Any] = {
    "exit_code": 137,
    "stdout": "1\n",
    "stderr": "",
    "timed_out": False,
    "truncated": False,
    "duration_ms": 12,
    "sandbox_stopped": True,
    "stop_reason": "sandbox_stopped",
    "result": None,
    "error": None,
}
TIMED_OUT: dict[str, Any] = {
    **STOPPED,
    "exit_code": 124,
    "timed_out": True,
    "sandbox_stopped": False,
    "stop_reason": "timeout",
}
NORMAL: dict[str, Any] = {
    **STOPPED,
    "exit_code": 0,
    "sandbox_stopped": False,
    "stop_reason": None,
    "result": "42",
}


def sse_body(payload: dict[str, Any]) -> bytes:
    out = b'event: stdout\ndata: {"data": "1\\n"}\n\n'
    return out + f"event: result\ndata: {json.dumps(payload)}\n\n".encode()


def envelope(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data, "error": None, "meta": None}


def handler_for(payload: dict[str, Any]) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == STREAM:
            return httpx.Response(200, content=sse_body(payload), headers=SSE)
        assert request.url.path == RUN
        return httpx.Response(200, json=envelope(payload))

    return handler


def sync_context(payload: dict[str, Any]) -> CodeContext:
    transport = SyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    transport._http.close()
    transport._http = httpx.Client(
        transport=httpx.MockTransport(handler_for(payload)),
        **client_kwargs(BASE, KEY, TIMEOUT_S),
    )
    return CodeContext(SID, CID, "/work", transport)


def async_context(payload: dict[str, Any]) -> AsyncCodeContext:
    transport = AsyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler_for(payload)),
        **client_kwargs(BASE, KEY, TIMEOUT_S),
    )
    return AsyncCodeContext(SID, CID, "/work", transport)


def streamed_result(events: list[Any]) -> CellResult:
    assert isinstance(events[0], OutputChunk)
    final = events[-1]
    assert isinstance(final, CellResult)
    return final


def test_a_streamed_result_keeps_the_sandbox_stopped_reason() -> None:
    context = sync_context(STOPPED)

    streamed = streamed_result(list(context.run_stream("print(1)")))

    assert streamed.stop_reason == "sandbox_stopped"
    assert streamed.sandbox_stopped is True
    assert streamed == context.run("print(1)")


def test_a_streamed_result_keeps_timed_out_and_its_reason() -> None:
    context = sync_context(TIMED_OUT)

    streamed = streamed_result(list(context.run_stream("print(1)")))

    assert (streamed.timed_out, streamed.stop_reason) == (True, "timeout")
    assert streamed == context.run("print(1)")


def test_a_streamed_normal_end_has_no_stop_reason() -> None:
    streamed = streamed_result(list(sync_context(NORMAL).run_stream("40 + 2")))

    assert (streamed.stop_reason, streamed.timed_out, streamed.result) == (None, False, "42")


async def test_an_async_streamed_result_keeps_the_sandbox_stopped_reason() -> None:
    context = async_context(STOPPED)

    async with await context.run_stream("print(1)") as events:
        streamed = streamed_result([event async for event in events])

    assert streamed.stop_reason == "sandbox_stopped"
    assert streamed == await context.run("print(1)")


async def test_an_async_streamed_result_keeps_timed_out_and_its_reason() -> None:
    context = async_context(TIMED_OUT)

    async with await context.run_stream("print(1)") as events:
        streamed = streamed_result([event async for event in events])

    assert (streamed.timed_out, streamed.stop_reason) == (True, "timeout")
    assert streamed == await context.run("print(1)")


# --- failure exceptions pickle and copy ---------------------------------------------------------

FAILED_ATTRS = (
    "message",
    "sandbox_id",
    "state",
    "request_id",
    "error_reason",
    "error_code",
    "deleted",
)


def failures() -> list[SandboxFailedError]:
    failed = SandboxFailedError(
        "sandbox failed (request id req_1)",
        sandbox_id=SID,
        state="error",
        request_id="req_1",
        error_reason="oom",
        error_code="timeout",
    )
    destroyed = SandboxDestroyedError(
        "sandbox was deleted", sandbox_id=SID, state="destroyed", deleted=True
    )
    return [failed, failed.as_deleted(), destroyed]


def assert_same_failure(copy_: SandboxFailedError, original: SandboxFailedError) -> None:
    assert type(copy_) is type(original)
    assert copy_ is not original
    for attr in FAILED_ATTRS:
        assert getattr(copy_, attr) == getattr(original, attr), attr
    assert copy_.args == original.args
    assert str(copy_) == str(original)


@pytest.mark.parametrize("protocol", [2, 5])
@pytest.mark.parametrize("exc", failures(), ids=lambda e: type(e).__name__ + str(e.deleted))
def test_failure_exceptions_round_trip_through_pickle(
    exc: SandboxFailedError, protocol: int
) -> None:
    restored = pickle.loads(pickle.dumps(exc, protocol=protocol))

    assert_same_failure(restored, exc)


@pytest.mark.parametrize("exc", failures(), ids=lambda e: type(e).__name__ + str(e.deleted))
def test_failure_exceptions_survive_copy_and_deepcopy(exc: SandboxFailedError) -> None:
    assert_same_failure(copy.copy(exc), exc)
    assert_same_failure(copy.deepcopy(exc), exc)


def test_a_pickled_failure_keeps_the_code_in_str_and_extra_attributes() -> None:
    exc = failures()[0]
    exc.message += " (retry later)"
    exc.extra = "kept"  # type: ignore[attr-defined]

    restored = pickle.loads(pickle.dumps(exc))

    assert str(restored) == str(exc) == "sandbox failed (request id req_1) (retry later) [timeout]"
    assert restored.extra == "kept"
    assert isinstance(restored, SandboxFailedError)
    assert restored.as_deleted().deleted is True


def test_the_destroyed_subclass_is_still_caught_as_a_failure_after_pickling() -> None:
    restored = pickle.loads(pickle.dumps(failures()[2]))

    assert isinstance(restored, SandboxDestroyedError)
    assert isinstance(restored, SandboxFailedError)


# --- request ids: the create handle, an immediate error-state create, str() -------------------

CREATE_REQUEST_ID = "req_create_0001"
ERROR_SANDBOX = {"state": "error", "error_reason": "no such image", "error_code": "image_pull"}


def create_reply(**over: Any) -> httpx.Response:
    """The 201 create reply, with the ``x-request-id`` header the server sets."""
    body = {"success": True, "data": sandbox_json(**over), "meta": None}
    return httpx.Response(201, json=body, headers={"x-request-id": CREATE_REQUEST_ID})


def creates(**over: Any) -> Router:
    return Router(
        {
            ("POST", SANDBOXES): create_reply(**over),
            ("GET", ONE_SANDBOX): ok(),
            ("DELETE", ONE_SANDBOX): ok(sandbox_json(state="destroying")),
        }
    )


def test_the_created_handle_exposes_the_create_reply_request_id() -> None:
    client, _ = sync_client(creates())

    sandbox = client.create_sandbox(name="demo", wait=False)

    assert sandbox.request_id == CREATE_REQUEST_ID
    assert client.get(SID).request_id is None  # only create_sandbox sets it
    sandbox.refresh()
    assert sandbox.request_id == CREATE_REQUEST_ID


def test_the_handle_request_id_is_read_only() -> None:
    client, _ = sync_client(creates())
    sandbox = client.create_sandbox(name="demo", wait=False)

    with pytest.raises(AttributeError):
        sandbox.request_id = "req_other"  # type: ignore[misc]


async def test_the_async_created_handle_exposes_the_create_reply_request_id() -> None:
    client, _ = await async_client(creates())

    sandbox = await client.create_sandbox(name="demo", wait=False)

    assert sandbox.request_id == CREATE_REQUEST_ID
    assert (await client.get(SID)).request_id is None
    await client.aclose()


@pytest.mark.parametrize("delete_on_failure", [True, False])
def test_an_immediate_error_state_create_fails_with_the_create_reply_request_id(
    delete_on_failure: bool,
) -> None:
    client, _ = sync_client(creates(**ERROR_SANDBOX))

    with pytest.raises(SandboxFailedError) as caught:
        client.create_sandbox(name="demo", delete_on_failure=delete_on_failure)

    assert caught.value.request_id == CREATE_REQUEST_ID
    assert caught.value.deleted is delete_on_failure
    assert str(caught.value).endswith(f" (request id {CREATE_REQUEST_ID})")
    assert str(caught.value).count(CREATE_REQUEST_ID) == 1


@pytest.mark.parametrize("delete_on_failure", [True, False])
async def test_an_async_immediate_error_state_create_fails_with_the_create_reply_request_id(
    delete_on_failure: bool,
) -> None:
    client, _ = await async_client(creates(**ERROR_SANDBOX))

    with pytest.raises(SandboxFailedError) as caught:
        await client.create_sandbox(name="demo", delete_on_failure=delete_on_failure)

    assert caught.value.request_id == CREATE_REQUEST_ID
    assert caught.value.deleted is delete_on_failure
    assert str(caught.value).endswith(f" (request id {CREATE_REQUEST_ID})")
    await client.aclose()


def test_api_error_str_ends_with_the_request_id_when_it_is_set() -> None:
    error = NotFound("no such sandbox", request_id="req_9")

    assert str(error) == "no such sandbox (request id req_9)"
    assert error.message == "no such sandbox"  # the message itself never carries it
    assert error.args == ("no such sandbox",)


def test_api_error_str_is_the_bare_message_without_a_request_id() -> None:
    assert str(ApiError("boom")) == "boom"
    assert str(ValidationFailed("bad", details={"field": "name"})) == "bad"


def test_a_server_api_error_names_the_reply_request_id_in_str() -> None:
    error = {"code": "NOT_FOUND", "message": "gone", "details": {}, "request_id": "req_srv"}
    reply = httpx.Response(404, json={"success": False, "data": None, "error": error})
    client, _ = sync_client(Router({("GET", ONE_SANDBOX): reply}))

    with pytest.raises(NotFound) as caught:
        client.get(SID)

    assert str(caught.value) == "gone (request id req_srv)"


def test_sandbox_failed_str_ends_with_the_request_id_after_the_code() -> None:
    failure = SandboxFailedError(
        "sandbox x is error: oom",
        sandbox_id=SID,
        state="error",
        request_id="req_2",
        error_code="oom_killed",
    )

    assert str(failure) == "sandbox x is error: oom [oom_killed] (request id req_2)"
    assert failure.message == "sandbox x is error: oom"
    assert str(failure.as_deleted()).endswith("[oom_killed] (request id req_2)")


def test_sandbox_failed_str_without_a_request_id_or_code_is_the_message() -> None:
    failure = SandboxFailedError("sandbox x is error", sandbox_id=SID, state="error")

    assert str(failure) == "sandbox x is error"


def test_sandbox_failed_str_names_the_request_id_once_when_the_message_has_it() -> None:
    failure = SandboxFailedError(
        "sandbox x is error (request id req_3)",
        sandbox_id=SID,
        state="error",
        request_id="req_3",
        error_code="timeout",
    )

    assert str(failure) == "sandbox x is error [timeout] (request id req_3)"
    assert str(failure).count("req_3") == 1


def test_a_request_id_set_after_the_raise_shows_in_str() -> None:
    failure = SandboxFailedError("sandbox x is error", sandbox_id=SID, state="error")
    failure.request_id = "req_late"

    assert str(failure) == "sandbox x is error (request id req_late)"
