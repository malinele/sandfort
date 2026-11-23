"""SDK v0: sync and async clients against respx-mocked endpoints (daemon-free)."""

import asyncio
import dataclasses
import inspect
import json
import logging
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_sdk import (  # noqa: E402
    ApiError,
    AsyncClient,
    CapacityExceeded,
    Client,
    Conflict,
    DriverError,
    DriverTimeout,
    ExecResult,
    Forbidden,
    InternalError,
    InvalidResponseError,
    InvalidState,
    IsolationInfo,
    NotFound,
    Page,
    PayloadTooLarge,
    QuotaExceeded,
    RateLimited,
    Resources,
    SandboxFailedError,
    SandboxTimeoutError,
    SandfortSDKError,
    TransportError,
    Unauthorized,
    Unprocessable,
    Unsupported,
    ValidationFailed,
)
from sandfort_sdk import async_client as async_client_module  # noqa: E402
from sandfort_sdk._transport import HTTP_MARGIN_S, Reply  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOX_URL = f"/v1/sandboxes/{SID}"
EXEC_URL = f"{SANDBOX_URL}/toolbox/process/execute"
CODE_RUN_URL = f"{SANDBOX_URL}/toolbox/process/code-run"
EXEC_PAYLOAD = {
    "exit_code": 0,
    "stdout": "hi\n",
    "stderr": "",
    "timed_out": False,
    "truncated": False,
    "duration_ms": 12,
}


def sandbox_json(state: str = "started", **overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "id": SID,
        "name": "demo",
        "state": state,
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "env": {},
        "labels": {},
        "network": {"block_all": False},
        "public": False,
        "auto_stop_minutes": 15,
        "auto_delete_minutes": -1,
        "error_reason": None,
        "job_id": None,
    }
    return {**data, **overrides}


def envelope(data: object, next_cursor: str | None = None) -> dict[str, object]:
    meta = {"next_cursor": next_cursor} if next_cursor is not None else None
    return {"success": True, "data": data, "error": None, "meta": meta}


def error_envelope(
    code: str, message: str = "boom", details: dict[str, object] | None = None
) -> dict[str, object]:
    error = {"code": code, "message": message, "details": details or {}, "request_id": "req_1"}
    return {"success": False, "data": None, "error": error, "meta": None}


def reply(data: object, next_cursor: str | None = None) -> httpx.Response:
    return httpx.Response(200, json=envelope(data, next_cursor))


async def call(fn, *args, **kwargs):  # type: ignore[no-untyped-def]
    """Invoke a sync or async SDK callable and return its result."""
    result = fn(*args, **kwargs)
    return await result if inspect.isawaitable(result) else result


async def collect(client, **kwargs):  # type: ignore[no-untyped-def]
    iterator = client.iter_sandboxes(**kwargs)
    if hasattr(iterator, "__aiter__"):
        return [item async for item in iterator]
    return list(iterator)


def new_client(kind: str, **kwargs):  # type: ignore[no-untyped-def]
    cls = Client if kind == "sync" else AsyncClient
    return cls(BASE, KEY, **kwargs)


async def close(client) -> None:  # type: ignore[no-untyped-def]
    await call(client.close if isinstance(client, Client) else client.aclose)


@pytest.fixture
def api():  # type: ignore[no-untyped-def]
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        yield router
        for recorded in router.calls:
            assert recorded.request.headers["authorization"] == f"Bearer {KEY}"


@pytest.fixture(params=["sync", "async"])
def kind(request) -> str:  # type: ignore[no-untyped-def]
    return request.param


@pytest.fixture
async def client(kind):  # type: ignore[no-untyped-def]
    # One attempt per call: error mapping is checked here, retries in test_sdk_retries.py.
    instance = new_client(kind, max_retries=0)
    yield instance
    await close(instance)


async def started_sandbox(api, client):  # type: ignore[no-untyped-def]
    api.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json()))
    return await call(client.get, SID)


# --- create_sandbox --------------------------------------------------------------------


async def test_create_without_wait_posts_body_and_returns_facade(api, client):
    route = api.post("/v1/sandboxes").respond(
        201, json=envelope(sandbox_json("pending", job_id="job_1"))
    )

    sandbox = await call(
        client.create_sandbox,
        name="demo",
        resources=Resources(cpu_millicores=500, memory_mib=256, disk_gib=2),
        env={"A": "1"},
        labels={"k": "v"},
        block_network=True,
        auto_stop_minutes=5,
        wait=False,
    )

    assert (sandbox.id, sandbox.state, sandbox.info.job_id) == (SID, "pending", "job_1")
    assert json.loads(route.calls.last.request.content) == {
        "name": "demo",
        "resources": {"cpu_millicores": 500, "memory_mib": 256, "disk_gib": 2},
        "env": {"A": "1"},
        "labels": {"k": "v"},
        "network": {"block_all": True},
        "auto_stop_minutes": 5,
    }
    assert api.calls.call_count == 1


async def test_create_already_started_skips_polling(api, client):
    route = api.post("/v1/sandboxes").respond(201, json=envelope(sandbox_json("started")))

    sandbox = await call(client.create_sandbox)

    assert sandbox.state == "started"
    assert json.loads(route.calls.last.request.content) == {}
    assert api.calls.call_count == 1


async def test_create_sends_the_isolation_tier_and_the_handle_reports_it(api, client):
    route = api.post("/v1/sandboxes").respond(
        201, json=envelope(sandbox_json("started", isolation="gvisor"))
    )

    sandbox = await call(client.create_sandbox, isolation="gvisor")

    assert json.loads(route.calls.last.request.content) == {"isolation": "gvisor"}
    assert (sandbox.isolation, sandbox.info.isolation) == ("gvisor", "gvisor")


async def test_create_without_isolation_leaves_the_field_out(api, client):
    route = api.post("/v1/sandboxes").respond(201, json=envelope(sandbox_json("started")))

    await call(client.create_sandbox, name="demo", isolation=None)

    assert "isolation" not in json.loads(route.calls.last.request.content)


async def test_unavailable_isolation_tier_surfaces_the_server_message(api, client):
    message = "isolation 'microvm' is not available here; available: container, gvisor"
    api.post("/v1/sandboxes").respond(422, json=error_envelope("UNPROCESSABLE", message))

    with pytest.raises(Unprocessable, match="not available here"):
        await call(client.create_sandbox, isolation="microvm", wait=False)


async def test_sandbox_without_isolation_parses_as_container(api, client):
    sandbox = await started_sandbox(api, client)

    assert sandbox.isolation == "container"
    assert sandbox.info.isolation == "container"


async def test_isolation_follows_a_refresh(api, client):
    sandbox = await started_sandbox(api, client)
    api.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json(isolation="microvm")))

    await call(sandbox.refresh)

    assert sandbox.isolation == "microvm"


async def test_client_isolation_returns_the_default_and_available_tiers(api, client):
    route = api.get("/v1/isolation").respond(
        200, json=envelope({"default": "container", "available": ["container", "gvisor"]})
    )

    info = await call(client.isolation)

    assert route.call_count == 1
    assert info == IsolationInfo(default="container", available=("container", "gvisor"))
    assert isinstance(info.available, tuple)
    with pytest.raises(AttributeError):
        info.default = "gvisor"  # type: ignore[misc]


@pytest.mark.parametrize("data", [{"default": "container"}, {"available": []}, ["container"]])
async def test_client_isolation_rejects_a_malformed_payload(api, client, data):
    api.get("/v1/isolation").respond(200, json=envelope(data))

    with pytest.raises(InvalidResponseError):
        await call(client.isolation)


async def test_create_wait_polls_until_started(api, client):
    api.post("/v1/sandboxes").respond(201, json=envelope(sandbox_json("pending")))
    poll = api.get(SANDBOX_URL)
    poll.side_effect = [reply(sandbox_json("creating")), reply(sandbox_json("started"))]

    sandbox = await call(client.create_sandbox, poll_interval_s=0)

    assert sandbox.state == "started"
    assert poll.call_count == 2
    for recorded in poll.calls:
        params = recorded.request.url.params
        assert params["wait_for"] == "started"
        assert 0 < float(params["timeout_s"]) <= 30


async def test_create_wait_raises_when_sandbox_errors(api, client):
    api.post("/v1/sandboxes").respond(201, json=envelope(sandbox_json("pending")))
    api.get(SANDBOX_URL).respond(
        200, json=envelope(sandbox_json("error", error_reason="image pull failed"))
    )
    delete = api.delete(SANDBOX_URL).respond(200, json=envelope(sandbox_json("destroying")))

    with pytest.raises(SandboxFailedError, match="image pull failed") as info:
        await call(client.create_sandbox, poll_interval_s=0)

    assert (info.value.sandbox_id, info.value.state) == (SID, "error")
    assert info.value.deleted is True
    assert delete.call_count == 1


async def test_create_wait_keeps_the_failed_sandbox_when_delete_on_failure_is_false(api, client):
    api.post("/v1/sandboxes").respond(201, json=envelope(sandbox_json("pending")))
    api.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json("error")))
    delete = api.delete(SANDBOX_URL).respond(200, json=envelope(sandbox_json("destroying")))

    with pytest.raises(SandboxFailedError) as info:
        await call(client.create_sandbox, poll_interval_s=0, delete_on_failure=False)

    assert info.value.deleted is False
    assert delete.call_count == 0


async def test_create_wait_times_out_when_budget_is_spent(api, client):
    api.post("/v1/sandboxes").respond(201, json=envelope(sandbox_json("pending")))

    with pytest.raises(SandboxTimeoutError):
        await call(client.create_sandbox, wait_timeout_s=1e-9)  # spent by the POST

    assert api.calls.call_count == 1


async def test_create_wait_timeout_names_the_sandbox_and_its_last_state(api, client):
    api.post("/v1/sandboxes").respond(201, json=envelope(sandbox_json("pending")))

    with pytest.raises(SandboxTimeoutError) as raised:
        await call(client.create_sandbox, wait_timeout_s=1e-9)  # spent by the POST

    assert (raised.value.sandbox_id, raised.value.state) == (SID, "pending")
    assert "still pending" in str(raised.value)


def test_sandbox_timeout_error_still_builds_from_a_message_alone():
    error = SandboxTimeoutError("took too long")

    assert str(error) == "took too long"
    assert (error.sandbox_id, error.state) == (None, None)
    assert isinstance(error, SandfortSDKError)


# --- AsyncClient.create_sandbox: cancellation safety -----------------------------------


class FakeAsyncTransport:
    """Stands in for ``AsyncTransport``: records calls, blocks POST or GET on demand."""

    def __init__(
        self, *, post_gate: asyncio.Event | None = None, block_polls: bool = False
    ) -> None:
        self.post_gate = post_gate
        self.block_polls = block_polls
        self.calls: list[tuple[str, str]] = []
        self.delete_error: Exception | None = None

    async def aclose(self) -> None:
        self.calls.append(("CLOSE", ""))

    @property
    def deletes(self) -> list[str]:
        return [path for method, path in self.calls if method == "DELETE"]

    async def request(self, method: str, path: str, **kwargs: object) -> Reply:
        self.calls.append((method, path))
        if method == "POST":
            if self.post_gate is not None:
                await self.post_gate.wait()
            return Reply(sandbox_json("pending"), None)
        if method == "GET":
            if self.block_polls:
                await asyncio.Event().wait()
            return Reply(sandbox_json("pending"), None)
        if self.delete_error is not None:
            raise self.delete_error
        return Reply(sandbox_json("destroying"), None)


async def drain_background_tasks() -> None:
    """Wait until every cleanup task the SDK spawned has finished."""
    await asyncio.sleep(0)
    while async_client_module._BACKGROUND_TASKS:
        await asyncio.gather(*list(async_client_module._BACKGROUND_TASKS), return_exceptions=True)
        await asyncio.sleep(0)


def fake_client(fake: FakeAsyncTransport) -> AsyncClient:
    client = AsyncClient(BASE, KEY)
    client._transport = fake  # type: ignore[assignment]
    return client


async def cancel_create(fake: FakeAsyncTransport, **kwargs: object) -> None:
    """Start ``create_sandbox`` on the fake, let it run for a moment, then cancel it."""
    await cancel_create_on(fake_client(fake), **kwargs)


async def cancel_create_on(client: AsyncClient, **kwargs: object) -> None:
    task = asyncio.ensure_future(client.create_sandbox(poll_interval_s=0, **kwargs))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_create_cancelled_during_the_post_deletes_the_sandbox_once_it_exists():
    gate = asyncio.Event()
    fake = FakeAsyncTransport(post_gate=gate)

    await cancel_create(fake)
    assert fake.deletes == []  # the POST has not completed yet: no id to delete
    gate.set()
    await drain_background_tasks()

    assert fake.deletes == [SANDBOX_URL]
    assert fake.calls == [("POST", "/v1/sandboxes"), ("DELETE", SANDBOX_URL)]


async def test_create_cancelled_during_the_wait_loop_deletes_the_known_sandbox():
    fake = FakeAsyncTransport(block_polls=True)

    await cancel_create(fake)
    await drain_background_tasks()

    assert [method for method, _ in fake.calls] == ["POST", "GET", "DELETE"]
    assert fake.deletes == [SANDBOX_URL]


@pytest.mark.parametrize("during", ["post", "wait"])
async def test_create_cancelled_with_delete_on_cancel_off_deletes_nothing(during):
    gate = asyncio.Event()
    fake = FakeAsyncTransport(post_gate=gate if during == "post" else None, block_polls=True)

    await cancel_create(fake, delete_on_cancel=False)
    gate.set()
    await drain_background_tasks()

    assert fake.deletes == []


async def test_create_cancel_cleanup_that_fails_is_logged_and_never_raised(caplog):
    fake = FakeAsyncTransport(block_polls=True)
    fake.delete_error = TransportError("DELETE failed: connection reset")

    with caplog.at_level(logging.WARNING, logger="sandfort_sdk.async_client"):
        await cancel_create(fake)
        await drain_background_tasks()

    assert fake.deletes == [SANDBOX_URL]
    assert any(SID in record.getMessage() for record in caplog.records)


async def test_create_cancelled_while_the_post_fails_has_nothing_to_delete():
    gate = asyncio.Event()
    fake = FakeAsyncTransport(post_gate=gate)
    original = fake.request

    async def failing(method: str, path: str, **kwargs: object) -> Reply:
        if method == "POST":
            await gate.wait()
            raise TransportError("POST failed")
        return await original(method, path, **kwargs)

    fake.request = failing  # type: ignore[method-assign]

    await cancel_create(fake)
    gate.set()
    await drain_background_tasks()

    assert fake.deletes == []


async def test_aclose_right_after_a_cancelled_create_still_performs_the_delete_first():
    gate = asyncio.Event()
    fake = FakeAsyncTransport(post_gate=gate)
    client = fake_client(fake)

    await cancel_create_on(client)
    asyncio.get_running_loop().call_later(0.01, gate.set)
    await client.aclose()

    assert fake.calls == [("POST", "/v1/sandboxes"), ("DELETE", SANDBOX_URL), ("CLOSE", "")]


async def test_aclose_without_pending_cleanup_closes_immediately():
    fake = FakeAsyncTransport()

    await asyncio.wait_for(fake_client(fake).aclose(), timeout=0.5)

    assert fake.calls == [("CLOSE", "")]


async def test_aclose_does_not_wait_for_a_cleanup_beyond_the_bound(monkeypatch, caplog):
    monkeypatch.setattr(async_client_module, "CLEANUP_WAIT_S", 0.05)
    gate = asyncio.Event()  # never set while aclose runs: the create request hangs
    fake = FakeAsyncTransport(post_gate=gate)
    client = fake_client(fake)
    await cancel_create_on(client)

    started = time.monotonic()
    with caplog.at_level(logging.WARNING, logger="sandfort_sdk.async_client"):
        await asyncio.wait_for(client.aclose(), timeout=2)
    elapsed = time.monotonic() - started

    assert elapsed < 1
    assert fake.calls[-1] == ("CLOSE", "")
    assert any("unfinished" in record.getMessage() for record in caplog.records)
    gate.set()  # let the orphaned request end so it does not outlive the test
    await drain_background_tasks()


# --- list / get / lifecycle ------------------------------------------------------------


async def test_list_sandboxes_returns_page_with_cursor_and_filters(api, client):
    other = sandbox_json(id="sbx_02", name="other")
    route = api.get("/v1/sandboxes")
    route.side_effect = [reply([sandbox_json(), other], "c1"), reply([], None)]

    page = await call(
        client.list_sandboxes, state="started", labels={"a": "1", "b": "2"}, limit=2
    )
    last = await call(client.list_sandboxes, cursor=page.next_cursor)

    assert [item.id for item in page.items] == [SID, "sbx_02"]
    assert page.next_cursor == "c1"
    assert (last.items, last.next_cursor) == ((), None)
    first_params = route.calls[0].request.url.params
    assert first_params["state"] == "started"
    assert first_params.get_list("label") == ["a=1", "b=2"]
    assert first_params["limit"] == "2"
    assert "cursor" not in first_params
    assert route.calls[1].request.url.params["cursor"] == "c1"


async def test_iter_sandboxes_follows_cursor_across_pages(api, client):
    route = api.get("/v1/sandboxes")
    route.side_effect = [
        reply([sandbox_json(id="sbx_a")], "next"),
        reply([sandbox_json(id="sbx_b")], None),
    ]

    sandboxes = await collect(client, limit=1)

    assert [item.id for item in sandboxes] == ["sbx_a", "sbx_b"]
    assert route.calls[1].request.url.params["cursor"] == "next"


@pytest.mark.parametrize(
    ("method", "verb", "suffix", "state"),
    [
        ("get", "GET", "", "started"),
        ("start", "POST", "/start", "started"),
        ("stop", "POST", "/stop", "stopped"),
        ("delete", "DELETE", "", "destroying"),
    ],
)
async def test_lifecycle_calls_hit_expected_route(api, client, method, verb, suffix, state):
    route = api.route(method=verb, path=f"{SANDBOX_URL}{suffix}").respond(
        200, json=envelope(sandbox_json(state))
    )

    sandbox = await call(getattr(client, method), SID)

    assert (sandbox.id, sandbox.state) == (SID, state)
    assert route.call_count == 1
    assert "wait_for" not in route.calls.last.request.url.params


# --- handle lifecycle ------------------------------------------------------------------


async def test_stop_updates_the_same_handle(api, client):
    sandbox = await started_sandbox(api, client)
    route = api.post(f"{SANDBOX_URL}/stop").respond(200, json=envelope(sandbox_json("stopped")))

    returned = await call(sandbox.stop)

    assert returned is sandbox
    assert sandbox.state == "stopped"
    assert route.call_count == 1


async def test_start_updates_the_same_handle(api, client):
    api.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json("stopped")))
    sandbox = await call(client.get, SID)
    route = api.post(f"{SANDBOX_URL}/start").respond(200, json=envelope(sandbox_json("started")))

    returned = await call(sandbox.start)

    assert returned is sandbox
    assert sandbox.state == "started"
    assert route.call_count == 1


async def test_refresh_replaces_info_with_the_fresh_record(api, client):
    sandbox = await started_sandbox(api, client)
    api.get(SANDBOX_URL).respond(
        200, json=envelope(sandbox_json("error", error_reason="disk full"))
    )

    returned = await call(sandbox.refresh)

    assert returned is sandbox
    assert (sandbox.state, sandbox.error_reason) == ("error", "disk full")


async def test_delete_returns_the_handle_in_its_destroyed_state(api, client):
    sandbox = await started_sandbox(api, client)
    route = api.delete(SANDBOX_URL).respond(200, json=envelope(sandbox_json("destroyed")))

    returned = await call(sandbox.delete)

    assert returned is sandbox
    assert (sandbox.id, sandbox.state) == (SID, "destroyed")
    assert route.call_count == 1


async def test_name_and_error_reason_properties_read_the_record(api, client):
    api.get(SANDBOX_URL).respond(
        200, json=envelope(sandbox_json("error", name="builder", error_reason="oom"))
    )

    sandbox = await call(client.get, SID)

    assert (sandbox.name, sandbox.error_reason) == ("builder", "oom")
    with pytest.raises(AttributeError):
        sandbox.name = "other"


async def test_toolbox_keeps_working_after_a_lifecycle_call(api, client):
    sandbox = await started_sandbox(api, client)
    api.post(f"{SANDBOX_URL}/stop").respond(200, json=envelope(sandbox_json("stopped")))
    route = api.post(EXEC_URL).respond(200, json=envelope(EXEC_PAYLOAD))

    await call(sandbox.stop)
    result = await call(sandbox.process_exec, "echo hi")

    assert result.ok
    assert route.call_count == 1


async def test_lifecycle_error_leaves_the_handle_unchanged(api, client):
    sandbox = await started_sandbox(api, client)
    api.post(f"{SANDBOX_URL}/stop").respond(409, json=error_envelope("INVALID_STATE"))

    with pytest.raises(InvalidState):
        await call(sandbox.stop)

    assert sandbox.state == "started"


async def test_failed_create_error_carries_code_and_reason(api, client):
    api.post("/v1/sandboxes").respond(201, json=envelope(sandbox_json("pending")))
    api.get(SANDBOX_URL).respond(
        200, json=envelope(sandbox_json("error", error_reason="image pull failed"))
    )

    with pytest.raises(SandboxFailedError) as raised:
        await call(client.create_sandbox, poll_interval_s=0, delete_on_failure=False)

    assert raised.value.code == "SANDBOX_FAILED"
    assert raised.value.error_reason == "image pull failed"
    assert raised.value.request_id is None
    assert str(raised.value) == f"sandbox {SID} is error: image pull failed"


def test_sandbox_failed_error_keeps_its_original_keywords():
    exc = SandboxFailedError("boom", sandbox_id=SID, state="error")

    assert (exc.sandbox_id, exc.state) == (SID, "error")
    assert (exc.error_reason, exc.request_id) == (None, None)
    assert SandboxFailedError.code == "SANDBOX_FAILED"


def test_page_is_iterable_and_has_a_length():
    page = Page(("a", "b"), "next")

    assert list(page) == ["a", "b"]
    assert len(page) == 2
    assert (page.items, page.next_cursor) == (("a", "b"), "next")
    assert len(Page(())) == 0


async def test_list_sandboxes_page_can_be_iterated_directly(api, client):
    other = sandbox_json(id="sbx_02", name="other")
    api.get("/v1/sandboxes").respond(200, json=envelope([sandbox_json(), other]))

    page = await call(client.list_sandboxes)

    assert len(page) == 2
    assert [sandbox.id for sandbox in page] == [SID, "sbx_02"]


# --- Sandbox facade --------------------------------------------------------------------


async def test_process_exec_command_sends_all_fields(api, client):
    sandbox = await started_sandbox(api, client)
    route = api.post(EXEC_URL).respond(200, json=envelope(EXEC_PAYLOAD))

    result = await call(
        sandbox.process_exec, "echo hi", cwd="/tmp", env={"A": "1"}, timeout_s=5, stdin="x"
    )

    assert (result.exit_code, result.stdout, result.duration_ms) == (0, "hi\n", 12)
    assert result.ok
    assert json.loads(route.calls.last.request.content) == {
        "command": "echo hi",
        "cwd": "/tmp",
        "env": {"A": "1"},
        "stdin": "x",
        "timeout_s": 5,
    }


async def test_process_exec_defaults_sandbox_stopped_when_the_server_omits_it(api, client):
    sandbox = await started_sandbox(api, client)
    api.post(EXEC_URL).respond(200, json=envelope(EXEC_PAYLOAD))

    result = await call(sandbox.process_exec, "echo hi")

    assert "sandbox_stopped" not in EXEC_PAYLOAD
    assert result.sandbox_stopped is False


async def test_process_exec_parses_sandbox_stopped_without_changing_ok(api, client):
    sandbox = await started_sandbox(api, client)
    payload = {**EXEC_PAYLOAD, "exit_code": 137, "sandbox_stopped": True}
    api.post(EXEC_URL).respond(200, json=envelope(payload))

    result = await call(sandbox.process_exec, "stress")

    assert result.sandbox_stopped is True
    assert result.exit_code == 137
    assert not result.ok


async def test_process_exec_ok_ignores_sandbox_stopped_on_exit_zero(api, client):
    sandbox = await started_sandbox(api, client)
    payload = {**EXEC_PAYLOAD, "sandbox_stopped": True}
    api.post(EXEC_URL).respond(200, json=envelope(payload))

    result = await call(sandbox.process_exec, "true")

    assert (result.sandbox_stopped, result.ok) == (True, True)


async def test_process_exec_stop_reason_is_none_when_the_server_omits_it(api, client):
    sandbox = await started_sandbox(api, client)
    api.post(EXEC_URL).respond(200, json=envelope(EXEC_PAYLOAD))

    result = await call(sandbox.process_exec, "echo hi")

    assert "stop_reason" not in EXEC_PAYLOAD
    assert result.stop_reason is None


@pytest.mark.parametrize("reason", ["timeout", "output_limit", "sandbox_stopped", "killed"])
async def test_process_exec_parses_stop_reason(api, client, reason):
    sandbox = await started_sandbox(api, client)
    payload = {**EXEC_PAYLOAD, "exit_code": 137, "stop_reason": reason}
    api.post(EXEC_URL).respond(200, json=envelope(payload))

    result = await call(sandbox.process_exec, "x")

    assert result.stop_reason == reason


async def test_code_run_parses_stop_reason(api, client):
    sandbox = await started_sandbox(api, client)
    payload = {**EXEC_PAYLOAD, "exit_code": 124, "timed_out": True, "stop_reason": "timeout"}
    api.post(CODE_RUN_URL).respond(200, json=envelope(payload))

    result = await call(sandbox.code_run, "python", "import time; time.sleep(9)")

    assert (result.stop_reason, result.ok) == ("timeout", False)


def test_exec_result_parses_a_null_stop_reason():
    result = ExecResult.from_payload({**EXEC_PAYLOAD, "stop_reason": None})

    assert result.stop_reason is None


def test_exec_result_rejects_a_non_string_stop_reason():
    with pytest.raises(InvalidResponseError):
        ExecResult.from_payload({**EXEC_PAYLOAD, "stop_reason": 7})


async def test_auto_stop_and_auto_delete_properties_read_the_record(api, client):
    api.get(SANDBOX_URL).respond(
        200, json=envelope(sandbox_json(auto_stop_minutes=30, auto_delete_minutes=120))
    )

    sandbox = await call(client.get, SID)

    assert (sandbox.auto_stop_minutes, sandbox.auto_delete_minutes) == (30, 120)
    with pytest.raises(AttributeError):
        sandbox.auto_stop_minutes = 1


async def test_auto_stop_and_auto_delete_properties_follow_a_refresh(api, client):
    sandbox = await started_sandbox(api, client)
    assert (sandbox.auto_stop_minutes, sandbox.auto_delete_minutes) == (15, -1)
    api.get(SANDBOX_URL).respond(
        200, json=envelope(sandbox_json(auto_stop_minutes=0, auto_delete_minutes=5))
    )

    await call(sandbox.refresh)

    assert (sandbox.auto_stop_minutes, sandbox.auto_delete_minutes) == (0, 5)


async def test_process_exec_argv_form(api, client):
    sandbox = await started_sandbox(api, client)
    route = api.post(EXEC_URL).respond(200, json=envelope(EXEC_PAYLOAD))

    await call(sandbox.process_exec, argv=["ls", "-l"])

    assert json.loads(route.calls.last.request.content) == {"argv": ["ls", "-l"], "timeout_s": 60}


async def test_process_exec_requires_exactly_one_command_form(api, client):
    sandbox = await started_sandbox(api, client)

    with pytest.raises(ValueError, match="exactly one"):
        await call(sandbox.process_exec)
    with pytest.raises(ValueError, match="exactly one"):
        await call(sandbox.process_exec, "ls", argv=["ls"])

    assert api.calls.call_count == 1  # only the get


async def test_code_run_posts_language_and_code(api, client):
    sandbox = await started_sandbox(api, client)
    failing = {**EXEC_PAYLOAD, "exit_code": 1, "timed_out": True}
    route = api.post(CODE_RUN_URL).respond(200, json=envelope(failing))

    result = await call(
        sandbox.code_run, "python", "print(1)", argv=["a"], env={"A": "1"}, timeout_s=10
    )

    assert not result.ok
    assert result.timed_out
    assert json.loads(route.calls.last.request.content) == {
        "language": "python",
        "code": "print(1)",
        "argv": ["a"],
        "env": {"A": "1"},
        "timeout_s": 10,
    }


async def test_code_run_body_includes_cwd_only_when_set(api, client):
    sandbox = await started_sandbox(api, client)
    route = api.post(CODE_RUN_URL).respond(200, json=envelope(EXEC_PAYLOAD))

    await call(sandbox.process.code_run, "python", "print(1)", cwd="/work", timeout_s=5)
    await call(sandbox.process.code_run, "python", "print(1)", timeout_s=5)

    with_cwd, without = (json.loads(c.request.content) for c in route.calls)
    assert with_cwd["cwd"] == "/work"
    assert "cwd" not in without


async def test_convenience_code_run_sends_cwd_only_when_given(api, client):
    sandbox = await started_sandbox(api, client)
    route = api.post(CODE_RUN_URL).respond(200, json=envelope(EXEC_PAYLOAD))

    await call(sandbox.code_run, "python", "print(1)", cwd="/work", timeout_s=5)
    await call(sandbox.code_run, "python", "print(1)", timeout_s=5)

    with_cwd, without = (json.loads(c.request.content) for c in route.calls)
    assert with_cwd["cwd"] == "/work"
    assert "cwd" not in without


async def test_toolbox_error_maps_to_invalid_state(api, client):
    sandbox = await started_sandbox(api, client)
    api.post(EXEC_URL).respond(409, json=error_envelope("INVALID_STATE", "sandbox is stopped"))

    with pytest.raises(InvalidState, match="sandbox is stopped"):
        await call(sandbox.process_exec, "ls")


# --- errors ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "code", "exc_type"),
    [
        (400, "VALIDATION_ERROR", ValidationFailed),
        (401, "UNAUTHORIZED", Unauthorized),
        (403, "FORBIDDEN", Forbidden),
        (404, "NOT_FOUND", NotFound),
        (409, "CONFLICT", Conflict),
        (409, "INVALID_STATE", InvalidState),
        (413, "PAYLOAD_TOO_LARGE", PayloadTooLarge),
        (422, "UNPROCESSABLE", Unprocessable),
        (429, "QUOTA_EXCEEDED", QuotaExceeded),
        (500, "INTERNAL", InternalError),
        (501, "UNSUPPORTED", Unsupported),
        (502, "DRIVER_ERROR", DriverError),
        (503, "CAPACITY", CapacityExceeded),
        (504, "DRIVER_TIMEOUT", DriverTimeout),
    ],
)
async def test_error_envelope_maps_to_typed_exception(api, client, status, code, exc_type):
    details = {"state": "stopped"}
    api.get(SANDBOX_URL).respond(status, json=error_envelope(code, "boom", details))

    with pytest.raises(ApiError) as info:
        await call(client.get, SID)

    error = info.value
    assert type(error) is exc_type
    assert (error.code, error.status_code, error.message) == (code, status, "boom")
    assert error.details == details
    assert error.request_id == "req_1"


async def test_rate_limited_carries_retry_after(api, client):
    api.get(SANDBOX_URL).respond(
        429, json=error_envelope("RATE_LIMITED"), headers={"Retry-After": "7"}
    )

    with pytest.raises(RateLimited) as info:
        await call(client.get, SID)

    assert info.value.retry_after_s == 7


@pytest.mark.parametrize(
    ("method", "verb", "path", "kwargs"),
    [
        ("create_sandbox", "POST", "/v1/sandboxes", {"wait": False}),
        ("list_sandboxes", "GET", "/v1/sandboxes", {}),
        ("get", "GET", SANDBOX_URL, {}),
        ("start", "POST", f"{SANDBOX_URL}/start", {}),
        ("stop", "POST", f"{SANDBOX_URL}/stop", {}),
        ("delete", "DELETE", SANDBOX_URL, {}),
    ],
)
async def test_every_client_method_raises_typed_errors(api, client, method, verb, path, kwargs):
    api.route(method=verb, path=path).respond(403, json=error_envelope("FORBIDDEN", "no scope"))
    args = () if method in {"create_sandbox", "list_sandboxes"} else (SID,)

    with pytest.raises(Forbidden, match="no scope"):
        await call(getattr(client, method), *args, **kwargs)


async def test_unknown_code_falls_back_to_api_error(api, client):
    api.get(SANDBOX_URL).respond(405, json=error_envelope("METHOD_NOT_ALLOWED", "nope"))

    with pytest.raises(ApiError) as info:
        await call(client.get, SID)

    assert type(info.value) is ApiError
    assert (info.value.code, info.value.status_code) == ("METHOD_NOT_ALLOWED", 405)


async def test_non_envelope_error_response_becomes_api_error(api, client):
    api.get(SANDBOX_URL).respond(502, text="bad gateway")

    with pytest.raises(ApiError) as info:
        await call(client.get, SID)

    assert (info.value.code, info.value.status_code) == ("HTTP_502", 502)


@pytest.mark.parametrize(
    "body",
    [{"foo": 1}, envelope({"id": "sbx_x"}), envelope([1, 2])],
)
async def test_malformed_success_response_raises_invalid_response(api, client, body):
    api.get(SANDBOX_URL).respond(200, json=body)

    with pytest.raises(InvalidResponseError):
        await call(client.get, SID)


async def test_list_with_non_list_data_raises_invalid_response(api, client):
    api.get("/v1/sandboxes").respond(200, json=envelope({"not": "a list"}))

    with pytest.raises(InvalidResponseError):
        await call(client.list_sandboxes)


@pytest.mark.parametrize("failure", [httpx.ConnectError("refused"), httpx.ReadTimeout("slow")])
async def test_network_failures_become_transport_error(api, client, failure):
    api.get(SANDBOX_URL).mock(side_effect=failure)

    with pytest.raises(TransportError):
        await call(client.get, SID)


# --- auth, construction, timeouts ------------------------------------------------------


async def test_bearer_header_is_sent_on_every_request(api, client):
    api.post("/v1/sandboxes").respond(201, json=envelope(sandbox_json()))
    api.get("/v1/sandboxes").respond(200, json=envelope([]))
    api.route(method="DELETE", path=SANDBOX_URL).respond(200, json=envelope(sandbox_json()))

    await call(client.create_sandbox)
    await call(client.list_sandboxes)
    await call(client.delete, SID)

    assert api.calls.call_count == 3
    for recorded in api.calls:
        assert recorded.request.headers["authorization"] == f"Bearer {KEY}"


@pytest.mark.parametrize(
    ("base_url", "api_key", "message"),
    [(BASE, "", "api_key"), ("", KEY, "base_url")],
)
def test_constructor_rejects_empty_arguments(kind, base_url, api_key, message):
    cls = Client if kind == "sync" else AsyncClient

    with pytest.raises(ValueError, match=message):
        cls(base_url, api_key)


async def test_api_key_with_surrounding_whitespace_is_trimmed(kind):
    cls = Client if kind == "sync" else AsyncClient
    instance = cls(f" {BASE}/ \n", f"  {KEY}\n ")
    try:
        with respx.mock(base_url=BASE, assert_all_called=False) as router:
            router.get("/v1/sandboxes").respond(200, json=envelope([]))
            await call(instance.list_sandboxes)
            sent = router.calls[0].request.headers["authorization"]
    finally:
        await close(instance)

    assert sent == f"Bearer {KEY}"
    assert "\n" not in sent


@pytest.mark.parametrize("api_key", ["", "   ", "\n", " \t\r\n "])
def test_blank_api_key_error_never_contains_key_characters(kind, api_key):
    cls = Client if kind == "sync" else AsyncClient

    with pytest.raises(ValueError, match="api_key must not be empty") as excinfo:
        cls(BASE, api_key)

    assert str(excinfo.value) == "api_key must not be empty"


@pytest.mark.parametrize("api_key", ["sf_secret\nkey", "sf_secret key", "sf_secret\x00key"])
def test_malformed_api_key_error_never_contains_the_key(kind, api_key):
    cls = Client if kind == "sync" else AsyncClient

    with pytest.raises(ValueError, match="api_key is malformed") as excinfo:
        cls(BASE, f"{api_key}\n")

    message = str(excinfo.value)
    assert "sf_secret" not in message
    assert repr(api_key) not in message


async def test_timeouts_are_configurable_and_cover_server_side_budgets(api, kind):
    instance = new_client(kind, timeout=5)
    try:
        api.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json()))
        api.post(EXEC_URL).respond(200, json=envelope(EXEC_PAYLOAD))
        sandbox = await call(instance.get, SID)
        await call(sandbox.process_exec, "sleep 90", timeout_s=100)
    finally:
        await close(instance)

    get_call, exec_call = api.calls[0], api.calls[1]
    assert get_call.request.extensions["timeout"]["read"] == 5
    assert exec_call.request.extensions["timeout"]["read"] == 100 + HTTP_MARGIN_S


def test_sync_client_works_as_context_manager(api):
    api.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json()))

    with Client(BASE, KEY) as instance:
        assert instance.get(SID).id == SID


async def test_async_client_works_as_context_manager(api):
    api.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json()))

    async with AsyncClient(BASE, KEY) as instance:
        assert (await instance.get(SID)).id == SID


# --- preview ---------------------------------------------------------------------------

PREVIEW_URL = f"{SANDBOX_URL}/preview-tokens"
PREVIEW_PAYLOAD = {
    "token": "pvt_abc",
    "url": f"http://3000-{SID}.preview.test?sandfort_preview_token=pvt_abc",
    "port": 3000,
    "expires_at": "2026-11-05T12:00:00+00:00",
}


async def test_preview_posts_the_port_and_parses_the_response(api, client):
    sandbox = await started_sandbox(api, client)
    route = api.post(PREVIEW_URL).respond(201, json=envelope(PREVIEW_PAYLOAD))

    info = await call(sandbox.preview, 3000)

    assert json.loads(route.calls.last.request.content) == {"port": 3000}
    assert (info.url, info.token, info.port) == (
        PREVIEW_PAYLOAD["url"],
        "pvt_abc",
        3000,
    )
    assert info.expires_at == datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
    with pytest.raises(dataclasses.FrozenInstanceError):
        info.token = "other"  # type: ignore[misc]


async def test_preview_sends_the_ttl_when_given(api, client):
    sandbox = await started_sandbox(api, client)
    route = api.post(PREVIEW_URL).respond(201, json=envelope(PREVIEW_PAYLOAD))

    await call(sandbox.preview, 3000, ttl_seconds=600)

    assert json.loads(route.calls.last.request.content) == {"port": 3000, "ttl_seconds": 600}


async def test_preview_surfaces_server_errors(api, client):
    sandbox = await started_sandbox(api, client)
    api.post(PREVIEW_URL).respond(404, json=error_envelope("NOT_FOUND", "no such sandbox"))

    with pytest.raises(NotFound):
        await call(sandbox.preview, 3000)


async def test_preview_rejects_a_payload_without_a_token(api, client):
    sandbox = await started_sandbox(api, client)
    broken = {key: value for key, value in PREVIEW_PAYLOAD.items() if key != "token"}
    api.post(PREVIEW_URL).respond(201, json=envelope(broken))

    with pytest.raises(InvalidResponseError):
        await call(sandbox.preview, 3000)
