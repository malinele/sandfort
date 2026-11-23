"""SDK r30: RATE_LIMITED retries, typed 503/idempotency errors, bounded create, handles."""

import logging
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
import sandfort_sdk  # noqa: E402
from sandfort_sdk import (  # noqa: E402
    AmbiguousSandboxName,
    ApiError,
    AsyncClient,
    CapacityExceeded,
    Client,
    IdempotencyMismatch,
    InternalError,
    NotFound,
    QuotaExceeded,
    RateLimited,
    RequestTimedOut,
    SandboxFailedError,
    SandboxTimeoutError,
    SandfortSDKError,
    ServiceUnavailable,
    TransportError,
    ValidationFailed,
)
from sandfort_sdk._requests import retry_pause  # noqa: E402
from sandfort_sdk._transport import AsyncTransport, SyncTransport, client_kwargs  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
TIMEOUT_S = 30.0
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOXES = "/v1/sandboxes"
ONE_SANDBOX = f"{SANDBOXES}/{SID}"
WAIT_S = 2.0
READ_MARGIN_S = 5.0


def sandbox_json(**over: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": SID,
        "name": "demo",
        "state": "started",
        "resources": {"cpu_millicores": 2000, "memory_mib": 1024, "disk_gib": 5},
        "env": {"TOKEN": "***", "MODE": "***"},
        "labels": {"team": "agents"},
        "network": {"block_all": True},
        "public": True,
        "auto_stop_minutes": 15,
        "auto_delete_minutes": -1,
        "error_reason": None,
        "job_id": "job_1",
        "isolation": "gvisor",
    }
    return {**data, **over}


def ok(data: Any = None, status: int = 200) -> httpx.Response:
    body = {"success": True, "data": sandbox_json() if data is None else data, "meta": None}
    return httpx.Response(status, json=body)


def gone() -> httpx.Response:
    return ok(sandbox_json(state="destroying"))


def listing(*items: dict[str, Any]) -> httpx.Response:
    return httpx.Response(200, json={"success": True, "data": list(items), "meta": None})


def failed(status: int, code: str, headers: dict[str, str] | None = None) -> httpx.Response:
    error = {"code": code, "message": "boom", "details": {}, "request_id": "req_1"}
    body = {"success": False, "data": None, "error": error, "meta": None}
    return httpx.Response(status, json=body, headers=headers)


Answer = httpx.Response | Exception


class Router:
    """Answers by (method, path); the last answer of a route repeats. Records every request."""

    def __init__(self, routes: dict[tuple[str, str], Answer | list[Answer]]) -> None:
        self.routes = {key: v if isinstance(v, list) else [v] for key, v in routes.items()}
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answers = self.routes[(request.method, request.url.path)]
        answer = answers.pop(0) if len(answers) > 1 else answers[0]
        if isinstance(answer, Exception):
            raise answer
        return answer

    def seen(self, method: str, path: str) -> list[httpx.Request]:
        return [r for r in self.requests if (r.method, r.url.path) == (method, path)]


def sandbox_with_delete(delete: Answer) -> Router:
    """A router that serves one sandbox and answers its DELETE with ``delete``."""
    return Router({("GET", ONE_SANDBOX): ok(), ("DELETE", ONE_SANDBOX): delete})


def fresh_listing(**over: Any) -> httpx.Response:
    """A listing with the sandbox created now (so the cleanup counts it as this create's)."""
    return listing(sandbox_json(created_at=datetime.now(UTC).isoformat(), **over))


def create_times_out(found: Answer | list[Answer] | None = None) -> Router:
    """The create POST times out; ``found`` answers the by-name lookups (before and after)."""
    routes: dict[tuple[str, str], Answer | list[Answer]] = {
        ("POST", SANDBOXES): httpx.ReadTimeout("the create is still running")
    }
    if found is not None:
        routes[("GET", SANDBOXES)] = found
        routes[("DELETE", ONE_SANDBOX)] = gone()
    return Router(routes)


def sync_client(router: Router, *, max_retries: int = 2) -> tuple[Client, list[float]]:
    sleeps: list[float] = []
    client = Client(BASE, KEY, max_retries=max_retries)
    client._transport.close()
    transport = SyncTransport(
        BASE, KEY, TIMEOUT_S, max_retries=max_retries, sleep=sleeps.append, rand=lambda: 1.0
    )
    transport._http.close()
    transport._http = httpx.Client(
        transport=httpx.MockTransport(router), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    client._transport = transport
    return client, sleeps


async def async_client(
    router: Router, *, max_retries: int = 2
) -> tuple[AsyncClient, list[float]]:
    sleeps: list[float] = []

    async def record(seconds: float) -> None:
        sleeps.append(seconds)

    client = AsyncClient(BASE, KEY, max_retries=max_retries)
    await client._transport.aclose()
    transport = AsyncTransport(
        BASE, KEY, TIMEOUT_S, max_retries=max_retries, sleep=record, rand=lambda: 1.0
    )
    await transport._http.aclose()
    transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(router), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    client._transport = transport
    return client, sleeps


# --- 1. RATE_LIMITED is retried for every method -----------------------------------------


def test_rate_limited_is_retried_for_a_post_without_an_idempotency_key() -> None:
    limited = failed(429, "RATE_LIMITED", {"Retry-After": "3"})
    router = Router({("POST", SANDBOXES): [limited, ok(status=202)]})
    client, sleeps = sync_client(router)

    sandbox = client.create_sandbox(wait=False)

    assert sandbox.id == SID
    assert len(router.seen("POST", SANDBOXES)) == 2
    assert sleeps == [3.0]


def test_rate_limited_retry_after_is_capped_at_30_seconds_for_a_post() -> None:
    limited = failed(429, "RATE_LIMITED", {"Retry-After": "999"})
    router = Router({("POST", SANDBOXES): [limited, ok(status=202)]})
    client, sleeps = sync_client(router)

    client.create_sandbox(wait=False)

    assert sleeps == [30.0]


def test_rate_limited_post_gives_up_after_max_retries_with_the_last_error() -> None:
    router = Router({("POST", SANDBOXES): failed(429, "RATE_LIMITED", {"Retry-After": "1"})})
    client, sleeps = sync_client(router, max_retries=2)

    with pytest.raises(RateLimited):
        client.create_sandbox(wait=False)

    assert len(router.requests) == 3
    assert sleeps == [1.0, 1.0]


def test_quota_exceeded_post_is_not_retried() -> None:
    router = Router({("POST", SANDBOXES): failed(429, "QUOTA_EXCEEDED", {"Retry-After": "1"})})
    client, sleeps = sync_client(router)

    with pytest.raises(QuotaExceeded):
        client.create_sandbox(wait=False)

    assert len(router.requests) == 1
    assert sleeps == []


def test_a_429_with_another_code_is_not_retried_for_an_unkeyed_post() -> None:
    router = Router({("POST", SANDBOXES): failed(429, "SOMETHING_ELSE", {"Retry-After": "1"})})
    client, sleeps = sync_client(router)

    with pytest.raises(ApiError):
        client.create_sandbox(wait=False)

    assert len(router.requests) == 1
    assert sleeps == []


def test_an_unkeyed_post_is_still_not_retried_after_503_or_a_lost_connection() -> None:
    for answer in (failed(503, "CAPACITY"), httpx.ConnectError("down")):
        router = Router({("POST", SANDBOXES): answer})
        client, sleeps = sync_client(router)

        with pytest.raises((ServiceUnavailable, TransportError)):
            client.create_sandbox(wait=False)

        assert len(router.requests) == 1
        assert sleeps == []


def test_retry_pause_for_a_call_that_is_not_repeatable() -> None:
    def pause(outcome: httpx.Response | httpx.HTTPError) -> float | None:
        return retry_pause(outcome, 0, lambda: 1.0, keyed_post=False, repeatable=False)

    request = httpx.Request("POST", BASE)
    assert pause(failed(429, "RATE_LIMITED", {"Retry-After": "4"})) == 4.0
    assert pause(failed(429, "QUOTA_EXCEEDED")) is None
    assert pause(failed(503, "CAPACITY")) is None
    assert pause(httpx.ReadTimeout("slow", request=request)) is None


async def test_async_rate_limited_post_is_retried_after_retry_after() -> None:
    limited = failed(429, "RATE_LIMITED", {"Retry-After": "2"})
    router = Router({("POST", SANDBOXES): [limited, ok(status=202)]})
    client, sleeps = await async_client(router)

    sandbox = await client.create_sandbox(wait=False)

    assert sandbox.id == SID
    assert sleeps == [2.0]
    await client.aclose()


# --- 2. typed exceptions -----------------------------------------------------------------


def test_idempotency_mismatch_is_a_validation_failed_with_its_code() -> None:
    router = Router({("POST", SANDBOXES): failed(422, "IDEMPOTENCY_MISMATCH")})
    client, _ = sync_client(router)

    with pytest.raises(IdempotencyMismatch) as caught:
        client.create_sandbox(wait=False, idempotency_key="k1")

    assert isinstance(caught.value, ValidationFailed)
    assert caught.value.code == "IDEMPOTENCY_MISMATCH"
    assert caught.value.status_code == 422


@pytest.mark.parametrize("code", ["NODE_UNAVAILABLE", "CAPACITY", "SOMETHING_NEW"])
def test_every_503_is_a_service_unavailable(code: str) -> None:
    router = Router({("GET", ONE_SANDBOX): failed(503, code, {"Retry-After": "7"})})
    client, _ = sync_client(router, max_retries=0)

    with pytest.raises(ServiceUnavailable) as caught:
        client.get(SID)

    assert isinstance(caught.value, ApiError)
    assert caught.value.code == code
    assert caught.value.status_code == 503
    assert caught.value.retry_after_s == 7


def test_a_503_without_an_envelope_is_a_service_unavailable() -> None:
    router = Router({("GET", ONE_SANDBOX): httpx.Response(503, text="upstream down")})
    client, _ = sync_client(router, max_retries=0)

    with pytest.raises(ServiceUnavailable):
        client.get(SID)


def test_capacity_exceeded_stays_catchable_and_is_a_service_unavailable() -> None:
    router = Router({("GET", ONE_SANDBOX): failed(503, "CAPACITY")})
    client, _ = sync_client(router, max_retries=0)

    with pytest.raises(CapacityExceeded) as caught:
        client.get(SID)

    assert isinstance(caught.value, ServiceUnavailable)


def test_the_new_errors_are_exported_and_the_base_class_is_documented() -> None:
    for name in ("IdempotencyMismatch", "ServiceUnavailable", "RequestTimedOut"):
        assert name in sandfort_sdk.__all__
    assert issubclass(ServiceUnavailable, ApiError)
    assert issubclass(IdempotencyMismatch, ValidationFailed)
    doc = sandfort_sdk.exceptions.__doc__ or ""
    assert "SandfortSDKError" in doc and "base to catch everything" in doc
    siblings = (SandboxFailedError, SandboxTimeoutError, AmbiguousSandboxName, TransportError)
    for sibling in siblings:
        assert issubclass(sibling, SandfortSDKError)
        assert not issubclass(sibling, ApiError)
        assert sibling.__name__ in doc


# --- 3. create honours its wait timeout --------------------------------------------------


def test_create_post_gets_a_read_timeout_of_the_time_left_in_the_wait_budget() -> None:
    router = create_times_out()
    client, _ = sync_client(router)

    with pytest.raises(SandboxTimeoutError):
        client.create_sandbox(name="demo", wait_timeout_s=WAIT_S, delete_on_failure=False)

    (post,) = router.seen("POST", SANDBOXES)
    assert 0 < post.extensions["timeout"]["read"] <= WAIT_S
    assert post.extensions["timeout"]["read"] == pytest.approx(WAIT_S, abs=0.5)


def test_create_timeout_raises_within_the_bound_and_names_the_sandbox() -> None:
    router = create_times_out(found=listing())
    client, sleeps = sync_client(router)

    started = time.monotonic()
    with pytest.raises(SandboxTimeoutError) as caught:
        client.create_sandbox(name="demo", wait_timeout_s=WAIT_S)

    assert time.monotonic() - started < WAIT_S + READ_MARGIN_S
    assert len(router.seen("POST", SANDBOXES)) == 1  # a timeout is never resent
    assert sleeps == []
    assert "'demo'" in str(caught.value)
    assert "may still finish on the server" in str(caught.value)
    assert "idempotency key" not in str(caught.value)
    assert isinstance(caught.value.__cause__, RequestTimedOut)


def test_create_timeout_with_a_key_says_resending_with_it_returns_the_sandbox() -> None:
    router = create_times_out()
    client, _ = sync_client(router)

    with pytest.raises(SandboxTimeoutError) as caught:
        client.create_sandbox(
            name="demo", wait_timeout_s=WAIT_S, idempotency_key="key-1", delete_on_failure=False
        )

    message = str(caught.value)
    assert "key-1" in message
    assert "resending the same call" in message and "returns the sandbox" in message
    assert len(router.seen("POST", SANDBOXES)) == 1


def test_create_timeout_deletes_the_sandbox_found_by_name() -> None:
    router = create_times_out(found=[listing(), fresh_listing(state="pending")])
    client, _ = sync_client(router)

    with pytest.raises(SandboxTimeoutError):
        client.create_sandbox(name="demo", wait_timeout_s=WAIT_S)

    assert len(router.seen("GET", SANDBOXES)) == 2  # once before the create, once after
    assert len(router.seen("DELETE", ONE_SANDBOX)) == 1


def test_create_timeout_cleanup_is_skipped_without_a_name_or_when_disabled() -> None:
    router = create_times_out()
    client, _ = sync_client(router)

    with pytest.raises(SandboxTimeoutError) as unnamed:
        client.create_sandbox(wait_timeout_s=WAIT_S)
    with pytest.raises(SandboxTimeoutError):
        client.create_sandbox(name="demo", wait_timeout_s=WAIT_S, delete_on_failure=False)

    assert [r.method for r in router.requests] == ["POST", "POST"]
    assert "no name" in str(unnamed.value)


def test_create_timeout_cleanup_failure_is_logged_and_the_timeout_still_raised(
    caplog: pytest.LogCaptureFixture,
) -> None:
    router = create_times_out(found=[listing(), failed(500, "INTERNAL")])
    client, _ = sync_client(router)

    with caplog.at_level(logging.WARNING, logger="sandfort_sdk.client"):
        with pytest.raises(SandboxTimeoutError):
            client.create_sandbox(name="demo", wait_timeout_s=WAIT_S)

    assert "after a create timeout" in caplog.text
    assert router.seen("DELETE", ONE_SANDBOX) == []


def test_create_without_waiting_keeps_the_default_timeout_and_the_plain_error() -> None:
    router = create_times_out()
    client, _ = sync_client(router, max_retries=0)

    with pytest.raises(RequestTimedOut):
        client.create_sandbox(name="demo", wait=False)

    (post,) = router.seen("POST", SANDBOXES)
    assert post.extensions["timeout"]["read"] == pytest.approx(TIMEOUT_S)


def test_a_bounded_request_does_not_resend_after_a_timeout_even_with_a_key() -> None:
    router = create_times_out()
    client, _ = sync_client(router)

    with pytest.raises(RequestTimedOut):
        client._transport.request(
            "POST", SANDBOXES, headers={"Idempotency-Key": "k"}, read_timeout_s=1.0
        )

    assert len(router.requests) == 1


async def test_async_create_timeout_raises_names_the_sandbox_and_cleans_up() -> None:
    router = create_times_out(found=[listing(), fresh_listing(state="pending")])
    client, sleeps = await async_client(router)

    with pytest.raises(SandboxTimeoutError) as caught:
        await client.create_sandbox(name="demo", wait_timeout_s=WAIT_S, idempotency_key="key-2")

    (post,) = router.seen("POST", SANDBOXES)
    assert post.extensions["timeout"]["read"] == pytest.approx(WAIT_S, abs=0.5)
    message = str(caught.value)
    assert "'demo'" in message and SID in message and "was deleted" in message
    assert "may still finish" not in message and "key-2" not in message
    assert caught.value.sandbox_id == SID
    assert sleeps == []
    assert len(router.seen("DELETE", ONE_SANDBOX)) == 1
    await client.aclose()


async def test_async_create_timeout_without_delete_on_failure_leaves_the_sandbox() -> None:
    router = create_times_out()
    client, _ = await async_client(router)

    with pytest.raises(SandboxTimeoutError):
        await client.create_sandbox(name="demo", wait_timeout_s=WAIT_S, delete_on_failure=False)

    assert [r.method for r in router.requests] == ["POST"]
    await client.aclose()


# --- 4. handle properties ----------------------------------------------------------------


def test_the_handle_exposes_every_info_field_read_only() -> None:
    created = "2026-11-06T10:00:00+00:00"
    payload = sandbox_json(snapshot="snap_1", created_at=created)
    client, _ = sync_client(Router({("GET", ONE_SANDBOX): ok(payload)}))

    sandbox = client.get(SID)

    assert sandbox.labels == {"team": "agents"}
    assert sandbox.resources.cpu_millicores == 2000 and sandbox.resources.disk_gib == 5
    assert sandbox.env == {"TOKEN": "***", "MODE": "***"}
    assert sandbox.env_keys == ("TOKEN", "MODE")
    assert sandbox.snapshot == "snap_1"
    assert sandbox.created_at == datetime.fromisoformat(created)
    assert sandbox.block_network is True and sandbox.public is True
    assert sandbox.job_id == "job_1"
    assert (sandbox.id, sandbox.name, sandbox.state) == (SID, "demo", "started")
    assert sandbox.isolation == "gvisor" and sandbox.auto_stop_minutes == 15
    assert sandbox.auto_delete_minutes == -1 and sandbox.error_reason is None
    with pytest.raises(AttributeError):
        sandbox.labels = {}  # type: ignore[misc]
    sandbox.labels["x"] = "y"  # a copy: the record is untouched
    assert sandbox.labels == {"team": "agents"}


def test_snapshot_and_created_at_are_none_when_the_server_omits_them() -> None:
    client, _ = sync_client(Router({("GET", ONE_SANDBOX): ok()}))

    sandbox = client.get(SID)

    assert sandbox.snapshot is None and sandbox.created_at is None


async def test_the_async_handle_exposes_the_same_properties() -> None:
    payload = sandbox_json(snapshot="snap_1", created_at="2026-11-06T10:00:00+00:00")
    client, _ = await async_client(Router({("GET", ONE_SANDBOX): ok(payload)}))

    sandbox = await client.get(SID)

    assert sandbox.labels == {"team": "agents"} and sandbox.env_keys == ("TOKEN", "MODE")
    assert sandbox.resources.memory_mib == 1024 and sandbox.snapshot == "snap_1"
    assert sandbox.created_at is not None and sandbox.public is True
    await client.aclose()


# --- 5. context managers -----------------------------------------------------------------


def test_leaving_the_with_block_deletes_the_sandbox() -> None:
    router = sandbox_with_delete(gone())
    client, _ = sync_client(router)

    with client.get(SID) as sandbox:
        assert sandbox.state == "started"

    assert len(router.seen("DELETE", ONE_SANDBOX)) == 1
    assert sandbox.state == "destroying"


def test_with_block_ignores_a_delete_of_an_already_deleted_sandbox() -> None:
    router = sandbox_with_delete(failed(404, "NOT_FOUND"))
    client, _ = sync_client(router)

    with client.get(SID):
        pass

    assert len(router.seen("DELETE", ONE_SANDBOX)) == 1


def test_with_block_raises_another_delete_error() -> None:
    router = sandbox_with_delete(failed(500, "INTERNAL"))
    client, _ = sync_client(router)

    with pytest.raises(InternalError), client.get(SID):
        pass


def test_with_block_does_not_mask_the_exception_in_flight(
    caplog: pytest.LogCaptureFixture,
) -> None:
    router = sandbox_with_delete(failed(500, "INTERNAL"))
    client, _ = sync_client(router)

    with caplog.at_level(logging.WARNING, logger="sandfort_sdk.handles"):
        with pytest.raises(ValueError, match="agent crashed"), client.get(SID):
            raise ValueError("agent crashed")

    assert len(router.seen("DELETE", ONE_SANDBOX)) == 1
    assert "cannot delete sandbox" in caplog.text


def test_with_block_deletes_the_sandbox_when_the_body_raises() -> None:
    router = sandbox_with_delete(gone())
    client, _ = sync_client(router)

    with pytest.raises(RuntimeError), client.get(SID):
        raise RuntimeError("boom")

    assert len(router.seen("DELETE", ONE_SANDBOX)) == 1


async def test_async_with_block_deletes_the_sandbox() -> None:
    router = sandbox_with_delete(gone())
    client, _ = await async_client(router)

    async with await client.get(SID) as sandbox:
        assert sandbox.state == "started"

    assert len(router.seen("DELETE", ONE_SANDBOX)) == 1
    assert sandbox.state == "destroying"
    await client.aclose()


async def test_async_with_block_ignores_an_already_deleted_sandbox() -> None:
    router = sandbox_with_delete(failed(404, "NOT_FOUND"))
    client, _ = await async_client(router)

    async with await client.get(SID):
        pass

    assert len(router.seen("DELETE", ONE_SANDBOX)) == 1
    await client.aclose()


async def test_async_with_block_raises_other_errors_but_never_masks_an_inflight_one() -> None:
    router = sandbox_with_delete(failed(500, "INTERNAL"))
    client, _ = await async_client(router)

    with pytest.raises(InternalError):
        async with await client.get(SID):
            pass
    with pytest.raises(ValueError, match="agent crashed"):
        async with await client.get(SID):
            raise ValueError("agent crashed")

    assert len(router.seen("DELETE", ONE_SANDBOX)) == 2
    await client.aclose()


def test_not_found_is_what_a_second_delete_raises() -> None:
    # Guards the assumption behind "ignore an already-deleted sandbox": the typed 404.
    client, _ = sync_client(Router({("DELETE", ONE_SANDBOX): failed(404, "NOT_FOUND")}))

    with pytest.raises(NotFound):
        client.delete(SID)
