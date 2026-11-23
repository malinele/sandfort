"""SDK retries: which answers and failures are resent, how long it waits, and when it never does."""

import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
from sandfort_sdk import (  # noqa: E402
    AsyncClient,
    CapacityExceeded,
    Client,
    Conflict,
    QuotaExceeded,
    RateLimited,
    Resources,
    TransportError,
)
from sandfort_sdk._requests import (  # noqa: E402
    backoff_s,
    idempotency_headers,
    is_repeatable,
    jittered_s,
    parse_retry_after,
    rate_limit_pause_s,
)
from sandfort_sdk._transport import AsyncTransport, SyncTransport, client_kwargs  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
TIMEOUT_S = 30.0
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOX_URL = f"/v1/sandboxes/{SID}"
Handler = Callable[[httpx.Request], httpx.Response]


def sandbox_json() -> dict[str, object]:
    return {
        "id": SID,
        "name": "demo",
        "state": "started",
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


def ok(status: int = 200) -> httpx.Response:
    body = {"success": True, "data": sandbox_json(), "error": None, "meta": None}
    return httpx.Response(status, json=body)


def failed(status: int, code: str, headers: dict[str, str] | None = None) -> httpx.Response:
    error = {"code": code, "message": "boom", "details": {}, "request_id": "req_1"}
    body = {"success": False, "data": None, "error": error, "meta": None}
    return httpx.Response(status, json=body, headers=headers)


def failed_with(status: int, code: str, details: dict[str, str]) -> httpx.Response:
    error = {"code": code, "message": "boom", "details": details, "request_id": "req_1"}
    body = {"success": False, "data": None, "error": error, "meta": None}
    return httpx.Response(status, json=body)


def in_progress() -> httpx.Response:
    return failed_with(409, "CONFLICT", {"reason": "in_progress"})


def rate_limited(retry_after: str = "3") -> httpx.Response:
    return failed(429, "RATE_LIMITED", {"Retry-After": retry_after})


def unavailable() -> httpx.Response:
    return failed(503, "CAPACITY")


class Script:
    """Answers from a fixed list (the last one repeats) and records every request it saw."""

    def __init__(self, *answers: httpx.Response | Exception) -> None:
        self._answers = list(answers)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = self._answers.pop(0) if len(self._answers) > 1 else self._answers[0]
        if isinstance(answer, Exception):
            raise answer
        return answer


def full_delay() -> float:
    """A random draw of 1.0: jitter then keeps the whole computed delay."""
    return 1.0


def sync_client(
    handler: Handler, *, max_retries: int = 2, rand: Callable[[], float] = full_delay
) -> tuple[Client, list[float]]:
    sleeps: list[float] = []
    client = Client(BASE, KEY, max_retries=max_retries)
    client._transport.close()
    transport = SyncTransport(
        BASE, KEY, TIMEOUT_S, max_retries=max_retries, sleep=sleeps.append, rand=rand
    )
    transport._http.close()
    transport._http = httpx.Client(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    client._transport = transport
    return client, sleeps


async def async_client(
    handler: Handler, *, max_retries: int = 2, rand: Callable[[], float] = full_delay
) -> tuple[AsyncClient, list[float]]:
    sleeps: list[float] = []

    async def record(seconds: float) -> None:
        sleeps.append(seconds)

    client = AsyncClient(BASE, KEY, max_retries=max_retries)
    await client._transport.aclose()
    transport = AsyncTransport(
        BASE, KEY, TIMEOUT_S, max_retries=max_retries, sleep=record, rand=rand
    )
    await transport._http.aclose()
    transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    client._transport = transport
    return client, sleeps


def test_get_answered_429_then_200_succeeds_after_one_retry_after_sleep() -> None:
    script = Script(rate_limited("3"), ok())
    client, sleeps = sync_client(script)

    sandbox = client.get(SID)

    assert sandbox.id == SID
    assert len(script.requests) == 2
    assert sleeps == [3.0]


def test_max_retries_zero_raises_rate_limited_at_once() -> None:
    script = Script(rate_limited("3"), ok())
    client, sleeps = sync_client(script, max_retries=0)

    with pytest.raises(RateLimited) as caught:
        client.get(SID)

    assert caught.value.retry_after_s == 3
    assert len(script.requests) == 1
    assert sleeps == []


def test_retries_exhausted_raise_the_last_rate_limited_unchanged() -> None:
    script = Script(rate_limited("2"))
    client, sleeps = sync_client(script, max_retries=2)

    with pytest.raises(RateLimited) as caught:
        client.get(SID)

    assert caught.value.status_code == 429
    assert len(script.requests) == 3
    assert sleeps == [2.0, 2.0]


def test_retry_after_is_capped_at_30_seconds() -> None:
    script = Script(rate_limited("600"), ok())
    client, sleeps = sync_client(script)

    client.get(SID)

    assert sleeps == [30.0]


def test_post_without_idempotency_key_answered_503_is_not_retried() -> None:
    script = Script(unavailable(), ok(201))
    client, sleeps = sync_client(script)

    with pytest.raises(CapacityExceeded) as caught:
        client.create_sandbox(wait=False)

    assert caught.value.status_code == 503
    assert len(script.requests) == 1
    assert "idempotency-key" not in script.requests[0].headers
    assert sleeps == []


def test_post_without_idempotency_key_is_not_retried_after_a_connection_error() -> None:
    script = Script(httpx.ConnectError("refused"), ok())
    client, sleeps = sync_client(script)

    with pytest.raises(TransportError):
        client.start(SID)

    assert len(script.requests) == 1
    assert sleeps == []


def test_create_with_idempotency_key_sends_the_header_and_is_retried_after_503() -> None:
    script = Script(unavailable(), ok(201))
    client, sleeps = sync_client(script)

    sandbox = client.create_sandbox(
        name="demo", resources=Resources(cpu_millicores=500), idempotency_key="key-1", wait=False
    )

    assert sandbox.id == SID
    assert [r.headers["Idempotency-Key"] for r in script.requests] == ["key-1", "key-1"]
    assert script.requests[0].content == script.requests[1].content
    assert sleeps == [0.5]


def test_connection_error_on_get_is_retried_then_raised_after_the_limit() -> None:
    script = Script(httpx.ConnectError("refused"))
    client, sleeps = sync_client(script, max_retries=2)

    with pytest.raises(TransportError) as caught:
        client.get(SID)

    assert "ConnectError" in str(caught.value)
    assert isinstance(caught.value.__cause__, httpx.ConnectError)
    assert len(script.requests) == 3
    assert sleeps == [0.5, 1.0]


def test_timeout_on_get_is_retried_and_then_succeeds() -> None:
    script = Script(httpx.ReadTimeout("slow"), ok())
    client, sleeps = sync_client(script)

    assert client.get(SID).id == SID
    assert sleeps == [0.5]


def test_delete_answered_503_is_retried() -> None:
    script = Script(unavailable(), unavailable(), ok())
    client, sleeps = sync_client(script)

    client.delete(SID)

    assert [r.method for r in script.requests] == ["DELETE"] * 3
    assert sleeps == [0.5, 1.0]


def test_other_error_answers_are_never_retried() -> None:
    script = Script(failed(500, "INTERNAL"), ok())
    client, sleeps = sync_client(script)

    with pytest.raises(Exception, match="boom"):
        client.get(SID)

    assert len(script.requests) == 1
    assert sleeps == []


def test_a_stream_is_never_retried() -> None:
    script = Script(unavailable(), ok())
    client, sleeps = sync_client(script)

    with pytest.raises(CapacityExceeded):
        client._transport.open_stream("GET", f"{SANDBOX_URL}/toolbox/fs/download")

    assert len(script.requests) == 1
    assert sleeps == []


def test_backoff_doubles_from_half_a_second_and_is_capped_at_8_seconds() -> None:
    assert [backoff_s(n) for n in range(6)] == [0.5, 1.0, 2.0, 4.0, 8.0, 8.0]


def test_rate_limit_pause_clamps_into_zero_to_30_seconds() -> None:
    assert [rate_limit_pause_s(n) for n in (-5, 0, 7, 31)] == [0.0, 0.0, 7.0, 30.0]


@pytest.mark.parametrize(
    ("method", "headers", "repeatable"),
    [
        ("GET", None, True),
        ("HEAD", None, True),
        ("delete", None, True),
        ("POST", None, False),
        ("POST", {"idempotency-key": "k"}, True),
        ("PUT", {"Idempotency-Key": "k"}, False),
        ("PATCH", None, False),
    ],
)
def test_only_safe_requests_are_repeatable(
    method: str, headers: dict[str, str] | None, repeatable: bool
) -> None:
    assert is_repeatable(method, headers) is repeatable


def test_blank_idempotency_key_is_rejected_before_sending() -> None:
    assert idempotency_headers(None) is None
    with pytest.raises(ValueError, match="idempotency_key"):
        idempotency_headers("  ")


def test_negative_max_retries_is_rejected() -> None:
    with pytest.raises(ValueError, match="max_retries"):
        Client(BASE, KEY, max_retries=-1)


async def test_async_get_answered_429_then_200_succeeds_after_one_awaited_sleep() -> None:
    script = Script(rate_limited("4"), ok())
    client, sleeps = await async_client(script)

    try:
        sandbox = await client.get(SID)
    finally:
        await client.aclose()

    assert sandbox.id == SID
    assert len(script.requests) == 2
    assert sleeps == [4.0]


async def test_async_create_with_idempotency_key_sends_the_header() -> None:
    script = Script(unavailable(), ok(201))
    client, sleeps = await async_client(script)

    try:
        await client.create_sandbox(idempotency_key="key-2", wait=False)
    finally:
        await client.aclose()

    assert [r.headers["Idempotency-Key"] for r in script.requests] == ["key-2", "key-2"]
    assert sleeps == [0.5]


# --- full jitter, HTTP-date Retry-After, quota and in-progress rules ---------------------------


@pytest.mark.parametrize(("draw", "expected"), [(0.0, 0.25), (0.5, 0.375), (1.0, 0.5)])
def test_503_backoff_sleeps_between_half_and_all_of_the_delay(draw: float, expected: float) -> None:
    script = Script(unavailable(), ok())
    client, sleeps = sync_client(script, rand=lambda: draw)

    client.get(SID)

    assert sleeps == [pytest.approx(expected)]


def test_transport_error_backoff_is_jittered_on_every_attempt() -> None:
    script = Script(httpx.ConnectError("refused"))
    client, sleeps = sync_client(script, max_retries=4, rand=lambda: 0.0)

    with pytest.raises(TransportError):
        client.get(SID)

    assert sleeps == [0.25, 0.5, 1.0, 2.0]


def test_jittered_s_stays_between_half_and_all_and_clamps_the_draw() -> None:
    assert jittered_s(4.0, 0.0) == 2.0
    assert jittered_s(4.0, 1.0) == 4.0
    assert jittered_s(4.0, -3.0) == 2.0
    assert jittered_s(4.0, 9.0) == 4.0


def test_default_random_source_keeps_the_sleep_within_bounds() -> None:
    script = Script(unavailable(), ok())
    sleeps: list[float] = []
    transport = SyncTransport(BASE, KEY, TIMEOUT_S, sleep=sleeps.append)
    transport._http.close()
    transport._http = httpx.Client(
        transport=httpx.MockTransport(script), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )

    transport.request("GET", SANDBOX_URL)

    assert len(sleeps) == 1
    assert 0.25 <= sleeps[0] <= 0.5


def test_parse_retry_after_reads_seconds_and_http_dates() -> None:
    now = datetime(2026, 11, 6, 12, 0, 0, tzinfo=UTC)

    def date(offset_s: int) -> str:
        return format_datetime(now + timedelta(seconds=offset_s), usegmt=True)

    assert parse_retry_after("7", now) == 7
    assert parse_retry_after(date(12), now) == 12
    assert parse_retry_after(date(-5), now) == 0
    assert parse_retry_after("not a date", now) == 1
    assert parse_retry_after(None, now) == 1


def test_http_date_retry_after_is_waited_and_capped_at_30_seconds() -> None:
    far = format_datetime(datetime.now(UTC) + timedelta(seconds=600), usegmt=True)
    script = Script(failed(429, "RATE_LIMITED", {"Retry-After": far}), ok())
    client, sleeps = sync_client(script)

    client.get(SID)

    assert sleeps == [30.0]


def test_http_date_retry_after_in_the_past_waits_zero_seconds() -> None:
    past = format_datetime(datetime.now(UTC) - timedelta(seconds=60), usegmt=True)
    script = Script(failed(429, "RATE_LIMITED", {"Retry-After": past}), ok())
    client, sleeps = sync_client(script)

    client.get(SID)

    assert sleeps == [0.0]


def test_429_quota_exceeded_is_never_retried() -> None:
    script = Script(failed(429, "QUOTA_EXCEEDED", {"Retry-After": "1"}), ok())
    client, sleeps = sync_client(script)

    with pytest.raises(QuotaExceeded):
        client.get(SID)

    assert len(script.requests) == 1
    assert sleeps == []


def test_409_in_progress_is_retried_for_a_post_with_an_idempotency_key() -> None:
    script = Script(in_progress(), in_progress(), ok(201))
    client, sleeps = sync_client(script)

    sandbox = client.create_sandbox(idempotency_key="key-3", wait=False)

    assert sandbox.id == SID
    assert len(script.requests) == 3
    assert sleeps == [0.5, 1.0]


def test_409_in_progress_without_an_idempotency_key_is_not_retried() -> None:
    script = Script(in_progress(), ok(201))
    client, sleeps = sync_client(script)

    with pytest.raises(Conflict):
        client.create_sandbox(wait=False)

    assert len(script.requests) == 1
    assert sleeps == []


def test_409_in_progress_on_a_get_is_not_retried() -> None:
    script = Script(in_progress(), ok())
    client, sleeps = sync_client(script)

    with pytest.raises(Conflict):
        client.get(SID)

    assert len(script.requests) == 1
    assert sleeps == []


def test_a_409_with_another_reason_is_not_retried_even_with_a_key() -> None:
    script = Script(failed_with(409, "CONFLICT", {"reason": "name_taken"}), ok(201))
    client, sleeps = sync_client(script)

    with pytest.raises(Conflict):
        client.create_sandbox(idempotency_key="key-4", wait=False)

    assert len(script.requests) == 1
    assert sleeps == []


async def test_async_409_in_progress_is_retried_with_jitter_for_a_keyed_post() -> None:
    script = Script(in_progress(), ok(201))
    client, sleeps = await async_client(script, rand=lambda: 0.0)

    try:
        await client.create_sandbox(idempotency_key="key-5", wait=False)
    finally:
        await client.aclose()

    assert len(script.requests) == 2
    assert sleeps == [0.25]
