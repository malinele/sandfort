"""SDK r30m: a safe create-timeout cleanup, 429 resends of replayable bodies, one deadline."""

import io
import logging
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
from sandfort_sdk import AsyncClient, Client, RateLimited, SandboxTimeoutError  # noqa: E402
from sandfort_sdk._create_cleanup import (  # noqa: E402
    CLOCK_SKEW_ALLOWANCE_S,
    made_by_this_create,
)
from sandfort_sdk._requests import plan_call, replayable_body  # noqa: E402
from sandfort_sdk._transport import AsyncTransport, SyncTransport, client_kwargs  # noqa: E402
from sandfort_sdk.exceptions import RequestTimedOut  # noqa: E402
from sandfort_sdk.fs import AsyncFs, Fs  # noqa: E402
from sandfort_sdk.models import SandboxInfo  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
TIMEOUT_S = 30.0
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
OTHER = "sbx_01HYYYYYYYYYYYYYYYYYYYYYYY"
SANDBOXES = "/v1/sandboxes"
ONE_SANDBOX = f"{SANDBOXES}/{SID}"
UPLOAD = f"{ONE_SANDBOX}/toolbox/fs/upload"
WAIT_S = 2.0

Answer = httpx.Response | Exception


def sandbox_json(sid: str = SID, *, age_s: float | None = 0.0, **over: Any) -> dict[str, Any]:
    """A sandbox payload (the optional fields keep their defaults) created ``age_s`` ago."""
    created = None if age_s is None else (datetime.now(UTC) - timedelta(seconds=age_s))
    when = None if created is None else created.isoformat()
    return {"id": sid, "name": "demo", "state": "pending", "created_at": when, **over}


def ok(data: Any) -> httpx.Response:
    return httpx.Response(200, json={"success": True, "data": data, "meta": None})


def listing(*items: dict[str, Any]) -> httpx.Response:
    return ok(list(items))


def rate_limited(retry_after: str = "1") -> httpx.Response:
    error = {"code": "RATE_LIMITED", "message": "slow down", "details": {}, "request_id": "r"}
    body = {"success": False, "data": None, "error": error, "meta": None}
    return httpx.Response(429, json=body, headers={"Retry-After": retry_after})


class Router:
    """Answers by (method, path); the last answer repeats; ``delay_s`` slows a route."""

    def __init__(
        self,
        routes: dict[tuple[str, str], Answer | list[Answer]],
        delay_s: dict[tuple[str, str], float] | None = None,
    ) -> None:
        self.routes = {key: v if isinstance(v, list) else [v] for key, v in routes.items()}
        self.delay_s = delay_s or {}
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        key = (request.method, request.url.path)
        time.sleep(self.delay_s.get(key, 0.0))
        answers = self.routes[key]
        answer = answers.pop(0) if len(answers) > 1 else answers[0]
        if isinstance(answer, Exception):
            raise answer
        return answer

    def seen(self, method: str, path: str) -> list[httpx.Request]:
        return [r for r in self.requests if (r.method, r.url.path) == (method, path)]


def sync_client(router: Router) -> tuple[Client, list[float]]:
    sleeps: list[float] = []
    client = Client(BASE, KEY)
    client._transport.close()
    transport = SyncTransport(BASE, KEY, TIMEOUT_S, sleep=sleeps.append, rand=lambda: 1.0)
    transport._http.close()
    transport._http = httpx.Client(
        transport=httpx.MockTransport(router), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    client._transport = transport
    return client, sleeps


async def async_client(router: Router) -> tuple[AsyncClient, list[float]]:
    sleeps: list[float] = []

    async def record(seconds: float) -> None:
        sleeps.append(seconds)

    client = AsyncClient(BASE, KEY)
    await client._transport.aclose()
    transport = AsyncTransport(BASE, KEY, TIMEOUT_S, sleep=record, rand=lambda: 1.0)
    await transport._http.aclose()
    transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(router), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    client._transport = transport
    return client, sleeps


def timed_out_create(before: Answer, after: Answer, post: Exception | None = None) -> Router:
    """The create POST times out; the by-name lookups answer ``before`` then ``after``."""
    return Router(
        {
            ("GET", SANDBOXES): [before, after],
            ("POST", SANDBOXES): post or httpx.ReadTimeout("the create is still running"),
            ("DELETE", ONE_SANDBOX): ok(sandbox_json(state="destroying")),
            ("DELETE", f"{SANDBOXES}/{OTHER}"): ok(sandbox_json(OTHER, state="destroying")),
        }
    )


def deletes(router: Router) -> list[httpx.Request]:
    return [r for r in router.requests if r.method == "DELETE"]


# --- 1. the timeout cleanup deletes only the sandbox this call made -----------------------


# Routers are built per test: an httpx.Response is consumed by the client that reads it.
def held_before() -> Router:
    taken = sandbox_json(OTHER, state="started", age_s=5)
    return timed_out_create(listing(taken), listing(taken))


def free_then_fresh() -> Router:
    return timed_out_create(listing(), listing(sandbox_json(age_s=0)))


def free_then_old() -> Router:
    return timed_out_create(listing(), listing(sandbox_json(age_s=CLOCK_SKEW_ALLOWANCE_S + 120)))


def check_fails() -> Router:
    error = httpx.Response(500, json={"success": False, "data": None, "error": {}})
    return timed_out_create(error, listing(sandbox_json(age_s=0)))


def connect_timeout() -> Router:
    post = httpx.ConnectTimeout("no route")
    return timed_out_create(listing(), listing(sandbox_json(age_s=0)), post=post)


# scenario: (router, the requests sent in order, the sandbox id a warning names or None)
CLEANUP_SCENARIOS: dict[str, tuple[Callable[[], Router], list[str], str | None]] = {
    "name-held-before-is-never-deleted": (held_before, ["GET", "POST"], OTHER),
    "free-name-and-fresh-sandbox-is-deleted": (
        free_then_fresh, ["GET", "POST", "GET", "DELETE"], None,
    ),
    "found-sandbox-older-than-the-call-is-left-alone": (
        free_then_old, ["GET", "POST", "GET"], SID,
    ),
    "failed-check-before-skips-the-cleanup": (check_fails, ["GET", "POST"], None),
    "connect-timeout-triggers-no-lookup-and-no-delete": (connect_timeout, ["GET", "POST"], None),
}  # fmt: skip


def assert_cleanup(
    scenario: str, router: Router, error: SandboxTimeoutError, log: pytest.LogCaptureFixture
) -> None:
    _, methods, named = CLEANUP_SCENARIOS[scenario]
    assert [r.method for r in router.requests] == methods
    assert [r.url.path for r in deletes(router)] == ([ONE_SANDBOX] if "DELETE" in methods else [])
    if named is not None:
        assert named in log.text and "alone" in log.text
    cause = error.__cause__
    assert isinstance(cause, RequestTimedOut)
    assert cause.request_sent is (scenario != "connect-timeout-triggers-no-lookup-and-no-delete")


@pytest.mark.parametrize("scenario", CLEANUP_SCENARIOS)
def test_the_timeout_cleanup_deletes_only_a_sandbox_this_create_made(
    scenario: str, caplog: pytest.LogCaptureFixture
) -> None:
    router = CLEANUP_SCENARIOS[scenario][0]()
    client, _ = sync_client(router)

    with caplog.at_level(logging.WARNING), pytest.raises(SandboxTimeoutError) as caught:
        client.create_sandbox(name="demo", wait_timeout_s=WAIT_S)

    assert_cleanup(scenario, router, caught.value, caplog)


@pytest.mark.parametrize("scenario", CLEANUP_SCENARIOS)
async def test_async_the_timeout_cleanup_deletes_only_a_sandbox_this_create_made(
    scenario: str, caplog: pytest.LogCaptureFixture
) -> None:
    router = CLEANUP_SCENARIOS[scenario][0]()
    client, _ = await async_client(router)

    with caplog.at_level(logging.WARNING), pytest.raises(SandboxTimeoutError) as caught:
        await client.create_sandbox(name="demo", wait_timeout_s=WAIT_S)

    assert_cleanup(scenario, router, caught.value, caplog)
    await client.aclose()


def test_made_by_this_create_allows_the_clock_skew_and_refuses_unknown_ages() -> None:
    posted = datetime.now(UTC)
    inside = SandboxInfo.from_payload(sandbox_json(age_s=CLOCK_SKEW_ALLOWANCE_S / 2))
    outside = SandboxInfo.from_payload(sandbox_json(age_s=CLOCK_SKEW_ALLOWANCE_S + 1))
    unknown = SandboxInfo.from_payload(sandbox_json(age_s=None))
    naive = SandboxInfo.from_payload(
        sandbox_json(created_at=posted.replace(tzinfo=None).isoformat())
    )

    assert made_by_this_create(inside, posted)
    assert made_by_this_create(naive, posted)  # a naive timestamp is read as UTC
    assert not made_by_this_create(outside, posted)
    assert not made_by_this_create(unknown, posted)


@pytest.mark.parametrize(
    ("error", "sent"),
    [
        (httpx.ConnectTimeout("c"), False),
        (httpx.PoolTimeout("p"), False),
        (httpx.ReadTimeout("r"), True),
        (httpx.WriteTimeout("w"), True),
    ],
)
def test_a_timeout_says_whether_the_request_left_the_client(error: Exception, sent: bool) -> None:
    client, _ = sync_client(Router({("GET", ONE_SANDBOX): error}))
    client._transport._max_retries = 0

    with pytest.raises(RequestTimedOut) as caught:
        client.get(SID)

    assert caught.value.request_sent is sent


# --- 2. a 429 RATE_LIMITED resends only a body that can be sent again ---------------------


def uploaded() -> httpx.Response:
    return ok({"path": "/a", "size_bytes": 4})


def test_a_rate_limited_streamed_upload_is_not_resent_and_raises() -> None:
    router = Router({("PUT", UPLOAD): [rate_limited(), uploaded()]})
    client, sleeps = sync_client(router)

    with pytest.raises(RateLimited):
        Fs(SID, client._transport).upload_file("/a", io.BytesIO(b"data"))

    assert len(router.seen("PUT", UPLOAD)) == 1
    assert sleeps == []


def test_a_rate_limited_bytes_upload_is_resent() -> None:
    router = Router({("PUT", UPLOAD): [rate_limited(), uploaded()]})
    client, sleeps = sync_client(router)

    result = Fs(SID, client._transport).upload_file("/a", b"data")

    assert result.size_bytes == 4
    assert [r.content for r in router.seen("PUT", UPLOAD)] == [b"data", b"data"]
    assert sleeps == [1.0]


def test_a_rate_limited_json_post_is_resent() -> None:
    router = Router({("POST", SANDBOXES): [rate_limited("2"), ok(sandbox_json())]})
    client, sleeps = sync_client(router)

    client._transport.request("POST", SANDBOXES, json={"name": "demo"})

    assert len(router.seen("POST", SANDBOXES)) == 2
    assert sleeps == [2.0]


async def test_async_a_rate_limited_streamed_upload_is_not_resent_and_raises() -> None:
    router = Router({("PUT", UPLOAD): [rate_limited(), uploaded()]})
    client, sleeps = await async_client(router)

    with pytest.raises(RateLimited):
        await AsyncFs(SID, client._transport).upload_file("/a", io.BytesIO(b"data"))

    assert len(router.seen("PUT", UPLOAD)) == 1
    assert sleeps == []
    await client.aclose()


async def test_async_a_rate_limited_bytes_upload_is_resent() -> None:
    router = Router({("PUT", UPLOAD): [rate_limited(), uploaded()]})
    client, sleeps = await async_client(router)

    await AsyncFs(SID, client._transport).upload_file("/a", b"data")

    assert len(router.seen("PUT", UPLOAD)) == 2
    assert sleeps == [1.0]
    await client.aclose()


def test_only_bodies_held_in_memory_are_replayable() -> None:
    for body in (None, b"x", bytearray(b"x"), memoryview(b"x")):
        assert replayable_body(body)
    assert not replayable_body(iter([b"x"])) and not replayable_body(io.BytesIO(b"x"))
    stream = iter([b"x"])
    assert plan_call("PUT", None, stream, timeout=1, max_retries=2, read_timeout_s=None,
                     deadline=None).retries == 0  # fmt: skip


# --- 3. one deadline bounds the whole blocking create -------------------------------------

SLOW_WAIT_S = 1.0
SLOW_POST_S = 0.6
SLOW_POLL_S = 0.1
MARGIN_S = 0.4  # the old code (deadline started after the POST) took >= 1.6 s here


def slow_start() -> Router:
    pending = ok(sandbox_json())
    return Router(
        {("POST", SANDBOXES): pending, ("GET", ONE_SANDBOX): pending},
        delay_s={("POST", SANDBOXES): SLOW_POST_S, ("GET", ONE_SANDBOX): SLOW_POLL_S},
    )


def assert_bounded(router: Router, elapsed: float, caught: SandboxTimeoutError) -> None:
    assert elapsed < SLOW_WAIT_S + MARGIN_S
    assert caught.sandbox_id == SID
    (post,) = router.seen("POST", SANDBOXES)
    assert post.extensions["timeout"]["read"] <= SLOW_WAIT_S
    for poll in router.seen("GET", ONE_SANDBOX):
        assert poll.extensions["timeout"]["read"] <= SLOW_WAIT_S - SLOW_POST_S
        assert float(poll.url.params["timeout_s"]) <= SLOW_WAIT_S - SLOW_POST_S


def test_a_slow_post_and_a_slow_start_stay_within_the_wait_timeout() -> None:
    router = slow_start()
    client, _ = sync_client(router)

    started = time.monotonic()
    with pytest.raises(SandboxTimeoutError) as caught:
        client.create_sandbox(wait_timeout_s=SLOW_WAIT_S, poll_interval_s=0.05)

    assert_bounded(router, time.monotonic() - started, caught.value)


async def test_async_a_slow_post_and_a_slow_start_stay_within_the_wait_timeout() -> None:
    router = slow_start()
    client, _ = await async_client(router)

    started = time.monotonic()
    with pytest.raises(SandboxTimeoutError) as caught:
        await client.create_sandbox(wait_timeout_s=SLOW_WAIT_S, poll_interval_s=0.05)

    assert_bounded(router, time.monotonic() - started, caught.value)
    await client.aclose()


def test_a_rate_limited_pause_past_the_deadline_is_not_taken() -> None:
    router = Router({("POST", SANDBOXES): [rate_limited("5"), ok(sandbox_json())]})
    client, sleeps = sync_client(router)

    with pytest.raises(RateLimited):
        client.create_sandbox(wait_timeout_s=WAIT_S)

    assert len(router.seen("POST", SANDBOXES)) == 1
    assert sleeps == []


def test_a_rate_limited_pause_within_the_deadline_is_taken() -> None:
    started = ok(sandbox_json(state="started"))
    router = Router({("POST", SANDBOXES): [rate_limited("1"), started]})
    client, sleeps = sync_client(router)

    sandbox = client.create_sandbox(wait_timeout_s=WAIT_S)

    assert sandbox.state == "started"
    assert sleeps == [1.0]


async def test_async_a_rate_limited_pause_past_the_deadline_is_not_taken() -> None:
    router = Router({("POST", SANDBOXES): [rate_limited("5"), ok(sandbox_json())]})
    client, sleeps = await async_client(router)

    with pytest.raises(RateLimited):
        await client.create_sandbox(wait_timeout_s=WAIT_S)

    assert sleeps == []
    await client.aclose()
