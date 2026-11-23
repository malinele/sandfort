"""SDK r30s: ``request_sent`` survives retries; the create deadline bounds every attempt."""

import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
from sandfort_sdk import AsyncClient, Client, SandboxTimeoutError, async_client  # noqa: E402
from sandfort_sdk import client as sync_client_module  # noqa: E402
from sandfort_sdk._transport import AsyncTransport, SyncTransport, client_kwargs  # noqa: E402
from sandfort_sdk.exceptions import RequestTimedOut  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
TIMEOUT_S = 30.0
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOXES = "/v1/sandboxes"
ONE_SANDBOX = f"{SANDBOXES}/{SID}"
WAIT_S = 10.0
MARGIN_S = 0.1
KEYED = {"Idempotency-Key": "key-1"}
STALL = None  # the attempt uses up its whole read timeout, then times out

Clock = Callable[[], float]
Answer = httpx.Response | Exception
Step = tuple[float | None, Answer]  # (seconds the attempt takes, what it ends with)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass(frozen=True)
class Call:
    method: str
    timeout: dict[str, float | None]
    at: float


class Router:
    """Answers by (method, path); each answer may take (fake) time; the last one repeats."""

    def __init__(self, clock: FakeClock, routes: dict[tuple[str, str], list[Step]]) -> None:
        self.clock = clock
        self.routes = {key: list(steps) for key, steps in routes.items()}
        self.calls: list[Call] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        timeout = dict(request.extensions["timeout"])
        key = (request.method, request.url.path)
        self.calls.append(Call(key[0], timeout, self.clock.now))
        steps = self.routes[key]
        spend, answer = steps.pop(0) if len(steps) > 1 else steps[0]
        self.clock.advance((timeout["read"] or 0.0) if spend is STALL else spend)
        if isinstance(answer, Exception):
            raise answer
        return answer

    def methods(self) -> list[str]:
        return [c.method for c in self.calls]


def ok(data: Any) -> httpx.Response:
    return httpx.Response(200, json={"success": True, "data": data, "meta": None})


def fresh_sandbox(**over: Any) -> dict[str, Any]:
    created = datetime.now(UTC).isoformat()
    return {"id": SID, "name": "demo", "state": "pending", "created_at": created, **over}


def create_routes(post: list[Step]) -> dict[tuple[str, str], list[Step]]:
    """A named create: the name is free before, the sandbox exists after the POST."""
    return {
        ("GET", SANDBOXES): [(0, ok([])), (0, ok([fresh_sandbox()]))],
        ("POST", SANDBOXES): post,
        ("DELETE", ONE_SANDBOX): [(0, ok(fresh_sandbox(state="destroying")))],
    }


def sync_transport(router: Router, clock: Clock, extra_pause: float = 0.0) -> SyncTransport:
    def sleep(seconds: float) -> None:
        router.clock.advance(seconds + extra_pause)

    transport = SyncTransport(BASE, KEY, TIMEOUT_S, sleep=sleep, rand=lambda: 1.0, clock=clock)
    transport._http.close()
    transport._http = httpx.Client(
        transport=httpx.MockTransport(router), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return transport


def async_transport(router: Router, clock: Clock, extra_pause: float = 0.0) -> AsyncTransport:
    async def sleep(seconds: float) -> None:
        router.clock.advance(seconds + extra_pause)

    transport = AsyncTransport(BASE, KEY, TIMEOUT_S, sleep=sleep, rand=lambda: 1.0, clock=clock)
    transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(router), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return transport


def sync_client(router: Router, clock: Clock = time.monotonic) -> Client:
    client = Client(BASE, KEY)
    client._transport.close()
    client._transport = sync_transport(router, clock)
    return client


def async_client_for(router: Router, clock: Clock = time.monotonic) -> AsyncClient:
    client = AsyncClient(BASE, KEY)
    client._transport = async_transport(router, clock)
    return client


def fake_time(clock: FakeClock) -> SimpleNamespace:
    return SimpleNamespace(monotonic=clock)


# --- 1. request_sent is kept across the attempts of one call ------------------------------

LOST = [httpx.ReadError("connection lost"), httpx.RemoteProtocolError("server disconnected")]
UNSENT = [httpx.ConnectTimeout("no route"), httpx.PoolTimeout("no connection free")]


@pytest.mark.parametrize("lost", LOST, ids=["read-error", "remote-protocol"])
@pytest.mark.parametrize("unsent", UNSENT, ids=["connect-timeout", "pool-timeout"])
def test_a_lost_connection_then_a_connect_timeout_still_says_the_request_was_sent(
    lost: Exception, unsent: Exception
) -> None:
    clock = FakeClock()
    router = Router(clock, {("POST", SANDBOXES): [(0, lost), (0, unsent)]})
    transport = sync_transport(router, clock)

    with pytest.raises(RequestTimedOut) as caught:
        transport.request("POST", SANDBOXES, headers=KEYED)

    assert len(router.calls) == 3  # without a deadline a timeout is resent too
    assert caught.value.request_sent is True


@pytest.mark.parametrize("unsent", UNSENT, ids=["connect-timeout", "pool-timeout"])
def test_only_timeouts_before_the_request_could_be_written_say_it_was_not_sent(
    unsent: Exception,
) -> None:
    clock = FakeClock()
    router = Router(clock, {("GET", ONE_SANDBOX): [(0, unsent)]})
    transport = sync_transport(router, clock)

    with pytest.raises(RequestTimedOut) as caught:
        transport.request("GET", ONE_SANDBOX)

    assert len(router.calls) == 3  # every attempt was resent and none could have been written
    assert caught.value.request_sent is False


@pytest.mark.parametrize("lost", LOST, ids=["read-error", "remote-protocol"])
async def test_async_a_lost_connection_then_a_connect_timeout_says_it_was_sent(
    lost: Exception,
) -> None:
    clock = FakeClock()
    router = Router(clock, {("POST", SANDBOXES): [(0, lost), (0, UNSENT[0])]})
    transport = async_transport(router, clock)

    with pytest.raises(RequestTimedOut) as caught:
        await transport.request("POST", SANDBOXES, headers=KEYED)

    assert len(router.calls) == 3
    assert caught.value.request_sent is True


async def test_async_only_timeouts_before_the_request_could_be_written_say_not_sent() -> None:
    clock = FakeClock()
    router = Router(clock, {("GET", ONE_SANDBOX): [(0, UNSENT[1])]})
    transport = async_transport(router, clock)

    with pytest.raises(RequestTimedOut) as caught:
        await transport.request("GET", ONE_SANDBOX)

    assert len(router.calls) == 3
    assert caught.value.request_sent is False


def lost_then_connect_timeout() -> Router:
    post: list[Step] = [(0, LOST[0]), (0, UNSENT[0])]
    return Router(FakeClock(), create_routes(post))


def test_create_after_a_lost_connection_then_a_connect_timeout_runs_the_cleanup() -> None:
    router = lost_then_connect_timeout()
    client = sync_client(router)

    with pytest.raises(SandboxTimeoutError) as caught:
        client.create_sandbox(name="demo", wait_timeout_s=WAIT_S, idempotency_key="key-1")

    assert router.methods() == ["GET", "POST", "POST", "GET", "DELETE"]
    assert isinstance(caught.value.__cause__, RequestTimedOut)
    assert caught.value.__cause__.request_sent is True


async def test_async_create_after_a_lost_connection_then_a_connect_timeout_runs_cleanup() -> None:
    router = lost_then_connect_timeout()
    client = async_client_for(router)

    with pytest.raises(SandboxTimeoutError) as caught:
        await client.create_sandbox(name="demo", wait_timeout_s=WAIT_S, idempotency_key="key-1")

    assert router.methods() == ["GET", "POST", "POST", "GET", "DELETE"]
    assert isinstance(caught.value.__cause__, RequestTimedOut)
    assert caught.value.__cause__.request_sent is True
    await client.aclose()


def test_create_with_a_plain_connect_timeout_on_the_first_attempt_runs_no_cleanup() -> None:
    router = Router(FakeClock(), create_routes([(0, UNSENT[0])]))
    client = sync_client(router)

    with pytest.raises(SandboxTimeoutError) as caught:
        client.create_sandbox(name="demo", wait_timeout_s=WAIT_S)

    assert router.methods() == ["GET", "POST"]  # the name check, then the one attempt
    assert isinstance(caught.value.__cause__, RequestTimedOut)
    assert caught.value.__cause__.request_sent is False


async def test_async_create_with_a_plain_connect_timeout_runs_no_cleanup() -> None:
    router = Router(FakeClock(), create_routes([(0, UNSENT[0])]))
    client = async_client_for(router)

    with pytest.raises(SandboxTimeoutError) as caught:
        await client.create_sandbox(name="demo", wait_timeout_s=WAIT_S)

    assert router.methods() == ["GET", "POST"]
    assert isinstance(caught.value.__cause__, RequestTimedOut)
    assert caught.value.__cause__.request_sent is False
    await client.aclose()


# --- 2. under a deadline every attempt gets at most the time left -------------------------

SLOW_LOSSES: list[Step] = [(3.0, LOST[0]), (3.0, LOST[1]), (1.0, httpx.ReadTimeout("slow"))]
TIMEOUT_PARTS = ("connect", "write", "read", "pool")


def assert_within_time_left(router: Router, deadline: float) -> None:
    assert len(router.calls) == 3
    for call in router.calls:
        left = deadline - call.at
        for part in TIMEOUT_PARTS:
            value = call.timeout[part]
            assert value is not None
            assert 0 < value <= left + 1e-9, (part, value, left)


def test_every_attempt_under_a_deadline_gets_timeouts_of_at_most_the_time_left() -> None:
    clock = FakeClock()
    router = Router(clock, {("POST", SANDBOXES): SLOW_LOSSES})
    transport = sync_transport(router, clock)
    deadline = clock.now + WAIT_S

    with pytest.raises(RequestTimedOut) as caught:
        transport.request("POST", SANDBOXES, headers=KEYED, deadline=deadline)

    assert_within_time_left(router, deadline)
    assert [c.timeout["read"] for c in router.calls] == pytest.approx([10.0, 6.5, 2.5])
    assert caught.value.request_sent is True


async def test_async_every_attempt_under_a_deadline_gets_timeouts_of_at_most_time_left() -> None:
    clock = FakeClock()
    router = Router(clock, {("POST", SANDBOXES): SLOW_LOSSES})
    transport = async_transport(router, clock)
    deadline = clock.now + WAIT_S

    with pytest.raises(RequestTimedOut) as caught:
        await transport.request("POST", SANDBOXES, headers=KEYED, deadline=deadline)

    assert_within_time_left(router, deadline)
    assert caught.value.request_sent is True


def test_without_a_deadline_the_attempts_keep_the_plain_timeout() -> None:
    clock = FakeClock()
    router = Router(clock, {("GET", ONE_SANDBOX): [(5.0, ok({"id": SID}))]})
    transport = sync_transport(router, clock)

    transport.request("GET", ONE_SANDBOX)

    assert router.calls[0].timeout == dict.fromkeys(TIMEOUT_PARTS, TIMEOUT_S)


# --- 3. no attempt starts once the deadline has passed ------------------------------------


def test_no_attempt_starts_after_a_pause_that_overshot_the_deadline() -> None:
    clock = FakeClock()
    router = Router(clock, {("POST", SANDBOXES): [(0, LOST[0]), (0, ok({"id": SID}))]})
    transport = sync_transport(router, clock, extra_pause=WAIT_S * 2)

    with pytest.raises(RequestTimedOut) as caught:
        transport.request("POST", SANDBOXES, headers=KEYED, deadline=clock.now + WAIT_S)

    assert len(router.calls) == 1
    assert caught.value.request_sent is True


async def test_async_no_attempt_starts_after_a_pause_that_overshot_the_deadline() -> None:
    clock = FakeClock()
    router = Router(clock, {("POST", SANDBOXES): [(0, LOST[0]), (0, ok({"id": SID}))]})
    transport = async_transport(router, clock, extra_pause=WAIT_S * 2)

    with pytest.raises(RequestTimedOut) as caught:
        await transport.request("POST", SANDBOXES, headers=KEYED, deadline=clock.now + WAIT_S)

    assert len(router.calls) == 1
    assert caught.value.request_sent is True


def test_a_failure_that_ends_after_the_deadline_is_a_timeout_not_a_resend() -> None:
    clock = FakeClock()
    router = Router(clock, {("POST", SANDBOXES): [(WAIT_S + 1, LOST[0]), (0, ok({"id": SID}))]})
    transport = sync_transport(router, clock)

    with pytest.raises(RequestTimedOut) as caught:
        transport.request("POST", SANDBOXES, headers=KEYED, deadline=clock.now + WAIT_S)

    assert len(router.calls) == 1
    assert caught.value.request_sent is True


async def test_async_a_failure_that_ends_after_the_deadline_is_a_timeout_not_a_resend() -> None:
    clock = FakeClock()
    router = Router(clock, {("POST", SANDBOXES): [(WAIT_S + 1, LOST[0]), (0, ok({"id": SID}))]})
    transport = async_transport(router, clock)

    with pytest.raises(RequestTimedOut) as caught:
        await transport.request("POST", SANDBOXES, headers=KEYED, deadline=clock.now + WAIT_S)

    assert len(router.calls) == 1
    assert caught.value.request_sent is True


# --- 4. a blocking create with a fake clock never runs past its deadline ------------------

# A slow first attempt that loses the connection, then one that stalls to its read timeout.
SLOW_THEN_STALL: list[Step] = [(4.0, LOST[0]), (STALL, httpx.ReadTimeout("still running"))]


def test_blocking_create_with_a_fake_clock_never_runs_past_its_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = FakeClock()
    monkeypatch.setattr(sync_client_module, "time", fake_time(clock))
    router = Router(clock, create_routes(SLOW_THEN_STALL))
    client = sync_client(router, clock)
    started = clock.now

    with pytest.raises(SandboxTimeoutError) as caught:
        client.create_sandbox(name="demo", wait_timeout_s=WAIT_S, idempotency_key="key-1")

    assert clock.now - started <= WAIT_S + MARGIN_S
    assert router.methods().count("POST") == 2
    assert router.methods()[-2:] == ["GET", "DELETE"]  # the cleanup ran: it was sent
    assert isinstance(caught.value.__cause__, RequestTimedOut)


async def test_async_blocking_create_with_a_fake_clock_never_runs_past_its_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = FakeClock()
    monkeypatch.setattr(async_client, "time", fake_time(clock))
    router = Router(clock, create_routes(SLOW_THEN_STALL))
    client = async_client_for(router, clock)
    started = clock.now

    with pytest.raises(SandboxTimeoutError) as caught:
        await client.create_sandbox(name="demo", wait_timeout_s=WAIT_S, idempotency_key="key-1")

    assert clock.now - started <= WAIT_S + MARGIN_S
    assert router.methods().count("POST") == 2
    assert router.methods()[-2:] == ["GET", "DELETE"]
    assert isinstance(caught.value.__cause__, RequestTimedOut)
    await client.aclose()
