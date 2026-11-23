"""SDK round 43: ``AsyncClient.start(wait=...)`` parity and wait-budget validation.

``AsyncClient.start`` takes the keyword-only ``wait``, ``wait_timeout_s`` and
``poll_interval_s`` of ``Client.start`` (one deadline before the POST, the POST sent under it,
the long-poll for ``started`` under what is left). A ``wait_timeout_s`` that is not a finite
number greater than 0 is a :class:`ValueError` in ``start`` and ``create_sandbox`` of both
clients, when a wait is requested.
"""

import math
import sys
from pathlib import Path
from typing import Any

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
from sandfort_sdk import AsyncClient, Client, SandboxTimeoutError  # noqa: E402
from sandfort_sdk._transport import (  # noqa: E402
    AsyncTransport,
    SyncTransport,
    client_kwargs,
)

BASE = "http://sandfort.test"
KEY = "sf_test_key"
TIMEOUT_S = 30.0
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
ONE_SANDBOX = f"/v1/sandboxes/{SID}"
START = f"{ONE_SANDBOX}/start"
WAIT_S = 0.5
POLL_S = 0.01
BAD_BUDGETS = [0, 0.0, -1, -0.5, math.nan, math.inf, -math.inf]
BUDGET_MESSAGE = "wait_timeout_s must be a finite number greater than 0"


def reply(state: str) -> httpx.Response:
    data: dict[str, Any] = {
        "id": SID,
        "name": "demo",
        "state": state,
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
    }
    return httpx.Response(200, json={"success": True, "data": data, "error": None, "meta": None})


class Server:
    """Answers the POST and the GETs in turn; records every request."""

    def __init__(self, post: httpx.Response, *polls: httpx.Response) -> None:
        self.post = post
        self.polls = list(polls)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.method == "POST":
            return self.post
        return self.polls.pop(0) if len(self.polls) > 1 else self.polls[0]

    def seen(self, method: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.method == method]


def make_client(handler: Any) -> Client:
    client = Client(BASE, KEY)
    client._transport.close()
    transport = SyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    transport._http.close()
    transport._http = httpx.Client(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    client._transport = transport
    return client


def make_async_client(handler: Any) -> AsyncClient:
    client = AsyncClient(BASE, KEY)
    transport = AsyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    client._transport = transport
    return client


# --- async start with wait -------------------------------------------------------------------


async def test_async_start_wait_returns_once_started() -> None:
    server = Server(reply("starting"), reply("starting"), reply("started"))
    client = make_async_client(server)

    sandbox = await client.start(SID, wait=True, wait_timeout_s=5, poll_interval_s=POLL_S)

    assert sandbox.id == SID and sandbox.info.state == "started"
    assert len(server.seen("POST")) == 1
    assert len(server.seen("GET")) == 2


async def test_async_start_wait_long_polls_for_started_under_the_budget() -> None:
    server = Server(reply("starting"), reply("started"))
    client = make_async_client(server)

    await client.start(SID, wait=True, wait_timeout_s=5, poll_interval_s=POLL_S)

    (get,) = server.seen("GET")
    assert get.url.path == ONE_SANDBOX
    assert get.url.params["wait_for"] == "started"
    assert 0 <= float(get.url.params["timeout_s"]) <= 5


async def test_async_start_post_is_sent_with_the_wait_deadline() -> None:
    server = Server(reply("started"))
    client = make_async_client(server)

    await client.start(SID, wait=True, wait_timeout_s=WAIT_S)

    (post,) = server.seen("POST")
    assert 0 < post.extensions["timeout"]["read"] <= WAIT_S
    assert [r.method for r in server.requests] == ["POST"]  # already started: no extra fetch


async def test_async_start_post_that_outlives_the_budget_is_a_wait_timeout() -> None:
    def timed_out(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("the start is still running", request=request)

    client = make_async_client(timed_out)

    with pytest.raises(SandboxTimeoutError) as caught:
        await client.start(SID, wait=True, wait_timeout_s=WAIT_S)

    assert caught.value.sandbox_id == SID and not caught.value.deleted
    assert "may still finish" in str(caught.value)


async def test_async_start_wait_that_runs_out_names_the_sandbox_and_its_state() -> None:
    server = Server(reply("starting"), reply("starting"))
    client = make_async_client(server)

    with pytest.raises(SandboxTimeoutError) as caught:
        await client.start(SID, wait=True, wait_timeout_s=0.2, poll_interval_s=POLL_S)

    assert caught.value.sandbox_id == SID and caught.value.state == "starting"


async def test_async_start_without_wait_is_one_post_as_before() -> None:
    server = Server(reply("starting"), reply("started"))
    client = make_async_client(server)

    sandbox = await client.start(SID)

    assert sandbox.info.state == "starting"
    assert [(r.method, r.url.path) for r in server.requests] == [("POST", START)]


async def test_async_start_without_wait_ignores_the_wait_settings() -> None:
    server = Server(reply("starting"), reply("started"))
    client = make_async_client(server)

    sandbox = await client.start(SID, wait_timeout_s=0, poll_interval_s=POLL_S)

    assert sandbox.info.state == "starting"
    assert len(server.requests) == 1


# --- budget validation -----------------------------------------------------------------------


@pytest.mark.parametrize("budget", BAD_BUDGETS)
def test_sync_start_rejects_an_unusable_budget_before_any_request(budget: float) -> None:
    server = Server(reply("started"))
    client = make_client(server)

    with pytest.raises(ValueError, match=BUDGET_MESSAGE):
        client.start(SID, wait=True, wait_timeout_s=budget)

    assert server.requests == []


@pytest.mark.parametrize("budget", BAD_BUDGETS)
async def test_async_start_rejects_an_unusable_budget_before_any_request(budget: float) -> None:
    server = Server(reply("started"))
    client = make_async_client(server)

    with pytest.raises(ValueError, match=BUDGET_MESSAGE):
        await client.start(SID, wait=True, wait_timeout_s=budget)

    assert server.requests == []


@pytest.mark.parametrize("budget", BAD_BUDGETS)
def test_sync_create_sandbox_rejects_an_unusable_budget_before_any_request(
    budget: float,
) -> None:
    server = Server(reply("started"))
    client = make_client(server)

    with pytest.raises(ValueError, match=BUDGET_MESSAGE):
        client.create_sandbox(name="demo", wait=True, wait_timeout_s=budget)

    assert server.requests == []


@pytest.mark.parametrize("budget", BAD_BUDGETS)
async def test_async_create_sandbox_rejects_an_unusable_budget_before_any_request(
    budget: float,
) -> None:
    server = Server(reply("started"))
    client = make_async_client(server)

    with pytest.raises(ValueError, match=BUDGET_MESSAGE):
        await client.create_sandbox(name="demo", wait=True, wait_timeout_s=budget)

    assert server.requests == []


def test_sync_create_sandbox_ignores_the_budget_without_wait() -> None:
    server = Server(reply("starting"))
    client = make_client(server)

    sandbox = client.create_sandbox(wait=False, wait_timeout_s=0)

    assert sandbox.info.state == "starting"
    assert [r.method for r in server.requests] == ["POST"]


async def test_async_create_sandbox_ignores_the_budget_without_wait() -> None:
    server = Server(reply("starting"))
    client = make_async_client(server)

    sandbox = await client.create_sandbox(wait=False, wait_timeout_s=math.nan)

    assert sandbox.info.state == "starting"
    assert [r.method for r in server.requests] == ["POST"]


# --- sync behaviour unchanged for a valid budget ---------------------------------------------


def test_sync_start_wait_with_a_valid_budget_is_unchanged() -> None:
    server = Server(reply("starting"), reply("starting"), reply("started"))
    client = make_client(server)

    sandbox = client.start(SID, wait=True, wait_timeout_s=5, poll_interval_s=POLL_S)

    assert sandbox.info.state == "started"
    assert len(server.seen("POST")) == 1
    assert len(server.seen("GET")) == 2


def test_sync_start_wait_with_the_default_budget_is_unchanged() -> None:
    server = Server(reply("started"))
    client = make_client(server)

    sandbox = client.start(SID, wait=True)

    assert sandbox.info.state == "started"
    assert [r.method for r in server.requests] == ["POST"]


def test_sync_create_sandbox_with_a_valid_budget_is_unchanged() -> None:
    server = Server(reply("started"))
    client = make_client(server)

    sandbox = client.create_sandbox(wait=True, wait_timeout_s=5)

    assert sandbox.info.state == "started"
    assert [r.method for r in server.requests] == ["POST"]


# --- handle start: wait passthrough ----------------------------------------------------------


def test_sync_handle_start_wait_returns_once_started() -> None:
    server = Server(reply("starting"), reply("starting"), reply("started"))
    handle = make_client(server).start(SID)  # a handle from the one-request start
    server.requests.clear()

    returned = handle.start(wait=True, wait_timeout_s=5, poll_interval_s=POLL_S)

    assert returned is handle and handle.info.state == "started"
    assert len(server.seen("POST")) == 1
    gets = server.seen("GET")
    assert len(gets) == 2 and all(g.url.params["wait_for"] == "started" for g in gets)


def test_sync_handle_start_wait_post_carries_the_deadline() -> None:
    server = Server(reply("started"))
    handle = make_client(server).start(SID)
    server.requests.clear()

    handle.start(wait=True, wait_timeout_s=WAIT_S)

    (post,) = server.requests
    assert post.url.path == START
    assert 0 < post.extensions["timeout"]["read"] <= WAIT_S


def test_sync_handle_start_wait_that_runs_out_names_the_sandbox() -> None:
    server = Server(reply("starting"), reply("starting"))
    handle = make_client(server).start(SID)

    with pytest.raises(SandboxTimeoutError) as caught:
        handle.start(wait=True, wait_timeout_s=0.2, poll_interval_s=POLL_S)

    assert caught.value.sandbox_id == SID and caught.value.state == "starting"


@pytest.mark.parametrize("budget", BAD_BUDGETS)
def test_sync_handle_start_rejects_an_unusable_budget_before_any_request(budget: float) -> None:
    server = Server(reply("starting"))
    handle = make_client(server).start(SID)
    server.requests.clear()

    with pytest.raises(ValueError, match=BUDGET_MESSAGE):
        handle.start(wait=True, wait_timeout_s=budget)

    assert server.requests == []


def test_sync_handle_start_without_arguments_is_one_post_as_before() -> None:
    server = Server(reply("starting"), reply("started"))
    handle = make_client(server).start(SID)
    server.requests.clear()

    returned = handle.start()

    assert returned is handle and handle.info.state == "starting"
    assert [(r.method, r.url.path) for r in server.requests] == [("POST", START)]


def test_sync_handle_start_without_wait_ignores_the_wait_settings() -> None:
    server = Server(reply("starting"), reply("started"))
    handle = make_client(server).start(SID)
    server.requests.clear()

    handle.start(wait_timeout_s=0, poll_interval_s=POLL_S)

    assert [r.method for r in server.requests] == ["POST"]


async def test_async_handle_start_wait_returns_once_started() -> None:
    server = Server(reply("starting"), reply("starting"), reply("started"))
    handle = await make_async_client(server).start(SID)
    server.requests.clear()

    returned = await handle.start(wait=True, wait_timeout_s=5, poll_interval_s=POLL_S)

    assert returned is handle and handle.info.state == "started"
    assert len(server.seen("POST")) == 1
    gets = server.seen("GET")
    assert len(gets) == 2 and all(g.url.params["wait_for"] == "started" for g in gets)


async def test_async_handle_start_wait_post_carries_the_deadline() -> None:
    server = Server(reply("started"))
    handle = await make_async_client(server).start(SID)
    server.requests.clear()

    await handle.start(wait=True, wait_timeout_s=WAIT_S)

    (post,) = server.requests
    assert post.url.path == START
    assert 0 < post.extensions["timeout"]["read"] <= WAIT_S


async def test_async_handle_start_wait_that_runs_out_names_the_sandbox() -> None:
    server = Server(reply("starting"), reply("starting"))
    handle = await make_async_client(server).start(SID)

    with pytest.raises(SandboxTimeoutError) as caught:
        await handle.start(wait=True, wait_timeout_s=0.2, poll_interval_s=POLL_S)

    assert caught.value.sandbox_id == SID and caught.value.state == "starting"


@pytest.mark.parametrize("budget", BAD_BUDGETS)
async def test_async_handle_start_rejects_an_unusable_budget_before_any_request(
    budget: float,
) -> None:
    server = Server(reply("starting"))
    handle = await make_async_client(server).start(SID)
    server.requests.clear()

    with pytest.raises(ValueError, match=BUDGET_MESSAGE):
        await handle.start(wait=True, wait_timeout_s=budget)

    assert server.requests == []


async def test_async_handle_start_without_arguments_is_one_post_as_before() -> None:
    server = Server(reply("starting"), reply("started"))
    handle = await make_async_client(server).start(SID)
    server.requests.clear()

    returned = await handle.start()

    assert returned is handle and handle.info.state == "starting"
    assert [(r.method, r.url.path) for r in server.requests] == [("POST", START)]


async def test_async_handle_start_without_wait_ignores_the_wait_settings() -> None:
    server = Server(reply("starting"), reply("started"))
    handle = await make_async_client(server).start(SID)
    server.requests.clear()

    await handle.start(wait_timeout_s=0, poll_interval_s=POLL_S)

    assert [r.method for r in server.requests] == ["POST"]
