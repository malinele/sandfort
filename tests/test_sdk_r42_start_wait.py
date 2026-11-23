"""SDK round 42: ``Client.start(wait=True)`` under one deadline, like ``create_sandbox``.

The deadline starts just before the start POST and covers it: a POST that outlives the budget is
a :class:`SandboxTimeoutError` naming the sandbox (not a hang). When the reply already says
``started`` no further request is sent. Plain ``start`` is the one POST it always was.
"""

import sys
import time
from pathlib import Path
from typing import Any

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
from sandfort_sdk import Client, SandboxFailedError, SandboxTimeoutError  # noqa: E402
from sandfort_sdk._transport import SyncTransport, client_kwargs  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
TIMEOUT_S = 30.0
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
ONE_SANDBOX = f"/v1/sandboxes/{SID}"
START = f"{ONE_SANDBOX}/start"
WAIT_S = 0.5
POLL_S = 0.01
HANG_MARGIN_S = 5.0


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
    """Answers the start POST and the GETs in turn; records every request."""

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


def test_start_wait_returns_once_started() -> None:
    server = Server(reply("starting"), reply("starting"), reply("started"))
    client = make_client(server)

    sandbox = client.start(SID, wait=True, wait_timeout_s=5, poll_interval_s=POLL_S)

    assert sandbox.id == SID and sandbox.info.state == "started"
    assert len(server.seen("POST")) == 1
    assert len(server.seen("GET")) == 2


def test_start_wait_long_polls_for_started_under_the_budget() -> None:
    server = Server(reply("starting"), reply("started"))
    client = make_client(server)

    client.start(SID, wait=True, wait_timeout_s=5, poll_interval_s=POLL_S)

    (get,) = server.seen("GET")
    assert get.url.path == ONE_SANDBOX
    assert get.url.params["wait_for"] == "started"
    assert 0 <= float(get.url.params["timeout_s"]) <= 5


def test_start_post_is_sent_with_the_wait_deadline() -> None:
    server = Server(reply("started"))
    client = make_client(server)

    client.start(SID, wait=True, wait_timeout_s=WAIT_S)

    (post,) = server.seen("POST")
    assert 0 < post.extensions["timeout"]["read"] <= WAIT_S


def test_start_wait_on_an_already_started_reply_makes_no_extra_fetch() -> None:
    server = Server(reply("started"))
    client = make_client(server)

    sandbox = client.start(SID, wait=True)

    assert sandbox.info.state == "started"
    assert [r.method for r in server.requests] == ["POST"]


def test_a_start_post_that_outlives_the_budget_is_a_wait_timeout_not_a_hang() -> None:
    requests: list[httpx.Request] = []

    def slow_post(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        time.sleep(WAIT_S * 2)
        raise httpx.ReadTimeout("the start is still running", request=request)

    client = make_client(slow_post)

    began = time.monotonic()
    with pytest.raises(SandboxTimeoutError) as caught:
        client.start(SID, wait=True, wait_timeout_s=WAIT_S)

    assert time.monotonic() - began < WAIT_S + HANG_MARGIN_S
    assert [r.method for r in requests] == ["POST"]  # no poll follows a timed-out start
    assert caught.value.sandbox_id == SID and not caught.value.deleted
    assert SID in str(caught.value) and "may still finish" in str(caught.value)


def test_a_wait_that_runs_out_names_the_sandbox_and_its_state() -> None:
    server = Server(reply("starting"), reply("starting"))
    client = make_client(server)

    with pytest.raises(SandboxTimeoutError) as caught:
        client.start(SID, wait=True, wait_timeout_s=0.2, poll_interval_s=POLL_S)

    assert caught.value.sandbox_id == SID and caught.value.state == "starting"


def test_start_wait_into_the_error_state_raises_and_deletes_nothing() -> None:
    server = Server(reply("starting"), reply("error"))
    client = make_client(server)

    with pytest.raises(SandboxFailedError):
        client.start(SID, wait=True, wait_timeout_s=5, poll_interval_s=POLL_S)

    assert not server.seen("DELETE")


def test_plain_start_is_one_post_and_returns_the_reply_as_is() -> None:
    server = Server(reply("starting"), reply("started"))
    client = make_client(server)

    sandbox = client.start(SID)

    assert sandbox.info.state == "starting"
    assert [(r.method, r.url.path) for r in server.requests] == [("POST", START)]


def test_plain_start_ignores_the_wait_settings() -> None:
    server = Server(reply("starting"), reply("started"))
    client = make_client(server)

    sandbox = client.start(SID, wait_timeout_s=0.1, poll_interval_s=POLL_S)

    assert sandbox.info.state == "starting"
    assert len(server.requests) == 1
