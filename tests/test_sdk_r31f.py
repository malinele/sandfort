"""SDK r31f: NameTaken and NoContainer (subclasses of Conflict), get_sandbox, and the request
id on a SandboxFailedError raised by a create."""

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
from sandfort_sdk import (  # noqa: E402
    AsyncClient,
    Client,
    Conflict,
    NameTaken,
    NoContainer,
    SandboxFailedError,
)
from sandfort_sdk._transport import client_kwargs  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
TIMEOUT_S = 30.0
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOXES = "/v1/sandboxes"
ONE_SANDBOX = f"{SANDBOXES}/{SID}"

Handler = Callable[[httpx.Request], httpx.Response]


def sandbox_json(state: str = "started", **over: Any) -> dict[str, Any]:
    return {"id": SID, "name": "demo", "state": state, **over}


def ok(data: Any, request_id: str | None = None) -> httpx.Response:
    headers = {} if request_id is None else {"x-request-id": request_id}
    body = {"success": True, "data": data, "meta": None}
    return httpx.Response(200, json=body, headers=headers)


def conflict(details: dict[str, Any] | None) -> httpx.Response:
    error = {"code": "CONFLICT", "message": "nope", "details": details, "request_id": "req_409"}
    return httpx.Response(409, json={"success": False, "data": None, "error": error})


def route(answers: dict[tuple[str, str], httpx.Response]) -> Handler:
    return lambda request: answers[(request.method, request.url.path)]


def sync_client(handler: Handler) -> Client:
    client = Client(BASE, KEY, max_retries=0)
    client._transport._http.close()
    client._transport._http = httpx.Client(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return client


def async_client(handler: Handler) -> AsyncClient:
    client = AsyncClient(BASE, KEY, max_retries=0)
    client._transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return client


def create_answering(answer: httpx.Response) -> Client:
    return sync_client(route({("POST", SANDBOXES): answer}))


# --- typed conflicts ----------------------------------------------------------------------


def test_409_name_taken_raises_name_taken_which_is_a_conflict() -> None:
    client = create_answering(conflict({"reason": "name_taken"}))

    with pytest.raises(NameTaken) as caught:
        client.create_sandbox(name="demo", wait=False)

    assert isinstance(caught.value, Conflict)
    assert (caught.value.code, caught.value.status_code) == ("CONFLICT", 409)
    assert caught.value.details["reason"] == "name_taken"
    assert caught.value.request_id == "req_409"


def test_409_name_taken_is_still_caught_by_except_conflict() -> None:
    client = create_answering(conflict({"reason": "name_taken"}))

    try:
        client.create_sandbox(name="demo", wait=False)
    except Conflict as exc:
        assert type(exc) is NameTaken
    else:
        pytest.fail("expected a Conflict")


def test_409_no_container_with_state_stopped_raises_no_container_with_state() -> None:
    client = create_answering(conflict({"reason": "no_container", "state": "stopped"}))

    with pytest.raises(NoContainer) as caught:
        client.create_sandbox(name="demo", wait=False)

    assert isinstance(caught.value, Conflict)
    assert caught.value.state == "stopped"


@pytest.mark.parametrize(
    "details", [{"reason": "no_container"}, {"reason": "no_container", "state": 7}]
)
def test_no_container_state_is_none_without_a_string_state(details: dict[str, Any]) -> None:
    client = create_answering(conflict(details))

    with pytest.raises(NoContainer) as caught:
        client.create_sandbox(name="demo", wait=False)

    assert caught.value.state is None


@pytest.mark.parametrize(
    "details", [{"reason": "already_exists"}, {"reason": "in_progress"}, {}, None]
)
def test_another_409_reason_stays_a_plain_conflict(details: dict[str, Any] | None) -> None:
    client = create_answering(conflict(details))

    with pytest.raises(Conflict) as caught:
        client.create_sandbox(name="demo", wait=False)

    assert type(caught.value) is Conflict


# --- get_sandbox ----------------------------------------------------------------------------


def test_get_sandbox_is_get() -> None:
    assert Client.get_sandbox is Client.get
    assert AsyncClient.get_sandbox is AsyncClient.get


def lookups() -> Handler:
    return route(
        {
            ("GET", ONE_SANDBOX): ok(sandbox_json()),
            ("GET", SANDBOXES): ok([sandbox_json()]),
        }
    )


def test_get_sandbox_returns_what_get_returns_by_id_and_by_name() -> None:
    client = sync_client(lookups())

    for ref in (SID, "demo"):
        assert client.get_sandbox(ref).info == client.get(ref).info


async def test_async_get_sandbox_returns_what_get_returns() -> None:
    client = async_client(lookups())

    for ref in (SID, "demo"):
        assert (await client.get_sandbox(ref)).info == (await client.get(ref)).info
    await client.aclose()


# --- the request id on a failed create ------------------------------------------------------


def failing_create(created_state: str = "creating") -> Handler:
    return route(
        {
            ("POST", SANDBOXES): ok(sandbox_json(created_state), "req_create"),
            ("GET", ONE_SANDBOX): ok(sandbox_json("error", error_reason="boom"), "req_poll"),
            ("DELETE", ONE_SANDBOX): ok(sandbox_json("destroying"), "req_delete"),
        }
    )


def test_failed_create_carries_the_request_id_of_the_reply_that_showed_the_failure() -> None:
    client = sync_client(failing_create())

    with pytest.raises(SandboxFailedError) as caught:
        client.create_sandbox(name="demo")

    assert caught.value.request_id == "req_poll"
    assert caught.value.deleted is True


def test_failed_create_whose_first_reply_is_already_failed_carries_that_reply_id() -> None:
    client = sync_client(failing_create(created_state="error"))

    with pytest.raises(SandboxFailedError) as caught:
        client.create_sandbox(name="demo")

    assert caught.value.request_id == "req_create"


async def test_async_failed_create_carries_the_request_id() -> None:
    client = async_client(failing_create())

    with pytest.raises(SandboxFailedError) as caught:
        await client.create_sandbox(name="demo")

    assert caught.value.request_id == "req_poll"
    assert caught.value.deleted is True
    await client.aclose()


def test_failed_create_without_a_request_id_header_leaves_it_none() -> None:
    handler = route(
        {
            ("POST", SANDBOXES): ok(sandbox_json("creating")),
            ("GET", ONE_SANDBOX): ok(sandbox_json("error")),
            ("DELETE", ONE_SANDBOX): ok(sandbox_json("destroying")),
        }
    )
    client = sync_client(handler)

    with pytest.raises(SandboxFailedError) as caught:
        client.create_sandbox(name="demo")

    assert caught.value.request_id is None
