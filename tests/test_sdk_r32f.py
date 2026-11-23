"""SDK r32f: the NotFound of a get by name carries the request id of the list reply that
showed no match (sync, async, ``get_sandbox``); a get by id keeps its own request id."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
from sandfort_sdk import NotFound  # noqa: E402

from test_sdk_r30 import (  # noqa: E402
    ONE_SANDBOX,
    SANDBOXES,
    SID,
    Router,
    async_client,
    gone,
    listing,
    sandbox_json,
    sync_client,
)

LIST_REQUEST_ID = "req_list_0001"
LAST_PAGE_REQUEST_ID = "req_list_0002"
GET_REQUEST_ID = "req_get_0001"
MISSING = "missing-name"


def with_request_id(response: httpx.Response, request_id: str) -> httpx.Response:
    """The same reply with an ``x-request-id`` header, as the server sets it."""
    return httpx.Response(
        response.status_code, content=response.content, headers={"x-request-id": request_id}
    )


def empty_listing(request_id: str = LIST_REQUEST_ID) -> httpx.Response:
    return with_request_id(listing(), request_id)


def two_pages_without_a_match() -> Router:
    """Two pages, none called ``MISSING``; the second (last) reply has its own request id."""
    first = httpx.Response(
        200,
        json={"success": True, "data": [sandbox_json()], "meta": {"next_cursor": "c1"}},
        headers={"x-request-id": LIST_REQUEST_ID},
    )
    last = with_request_id(listing(sandbox_json(name="other")), LAST_PAGE_REQUEST_ID)
    return Router({("GET", SANDBOXES): [first, last]})


# --- by-name get -------------------------------------------------------------------------


def test_get_by_name_not_found_carries_the_list_reply_request_id() -> None:
    client, _ = sync_client(Router({("GET", SANDBOXES): empty_listing()}))

    with pytest.raises(NotFound) as caught:
        client.get(MISSING)

    assert caught.value.request_id == LIST_REQUEST_ID
    assert caught.value.status_code == 404
    assert caught.value.message == f"no sandbox named '{MISSING}'"
    assert str(caught.value) == f"no sandbox named '{MISSING}' (request id {LIST_REQUEST_ID})"


def test_get_sandbox_by_name_not_found_carries_the_list_reply_request_id() -> None:
    client, _ = sync_client(Router({("GET", SANDBOXES): empty_listing()}))

    with pytest.raises(NotFound) as caught:
        client.get_sandbox(MISSING)

    assert caught.value.request_id == LIST_REQUEST_ID
    assert caught.value.message == f"no sandbox named '{MISSING}'"
    assert str(caught.value) == f"no sandbox named '{MISSING}' (request id {LIST_REQUEST_ID})"


def test_get_by_name_over_several_pages_uses_the_last_reply_request_id() -> None:
    router = two_pages_without_a_match()
    client, _ = sync_client(router)

    with pytest.raises(NotFound) as caught:
        client.get(MISSING)

    assert caught.value.request_id == LAST_PAGE_REQUEST_ID
    assert router.seen("GET", SANDBOXES)[1].url.params["cursor"] == "c1"


def test_get_by_name_not_found_without_a_request_id_header_is_none() -> None:
    client, _ = sync_client(Router({("GET", SANDBOXES): listing()}))

    with pytest.raises(NotFound) as caught:
        client.get(MISSING)

    assert caught.value.request_id is None


def test_get_by_name_still_finds_a_live_sandbox() -> None:
    reply = with_request_id(listing(sandbox_json(name=MISSING)), LIST_REQUEST_ID)
    client, _ = sync_client(Router({("GET", SANDBOXES): reply}))

    assert client.get(MISSING).id == SID


async def test_async_get_by_name_not_found_carries_the_list_reply_request_id() -> None:
    client, _ = await async_client(Router({("GET", SANDBOXES): empty_listing()}))

    with pytest.raises(NotFound) as caught:
        await client.get(MISSING)

    assert caught.value.request_id == LIST_REQUEST_ID
    assert caught.value.message == f"no sandbox named '{MISSING}'"
    assert str(caught.value) == f"no sandbox named '{MISSING}' (request id {LIST_REQUEST_ID})"
    await client.aclose()


async def test_async_get_sandbox_by_name_not_found_carries_the_list_reply_request_id() -> None:
    client, _ = await async_client(Router({("GET", SANDBOXES): empty_listing()}))

    with pytest.raises(NotFound) as caught:
        await client.get_sandbox(MISSING)

    assert caught.value.request_id == LIST_REQUEST_ID
    await client.aclose()


async def test_async_get_by_name_over_several_pages_uses_the_last_reply_request_id() -> None:
    client, _ = await async_client(two_pages_without_a_match())

    with pytest.raises(NotFound) as caught:
        await client.get(MISSING)

    assert caught.value.request_id == LAST_PAGE_REQUEST_ID
    await client.aclose()


# --- get by id keeps its request id ------------------------------------------------------


def not_found_by_id() -> Router:
    body = {
        "success": False,
        "data": None,
        "error": {"code": "NOT_FOUND", "message": "no such sandbox", "request_id": GET_REQUEST_ID},
        "meta": None,
    }
    return Router({("GET", ONE_SANDBOX): httpx.Response(404, json=body)})


def test_get_by_id_not_found_keeps_the_server_request_id() -> None:
    client, _ = sync_client(not_found_by_id())

    with pytest.raises(NotFound) as caught:
        client.get(SID)

    assert caught.value.request_id == GET_REQUEST_ID


async def test_async_get_by_id_not_found_keeps_the_server_request_id() -> None:
    client, _ = await async_client(not_found_by_id())

    with pytest.raises(NotFound) as caught:
        await client.get(SID)

    assert caught.value.request_id == GET_REQUEST_ID
    await client.aclose()


def test_get_by_id_does_not_list() -> None:
    router = Router({("GET", ONE_SANDBOX): gone()})
    client, _ = sync_client(router)

    client.get(SID)

    assert router.seen("GET", SANDBOXES) == []
