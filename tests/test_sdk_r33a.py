"""SDK r33a: a typed ``SortOrder``, ``SandboxTimeoutError.deleted``, ``Sandbox.updated_at``."""

import sys
import typing
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
import sandfort_sdk  # noqa: E402
from sandfort_sdk import AsyncClient, Client, SandboxTimeoutError, SortOrder  # noqa: E402
from sandfort_sdk._transport import client_kwargs  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
TIMEOUT_S = 30.0
WAIT_S = 2.0
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
OTHER = "sbx_01HYYYYYYYYYYYYYYYYYYYYYYY"
UPDATED = "2026-11-06T11:22:33+00:00"

Handler = Callable[[httpx.Request], httpx.Response]


def sandbox_json(sid: str = SID, *, age_s: float = 0.0, **over: Any) -> dict[str, Any]:
    created = (datetime.now(UTC) - timedelta(seconds=age_s)).isoformat()
    return {"id": sid, "name": "demo", "state": "pending", "created_at": created, **over}


def ok(data: Any) -> httpx.Response:
    return httpx.Response(200, json={"success": True, "data": data, "meta": None})


def timeout_api(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> Handler:
    """The create POST times out; the by-name lookups answer ``before`` then ``after``."""
    lookups = [before, after]

    def handle(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            raise httpx.ReadTimeout("the create is still running")
        if request.method == "DELETE":
            return ok(sandbox_json(state="destroying"))
        return ok(lookups.pop(0) if len(lookups) > 1 else lookups[0])

    return handle


def sync_client(handler: Handler) -> Client:
    client = Client(BASE, KEY)
    client._transport._http.close()
    client._transport._http = httpx.Client(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return client


async def async_client(handler: Handler) -> AsyncClient:
    client = AsyncClient(BASE, KEY)
    await client._transport._http.aclose()
    client._transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return client


# --- SortOrder ----------------------------------------------------------------------------


def test_sort_order_is_exported_and_is_a_literal_of_asc_and_desc() -> None:
    assert "SortOrder" in sandfort_sdk.__all__
    assert typing.get_origin(SortOrder) is Literal
    assert typing.get_args(SortOrder) == ("asc", "desc")


@pytest.mark.parametrize("owner", [Client, AsyncClient])
@pytest.mark.parametrize("method", ["list_sandboxes", "iter_sandboxes"])
def test_the_order_keyword_is_annotated_with_sort_order(owner: type, method: str) -> None:
    hints = typing.get_type_hints(getattr(owner, method))

    assert hints["order"] == SortOrder | None


def test_order_is_sent_as_given() -> None:
    seen: list[str | None] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.params.get("order"))
        return ok([])

    sync_client(handle).list_sandboxes(order="desc")

    assert seen == ["desc"]


# --- SandboxTimeoutError.deleted ----------------------------------------------------------


def test_a_timeout_whose_cleanup_deleted_the_sandbox_says_deleted_true() -> None:
    handler = timeout_api([], [sandbox_json()])

    with pytest.raises(SandboxTimeoutError) as caught:
        sync_client(handler).create_sandbox(name="demo", wait_timeout_s=WAIT_S)

    assert caught.value.deleted is True
    assert caught.value.sandbox_id == SID
    assert "was deleted" in str(caught.value)


def test_a_timeout_with_the_name_held_before_says_deleted_false() -> None:
    held = [sandbox_json(OTHER, age_s=5)]
    handler = timeout_api(held, held)

    with pytest.raises(SandboxTimeoutError) as caught:
        sync_client(handler).create_sandbox(name="demo", wait_timeout_s=WAIT_S)

    assert caught.value.deleted is False
    assert "was deleted" not in str(caught.value)


async def test_async_timeout_reports_deleted_true_and_false() -> None:
    client = await async_client(timeout_api([], [sandbox_json()]))
    with pytest.raises(SandboxTimeoutError) as cleaned:
        await client.create_sandbox(name="demo", wait_timeout_s=WAIT_S)
    await client.aclose()

    held = [sandbox_json(OTHER, age_s=5)]
    client = await async_client(timeout_api(held, held))
    with pytest.raises(SandboxTimeoutError) as left:
        await client.create_sandbox(name="demo", wait_timeout_s=WAIT_S)
    await client.aclose()

    assert (cleaned.value.deleted, left.value.deleted) == (True, False)


def test_existing_constructor_calls_keep_working() -> None:
    plain = SandboxTimeoutError("late")
    named = SandboxTimeoutError("late", sandbox_id=SID, state="pending")

    assert (plain.deleted, named.deleted) == (False, False)
    assert (named.sandbox_id, named.state) == (SID, "pending")


# --- Sandbox.updated_at -------------------------------------------------------------------


def listing(**over: Any) -> Handler:
    return lambda _request: ok([sandbox_json(**over)])


def test_the_handle_updated_at_equals_info_updated_at() -> None:
    handle = sync_client(listing(updated_at=UPDATED)).list_sandboxes().items[0]

    assert handle.updated_at == handle.info.updated_at
    assert handle.updated_at == datetime.fromisoformat(UPDATED)


def test_the_handle_updated_at_is_none_while_the_server_omits_it() -> None:
    handle = sync_client(listing()).list_sandboxes().items[0]

    assert handle.updated_at is None
    assert handle.updated_at == handle.info.updated_at


async def test_the_async_handle_updated_at_equals_info_updated_at() -> None:
    client = await async_client(listing(updated_at=UPDATED))
    handle = (await client.list_sandboxes()).items[0]
    await client.aclose()

    assert handle.updated_at == handle.info.updated_at
    assert handle.updated_at == datetime.fromisoformat(UPDATED)
