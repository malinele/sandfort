"""SDK round 60: the webhooks facade (``client.webhooks``).

Covers every call's method, path, query and body, model parsing (the attempt history and
payloads that lack the newer fields), cursor paging, the secret kept out of reprs and sync/async
parity. The transport is an ``httpx.MockTransport``; no socket is opened.
"""

import json
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
from sandfort_sdk import (  # noqa: E402
    AsyncClient,
    AsyncWebhooks,
    Client,
    DeliveryAttempt,
    DeliveryPage,
    InvalidResponseError,
    NotFound,
    WebhookDelivery,
    WebhookEndpoint,
    Webhooks,
)
from sandfort_sdk._transport import AsyncTransport, SyncTransport, client_kwargs  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
TIMEOUT_S = 30.0
HOOKS = "/v1/webhooks"
SECRET = "whsec_super_secret_value"
T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
Handler = Callable[[httpx.Request], httpx.Response]


def envelope(data: Any, cursor: str | None = None, status: int = 200) -> httpx.Response:
    meta = None if cursor is None else {"next_cursor": cursor}
    body = {"success": True, "data": data, "error": None, "meta": meta}
    return httpx.Response(status, json=body)


def endpoint(n: int = 1, **extra: Any) -> dict[str, Any]:
    return {
        "id": f"whk_{n}",
        "url": "https://hooks.example.com/in",
        "enabled": True,
        "event_types": ["sandbox.*"],
        "failure_count": 2,
        "created_at": "2026-11-01T12:00:00+00:00",
        **extra,
    }


def delivery(n: int = 1, **extra: Any) -> dict[str, Any]:
    return {
        "id": f"whd_{n:03d}",
        "endpoint_id": "whk_1",
        "event_id": f"evt_{n}",
        "event_type": "sandbox.started",
        "state": "failed",
        "attempts": 2,
        "next_attempt_at": None,
        "last_status": 500,
        "last_error": "http 500",
        "payload_sha256": "ab" * 32,
        "attempt_history": [
            {
                "kind": "attempt",
                "attempted_at": "2026-11-01T12:00:00+00:00",
                "status": 503,
                "error": "http 503",
                "duration_ms": 41,
                "actor_id": None,
            },
            {
                "kind": "redelivered",
                "attempted_at": "2026-11-01T12:05:00+00:00",
                "status": None,
                "error": None,
                "duration_ms": None,
                "actor_id": "key_9",
            },
        ],
        "created_at": "2026-11-01T12:00:00+00:00",
        "updated_at": "2026-11-01T12:06:00+00:00",
        **extra,
    }


class Server:
    """Answers each request from a queue (the last answer repeats); records every request."""

    def __init__(self, *replies: httpx.Response) -> None:
        self.replies = list(replies)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]

    def params(self, index: int = -1) -> dict[str, str]:
        return dict(self.requests[index].url.params)

    def body(self, index: int = -1) -> Any:
        return json.loads(self.requests[index].content)


def sync_hooks(handler: Handler) -> Webhooks:
    transport = SyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    transport._http.close()
    transport._http = httpx.Client(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return Webhooks(transport)


def async_hooks(handler: Handler) -> AsyncWebhooks:
    transport = AsyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return AsyncWebhooks(transport)


# --- models ----------------------------------------------------------------------------------


def test_endpoint_parses_every_field() -> None:
    parsed = WebhookEndpoint.from_payload(endpoint())

    assert parsed.id == "whk_1" and parsed.url == "https://hooks.example.com/in"
    assert parsed.enabled is True and parsed.event_types == ("sandbox.*",)
    assert parsed.failure_count == 2 and parsed.created_at == T0
    assert parsed.secret is None


def test_endpoint_is_frozen() -> None:
    parsed = WebhookEndpoint.from_payload(endpoint())

    with pytest.raises(AttributeError):
        parsed.enabled = False  # type: ignore[misc]


def test_endpoint_with_only_the_old_fields_gets_defaults() -> None:
    parsed = WebhookEndpoint.from_payload({"id": "whk_1", "url": "https://x.example.com"})

    assert parsed.event_types == () and parsed.enabled is True
    assert parsed.failure_count == 0 and parsed.created_at is None and parsed.secret is None


def test_endpoint_missing_id_is_an_invalid_response() -> None:
    with pytest.raises(InvalidResponseError):
        WebhookEndpoint.from_payload({"url": "https://x.example.com"})


def test_endpoint_secret_is_kept_out_of_repr_and_str() -> None:
    parsed = WebhookEndpoint.from_payload(endpoint(secret=SECRET))

    assert parsed.secret == SECRET
    assert SECRET not in repr(parsed) and SECRET not in str(parsed)
    assert "whk_1" in repr(parsed)


def test_delivery_parses_every_field_and_the_attempt_history() -> None:
    parsed = WebhookDelivery.from_payload(delivery())

    assert parsed.id == "whd_001" and parsed.endpoint_id == "whk_1"
    assert parsed.event_id == "evt_1" and parsed.event_type == "sandbox.started"
    assert parsed.state == "failed" and parsed.attempts == 2
    assert parsed.next_attempt_at is None and parsed.last_status == 500
    assert parsed.last_error == "http 500" and parsed.payload_sha256 == "ab" * 32
    assert parsed.created_at == T0
    assert parsed.updated_at == datetime(2026, 11, 1, 12, 6, tzinfo=UTC)
    assert isinstance(parsed.attempt_history, tuple)
    first, marker = parsed.attempt_history
    assert isinstance(first, DeliveryAttempt)
    assert first.kind == "attempt" and first.attempted_at == T0
    assert first.status == 503 and first.error == "http 503" and first.duration_ms == 41
    assert first.actor_id is None
    assert marker.kind == "redelivered" and marker.actor_id == "key_9"
    assert marker.status is None and marker.duration_ms is None


def test_delivery_attempt_is_frozen() -> None:
    attempt = WebhookDelivery.from_payload(delivery()).attempt_history[0]

    with pytest.raises(AttributeError):
        attempt.status = 200  # type: ignore[misc]


def test_delivery_is_frozen() -> None:
    parsed = WebhookDelivery.from_payload(delivery())

    with pytest.raises(AttributeError):
        parsed.state = "delivered"  # type: ignore[misc]


def test_delivery_without_the_newer_fields_defaults_to_empty_or_none() -> None:
    old = {
        "id": "whd_001",
        "endpoint_id": "whk_1",
        "event_id": "evt_1",
        "state": "pending",
        "attempts": 0,
        "created_at": "2026-11-01T12:00:00+00:00",
    }

    parsed = WebhookDelivery.from_payload(old)

    assert parsed.event_type is None and parsed.payload_sha256 is None
    assert parsed.last_error is None and parsed.last_status is None
    assert parsed.attempt_history == () and parsed.next_attempt_at is None
    assert parsed.updated_at is None


def test_delivery_with_null_history_is_an_empty_tuple() -> None:
    parsed = WebhookDelivery.from_payload(delivery(attempt_history=None))

    assert parsed.attempt_history == ()


def test_delivery_attempt_entry_with_missing_keys_defaults_to_none() -> None:
    parsed = WebhookDelivery.from_payload(delivery(attempt_history=[{"status": 200}]))

    entry = parsed.attempt_history[0]
    assert entry.kind == "attempt" and entry.status == 200
    assert entry.attempted_at is None and entry.error is None and entry.duration_ms is None


def test_delivery_missing_its_id_is_an_invalid_response() -> None:
    payload = delivery()
    del payload["id"]

    with pytest.raises(InvalidResponseError):
        WebhookDelivery.from_payload(payload)


def test_delivery_history_that_is_not_a_list_is_an_invalid_response() -> None:
    with pytest.raises(InvalidResponseError):
        WebhookDelivery.from_payload(delivery(attempt_history="boom"))


def test_delivery_page_is_frozen_and_holds_the_cursor() -> None:
    page = DeliveryPage((WebhookDelivery.from_payload(delivery()),), "cur_1")

    assert page.next_cursor == "cur_1" and len(page.deliveries) == 1
    with pytest.raises(AttributeError):
        page.next_cursor = None  # type: ignore[misc]


# --- sync calls ------------------------------------------------------------------------------


def test_create_posts_url_and_event_types_and_returns_the_secret_once() -> None:
    server = Server(envelope(endpoint(secret=SECRET), status=201))

    created = sync_hooks(server).create("https://hooks.example.com/in", ["sandbox.*"])

    request = server.requests[0]
    assert request.method == "POST" and request.url.path == HOOKS
    assert server.body() == {"url": "https://hooks.example.com/in", "event_types": ["sandbox.*"]}
    assert created.secret == SECRET and SECRET not in repr(created)


def test_create_sends_enabled_only_when_given() -> None:
    server = Server(envelope(endpoint(enabled=False), status=201))

    sync_hooks(server).create("https://hooks.example.com/in", [], enabled=False)

    assert server.body() == {
        "url": "https://hooks.example.com/in",
        "event_types": [],
        "enabled": False,
    }


def test_create_refuses_an_empty_url_before_any_request() -> None:
    server = Server(envelope(endpoint()))

    with pytest.raises(ValueError, match="url"):
        sync_hooks(server).create("  ", ["sandbox.*"])
    assert server.requests == []


def test_list_gets_the_collection() -> None:
    server = Server(envelope([endpoint(1), endpoint(2)]))

    result = sync_hooks(server).list()

    request = server.requests[0]
    assert request.method == "GET" and request.url.path == HOOKS
    assert [e.id for e in result] == ["whk_1", "whk_2"] and isinstance(result, tuple)


def test_list_that_is_not_a_list_is_an_invalid_response() -> None:
    with pytest.raises(InvalidResponseError):
        sync_hooks(Server(envelope({"id": "whk_1"}))).list()


def test_get_reads_one_endpoint_and_encodes_the_id() -> None:
    server = Server(envelope(endpoint()))

    result = sync_hooks(server).get("whk_1")

    assert server.requests[0].method == "GET"
    assert server.requests[0].url.path == f"{HOOKS}/whk_1" and result.id == "whk_1"
    sync_hooks(server).get("a/b")
    assert server.requests[1].url.raw_path.decode().split("?")[0] == f"{HOOKS}/a%2Fb"


def test_update_patches_only_the_given_fields() -> None:
    server = Server(envelope(endpoint(enabled=False)))

    result = sync_hooks(server).update("whk_1", enabled=False)

    request = server.requests[0]
    assert request.method == "PATCH" and request.url.path == f"{HOOKS}/whk_1"
    assert server.body() == {"enabled": False} and result.enabled is False


def test_update_sends_url_and_events_together() -> None:
    server = Server(envelope(endpoint()))

    sync_hooks(server).update("whk_1", url="https://new.example.com", events=["a.b"])

    assert server.body() == {"url": "https://new.example.com", "event_types": ["a.b"]}


def test_update_with_nothing_to_change_is_refused_before_any_request() -> None:
    server = Server(envelope(endpoint()))

    with pytest.raises(ValueError, match="nothing to update"):
        sync_hooks(server).update("whk_1")
    assert server.requests == []


def test_delete_sends_delete_and_returns_the_removed_endpoint() -> None:
    server = Server(envelope(endpoint()))

    removed = sync_hooks(server).delete("whk_1")

    request = server.requests[0]
    assert request.method == "DELETE" and request.url.path == f"{HOOKS}/whk_1"
    assert removed.id == "whk_1"


def test_a_missing_endpoint_raises_not_found() -> None:
    error = {"success": False, "data": None, "error": {"code": "NOT_FOUND", "message": "gone"}}

    with pytest.raises(NotFound):
        sync_hooks(Server(httpx.Response(404, json=error))).get("whk_9")


def test_deliveries_default_query_is_just_the_limit() -> None:
    server = Server(envelope([delivery(1)], cursor="cur_1"))

    page = sync_hooks(server).deliveries("whk_1")

    request = server.requests[0]
    assert request.method == "GET" and request.url.path == f"{HOOKS}/whk_1/deliveries"
    assert server.params() == {"limit": "50"}
    assert isinstance(page, DeliveryPage) and page.next_cursor == "cur_1"
    assert page.deliveries[0].id == "whd_001"


def test_deliveries_sends_the_filters_the_cursor_and_the_limit() -> None:
    server = Server(envelope([]))

    page = sync_hooks(server).deliveries(
        "whk_1", event_type="sandbox.started", state="failed", cursor="cur_1", limit=7
    )

    assert server.params() == {
        "event_type": "sandbox.started",
        "state": "failed",
        "cursor": "cur_1",
        "limit": "7",
    }
    assert page.deliveries == () and page.next_cursor is None


@pytest.mark.parametrize("limit", [0, 101, True, 5.0])
def test_deliveries_refuses_a_bad_limit_before_any_request(limit: Any) -> None:
    server = Server(envelope([]))

    with pytest.raises(ValueError, match="limit"):
        sync_hooks(server).deliveries("whk_1", limit=limit)
    assert server.requests == []


def test_deliveries_refuses_an_unknown_state_before_any_request() -> None:
    server = Server(envelope([]))

    with pytest.raises(ValueError, match="state"):
        sync_hooks(server).deliveries("whk_1", state="exploded")
    assert server.requests == []


def test_deliveries_refuses_an_empty_event_type_and_cursor() -> None:
    server = Server(envelope([]))

    with pytest.raises(ValueError, match="event_type"):
        sync_hooks(server).deliveries("whk_1", event_type="")
    with pytest.raises(ValueError, match="cursor"):
        sync_hooks(server).deliveries("whk_1", cursor=" ")
    assert server.requests == []


def test_iter_deliveries_follows_cursors_and_keeps_the_filters() -> None:
    server = Server(
        envelope([delivery(1), delivery(2)], cursor="cur_1"),
        envelope([], cursor="cur_2"),  # a filtered scan may return an empty page with a cursor
        envelope([delivery(3)]),
    )

    items = list(
        sync_hooks(server).iter_deliveries(
            "whk_1", event_type="sandbox.started", state="failed", limit=2
        )
    )

    assert [d.id for d in items] == ["whd_001", "whd_002", "whd_003"]
    assert [r.url.params.get("cursor") for r in server.requests] == [None, "cur_1", "cur_2"]
    assert all(r.url.params["state"] == "failed" for r in server.requests)
    assert all(r.url.params["event_type"] == "sandbox.started" for r in server.requests)
    assert all(r.url.params["limit"] == "2" for r in server.requests)


def test_iter_deliveries_is_lazy() -> None:
    server = Server(envelope([delivery(1)], cursor="cur_1"), envelope([delivery(2)]))

    stream = sync_hooks(server).iter_deliveries("whk_1")
    assert server.requests == []
    next(stream)

    assert len(server.requests) == 1


def test_get_delivery_reads_one_delivery() -> None:
    server = Server(envelope(delivery(1)))

    result = sync_hooks(server).get_delivery("whk_1", "whd_001")

    request = server.requests[0]
    assert request.method == "GET"
    assert request.url.path == f"{HOOKS}/whk_1/deliveries/whd_001"
    assert result.attempt_history[0].status == 503


def test_redeliver_posts_without_a_body_and_returns_the_delivery() -> None:
    server = Server(envelope(delivery(1, state="pending", attempts=0)))

    result = sync_hooks(server).redeliver("whk_1", "whd_001")

    request = server.requests[0]
    assert request.method == "POST"
    assert request.url.path == f"{HOOKS}/whk_1/deliveries/whd_001/redeliver"
    assert request.content == b"" and result.state == "pending" and result.attempts == 0


# --- async parity ----------------------------------------------------------------------------


async def test_async_create_list_get_update_delete() -> None:
    server = Server(
        envelope(endpoint(secret=SECRET), status=201),
        envelope([endpoint(1)]),
        envelope(endpoint()),
        envelope(endpoint(enabled=False)),
        envelope(endpoint()),
    )
    hooks = async_hooks(server)

    created = await hooks.create("https://hooks.example.com/in", ["sandbox.*"], enabled=True)
    listed = await hooks.list()
    fetched = await hooks.get("whk_1")
    updated = await hooks.update("whk_1", enabled=False)
    removed = await hooks.delete("whk_1")

    calls = [(r.method, r.url.path) for r in server.requests]
    assert calls == [
        ("POST", HOOKS),
        ("GET", HOOKS),
        ("GET", f"{HOOKS}/whk_1"),
        ("PATCH", f"{HOOKS}/whk_1"),
        ("DELETE", f"{HOOKS}/whk_1"),
    ]
    assert server.body(0) == {
        "url": "https://hooks.example.com/in",
        "event_types": ["sandbox.*"],
        "enabled": True,
    }
    assert server.body(3) == {"enabled": False}
    assert created.secret == SECRET and SECRET not in repr(created)
    assert [e.id for e in listed] == ["whk_1"] and fetched.id == "whk_1"
    assert updated.enabled is False and removed.id == "whk_1"


async def test_async_deliveries_query_and_validation() -> None:
    server = Server(envelope([delivery(1)], cursor="cur_1"))
    hooks = async_hooks(server)

    page = await hooks.deliveries(
        "whk_1", event_type="a.b", state="disabled", cursor="c", limit=3
    )

    assert server.params() == {
        "event_type": "a.b",
        "state": "disabled",
        "cursor": "c",
        "limit": "3",
    }
    assert page.next_cursor == "cur_1" and page.deliveries[0].event_type == "sandbox.started"
    with pytest.raises(ValueError, match="limit"):
        await hooks.deliveries("whk_1", limit=0)
    with pytest.raises(ValueError, match="nothing to update"):
        await hooks.update("whk_1")
    assert len(server.requests) == 1


async def test_async_iter_deliveries_pages_and_redeliver_and_get_delivery() -> None:
    server = Server(
        envelope([delivery(1)], cursor="cur_1"),
        envelope([delivery(2)]),
        envelope(delivery(2)),
        envelope(delivery(2, state="pending")),
    )
    hooks = async_hooks(server)

    items = [d async for d in hooks.iter_deliveries("whk_1", state="failed")]
    one = await hooks.get_delivery("whk_1", "whd_002")
    again = await hooks.redeliver("whk_1", "whd_002")

    assert [d.id for d in items] == ["whd_001", "whd_002"]
    assert [r.url.params.get("cursor") for r in server.requests[:2]] == [None, "cur_1"]
    assert server.requests[2].url.path == f"{HOOKS}/whk_1/deliveries/whd_002"
    assert server.requests[3].method == "POST"
    assert server.requests[3].url.path.endswith("/deliveries/whd_002/redeliver")
    assert one.id == "whd_002" and again.state == "pending"


# --- the clients expose the facade -----------------------------------------------------------


def test_client_webhooks_property_is_the_sync_facade() -> None:
    client = Client(BASE, KEY)
    try:
        assert isinstance(client.webhooks, Webhooks)
        assert client.webhooks is client.webhooks
    finally:
        client.close()


async def test_async_client_webhooks_property_is_the_async_facade() -> None:
    client = AsyncClient(BASE, KEY)
    try:
        assert isinstance(client.webhooks, AsyncWebhooks)
    finally:
        await client.aclose()
