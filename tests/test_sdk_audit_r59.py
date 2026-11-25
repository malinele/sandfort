"""SDK round 59: the audit events facade (``client.audit``).

Covers query building, cursor paging that reuses ``order``, datetime and argument validation,
model parsing (a missing ``details`` key included) and the verify and export paths. The
transport is an ``httpx.MockTransport``; no socket is opened.
"""

import base64
import dataclasses
import json
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from sandfort_sdk import (  # noqa: E402
    AsyncAudit,
    AsyncClient,
    Audit,
    AuditEvent,
    AuditPage,
    AuditVerifyResult,
    Client,
    HeadVerification,
    InvalidResponseError,
    NotFound,
)
from sandfort_sdk._transport import (  # noqa: E402
    AsyncTransport,
    SyncTransport,
    client_kwargs,
)
from sandfort_sdk.models import require_int_range  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
TIMEOUT_S = 30.0
LIST_PATH = "/v1/audit-events"
VERIFY_PATH = "/v1/audit-events/verify"
EXPORT_PATH = "/v1/audit-events/export"
T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
NDJSON = '{"id": "aud_001"}\n{"id": "aud_002"}\n'
Handler = Callable[[httpx.Request], httpx.Response]


def envelope(data: Any, cursor: str | None = None) -> httpx.Response:
    meta = None if cursor is None else {"next_cursor": cursor}
    return httpx.Response(200, json={"success": True, "data": data, "error": None, "meta": meta})


def event(n: int, **extra: Any) -> dict[str, Any]:
    return {
        "id": f"aud_{n:03d}",
        "org_id": "org_1",
        "actor_type": "api_key",
        "actor_id": "key_1",
        "action": "sandbox.create",
        "target_type": "sandbox",
        "target_id": f"sbx_{n}",
        "outcome": "success",
        "request_id": f"req_{n}",
        "ip": "10.0.0.1",
        "user_agent": "pytest",
        "occurred_at": "2026-11-01T12:00:00+00:00",
        "details": {"n": n},
        **extra,
    }


VERIFY_OK = {
    "ok": True,
    "checked": 3,
    "first_id": "aud_001",
    "last_id": "aud_003",
    "last_hash": "abc",
    "findings": [],
    "findings_truncated": False,
}


def ndjson_reply(body: str = NDJSON) -> httpx.Response:
    headers = {"content-type": "application/x-ndjson"}
    return httpx.Response(200, content=body.encode(), headers=headers)


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


def sync_audit(handler: Handler) -> Audit:
    transport = SyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    transport._http.close()
    transport._http = httpx.Client(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return Audit(transport)


def async_audit(handler: Handler) -> AsyncAudit:
    transport = AsyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return AsyncAudit(transport)


# --- models ----------------------------------------------------------------------------------


def test_event_parses_every_field_and_the_timestamp() -> None:
    parsed = AuditEvent.from_payload(event(1))

    assert parsed.id == "aud_001" and parsed.org_id == "org_1"
    assert parsed.actor_type == "api_key" and parsed.actor_id == "key_1"
    assert parsed.action == "sandbox.create" and parsed.outcome == "success"
    assert parsed.target_type == "sandbox" and parsed.target_id == "sbx_1"
    assert parsed.request_id == "req_1" and parsed.ip == "10.0.0.1"
    assert parsed.user_agent == "pytest"
    assert parsed.occurred_at == T0 and parsed.details == {"n": 1}


def test_event_without_details_key_has_an_empty_mapping() -> None:
    payload = event(1)
    del payload["details"]

    parsed = AuditEvent.from_payload(payload)

    assert dict(parsed.details) == {}


def test_event_with_null_optionals_keeps_them_none() -> None:
    payload = event(1, actor_id=None, target_id=None, ip=None, request_id=None, details=None)

    parsed = AuditEvent.from_payload(payload)

    assert parsed.actor_id is None and parsed.target_id is None
    assert parsed.ip is None and parsed.request_id is None and dict(parsed.details) == {}


def test_event_is_frozen() -> None:
    parsed = AuditEvent.from_payload(event(1))

    with pytest.raises(AttributeError):
        parsed.action = "other"  # type: ignore[misc]


def test_event_missing_a_required_key_is_an_invalid_response() -> None:
    payload = event(1)
    del payload["action"]

    with pytest.raises(InvalidResponseError):
        AuditEvent.from_payload(payload)


def test_verify_result_parses_the_minimal_and_the_full_shape() -> None:
    minimal = AuditVerifyResult.from_payload(VERIFY_OK)
    full = AuditVerifyResult.from_payload(
        {
            **VERIFY_OK,
            "ok": False,
            "anchor_id": "aud_002",
            "acknowledged_findings": 2,
            "reanchored_by": "aud_009",
            "findings": [{"kind": "link_broken", "event_id": "aud_003", "detail": "x"}],
            "reanchor": {
                "event_id": "aud_009",
                "operator": "ops",
                "reason_code": "migration",
                "acknowledged_through": "aud_002",
                "findings": 2,
                "note": None,
                "occurred_at": "2026-11-01T12:00:00+00:00",
            },
        }
    )

    assert minimal.ok and minimal.checked == 3 and minimal.findings == ()
    assert minimal.anchor_id is None and minimal.acknowledged_findings == 0
    assert minimal.reanchor is None and minimal.reanchored_by is None
    assert not full.ok and full.anchor_id == "aud_002" and full.acknowledged_findings == 2
    assert full.findings[0].kind == "link_broken" and full.findings[0].event_id == "aud_003"
    assert full.reanchor is not None and full.reanchor.operator == "ops"
    assert full.reanchor.occurred_at == T0


def test_verify_result_for_an_empty_chain_has_no_ids() -> None:
    empty = {**VERIFY_OK, "checked": 0, "first_id": None, "last_id": None, "last_hash": None}

    parsed = AuditVerifyResult.from_payload(empty)

    assert parsed.first_id is None and parsed.last_id is None and parsed.last_hash is None


# --- list: query building --------------------------------------------------------------------


def test_list_defaults_send_order_and_limit_only() -> None:
    server = Server(envelope([event(1), event(2)]))

    page = sync_audit(server).list()

    assert isinstance(page, AuditPage) and page.next_cursor is None
    assert [e.id for e in page.events] == ["aud_001", "aud_002"]
    assert server.requests[0].method == "GET" and server.requests[0].url.path == LIST_PATH
    assert server.params() == {"order": "asc", "limit": "50"}


def test_list_sends_every_filter_and_isoformat_datetimes() -> None:
    server = Server(envelope([]))
    start = datetime(2026, 11, 1, 0, 0, tzinfo=UTC)
    end = datetime(2026, 11, 2, 1, 30, tzinfo=timezone(timedelta(hours=2)))

    sync_audit(server).list(
        actor_id="key_1", action="sandbox.create", target_id="sbx_1", request_id="req_1",
        outcome="denied", from_=start, to=end, order="desc", cursor="c1", limit=100,
    )  # fmt: skip

    assert server.params() == {
        "actor_id": "key_1", "action": "sandbox.create", "target_id": "sbx_1",
        "request_id": "req_1", "outcome": "denied", "from": start.isoformat(),
        "to": end.isoformat(), "order": "desc", "cursor": "c1", "limit": "100",
    }  # fmt: skip
    assert server.params()["to"].endswith("+02:00")


def test_list_returns_the_next_cursor_from_meta() -> None:
    server = Server(envelope([event(1)], cursor="next-1"))

    page = sync_audit(server).list()

    assert page.next_cursor == "next-1"


def test_list_rejects_naive_datetimes_before_any_request() -> None:
    server = Server(envelope([]))
    audit = sync_audit(server)

    with pytest.raises(ValueError, match="from_"):
        audit.list(from_=datetime(2026, 11, 1))
    with pytest.raises(ValueError, match="to"):
        audit.list(to=datetime(2026, 11, 1))
    assert server.requests == []


@pytest.mark.parametrize("name", ["actor_id", "action", "target_id", "request_id", "outcome"])
def test_list_rejects_empty_string_filters(name: str) -> None:
    server = Server(envelope([]))

    with pytest.raises(ValueError, match=name):
        sync_audit(server).list(**{name: ""})
    assert server.requests == []


@pytest.mark.parametrize("limit", [0, -1, 101, 1000])
def test_list_rejects_a_limit_outside_1_to_100(limit: int) -> None:
    server = Server(envelope([]))

    with pytest.raises(ValueError, match="limit"):
        sync_audit(server).list(limit=limit)
    assert server.requests == []


@pytest.mark.parametrize("limit", [1, 100])
def test_list_accepts_the_limit_bounds(limit: int) -> None:
    server = Server(envelope([]))

    sync_audit(server).list(limit=limit)

    assert server.params()["limit"] == str(limit)


@pytest.mark.parametrize("order", ["", "up", "ASC", "newest"])
def test_list_rejects_an_unknown_order(order: str) -> None:
    server = Server(envelope([]))

    with pytest.raises(ValueError, match="order"):
        sync_audit(server).list(order=order)  # type: ignore[arg-type]
    assert server.requests == []


def test_list_with_a_non_list_payload_is_an_invalid_response() -> None:
    with pytest.raises(InvalidResponseError):
        sync_audit(Server(envelope({"events": []}))).list()


# --- iter: paging ----------------------------------------------------------------------------


def test_iter_pages_until_the_cursor_is_none_and_reuses_order() -> None:
    server = Server(
        envelope([event(1), event(2)], cursor="c1"),
        envelope([event(3)], cursor="c2"),
        envelope([event(4)]),
    )

    events = list(sync_audit(server).iter(order="desc", action="sandbox.create", limit=2))

    assert [e.id for e in events] == ["aud_001", "aud_002", "aud_003", "aud_004"]
    assert len(server.requests) == 3
    assert [server.params(i).get("cursor") for i in range(3)] == [None, "c1", "c2"]
    assert all(server.params(i)["order"] == "desc" for i in range(3))
    assert all(server.params(i)["action"] == "sandbox.create" for i in range(3))
    assert all(server.params(i)["limit"] == "2" for i in range(3))


def test_iter_stops_after_one_page_without_a_cursor() -> None:
    server = Server(envelope([event(1)]))

    assert [e.id for e in sync_audit(server).iter()] == ["aud_001"]
    assert len(server.requests) == 1


def test_iter_is_lazy() -> None:
    server = Server(envelope([event(1)], cursor="c1"), envelope([event(2)]))

    iterator = sync_audit(server).iter()
    assert server.requests == []
    assert next(iterator).id == "aud_001"
    assert len(server.requests) == 1


def test_iter_rejects_bad_arguments() -> None:
    server = Server(envelope([]))

    with pytest.raises(ValueError, match="limit"):
        list(sync_audit(server).iter(limit=0))
    assert server.requests == []


async def test_async_list_and_iter_page_with_the_same_order() -> None:
    server = Server(envelope([event(1)], cursor="c1"), envelope([event(2)]))
    audit = async_audit(server)

    page = await audit.list(order="desc", outcome="error")
    assert page.next_cursor == "c1"
    assert server.params() == {"order": "desc", "outcome": "error", "limit": "50"}

    server.requests.clear()
    server.replies = [envelope([event(1)], cursor="c1"), envelope([event(2)])]
    events = [e async for e in audit.iter(order="desc")]

    assert [e.id for e in events] == ["aud_001", "aud_002"]
    assert [server.params(i).get("cursor") for i in range(2)] == [None, "c1"]
    assert all(server.params(i)["order"] == "desc" for i in range(2))


async def test_async_list_validates_before_any_request() -> None:
    server = Server(envelope([]))
    audit = async_audit(server)

    with pytest.raises(ValueError, match="from_"):
        await audit.list(from_=datetime(2026, 11, 1))
    with pytest.raises(ValueError, match="limit"):
        await audit.list(limit=101)
    with pytest.raises(ValueError, match="actor_id"):
        await audit.list(actor_id="")
    assert server.requests == []


# --- verify ----------------------------------------------------------------------------------


def test_verify_without_an_anchor_sends_no_query() -> None:
    server = Server(envelope(VERIFY_OK))

    result = sync_audit(server).verify()

    assert isinstance(result, AuditVerifyResult) and result.ok and result.checked == 3
    assert server.requests[0].url.path == VERIFY_PATH and server.params() == {}


def test_verify_sends_from_id() -> None:
    server = Server(envelope({**VERIFY_OK, "anchor_id": "aud_002"}))

    result = sync_audit(server).verify("aud_002")

    assert server.params() == {"from_id": "aud_002"} and result.anchor_id == "aud_002"


def test_verify_rejects_an_empty_from_id() -> None:
    server = Server(envelope(VERIFY_OK))

    with pytest.raises(ValueError, match="from_id"):
        sync_audit(server).verify("")
    assert server.requests == []


async def test_async_verify() -> None:
    server = Server(envelope(VERIFY_OK))
    audit = async_audit(server)

    result = await audit.verify(from_id="aud_001")

    assert result.ok and server.params() == {"from_id": "aud_001"}
    with pytest.raises(ValueError, match="from_id"):
        await audit.verify(from_id="")


# --- export ----------------------------------------------------------------------------------


def test_export_returns_the_raw_body_and_sends_filters() -> None:
    server = Server(ndjson_reply())
    start = datetime(2026, 11, 1, tzinfo=UTC)

    body = sync_audit(server).export(from_=start, request_id="req_1", outcome="denied")

    assert body == NDJSON
    assert server.requests[0].url.path == EXPORT_PATH
    assert server.params() == {
        "from": start.isoformat(), "request_id": "req_1", "outcome": "denied",
    }  # fmt: skip


def test_export_without_filters_sends_no_query() -> None:
    server = Server(ndjson_reply(""))

    assert sync_audit(server).export() == ""
    assert server.params() == {}


def test_export_validates_its_filters() -> None:
    server = Server(ndjson_reply())
    audit = sync_audit(server)

    with pytest.raises(ValueError, match="to"):
        audit.export(to=datetime(2026, 11, 1))
    with pytest.raises(ValueError, match="outcome"):
        audit.export(outcome="")
    assert server.requests == []


def test_export_raises_a_typed_error_for_an_error_status() -> None:
    error = {"code": "NOT_FOUND", "message": "gone"}
    reply = httpx.Response(404, json={"success": False, "data": None, "error": error})

    with pytest.raises(NotFound):
        sync_audit(Server(reply)).export()


async def test_async_export() -> None:
    server = Server(ndjson_reply())

    body = await async_audit(server).export(request_id="req_9")

    assert body == NDJSON and server.params() == {"request_id": "req_9"}


# --- wiring ----------------------------------------------------------------------------------


def test_client_exposes_audit() -> None:
    with Client(BASE, KEY) as client:
        assert isinstance(client.audit, Audit)
        assert client.audit is client.audit


async def test_async_client_exposes_audit() -> None:
    client = AsyncClient(BASE, KEY, max_retries=0)
    try:
        assert isinstance(client.audit, AsyncAudit)
        assert client.audit is client.audit
    finally:
        await client.aclose()


async def test_async_client_audit_list_and_verify_use_the_async_transport() -> None:
    server = Server(envelope([event(1)], cursor="c1"), envelope(VERIFY_OK))
    client = AsyncClient(BASE, KEY, max_retries=0)
    await client._transport._http.aclose()
    client._transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(server), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    try:
        page = await client.audit.list(limit=5)
        result = await client.audit.verify()
    finally:
        await client.aclose()

    assert [e.id for e in page.events] == ["aud_001"] and page.next_cursor == "c1"
    assert result.ok and result.checked == 3
    assert [r.url.path for r in server.requests] == [LIST_PATH, VERIFY_PATH]


# --- models: strict validation ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("id", 5),
        ("id", None),
        ("org_id", ["org_1"]),
        ("action", 1.5),
        ("actor_type", True),
        ("outcome", 3),
        ("outcome", True),
        ("occurred_at", "not-a-date"),
        ("occurred_at", 12345),
        ("occurred_at", None),
    ],
)
def test_event_with_a_wrongly_typed_field_is_an_invalid_response(key: str, value: Any) -> None:
    with pytest.raises(InvalidResponseError):
        AuditEvent.from_payload(event(1, **{key: value}))


def test_event_without_an_outcome_defaults_to_success() -> None:
    payload = event(1)
    del payload["outcome"]

    assert AuditEvent.from_payload(payload).outcome == "success"
    assert AuditEvent.from_payload(event(1, outcome=None)).outcome == "success"


@pytest.mark.parametrize("details", ["text", [1, 2], 7])
def test_event_with_non_object_details_is_an_invalid_response(details: Any) -> None:
    with pytest.raises(InvalidResponseError):
        AuditEvent.from_payload(event(1, details=details))


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("ok", 1),
        ("ok", "true"),
        ("ok", None),
        ("checked", "3"),
        ("checked", 3.0),
        ("checked", True),
        ("checked", None),
        ("findings_truncated", 0),
        ("findings_truncated", "no"),
        ("acknowledged_findings", "2"),
        ("acknowledged_findings", 2.5),
        ("acknowledged_findings", True),
        ("findings", {"kind": "x"}),
    ],
)
def test_verify_result_with_a_wrongly_typed_field_is_an_invalid_response(
    key: str, value: Any
) -> None:
    with pytest.raises(InvalidResponseError):
        AuditVerifyResult.from_payload({**VERIFY_OK, key: value})


def test_verify_result_treats_a_null_acknowledged_count_as_zero() -> None:
    parsed = AuditVerifyResult.from_payload({**VERIFY_OK, "acknowledged_findings": None})

    assert parsed.acknowledged_findings == 0


@pytest.mark.parametrize(
    "finding",
    [
        {"kind": 1, "event_id": "aud_1", "detail": "x"},
        {"kind": "link_broken", "event_id": None, "detail": "x"},
        {"kind": "link_broken", "event_id": "aud_1", "detail": ["x"]},
    ],
)
def test_verify_finding_with_a_wrongly_typed_field_is_an_invalid_response(
    finding: dict[str, Any],
) -> None:
    with pytest.raises(InvalidResponseError):
        AuditVerifyResult.from_payload({**VERIFY_OK, "findings": [finding]})


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("findings", True),
        ("findings", "2"),
        ("findings", 1.5),
        ("event_id", 9),
        ("acknowledged_through", None),
        ("occurred_at", "yesterday"),
    ],
)
def test_reanchor_with_a_wrongly_typed_field_is_an_invalid_response(key: str, value: Any) -> None:
    reanchor = {
        "event_id": "aud_009",
        "acknowledged_through": "aud_002",
        "findings": 2,
        "occurred_at": "2026-11-01T12:00:00+00:00",
        key: value,
    }

    with pytest.raises(InvalidResponseError):
        AuditVerifyResult.from_payload({**VERIFY_OK, "reanchor": reanchor})


# --- models: deeply read-only details --------------------------------------------------------


def test_event_details_are_read_only_at_the_top_level() -> None:
    parsed = AuditEvent.from_payload(event(1))

    with pytest.raises(TypeError):
        parsed.details["n"] = 2  # type: ignore[index]


def test_event_details_freeze_nested_mappings_and_lists() -> None:
    nested = {"a": {"b": [1, {"c": [2, 3]}]}, "tags": ["x", "y"]}

    parsed = AuditEvent.from_payload(event(1, details=nested))

    inner = parsed.details["a"]
    with pytest.raises(TypeError):
        inner["b"] = 0
    assert isinstance(inner["b"], tuple) and isinstance(inner["b"][1], type(inner))
    with pytest.raises(TypeError):
        inner["b"][1]["c"] = 0
    assert inner["b"][1]["c"] == (2, 3)
    assert parsed.details["tags"] == ("x", "y")
    assert not hasattr(parsed.details["tags"], "append")


def test_event_details_do_not_alias_the_payload() -> None:
    nested = {"a": {"b": [1]}}
    parsed = AuditEvent.from_payload(event(1, details=nested))

    nested["a"]["b"].append(2)
    nested["a"]["new"] = True

    assert parsed.details["a"]["b"] == (1,) and "new" not in parsed.details["a"]


# --- models: int-only range helper -----------------------------------------------------------


@pytest.mark.parametrize("value", [1, 50, 100])
def test_require_int_range_returns_an_int_in_range(value: int) -> None:
    assert require_int_range(value, "limit", 1, 100) == value


@pytest.mark.parametrize("value", [5.0, 1.0, "5", None, True, False, 0, -1, 101, [5]])
def test_require_int_range_rejects_non_ints_bools_and_out_of_range(value: Any) -> None:
    with pytest.raises(ValueError, match="limit"):
        require_int_range(value, "limit", 1, 100)


def test_require_int_range_message_names_the_bounds_and_the_value() -> None:
    with pytest.raises(ValueError, match=r"between 1 and 100.*5\.0"):
        require_int_range(5.0, "limit", 1, 100)


# --- signed head: auditor-side verification ---------------------------------------------------

HEAD_ROW_ID = "aud_003"
HEAD_HASH = "ab" * 32
STATUS_PATH = "/v1/status"
UNSIGNED_FIELDS = ("signature", "hmac")


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def public_text(private: Ed25519PrivateKey) -> str:
    raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return b64(raw)


def canonical(record: dict[str, Any]) -> bytes:
    body = {k: v for k, v in record.items() if k not in UNSIGNED_FIELDS}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def unsigned_head() -> dict[str, Any]:
    return {
        "type": "audit_head",
        "org_id": "org_1",
        "row_id": HEAD_ROW_ID,
        "hash": HEAD_HASH,
        "hmac": "cd" * 32,
    }


def signed_head(private: Ed25519PrivateKey, **extra: Any) -> dict[str, Any]:
    """A signed head with a valid ``signed_at`` unless ``extra`` overrides it."""
    record = {
        **unsigned_head(),
        "alg": "ed25519",
        "public_key": public_text(private),
        "signed_at": SIGNED_AT,
        **extra,
    }
    record["signature"] = b64(private.sign(canonical(record)))
    return record


def legacy_head(private: Ed25519PrivateKey, **extra: Any) -> dict[str, Any]:
    """A signed head without ``signed_at`` (what beta.60 to beta.64 servers wrote)."""
    record = {**unsigned_head(), "alg": "ed25519", "public_key": public_text(private), **extra}
    record["signature"] = b64(private.sign(canonical(record)))
    return record


def head_line(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def status_reply(**extra: Any) -> httpx.Response:
    body = {"status": "ok", "version": "0.1.0", "started_at": T0.isoformat(), **extra}
    return envelope(body)


SIGNED_AT = "2026-11-11T04:00:00+00:00"
SIGNED_AT_VALUE = datetime(2026, 11, 11, 4, 0, tzinfo=UTC)
AuditFactory = Callable[[Server], Audit | AsyncAudit]


@pytest.fixture
def private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture(params=["sync", "async"])
def audit_factory(request: pytest.FixtureRequest) -> AuditFactory:
    def build(server: Server) -> Audit | AsyncAudit:
        return sync_audit(server) if request.param == "sync" else async_audit(server)

    return build


@pytest.fixture
def head_audit(audit_factory: AuditFactory) -> Audit | AsyncAudit:
    return audit_factory(Server(status_reply()))


async def check(audit: Audit | AsyncAudit, line: Any, key: Any) -> HeadVerification:
    """``verify_head`` on either facade: the async one returns an awaitable."""
    result = audit.verify_head(line, key)
    return result if isinstance(result, HeadVerification) else await result


# --- signed head: the caller's key is the only trust anchor ------------------------------------


async def test_verify_head_with_the_given_key_accepts_a_signed_line(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey
) -> None:
    line = head_line(signed_head(private_key))

    result = await check(head_audit, line, public_text(private_key))

    expected = HeadVerification(
        True, HEAD_ROW_ID, HEAD_HASH, public_text(private_key), None, SIGNED_AT_VALUE, "org_1"
    )
    assert result == expected


async def test_verify_head_accepts_a_mapping_and_an_unpadded_key(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey
) -> None:
    record = signed_head(private_key)
    unpadded = public_text(private_key).rstrip("=")

    assert (await check(head_audit, record, public_text(private_key))).ok
    assert (await check(head_audit, record, unpadded)).ok


async def test_verify_head_accepts_raw_key_bytes(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey
) -> None:
    raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    result = await check(head_audit, signed_head(private_key), raw)

    assert result.ok and result.public_key == public_text(private_key)


async def test_verify_head_ignores_the_hmac_field(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey
) -> None:
    record = {**signed_head(private_key), "hmac": "00" * 32}

    assert (await check(head_audit, record, public_text(private_key))).ok


async def test_verify_head_accepts_a_signed_line_that_names_no_key(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey
) -> None:
    record = {**unsigned_head(), "alg": "ed25519", "signed_at": SIGNED_AT}
    record["signature"] = b64(private_key.sign(canonical(record)))

    result = await check(head_audit, record, public_text(private_key))

    assert result.ok and result.public_key == public_text(private_key)


def test_verify_head_requires_a_public_key(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey
) -> None:
    record = signed_head(private_key)

    with pytest.raises(TypeError):
        head_audit.verify_head(record)  # type: ignore[call-arg]


@pytest.mark.parametrize("missing", [None, ""])
async def test_verify_head_with_no_key_value_raises_value_error(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey, missing: Any
) -> None:
    with pytest.raises(ValueError, match="public key"):
        await check(head_audit, signed_head(private_key), missing)


async def test_forged_head_signed_and_keyed_by_the_attacker_is_refused(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey
) -> None:
    attacker = Ed25519PrivateKey.generate()
    forged = signed_head(attacker, hash="ef" * 32)
    trusted = public_text(private_key)

    result = await check(head_audit, head_line(forged), trusted)

    assert not result.ok and result.reason == "key_mismatch"
    assert result.public_key == trusted
    assert result.public_key != public_text(attacker)


async def test_head_naming_another_key_than_the_callers_is_a_key_mismatch(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey
) -> None:
    other = public_text(Ed25519PrivateKey.generate())

    result = await check(head_audit, head_line(signed_head(private_key)), other)

    assert not result.ok and result.reason == "key_mismatch"
    assert result.public_key == other
    assert result.row_id == HEAD_ROW_ID and result.entry_hash == HEAD_HASH


async def test_unnamed_wrong_key_fails_on_the_signature(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey
) -> None:
    record = {**unsigned_head(), "alg": "ed25519", "signed_at": SIGNED_AT}
    record["signature"] = b64(private_key.sign(canonical(record)))
    other = public_text(Ed25519PrivateKey.generate())

    result = await check(head_audit, record, other)

    assert not result.ok and result.reason == "signature"


async def test_swapped_own_key_is_a_key_mismatch_against_the_trusted_key(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey
) -> None:
    attacker = Ed25519PrivateKey.generate()
    record = {**signed_head(private_key), "public_key": public_text(attacker)}

    result = await check(head_audit, record, public_text(private_key))

    assert not result.ok and result.reason == "key_mismatch"


async def test_malformed_own_key_is_a_key_mismatch(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey
) -> None:
    record = {**signed_head(private_key), "public_key": "not a key"}

    result = await check(head_audit, record, public_text(private_key))

    assert not result.ok and result.reason == "key_mismatch"


@pytest.mark.parametrize(
    ("field", "value"),
    [("hash", "ef" * 32), ("row_id", "aud_999"), ("org_id", "org_2"), ("extra", "added")],
)
async def test_tampered_line_fails_on_the_signature(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey, field: str, value: str
) -> None:
    record = {**signed_head(private_key), field: value}

    result = await check(head_audit, head_line(record), public_text(private_key))

    assert not result.ok and result.reason == "signature"


@pytest.mark.parametrize("bad_signature", ["not base64 !!", "AAAA", 7])
async def test_bad_signature_value_fails_without_raising(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey, bad_signature: Any
) -> None:
    record = {**signed_head(private_key), "signature": bad_signature}

    result = await check(head_audit, record, public_text(private_key))

    assert not result.ok and result.reason == "signature"


async def test_unsupported_algorithm_fails_on_the_signature(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey
) -> None:
    record = signed_head(private_key, alg="rsa")

    result = await check(head_audit, record, public_text(private_key))

    assert result.reason == "signature"


async def test_unsigned_line_is_reported_as_unsigned(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey
) -> None:
    key = public_text(private_key)

    result = await check(head_audit, head_line(unsigned_head()), key)

    assert result == HeadVerification(
        False, HEAD_ROW_ID, HEAD_HASH, key, "unsigned", None, "org_1"
    )


@pytest.mark.parametrize(
    "line",
    [
        "",
        "not json",
        "[1, 2]",
        '"audit_head"',
        '{"type": "export_summary", "rows": 2, "filters": []}',
        '{"type": "audit_head", "org_id": "org_1", "hash": "abc"}',
        '{"type": "audit_head", "org_id": "org_1", "row_id": "aud_1", "hash": 5}',
        '{"type": "audit_head", "org_id": "org_1", "row_id": "", "hash": "abc"}',
    ],
)
async def test_malformed_line_raises_value_error(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey, line: str
) -> None:
    with pytest.raises(ValueError, match="audit_head|JSON|object|row_id|hash"):
        await check(head_audit, line, public_text(private_key))


@pytest.mark.parametrize("record", [None, 5, ["x"], {"type": "audit_head", "bad": object()}])
async def test_non_line_value_raises_value_error(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey, record: Any
) -> None:
    with pytest.raises(ValueError):
        await check(head_audit, record, public_text(private_key))


@pytest.mark.parametrize("key", ["short", "!!!!", b64(b"\x01" * 31), b64(b"\x01" * 33)])
async def test_malformed_key_argument_raises_value_error(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey, key: str
) -> None:
    with pytest.raises(ValueError, match="public key"):
        await check(head_audit, signed_head(private_key), key)


# --- signed head: the trusted key on every outcome, and signed_at --------------------------------


def test_head_verification_has_no_anchored_field() -> None:
    names = [field.name for field in dataclasses.fields(HeadVerification)]

    assert names == ["ok", "row_id", "entry_hash", "public_key", "reason", "signed_at", "org_id"]


async def test_public_key_is_the_trusted_key_on_every_outcome(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey
) -> None:
    key = public_text(private_key)
    forged = signed_head(Ed25519PrivateKey.generate())

    outcomes = [
        await check(head_audit, signed_head(private_key), key),
        await check(head_audit, forged, key),
        await check(head_audit, unsigned_head(), key),
        await check(head_audit, legacy_head(private_key), key),
    ]

    assert [r.ok for r in outcomes] == [True, False, False, False]
    assert all(r.public_key == key for r in outcomes)


# --- signed head: a head without a valid signed_at is undated ------------------------------------


async def test_signed_head_without_signed_at_verifies_but_is_undated(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey
) -> None:
    key = public_text(private_key)

    result = await check(head_audit, head_line(legacy_head(private_key)), key)

    expected = HeadVerification(False, HEAD_ROW_ID, HEAD_HASH, key, "undated", None, "org_1")
    assert result == expected


@pytest.mark.parametrize("value", ["yesterday", "2026-11-11T04:00:00", 5, "", None])
async def test_signed_head_with_an_invalid_signed_at_is_undated(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey, value: Any
) -> None:
    record = signed_head(private_key, signed_at=value)

    result = await check(head_audit, record, public_text(private_key))

    assert not result.ok and result.reason == "undated" and result.signed_at is None


async def test_undated_needs_a_valid_signature_first(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey
) -> None:
    key = public_text(private_key)
    tampered = {**legacy_head(private_key), "hash": "ef" * 32}
    other_key = public_text(Ed25519PrivateKey.generate())

    assert (await check(head_audit, tampered, key)).reason == "signature"
    assert (await check(head_audit, legacy_head(private_key), other_key)).reason == "key_mismatch"
    assert (await check(head_audit, unsigned_head(), key)).reason == "unsigned"


async def test_undated_head_over_the_status_key_is_also_refused(
    audit_factory: AuditFactory, private_key: Ed25519PrivateKey
) -> None:
    server = Server(status_reply(audit_public_key=public_text(private_key)))

    result = await check(audit_factory(server), legacy_head(private_key), "status")

    assert not result.ok and result.reason == "undated"
    assert result.row_id == HEAD_ROW_ID and result.entry_hash == HEAD_HASH


def test_package_verify_head_reports_undated(private_key: Ed25519PrivateKey) -> None:
    import sandfort_sdk
    from sandfort_sdk import audit_head

    result = sandfort_sdk.verify_head(legacy_head(private_key), public_text(private_key))

    assert not result.ok and result.reason == audit_head.REASON_UNDATED == "undated"


def test_docstrings_document_the_undated_class_and_the_dropped_field() -> None:
    from sandfort_sdk import audit_head

    text = " ".join((audit_head.__doc__ or "", HeadVerification.__doc__ or ""))
    text += " " + (audit_head.verify_head.__doc__ or "")

    assert "undated" in text and "beta.60" in text and "beta.64" in text
    assert "anchored" in text  # says the field was removed, so release notes can quote it


def test_both_verify_head_docstrings_state_the_contract() -> None:
    for method in (Audit.verify_head, AsyncAudit.verify_head):
        doc = " ".join((method.__doc__ or "").split())
        assert "public_key" in doc and "no default" in doc, method
    async_doc = " ".join((AsyncAudit.verify_head.__doc__ or "").split())
    assert "coroutine" in async_doc and "await" in async_doc


async def test_signed_at_is_parsed_when_the_head_carries_it(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey
) -> None:
    record = signed_head(private_key, signed_at=SIGNED_AT)

    result = await check(head_audit, head_line(record), public_text(private_key))

    assert result.ok and result.signed_at == SIGNED_AT_VALUE


async def test_signed_at_accepts_a_z_suffix_and_an_offset(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey
) -> None:
    key = public_text(private_key)
    zulu = signed_head(private_key, signed_at="2026-11-11T04:00:00Z")
    offset = signed_head(private_key, signed_at="2026-11-11T06:00:00+02:00")

    assert (await check(head_audit, zulu, key)).signed_at == SIGNED_AT_VALUE
    assert (await check(head_audit, offset, key)).signed_at == SIGNED_AT_VALUE


async def test_signed_at_is_none_when_absent_and_the_head_is_not_ok(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey
) -> None:
    result = await check(head_audit, legacy_head(private_key), public_text(private_key))

    assert not result.ok and result.signed_at is None


async def test_signed_at_is_covered_by_the_signature(
    head_audit: Audit | AsyncAudit, private_key: Ed25519PrivateKey
) -> None:
    signed = signed_head(private_key, signed_at=SIGNED_AT)
    record = {**signed, "signed_at": "2026-12-01T00:00:00Z"}

    result = await check(head_audit, record, public_text(private_key))

    assert not result.ok and result.reason == "signature"


def test_head_verification_is_frozen() -> None:
    result = HeadVerification(True, "aud_1", "abc", "key", None, SIGNED_AT_VALUE)

    with pytest.raises(AttributeError):
        result.ok = False  # type: ignore[misc]


def test_head_verification_is_exported_from_the_package() -> None:
    import sandfort_sdk

    assert sandfort_sdk.HeadVerification is HeadVerification
    assert "HeadVerification" in sandfort_sdk.__all__
    assert "verify_head" in sandfort_sdk.__all__


def test_package_verify_head_needs_a_key_and_checks_it(private_key: Ed25519PrivateKey) -> None:
    import sandfort_sdk

    record = signed_head(private_key)

    assert sandfort_sdk.verify_head(record, public_text(private_key)).ok
    forged = signed_head(Ed25519PrivateKey.generate())
    assert sandfort_sdk.verify_head(forged, public_text(private_key)).reason == "key_mismatch"
    with pytest.raises(TypeError):
        sandfort_sdk.verify_head(record)  # type: ignore[call-arg]


# --- signed head: the status route as the trust anchor -----------------------------------------


async def test_status_key_is_fetched_from_the_status_route_and_anchors_the_check(
    audit_factory: AuditFactory, private_key: Ed25519PrivateKey
) -> None:
    server = Server(status_reply(audit_public_key=public_text(private_key)))
    audit = audit_factory(server)

    result = await check(audit, head_line(signed_head(private_key)), "status")

    expected = HeadVerification(
        True, HEAD_ROW_ID, HEAD_HASH, public_text(private_key), None, SIGNED_AT_VALUE, "org_1"
    )
    assert result == expected
    assert [r.url.path for r in server.requests] == [STATUS_PATH]


async def test_status_key_refuses_a_head_forged_with_its_own_key(
    audit_factory: AuditFactory, private_key: Ed25519PrivateKey
) -> None:
    server = Server(status_reply(audit_public_key=public_text(private_key)))
    forged = signed_head(Ed25519PrivateKey.generate(), hash="ef" * 32)

    result = await check(audit_factory(server), head_line(forged), "status")

    assert not result.ok and result.reason == "key_mismatch"
    assert result.public_key == public_text(private_key)


async def test_status_without_a_published_key_raises_value_error(
    audit_factory: AuditFactory, private_key: Ed25519PrivateKey
) -> None:
    audit = audit_factory(Server(status_reply(audit_public_key=None)))

    with pytest.raises(ValueError, match="audit_public_key"):
        await check(audit, signed_head(private_key), "status")


async def test_an_explicit_key_makes_no_request(
    audit_factory: AuditFactory, private_key: Ed25519PrivateKey
) -> None:
    server = Server(status_reply())

    await check(audit_factory(server), signed_head(private_key), public_text(private_key))

    assert server.requests == []


async def test_a_bad_line_is_rejected_before_the_status_request(
    audit_factory: AuditFactory,
) -> None:
    server = Server(status_reply(audit_public_key=b64(b"\x01" * 32)))

    with pytest.raises(ValueError, match="JSON"):
        await check(audit_factory(server), "not json", "status")
    assert server.requests == []


# --- signed head: public key from the status route ---------------------------------------------


def test_public_key_reads_audit_public_key_from_the_status_route(
    private_key: Ed25519PrivateKey,
) -> None:
    server = Server(status_reply(audit_public_key=public_text(private_key)))

    key = sync_audit(server).public_key()

    assert key == public_text(private_key)
    assert server.requests[0].method == "GET" and server.requests[0].url.path == STATUS_PATH


def test_public_key_is_none_when_unset_or_absent() -> None:
    assert sync_audit(Server(status_reply(audit_public_key=None))).public_key() is None
    assert sync_audit(Server(status_reply())).public_key() is None


def test_public_key_that_is_not_a_string_is_an_invalid_response() -> None:
    with pytest.raises(InvalidResponseError):
        sync_audit(Server(status_reply(audit_public_key=5))).public_key()


def test_public_key_from_a_non_object_status_is_an_invalid_response() -> None:
    with pytest.raises(InvalidResponseError):
        sync_audit(Server(envelope(["x"]))).public_key()


async def test_async_public_key_reads_the_status_route(private_key: Ed25519PrivateKey) -> None:
    server = Server(status_reply(audit_public_key=public_text(private_key)))

    key = await async_audit(server).public_key()

    assert key == public_text(private_key)
    assert server.requests[0].url.path == STATUS_PATH


async def test_async_public_key_is_none_when_unset() -> None:
    assert await async_audit(Server(status_reply(audit_public_key=None))).public_key() is None


async def test_async_public_key_feeds_verify_head(private_key: Ed25519PrivateKey) -> None:
    audit = async_audit(Server(status_reply(audit_public_key=public_text(private_key))))
    key = await audit.public_key()

    assert key is not None
    assert (await audit.verify_head(signed_head(private_key), key)).ok


