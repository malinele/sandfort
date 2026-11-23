"""Value objects of the webhook endpoints and their deliveries.

Parsing is lenient about the fields that were added over time: a payload without them (an
older server) gives ``None``, ``0`` or an empty tuple. Only the identifying keys are required.
The signing secret is present on the answer of ``create`` only and never appears in a repr.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sandfort_sdk.models import (
    _as_dict,
    _as_list,
    _bool,
    _int,
    _optional_str,
    _required,
    _str,
    _timestamp,
)

ATTEMPT_KIND = "attempt"


def _optional_int(value: Any, what: str) -> int | None:
    return None if value is None else _int(value, what)


def _event_types(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    return tuple(_str(item, "webhook event type") for item in _as_list(value, "event types"))


@dataclass(frozen=True, slots=True)
class DeliveryAttempt:
    """One entry of a delivery's history: an attempt, or a ``redelivered`` marker."""

    kind: str = ATTEMPT_KIND
    attempted_at: datetime | None = None
    status: int | None = None  # HTTP status the endpoint answered; None when none came back
    error: str | None = None  # short sanitised reason (``http 503``, a transport reason)
    duration_ms: int | None = None
    actor_id: str | None = None  # the API key that requeued the delivery (markers only)

    @classmethod
    def from_payload(cls, data: Any) -> "DeliveryAttempt":
        raw = _as_dict(data, "delivery attempt")
        kind = _optional_str(raw.get("kind"), "delivery attempt kind")
        return cls(
            kind=kind or ATTEMPT_KIND,
            attempted_at=_timestamp(raw.get("attempted_at"), "delivery attempt"),
            status=_optional_int(raw.get("status"), "delivery attempt status"),
            error=_optional_str(raw.get("error"), "delivery attempt error"),
            duration_ms=_optional_int(raw.get("duration_ms"), "delivery attempt duration"),
            actor_id=_optional_str(raw.get("actor_id"), "delivery attempt actor"),
        )


@dataclass(frozen=True, slots=True)
class WebhookEndpoint:
    id: str
    url: str
    enabled: bool = True
    event_types: tuple[str, ...] = ()
    failure_count: int = 0
    created_at: datetime | None = None
    secret: str | None = field(default=None, repr=False)  # set by ``create`` only

    @classmethod
    def from_payload(cls, data: Any) -> "WebhookEndpoint":
        raw = _as_dict(data, "webhook endpoint")
        endpoint_id, url = _required(raw, "webhook endpoint", "id", "url")
        enabled = raw.get("enabled")
        failures = raw.get("failure_count")
        return cls(
            id=_str(endpoint_id, "webhook endpoint id"),
            url=_str(url, "webhook endpoint url"),
            enabled=True if enabled is None else _bool(enabled, "webhook endpoint enabled"),
            event_types=_event_types(raw.get("event_types")),
            failure_count=0 if failures is None else _int(failures, "webhook failure count"),
            created_at=_timestamp(raw.get("created_at"), "webhook endpoint"),
            secret=_optional_str(raw.get("secret"), "webhook endpoint secret"),
        )


def _history(value: Any) -> tuple[DeliveryAttempt, ...]:
    if value is None:
        return ()
    items = _as_list(value, "delivery attempt history")
    return tuple(DeliveryAttempt.from_payload(item) for item in items)


@dataclass(frozen=True, slots=True)
class WebhookDelivery:
    id: str
    endpoint_id: str
    event_id: str
    state: str  # "pending" | "delivered" | "failed" | "disabled"
    attempts: int = 0
    event_type: str | None = None
    next_attempt_at: datetime | None = None
    last_status: int | None = None
    last_error: str | None = None
    payload_sha256: str | None = None  # hex sha256 of the signed body; the body is not stored
    attempt_history: tuple[DeliveryAttempt, ...] = ()  # oldest first
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @classmethod
    def from_payload(cls, data: Any) -> "WebhookDelivery":
        raw = _as_dict(data, "webhook delivery")
        delivery_id, endpoint_id, event_id, state = _required(
            raw, "webhook delivery", "id", "endpoint_id", "event_id", "state"
        )
        attempts = raw.get("attempts")
        return cls(
            id=_str(delivery_id, "webhook delivery id"),
            endpoint_id=_str(endpoint_id, "webhook delivery endpoint id"),
            event_id=_str(event_id, "webhook delivery event id"),
            state=_str(state, "webhook delivery state"),
            attempts=0 if attempts is None else _int(attempts, "webhook delivery attempts"),
            event_type=_optional_str(raw.get("event_type"), "webhook delivery event type"),
            next_attempt_at=_timestamp(raw.get("next_attempt_at"), "webhook delivery"),
            last_status=_optional_int(raw.get("last_status"), "webhook delivery last status"),
            last_error=_optional_str(raw.get("last_error"), "webhook delivery last error"),
            payload_sha256=_optional_str(raw.get("payload_sha256"), "webhook delivery hash"),
            attempt_history=_history(raw.get("attempt_history")),
            created_at=_timestamp(raw.get("created_at"), "webhook delivery"),
            updated_at=_timestamp(raw.get("updated_at"), "webhook delivery"),
        )


@dataclass(frozen=True, slots=True)
class DeliveryPage:
    """One page of deliveries; page on with ``cursor=page.next_cursor`` until it is ``None``.

    A page can be empty with a cursor when a filter skipped every row the server scanned.
    """

    deliveries: tuple[WebhookDelivery, ...]
    next_cursor: str | None = None
