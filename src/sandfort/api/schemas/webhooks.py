"""Request/response models for ``/v1/webhooks``.

The signing secret appears in exactly one response: the one that creates the endpoint.
"""

from collections.abc import Mapping
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, Field, StringConstraints

from sandfort.api.schemas.common import RequestModel
from sandfort.db.repositories.ports import WebhookDeliveryRecord, WebhookEndpointRecord

ATTEMPT_KIND = "attempt"  # the history kind of an entry that does not name one
MAX_URL_LENGTH = 2048
MAX_FILTERS = 32
EVENT_PATTERN = r"^(\*|[a-z_]+\.(\*|[a-z_]+))$"

EventFilter = Annotated[str, StringConstraints(pattern=EVENT_PATTERN, max_length=64)]


class CreateEndpointRequest(RequestModel):
    url: str = Field(min_length=1, max_length=MAX_URL_LENGTH)
    event_types: list[EventFilter] = Field(default_factory=list, max_length=MAX_FILTERS)
    enabled: bool = True


class UpdateEndpointRequest(RequestModel):
    url: str | None = Field(default=None, min_length=1, max_length=MAX_URL_LENGTH)
    event_types: list[EventFilter] | None = Field(default=None, max_length=MAX_FILTERS)
    enabled: bool | None = None


class EndpointResponse(BaseModel):
    id: str
    url: str
    enabled: bool
    event_types: list[str]
    failure_count: int
    created_at: datetime


class EndpointWithSecretResponse(EndpointResponse):
    secret: str


class AttemptEntryResponse(BaseModel):
    """One entry of a delivery's attempt history: a delivery attempt or a redelivery marker."""

    kind: str = Field(
        description="`attempt` for a delivery attempt, `redelivered` for a redelivery marker."
    )
    attempted_at: datetime | None = Field(
        description="When the attempt was made, or when the delivery was requeued."
    )
    status: int | None = Field(
        description="HTTP status the endpoint answered; null when none came back or for a marker."
    )
    error: str | None = Field(
        description="Short sanitised failure reason (`http <status>` or a transport reason); "
        "null on success and for a marker. Never the URL, a header or the body."
    )
    duration_ms: int | None = Field(
        description="How long the attempt took in milliseconds; null for a marker."
    )
    actor_id: str | None = Field(
        default=None,
        description="API key that requeued the delivery; set on `redelivered` entries only.",
    )


class DeliveryResponse(BaseModel):
    """A webhook delivery with its outcome so far and its attempt history."""

    id: str
    endpoint_id: str
    event_id: str
    event_type: str | None = Field(
        description="Type of the event delivered (e.g. `sandbox.started`); null on rows "
        "written before delivery detail was stored."
    )
    state: str
    attempts: int
    next_attempt_at: datetime | None
    last_status: int | None
    last_error: str | None = Field(
        description="Failure reason of the latest attempt (at most 200 characters); kept after "
        "a redelivery until the next attempt; null when it succeeded or none was made."
    )
    payload_sha256: str | None = Field(
        description="Hex sha256 of the signed request body; the body itself is not stored."
    )
    attempt_history: list[AttemptEntryResponse] = Field(
        description="Oldest first, capped at the newest 6 entries; a redelivery keeps it and "
        "appends a `redelivered` entry naming the actor."
    )
    created_at: datetime
    updated_at: datetime


def endpoint_response(endpoint: WebhookEndpointRecord) -> EndpointResponse:
    return EndpointResponse(
        id=endpoint.id,
        url=endpoint.url,
        enabled=endpoint.enabled,
        event_types=list(endpoint.event_types),
        failure_count=endpoint.failure_count,
        created_at=endpoint.created_at,
    )


def created_endpoint_response(endpoint: WebhookEndpointRecord) -> EndpointWithSecretResponse:
    fields = endpoint_response(endpoint).model_dump()
    return EndpointWithSecretResponse(**fields, secret=endpoint.secret)


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _number(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _moment(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def attempt_entry_response(entry: Mapping[str, Any]) -> AttemptEntryResponse:
    """The wire form of one stored history entry; only the documented keys are read.

    An attempt stores ``attempted_at``, a redelivery marker stores ``at`` and ``actor_id``.
    """
    return AttemptEntryResponse(
        kind=_text(entry.get("kind")) or ATTEMPT_KIND,
        attempted_at=_moment(entry.get("attempted_at", entry.get("at"))),
        status=_number(entry.get("status")),
        error=_text(entry.get("error")),
        duration_ms=_number(entry.get("duration_ms")),
        actor_id=_text(entry.get("actor_id")),
    )


def delivery_response(delivery: WebhookDeliveryRecord) -> DeliveryResponse:
    return DeliveryResponse(
        id=delivery.id,
        endpoint_id=delivery.endpoint_id,
        event_id=delivery.event_id,
        event_type=delivery.event_type,
        state=delivery.state,
        attempts=delivery.attempts,
        next_attempt_at=delivery.next_attempt_at,
        last_status=delivery.last_status,
        last_error=delivery.last_error,
        payload_sha256=delivery.payload_sha256,
        attempt_history=[attempt_entry_response(entry) for entry in delivery.attempt_history],
        created_at=delivery.created_at,
        updated_at=delivery.updated_at,
    )
