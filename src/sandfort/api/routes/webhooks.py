"""``/v1/webhooks``: endpoint management, delivery history and redelivery.

Every route needs the ``webhooks:write`` scope and is org scoped; another org's endpoint is a
404. Endpoint URLs are vetted by the SSRF guard on create and on every URL change (the
dispatcher vets again on each delivery attempt). The signing secret is generated here, sealed
with the configured ``SecretBox`` before it is stored, and returned in plaintext by the create
call only; no other route echoes it. Without ``SANDFORT_WEBHOOK_SECRET_KEY`` the secret is
stored as is, which the ``prod`` environment refuses. Updating an endpoint seals a legacy
plaintext secret when a key is configured.
"""

from dataclasses import dataclass, replace
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query

from sandfort.api.deps import get_audit_recorder, get_settings, get_uow
from sandfort.api.envelope import Envelope, ok
from sandfort.api.pagination import WEBHOOK_DELIVERIES, decode_cursor, encode_cursor
from sandfort.api.query_guard import KnownQuery, single_valued
from sandfort.api.schemas.common import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, Meta
from sandfort.api.schemas.webhooks import (
    CreateEndpointRequest,
    DeliveryResponse,
    EndpointResponse,
    EndpointWithSecretResponse,
    UpdateEndpointRequest,
    created_endpoint_response,
    delivery_response,
    endpoint_response,
)
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import require_scopes
from sandfort.clock import SystemClock
from sandfort.config import PROD_ENVIRONMENT, Settings
from sandfort.db.models.webhooks import DeliveryState
from sandfort.db.repositories.ports import (
    UnitOfWorkPort,
    WebhookDeliveryRecord,
    WebhookEndpointRecord,
)
from sandfort.db.repositories.webhooks import delivery_queries
from sandfort.domain.events import ActorType
from sandfort.domain.org import Scope
from sandfort.errors import DnsUnavailable, InternalError, InvalidState, NotFound, Unprocessable
from sandfort.ids import WEBHOOK, new_id
from sandfort.services.audit import AuditRecorder
from sandfort.webhooks.delivery import redeliver as requeue
from sandfort.webhooks.secret_box import SecretBox
from sandfort.webhooks.signing import generate_secret
from sandfort.webhooks.ssrf import HostNotResolved, ResolverUnavailable, UrlRejected, vet_url

router = APIRouter(prefix="/v1/webhooks", tags=["webhooks"])

ENDPOINT_CREATED = "webhook.endpoint_created"
ENDPOINT_DELETED = "webhook.endpoint_deleted"
DELIVERY_REDELIVERED = "webhook.redelivered"
REDELIVERABLE = (DeliveryState.FAILED.value, DeliveryState.DISABLED.value)
NOT_RESOLVED_REASON = "not_resolved"
DNS_UNAVAILABLE_MESSAGE = "could not verify the webhook host: DNS lookup failed; try again"
MAX_EVENT_TYPE_LENGTH = 64
SCAN_BATCH = MAX_PAGE_SIZE  # rows read per round when a filter has to skip some
SCAN_CAP = 10 * MAX_PAGE_SIZE  # rows a filtered list scans per request
_CLOCK = SystemClock()

Writer = Annotated[Principal, Depends(require_scopes(Scope.WEBHOOKS_WRITE))]
Uow = Annotated[UnitOfWorkPort, Depends(get_uow)]
Recorder = Annotated[AuditRecorder, Depends(get_audit_recorder)]
Config = Annotated[Settings, Depends(get_settings)]
ListOnce = Annotated[None, Depends(single_valued("event_type", "state", "cursor", "limit"))]


@dataclass(frozen=True, slots=True)
class DeliveryScan:
    """Deliveries that matched one filtered scan, and where an interrupted scan stopped."""

    rows: list[WebhookDeliveryRecord]
    resume_after: str | None  # last scanned id when the scan cap cut it short, else None


def _secret_box(settings: Settings) -> SecretBox:
    """The box for the configured key; ``prod`` refuses to store a secret without one."""
    box = SecretBox(settings.webhook_secret_key)
    if settings.environment == PROD_ENVIRONMENT and not box.enabled:
        raise InternalError("SANDFORT_WEBHOOK_SECRET_KEY is required in the prod environment")
    return box


async def _admit(url: str) -> None:
    """Raise 422 unless the SSRF guard admits ``url``; 503 when the host could not be checked.

    Only a resolver answer of "no such host" is a 422 ``not_resolved``. A resolver that failed
    (after one retry in the guard) is no verdict on the URL: 503 ``DNS_UNAVAILABLE``.
    """
    try:
        await vet_url(url)
    except HostNotResolved as exc:
        raise Unprocessable(
            f"webhook url rejected: {exc}", details={"reason": NOT_RESOLVED_REASON}
        ) from None
    except UrlRejected as exc:
        raise Unprocessable(f"webhook url rejected: {exc}") from None
    except ResolverUnavailable:
        raise DnsUnavailable(DNS_UNAVAILABLE_MESSAGE) from None


async def _audit(
    recorder: AuditRecorder,
    uow: UnitOfWorkPort,
    principal: Principal,
    action: str,
    endpoint_id: str,
    details: dict[str, Any],
) -> None:
    await recorder.record(
        uow,
        org_id=principal.org_id,
        actor_type=ActorType.API_KEY,
        actor_id=principal.key_id,
        action=action,
        target_type="webhook_endpoint",
        target_id=endpoint_id,
        details=details,
    )


async def _require(uow: UnitOfWorkPort, org_id: str, endpoint_id: str) -> WebhookEndpointRecord:
    endpoint = await uow.webhooks.get_endpoint(org_id, endpoint_id)
    if endpoint is None:
        raise NotFound(f"webhook endpoint {endpoint_id} not found")
    return endpoint


@router.post("", status_code=201)
async def create_endpoint(
    body: CreateEndpointRequest, principal: Writer, uow: Uow, recorder: Recorder, config: Config
) -> Envelope[EndpointWithSecretResponse]:
    box = _secret_box(config)
    await _admit(body.url)
    plaintext = generate_secret()
    endpoint = WebhookEndpointRecord(
        id=new_id(WEBHOOK),
        org_id=principal.org_id,
        url=body.url,
        secret=box.encrypt(plaintext),
        enabled=body.enabled,
        failure_count=0,
        event_types=list(body.event_types),
        created_at=_CLOCK.now(),
    )
    details = {"event_types": list(endpoint.event_types), "enabled": endpoint.enabled}
    async with uow:
        await uow.webhooks.add_endpoint(endpoint)
        await _audit(recorder, uow, principal, ENDPOINT_CREATED, endpoint.id, details)
        await uow.commit()
    return ok(created_endpoint_response(replace(endpoint, secret=plaintext)))


@router.get("")
async def list_endpoints(
    principal: Writer, uow: Uow, _known: KnownQuery
) -> Envelope[list[EndpointResponse]]:
    async with uow:
        endpoints = await uow.webhooks.list_endpoints(principal.org_id)
    return ok([endpoint_response(endpoint) for endpoint in endpoints])


@router.get("/{endpoint_id}")
async def get_endpoint(endpoint_id: str, principal: Writer, uow: Uow) -> Envelope[EndpointResponse]:
    async with uow:
        endpoint = await _require(uow, principal.org_id, endpoint_id)
    return ok(endpoint_response(endpoint))


@router.patch("/{endpoint_id}")
async def update_endpoint(
    endpoint_id: str, body: UpdateEndpointRequest, principal: Writer, uow: Uow, config: Config
) -> Envelope[EndpointResponse]:
    box = SecretBox(config.webhook_secret_key)
    async with uow:
        current = await _require(uow, principal.org_id, endpoint_id)
        if body.url is not None:
            await _admit(body.url)
        re_enabled = body.enabled is True and not current.enabled
        updated = replace(
            current,
            url=current.url if body.url is None else body.url,
            secret=box.reseal(current.secret),  # lazy: a legacy plaintext secret is sealed here
            enabled=current.enabled if body.enabled is None else body.enabled,
            event_types=current.event_types if body.event_types is None else body.event_types,
            failure_count=0 if re_enabled else current.failure_count,
        )
        saved = await uow.webhooks.update_endpoint(principal.org_id, updated)
        if saved is None:
            raise NotFound(f"webhook endpoint {endpoint_id} not found")
        await uow.commit()
    return ok(endpoint_response(saved))


@router.delete("/{endpoint_id}")
async def delete_endpoint(
    endpoint_id: str, principal: Writer, uow: Uow, recorder: Recorder
) -> Envelope[EndpointResponse]:
    async with uow:
        endpoint = await _require(uow, principal.org_id, endpoint_id)
        if not await uow.webhooks.delete_endpoint(principal.org_id, endpoint_id):
            raise NotFound(f"webhook endpoint {endpoint_id} not found")
        await _audit(recorder, uow, principal, ENDPOINT_DELETED, endpoint_id, {})
        await uow.commit()
    return ok(endpoint_response(endpoint))


def _matches(delivery: WebhookDeliveryRecord, event_type: str | None, state: str | None) -> bool:
    return (event_type is None or delivery.event_type == event_type) and (
        state is None or delivery.state == state
    )


async def _matching(
    uow: UnitOfWorkPort,
    org_id: str,
    endpoint_id: str,
    after: str | None,
    want: int,
    event_type: str | None,
    state: str | None,
) -> DeliveryScan:
    """Up to ``want`` deliveries after ``after`` that match the filters, in id order.

    The delivery read has no filter of its own, so rows are read in batches and skipped here.
    At most ``SCAN_CAP`` rows are scanned per call; when that bound stops the scan early,
    ``resume_after`` is the id of the last scanned row so the client can continue from there.
    """
    batch = SCAN_BATCH if event_type is not None or state is not None else want
    found: list[WebhookDeliveryRecord] = []
    scanned = 0
    cursor = after
    while True:
        rows = await delivery_queries(uow).list_deliveries(
            org_id, endpoint_id, cursor=cursor, limit=batch
        )
        for row in rows:
            if _matches(row, event_type, state):
                found.append(row)
                if len(found) == want:
                    return DeliveryScan(found, None)
        scanned += len(rows)
        if len(rows) < batch:
            return DeliveryScan(found, None)
        cursor = rows[-1].id
        if scanned >= SCAN_CAP:
            return DeliveryScan(found, cursor)


@router.get("/{endpoint_id}/deliveries")
async def list_deliveries(
    endpoint_id: str,
    principal: Writer,
    uow: Uow,
    _known: KnownQuery,
    _once: ListOnce,
    event_type: Annotated[
        str | None,
        Query(
            min_length=1,
            max_length=MAX_EVENT_TYPE_LENGTH,
            description="Only deliveries of this event type, e.g. `sandbox.started`.",
        ),
    ] = None,
    state: Annotated[
        DeliveryState | None, Query(description="Only deliveries in this state.")
    ] = None,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
) -> Envelope[list[DeliveryResponse]]:
    """List the deliveries of an endpoint in id order, optionally by event type and state.

    A cursor is bound to this endpoint and to the ``event_type`` and ``state`` filters; one
    presented with another endpoint or other filters answers 422 naming the differing field.
    Rows written before the delivery detail migration carry no ``event_type`` and so never
    match that filter. The dispatcher fills it in when it loads such a delivery (a pending one
    that is due, whether it is then sent or parked); a pre-migration row that is already
    delivered, failed or parked stays without one until a redelivery makes it due again.
    The server scans at most ``10 x`` the max page size (``SCAN_CAP`` = 1000) rows per request;
    when a filter skips so many rows that the bound is reached first, the page may be short
    or empty and ``meta.next_cursor`` points at the last scanned row, so the client continues
    from the cursor until it is ``null``.
    """
    state_value = None if state is None else state.value
    bound = {"endpoint_id": endpoint_id, "event_type": event_type, "state": state_value}
    after = None if cursor is None else decode_cursor(cursor, bound, resource=WEBHOOK_DELIVERIES)
    async with uow:
        await _require(uow, principal.org_id, endpoint_id)
        # Fetch one extra match to learn whether another page exists.
        scan = await _matching(
            uow, principal.org_id, endpoint_id, after, limit + 1, event_type, state_value
        )
    page = scan.rows[:limit]
    last = scan.resume_after
    if last is None and len(scan.rows) > limit:
        last = page[-1].id
    next_cursor = None if last is None else encode_cursor(last, bound, resource=WEBHOOK_DELIVERIES)
    return ok([delivery_response(item) for item in page], meta=Meta(next_cursor=next_cursor))


@router.get("/{endpoint_id}/deliveries/{delivery_id}")
async def get_delivery(
    endpoint_id: str, delivery_id: str, principal: Writer, uow: Uow, _known: KnownQuery
) -> Envelope[DeliveryResponse]:
    """One delivery of an endpoint with its outcome and attempt history."""
    async with uow:
        await _require(uow, principal.org_id, endpoint_id)
        delivery = await delivery_queries(uow).get_delivery(
            principal.org_id, endpoint_id, delivery_id
        )
    if delivery is None:
        raise NotFound(f"webhook delivery {delivery_id} not found")
    return ok(delivery_response(delivery))


@router.post("/{endpoint_id}/deliveries/{delivery_id}/redeliver")
async def redeliver(
    endpoint_id: str, delivery_id: str, principal: Writer, uow: Uow, recorder: Recorder
) -> Envelope[DeliveryResponse]:
    """Requeue a dead (``failed``) or parked (``disabled``) delivery; a delivered one is final.

    A new cycle starts: attempts go back to 0 and the delivery is ``pending`` and due at once.
    ``next_attempt_at`` stays null: the API process clock never schedules a send (a worker
    whose clock is behind would delay it); the dispatcher stamps the time on its next attempt.
    The attempt history is kept and a ``redelivered`` entry naming the calling key is
    appended; the last status and the last error are cleared together.
    """
    async with uow:
        endpoint = await _require(uow, principal.org_id, endpoint_id)
        delivery = await delivery_queries(uow).get_delivery(
            principal.org_id, endpoint_id, delivery_id
        )
        if delivery is None:
            raise NotFound(f"webhook delivery {delivery_id} not found")
        if delivery.state not in REDELIVERABLE:
            raise InvalidState(
                f"delivery is {delivery.state}; only failed deliveries can be redelivered",
                details={"state": delivery.state},
            )
        if not endpoint.enabled:
            raise InvalidState("webhook endpoint is disabled; enable it first")
        requeued = requeue(delivery, actor_id=principal.key_id, now=_CLOCK.now())
        saved = await uow.webhooks.update_delivery_state(requeued)
        if saved is None:
            raise NotFound(f"webhook delivery {delivery_id} not found")
        details = {"delivery_id": delivery_id}
        await _audit(recorder, uow, principal, DELIVERY_REDELIVERED, endpoint_id, details)
        await uow.commit()
    return ok(delivery_response(saved))
