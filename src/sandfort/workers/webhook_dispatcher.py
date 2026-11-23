"""Webhook dispatcher: outbox fan-out, signed delivery, backoff and auto-disable.

One pass does two things. *Fan-out* turns each undispatched outbox event into one ``pending``
delivery per enabled endpoint of the event's org whose filter matches (an empty filter matches
everything; ``sandbox.*`` and ``*`` are prefix wildcards), then stamps the event dispatched.
The unique (endpoint, event) pair keeps fan-out idempotent after a crash. *Send* attempts every
due delivery: a 2xx marks it ``delivered`` (never sent again), anything else (including a 3xx,
which is never followed, and a transport error) schedules the next attempt on the backoff
schedule and, once the schedule is spent, ends the delivery as ``failed`` (dead). A delivery
whose endpoint is gone or disabled is parked as ``disabled`` (a ``parked`` history entry and
``last_error`` "endpoint disabled"); a redelivery requeues it.

Delivery detail: each outcome appends to the history read inside the recording transaction, so
a marker added meanwhile by a redelivery survives. A delivery written before the detail
migration has no ``event_type`` until the dispatcher loads it as due; it is then filled from
the event row (sent or parked alike). A pre-migration row that is no longer due (delivered,
failed or parked) keeps it null until a redelivery makes it due again.

An endpoint counts consecutive failed attempts; at ``DISABLE_THRESHOLD`` it is disabled and
``webhook.endpoint_disabled`` is audited. A success resets the count.

Send order and concurrency: the due batch is interleaved round-robin by org (``round_robin``:
one delivery of every org per round, each org in its own order), so one org's backlog cannot
fill the front of the batch. The result is split into one lane per endpoint
(``endpoint_lanes``) and the lanes run concurrently. A lane attempts its deliveries one after
another in batch order, so an endpoint sees them in order, never has more than one request in
flight from a pass, and its failure count is never updated by two attempts at once (the
auto-disable threshold stays exact). Every attempt holds one of ``MAX_IN_FLIGHT`` semaphore
slots, released between the attempts of a lane so waiting lanes take turns: a slow or silent
endpoint ties up one slot for at most the delivery deadline per attempt while the other
endpoints keep delivering. A pass still ends only once its longest lane has drained.

No HTTP call runs inside an open transaction. Log lines carry ids, statuses and exception class
names only: never URLs, headers, secrets or exception text.
"""

import asyncio
import json
import logging
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import replace
from datetime import datetime, timedelta

import httpx

from sandfort.clock import Clock
from sandfort.db.models.webhooks import DeliveryState
from sandfort.db.repositories.events import event_lookup
from sandfort.db.repositories.ports import (
    OutboxEventRecord,
    UnitOfWorkPort,
    WebhookDeliveryRecord,
    WebhookEndpointRecord,
)
from sandfort.db.repositories.webhooks import delivery_queries
from sandfort.domain.events import ActorType
from sandfort.errors import Conflict
from sandfort.ids import WEBHOOK, new_id
from sandfort.services.audit import AuditRecorder
from sandfort.webhooks.delivery import (
    DEFAULT_TIMEOUT_S,
    DeliveryError,
    HistoryEntry,
    append_capped,
    deliver,
)
from sandfort.webhooks.secret_box import SecretBox
from sandfort.workers.reconciler import PassLoop
from sandfort.workers.webhook_attempts import (
    EVENT_MISSING_ERROR,
    PARKED_ERROR,
    AttemptOutcome,
    attempt_entry,
    body_digest,
    failure_text,
    parked_entry,
)

logger = logging.getLogger(__name__)

BACKOFF_SCHEDULE_S = (1, 5, 25, 60, 300)
DISABLE_THRESHOLD = 50
BATCH_SIZE = 100
MAX_IN_FLIGHT = 8  # concurrent attempts of one pass, across all endpoints
ENDPOINT_DISABLED = "webhook.endpoint_disabled"
UNKNOWN_ORG = ""  # ordering key of a delivery whose event is gone (it is parked, never sent)


def matches(event_types: Sequence[str], event_type: str) -> bool:
    """True when the endpoint filter admits ``event_type`` (empty filter admits all)."""
    if not event_types:
        return True
    return any(
        pattern in ("*", event_type)
        or (pattern.endswith(".*") and event_type.startswith(pattern[:-1]))
        for pattern in event_types
    )


def next_delay_s(attempts_made: int) -> int | None:
    """Seconds until the next attempt after ``attempts_made`` failures; None when dead."""
    if attempts_made <= len(BACKOFF_SCHEDULE_S):
        return BACKOFF_SCHEDULE_S[attempts_made - 1]
    return None


def build_body(event: OutboxEventRecord) -> bytes:
    """The JSON bytes that are signed and sent; identical for every retry of an event."""
    document = {
        "id": event.id,
        "type": event.event_type,
        "created_at": event.created_at.isoformat(),
        "data": dict(event.payload),
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def _grouped[T](items: Iterable[T], key: Callable[[T], str]) -> list[list[T]]:
    """``items`` split by ``key``: groups in first-appearance order, each in input order."""
    groups: dict[str, list[T]] = {}
    for item in items:
        groups.setdefault(key(item), []).append(item)
    return list(groups.values())


def round_robin[T](items: Iterable[T], key: Callable[[T], str]) -> list[T]:
    """Interleave ``items`` by ``key``: every round takes the next item of each group.

    Groups take turns in the order they first appear and each keeps its own order, so a long
    run of one key (one org's backlog) cannot hold the front of the result.
    """
    groups = _grouped(items, key)
    depth = max((len(group) for group in groups), default=0)
    return [group[turn] for turn in range(depth) for group in groups if turn < len(group)]


def endpoint_lanes(batch: Iterable[WebhookDeliveryRecord]) -> list[list[WebhookDeliveryRecord]]:
    """One lane per endpoint, lanes in first-appearance order, each lane in batch order."""
    return _grouped(batch, lambda delivery: delivery.endpoint_id)


async def _events_of(
    uow: UnitOfWorkPort, due: Sequence[WebhookDeliveryRecord]
) -> dict[str, OutboxEventRecord]:
    """The events behind ``due`` by id, each read once (fan-out shares one event)."""
    lookup = event_lookup(uow)
    found = [await lookup.get(event_id) for event_id in dict.fromkeys(d.event_id for d in due)]
    return {event.id: event for event in found if event is not None}


def _org_of(events: Mapping[str, OutboxEventRecord], delivery: WebhookDeliveryRecord) -> str:
    event = events.get(delivery.event_id)
    return UNKNOWN_ORG if event is None else event.org_id


async def _stored_history(
    uow: UnitOfWorkPort, delivery: WebhookDeliveryRecord, event: OutboxEventRecord | None
) -> Sequence[HistoryEntry]:
    """The attempt history as stored now (a redelivery may have added a marker mid-attempt).

    Read inside the transaction that writes the new entry, so the append starts from the row
    and not from the copy loaded at the start of the pass; falls back to that copy when the
    event is gone (no org to scope the read) or the row vanished.
    """
    if event is None:
        return delivery.attempt_history
    current = await delivery_queries(uow).get_delivery(
        event.org_id, delivery.endpoint_id, delivery.id
    )
    return delivery.attempt_history if current is None else current.attempt_history


def _name(exc: BaseException) -> str:
    return type(exc).__name__


class WebhookDispatcher:
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWorkPort],
        clock: Clock,
        *,
        interval_s: float,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        transport: httpx.AsyncBaseTransport | None = None,
        audit: AuditRecorder | None = None,
        secret_box: SecretBox | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._secret_box = secret_box
        self._timeout_s = timeout_s
        self._transport = transport
        self._audit = audit or AuditRecorder(clock)
        self._loop = PassLoop("webhook dispatcher", self.run_once, interval_s)

    @property
    def running(self) -> bool:
        return self._loop.running

    def start(self) -> None:
        self._loop.start()

    async def stop(self) -> None:
        await self._loop.stop()

    async def run_once(self) -> None:
        """One pass: fan out undispatched events, then send every due delivery."""
        await self._fan_out()
        await self._send_due()

    # -- fan-out ---------------------------------------------------------------------

    async def _fan_out(self) -> None:
        async with self._uow_factory() as uow:
            events = await uow.events.list_undispatched(limit=BATCH_SIZE)
        for event in events:
            try:
                await self._fan_out_event(event)
            except Exception as exc:  # one bad event must not starve the rest
                logger.warning("webhook fan-out failed for event %s: %s", event.id, _name(exc))

    async def _fan_out_event(self, event: OutboxEventRecord) -> None:
        async with self._uow_factory() as uow:
            endpoints = await uow.webhooks.list_endpoints(event.org_id)
        for endpoint in endpoints:
            if endpoint.enabled and matches(endpoint.event_types, event.event_type):
                await self._record_delivery(event, endpoint)
        async with self._uow_factory() as uow:
            await uow.events.mark_dispatched(event.id, self._clock.now())
            await uow.commit()

    async def _record_delivery(
        self, event: OutboxEventRecord, endpoint: WebhookEndpointRecord
    ) -> None:
        now = self._clock.now()
        delivery = WebhookDeliveryRecord(
            id=new_id(WEBHOOK),
            endpoint_id=endpoint.id,
            event_id=event.id,
            state=DeliveryState.PENDING.value,
            attempts=0,
            next_attempt_at=None,
            last_status=None,
            created_at=now,
            updated_at=now,
            event_type=event.event_type,
            payload_sha256=body_digest(build_body(event)),
        )
        try:
            async with self._uow_factory() as uow:  # own unit: a duplicate poisons its session
                await uow.webhooks.record_delivery(delivery)
                await uow.commit()
        except Conflict:
            return  # fanned out by an earlier pass that died before stamping the event

    # -- sending ---------------------------------------------------------------------

    async def _send_due(self) -> None:
        """Send the due batch: fair across orgs, in order per endpoint, endpoints in parallel."""
        async with self._uow_factory() as uow:
            due = await uow.webhooks.due_deliveries(self._clock.now(), limit=BATCH_SIZE)
            if not due:
                return
            events = await _events_of(uow, due)
            due = await self._backfill_event_types(uow, due, events)
        ordered = round_robin(due, lambda delivery: _org_of(events, delivery))
        slots = asyncio.Semaphore(MAX_IN_FLIGHT)
        async with asyncio.TaskGroup() as lanes:
            for lane in endpoint_lanes(ordered):
                lanes.create_task(self._drain(lane, events, slots))

    async def _backfill_event_types(
        self,
        uow: UnitOfWorkPort,
        due: Sequence[WebhookDeliveryRecord],
        events: Mapping[str, OutboxEventRecord],
    ) -> list[WebhookDeliveryRecord]:
        """``due`` with ``event_type`` filled from the event row where a legacy row lacks it.

        Rows written before the detail migration carry no event type, so the API filter would
        never match them; the fill is stored in the loading transaction, before any send.
        """
        filled: list[WebhookDeliveryRecord] = []
        changed = False
        for delivery in due:
            event = events.get(delivery.event_id)
            if delivery.event_type is not None or event is None:
                filled.append(delivery)
                continue
            complete = replace(delivery, event_type=event.event_type)
            await uow.webhooks.update_delivery_state(complete)
            filled.append(complete)
            changed = True
        if changed:
            await uow.commit()
        return filled

    async def _drain(
        self,
        lane: Sequence[WebhookDeliveryRecord],
        events: Mapping[str, OutboxEventRecord],
        slots: asyncio.Semaphore,
    ) -> None:
        """Attempt one endpoint's deliveries in batch order, one at a time, each in a slot."""
        for delivery in lane:
            async with slots:
                try:
                    await self._attempt(delivery, events.get(delivery.event_id))
                except Exception as exc:  # one crashed attempt must not end the lane
                    logger.warning("webhook attempt crashed for %s: %s", delivery.id, _name(exc))

    async def _attempt(
        self, delivery: WebhookDeliveryRecord, event: OutboxEventRecord | None
    ) -> None:
        """Send one delivery; the endpoint is re-read (its lane may have just disabled it)."""
        async with self._uow_factory() as uow:
            endpoint = (
                None
                if event is None
                else await uow.webhooks.get_endpoint(event.org_id, delivery.endpoint_id)
            )
            if event is None or endpoint is None or not endpoint.enabled:
                await self._park(uow, delivery, event)
                return
        started_at = self._clock.now()
        outcome = await self._send(endpoint, event)
        await self._record_outcome(delivery, event, outcome, started_at)

    async def _park(
        self, uow: UnitOfWorkPort, delivery: WebhookDeliveryRecord, event: OutboxEventRecord | None
    ) -> None:
        """Park ``delivery`` as ``disabled``: a ``parked`` history entry and a last error."""
        now = self._clock.now()
        reason = PARKED_ERROR if event is not None else EVENT_MISSING_ERROR
        history = await _stored_history(uow, delivery, event)
        parked = replace(
            delivery,
            state=DeliveryState.DISABLED.value,
            next_attempt_at=None,
            last_status=None,  # the status of an earlier attempt no longer describes the row
            updated_at=now,
            last_error=reason,
            attempt_history=append_capped(history, parked_entry(now, reason)),
        )
        await uow.webhooks.update_delivery_state(parked)
        await uow.commit()

    async def _send(
        self, endpoint: WebhookEndpointRecord, event: OutboxEventRecord
    ) -> AttemptOutcome:
        started = time.monotonic()
        status: int | None = None
        reason: str | None = None
        try:
            status = await deliver(
                endpoint,
                message_id=event.id,
                timestamp=int(self._clock.now().timestamp()),
                payload=build_body(event),
                timeout_s=self._timeout_s,
                transport=self._transport,
                secret_box=self._secret_box,
            )
        except DeliveryError as error:
            logger.warning("webhook delivery failed: %s", error)  # id:ClassName only
            reason = error.reason
        return AttemptOutcome(status, reason, int((time.monotonic() - started) * 1000))

    async def _record_outcome(
        self,
        delivery: WebhookDeliveryRecord,
        event: OutboxEventRecord,
        outcome: AttemptOutcome,
        started_at: datetime,
    ) -> None:
        """Persist the attempt: counters, schedule, last error and one history entry together."""
        success = outcome.success
        now = self._clock.now()
        attempts = delivery.attempts + 1
        state = DeliveryState.DELIVERED
        next_attempt_at: datetime | None = None
        if not success:
            delay = next_delay_s(attempts)
            state = DeliveryState.FAILED if delay is None else DeliveryState.PENDING
            next_attempt_at = None if delay is None else now + timedelta(seconds=delay)
        async with self._uow_factory() as uow:
            history = await _stored_history(uow, delivery, event)  # not the stale in-memory copy
            await uow.webhooks.update_delivery_state(
                replace(
                    delivery,
                    state=state.value,
                    attempts=attempts,
                    next_attempt_at=next_attempt_at,
                    last_status=outcome.status,
                    updated_at=now,
                    event_type=delivery.event_type or event.event_type,  # backfills old rows
                    payload_sha256=delivery.payload_sha256 or body_digest(build_body(event)),
                    last_error=failure_text(outcome),
                    attempt_history=append_capped(history, attempt_entry(outcome, started_at)),
                )
            )
            endpoint = await uow.webhooks.get_endpoint(event.org_id, delivery.endpoint_id)
            if endpoint is not None:  # fresh read: the API may have changed it meanwhile
                await self._track_endpoint(uow, endpoint, success)
            await uow.commit()

    async def _track_endpoint(
        self, uow: UnitOfWorkPort, endpoint: WebhookEndpointRecord, success: bool
    ) -> None:
        if success:
            if endpoint.failure_count:
                await uow.webhooks.update_endpoint(
                    endpoint.org_id, replace(endpoint, failure_count=0)
                )
            return
        count = endpoint.failure_count + 1
        disable = endpoint.enabled and count >= DISABLE_THRESHOLD
        await uow.webhooks.update_endpoint(
            endpoint.org_id,
            replace(endpoint, failure_count=count, enabled=endpoint.enabled and not disable),
        )
        if disable:
            await self._audit.record(
                uow,
                org_id=endpoint.org_id,
                actor_type=ActorType.SYSTEM,
                actor_id=None,
                action=ENDPOINT_DISABLED,
                target_type="webhook_endpoint",
                target_id=endpoint.id,
                details={"failure_count": count},
            )
