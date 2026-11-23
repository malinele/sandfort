"""SQLAlchemy ``WebhookRepository``.

* endpoint methods are org scoped in SQL; a cross-org read or write yields ``None``/``False``.
* ``secret`` is persisted exactly as given; this layer neither encrypts nor decrypts. The
  caller seals it with ``webhooks.secret_box.SecretBox`` (``enc1:`` + fernet token) when
  ``SANDFORT_WEBHOOK_SECRET_KEY`` is set, so a row may hold either that sealed form or legacy
  plaintext written before a key existed. The dispatcher unseals it right before signing.
* ``record_delivery`` raises ``Conflict`` for a second row with the same (endpoint, event).
* ``due_deliveries`` is a system path: ``pending`` rows whose ``next_attempt_at`` is ``NULL``
  or not after ``now``, oldest first.
* ``update_delivery_state`` persists state, attempts, next_attempt_at, last_status, updated_at
  and the delivery detail (event_type, payload_sha256, last_error, attempt_history) of the given
  record; ``None`` when the delivery does not exist.

The delivery reads the API needs (``list_deliveries``, ``get_delivery``) live on the SQL class
and are reached through ``delivery_queries`` because the frozen port does not carry them.
"""

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sandfort.db.models.webhooks import DeliveryState, WebhookDeliveryRow, WebhookEndpointRow
from sandfort.db.repositories.ports import (
    UnitOfWorkPort,
    WebhookDeliveryRecord,
    WebhookEndpointRecord,
)
from sandfort.db.support import as_utc, flush_or_conflict, opt_utc, rowcount
from sandfort.errors import InternalError

MAX_BATCH_SIZE = 500


def _endpoint(row: WebhookEndpointRow) -> WebhookEndpointRecord:
    return WebhookEndpointRecord(
        id=row.id,
        org_id=row.org_id,
        url=row.url,
        secret=row.secret,
        enabled=row.enabled,
        failure_count=row.failure_count,
        event_types=list(row.event_types),
        created_at=as_utc(row.created_at),
    )


def _delivery(row: WebhookDeliveryRow) -> WebhookDeliveryRecord:
    return WebhookDeliveryRecord(
        id=row.id,
        endpoint_id=row.endpoint_id,
        event_id=row.event_id,
        state=row.state,
        attempts=row.attempts,
        next_attempt_at=opt_utc(row.next_attempt_at),
        last_status=row.last_status,
        created_at=as_utc(row.created_at),
        updated_at=as_utc(row.updated_at),
        event_type=row.event_type,
        payload_sha256=row.payload_sha256,
        last_error=row.last_error,
        attempt_history=tuple(row.attempt_history or ()),
    )


class SqlWebhookRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add_endpoint(self, endpoint: WebhookEndpointRecord) -> None:
        self._session.add(
            WebhookEndpointRow(
                id=endpoint.id,
                org_id=endpoint.org_id,
                url=endpoint.url,
                secret=endpoint.secret,
                enabled=endpoint.enabled,
                failure_count=endpoint.failure_count,
                event_types=list(endpoint.event_types),
                created_at=as_utc(endpoint.created_at),
            )
        )
        await flush_or_conflict(
            self._session, "webhook endpoint id already exists, or its org does not exist"
        )

    async def get_endpoint(self, org_id: str, endpoint_id: str) -> WebhookEndpointRecord | None:
        stmt = (
            select(WebhookEndpointRow)
            .where(WebhookEndpointRow.org_id == org_id, WebhookEndpointRow.id == endpoint_id)
            .execution_options(populate_existing=True)
        )
        row = (await self._session.execute(stmt)).scalar_one_or_none()
        return None if row is None else _endpoint(row)

    async def list_endpoints(self, org_id: str) -> Sequence[WebhookEndpointRecord]:
        stmt = (
            select(WebhookEndpointRow)
            .where(WebhookEndpointRow.org_id == org_id)
            .order_by(WebhookEndpointRow.id)
            .execution_options(populate_existing=True)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_endpoint(row) for row in rows]

    async def update_endpoint(
        self, org_id: str, endpoint: WebhookEndpointRecord
    ) -> WebhookEndpointRecord | None:
        stmt = (
            update(WebhookEndpointRow)
            .where(WebhookEndpointRow.org_id == org_id, WebhookEndpointRow.id == endpoint.id)
            .values(
                url=endpoint.url,
                secret=endpoint.secret,
                enabled=endpoint.enabled,
                failure_count=endpoint.failure_count,
                event_types=list(endpoint.event_types),
            )
            .execution_options(synchronize_session=False)
        )
        if rowcount(await self._session.execute(stmt)) == 0:
            return None
        return await self.get_endpoint(org_id, endpoint.id)

    async def delete_endpoint(self, org_id: str, endpoint_id: str) -> bool:
        if await self.get_endpoint(org_id, endpoint_id) is None:
            return False
        await self._session.execute(
            delete(WebhookDeliveryRow)
            .where(WebhookDeliveryRow.endpoint_id == endpoint_id)
            .execution_options(synchronize_session=False)
        )
        result = await self._session.execute(
            delete(WebhookEndpointRow)
            .where(WebhookEndpointRow.org_id == org_id, WebhookEndpointRow.id == endpoint_id)
            .execution_options(synchronize_session=False)
        )
        return rowcount(result) > 0

    async def record_delivery(self, delivery: WebhookDeliveryRecord) -> None:
        self._session.add(
            WebhookDeliveryRow(
                id=delivery.id,
                endpoint_id=delivery.endpoint_id,
                event_id=delivery.event_id,
                state=delivery.state,
                attempts=delivery.attempts,
                next_attempt_at=opt_utc(delivery.next_attempt_at),
                last_status=delivery.last_status,
                created_at=as_utc(delivery.created_at),
                updated_at=as_utc(delivery.updated_at),
                event_type=delivery.event_type,
                payload_sha256=delivery.payload_sha256,
                last_error=delivery.last_error,
                attempt_history=[dict(entry) for entry in delivery.attempt_history],
            )
        )
        await flush_or_conflict(
            self._session, "delivery already exists for this endpoint and event"
        )

    async def due_deliveries(
        self, now: datetime, *, limit: int = 100
    ) -> Sequence[WebhookDeliveryRecord]:
        stmt = (
            select(WebhookDeliveryRow)
            .where(
                WebhookDeliveryRow.state == DeliveryState.PENDING.value,
                (WebhookDeliveryRow.next_attempt_at.is_(None))
                | (WebhookDeliveryRow.next_attempt_at <= as_utc(now)),
            )
            .order_by(WebhookDeliveryRow.created_at, WebhookDeliveryRow.id)
            .limit(max(1, min(limit, MAX_BATCH_SIZE)))
            .execution_options(populate_existing=True)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_delivery(row) for row in rows]

    async def update_delivery_state(
        self, delivery: WebhookDeliveryRecord
    ) -> WebhookDeliveryRecord | None:
        stmt = (
            update(WebhookDeliveryRow)
            .where(WebhookDeliveryRow.id == delivery.id)
            .values(
                state=delivery.state,
                attempts=delivery.attempts,
                next_attempt_at=opt_utc(delivery.next_attempt_at),
                last_status=delivery.last_status,
                updated_at=as_utc(delivery.updated_at),
                event_type=delivery.event_type,
                payload_sha256=delivery.payload_sha256,
                last_error=delivery.last_error,
                attempt_history=[dict(entry) for entry in delivery.attempt_history],
            )
            .execution_options(synchronize_session=False)
        )
        if rowcount(await self._session.execute(stmt)) == 0:
            return None
        return await self._get_delivery(delivery.id)

    async def list_deliveries(
        self, org_id: str, endpoint_id: str, *, cursor: str | None = None, limit: int = 50
    ) -> Sequence[WebhookDeliveryRecord]:
        """Deliveries of an endpoint of ``org_id`` in id order after ``cursor``."""
        stmt = (
            select(WebhookDeliveryRow)
            .join(WebhookEndpointRow, WebhookEndpointRow.id == WebhookDeliveryRow.endpoint_id)
            .where(WebhookEndpointRow.org_id == org_id, WebhookEndpointRow.id == endpoint_id)
        )
        if cursor is not None:
            stmt = stmt.where(WebhookDeliveryRow.id > cursor)
        stmt = (
            stmt.order_by(WebhookDeliveryRow.id)
            .limit(max(1, min(limit, MAX_BATCH_SIZE)))
            .execution_options(populate_existing=True)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_delivery(row) for row in rows]

    async def get_delivery(
        self, org_id: str, endpoint_id: str, delivery_id: str
    ) -> WebhookDeliveryRecord | None:
        found = await self._get_delivery(delivery_id)
        if found is None or found.endpoint_id != endpoint_id:
            return None
        if await self.get_endpoint(org_id, endpoint_id) is None:
            return None
        return found

    async def _get_delivery(self, delivery_id: str) -> WebhookDeliveryRecord | None:
        stmt = (
            select(WebhookDeliveryRow)
            .where(WebhookDeliveryRow.id == delivery_id)
            .execution_options(populate_existing=True)
        )
        row = (await self._session.execute(stmt)).scalar_one_or_none()
        return None if row is None else _delivery(row)


class DeliveryQueries(Protocol):
    async def list_deliveries(
        self, org_id: str, endpoint_id: str, *, cursor: str | None = None, limit: int = 50
    ) -> Sequence[WebhookDeliveryRecord]: ...

    async def get_delivery(
        self, org_id: str, endpoint_id: str, delivery_id: str
    ) -> WebhookDeliveryRecord | None: ...


_MAX_WRAPPER_DEPTH = 8


def _unwrapped(repository: object) -> object:
    """Follow the public ``wrapped`` attribute of decorators down to the repository they wrap."""
    for _ in range(_MAX_WRAPPER_DEPTH):
        if isinstance(repository, SqlWebhookRepository):
            break
        inner = getattr(repository, "wrapped", None)
        if inner is None:
            break
        repository = inner
    return repository


def delivery_queries(uow: UnitOfWorkPort) -> DeliveryQueries:
    """The delivery reads of the SQL repository (the frozen port only writes and polls).

    A decorator around the repository (for example the metering one) is looked through.
    """
    repository = _unwrapped(uow.webhooks)
    if not isinstance(repository, SqlWebhookRepository):
        raise InternalError("webhook repository does not support delivery queries")
    return repository
