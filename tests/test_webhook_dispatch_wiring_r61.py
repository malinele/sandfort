"""Hotfix (beta.65): the dispatcher wired with ``with_delivery_metrics`` must not crash.

The production wiring wraps ``uow.webhooks`` in a metering decorator. The history re-read goes
through ``delivery_queries`` / ``event_lookup``, which must see through that decorator. These
tests build the dispatcher exactly as production does; delivery goes to ``httpx.MockTransport``.
"""

from collections.abc import AsyncIterator, Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.repositories.events import event_lookup
from sandfort.db.repositories.ports import (
    UnitOfWorkPort,
    WebhookDeliveryRecord,
    WebhookEndpointRecord,
)
from sandfort.db.repositories.webhooks import delivery_queries
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import EventType
from sandfort.domain.org import Org
from sandfort.errors import InternalError
from sandfort.ids import WEBHOOK, new_id, new_org_id
from sandfort.observability.metrics import (
    REGISTRY,
    WEBHOOK_DELIVERIES_TOTAL,
    with_delivery_metrics,
)
from sandfort.services.events import OutboxEventPublisher
from sandfort.webhooks import signing
from sandfort.workers.webhook_dispatcher import WebhookDispatcher

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
HOOK_URL = "https://hooks.example.com/in"
PUBLIC_IP = "93.184.216.34"
LATE = timedelta(hours=1)


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    db_path = tmp_path / "wiring.db"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")
    command.upgrade(config, "head")
    url = f"sqlite+aiosqlite:///{db_path}"
    application = create_app(Settings(driver="fake", database_url=url, api_key_pepper="pepper"))
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture(autouse=True)
def public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolve(host: str) -> list[str]:
        return [PUBLIC_IP]

    monkeypatch.setattr("sandfort.webhooks.ssrf.resolve_host", resolve)


class Transport:
    """Answers every request with one status and remembers the requests."""

    def __init__(self, status: int) -> None:
        self._status = status
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self._status)


def metered_factory(app: FastAPI) -> Callable[[], UnitOfWorkPort]:
    return with_delivery_metrics(lambda: UnitOfWork(app.state.session_factory))


def metered_dispatcher(app: FastAPI, clock: FrozenClock, sent: Transport) -> WebhookDispatcher:
    return WebhookDispatcher(
        metered_factory(app),
        clock,
        interval_s=1,
        transport=httpx.MockTransport(sent),
    )


def counted(outcome: str) -> float:
    value = REGISTRY.get_sample_value(WEBHOOK_DELIVERIES_TOTAL, {"outcome": outcome})
    return value or 0.0


async def seed(app: FastAPI) -> tuple[str, WebhookEndpointRecord]:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    endpoint = WebhookEndpointRecord(
        id=new_id(WEBHOOK),
        org_id=org.id,
        url=HOOK_URL,
        secret=signing.generate_secret(),
        enabled=True,
        failure_count=0,
        event_types=[],
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.webhooks.add_endpoint(endpoint)
        publisher = OutboxEventPublisher(FrozenClock(NOW))
        payload = {"sandbox_id": "sbx_x", "state": "started"}
        await publisher.publish(uow, EventType.SANDBOX_STARTED, org.id, payload)
        await uow.commit()
    return org.id, endpoint


async def only_delivery(app: FastAPI, org_id: str, endpoint_id: str) -> WebhookDeliveryRecord:
    async with UnitOfWork(app.state.session_factory) as uow:
        (found,) = await delivery_queries(uow).list_deliveries(org_id, endpoint_id)
    return found


# --- 1. the lookups see through the metering decorator ------------------------------------


async def test_delivery_queries_and_event_lookup_accept_a_metered_unit_of_work(
    app: FastAPI,
) -> None:
    org_id, endpoint = await seed(app)
    await metered_dispatcher(app, FrozenClock(NOW), Transport(500)).run_once()
    expected = await only_delivery(app, org_id, endpoint.id)

    async with metered_factory(app)() as uow:
        queries = delivery_queries(uow)
        listed = await queries.list_deliveries(org_id, endpoint.id)
        fetched = await queries.get_delivery(org_id, endpoint.id, expected.id)
        event = await event_lookup(uow).get(expected.event_id)

    assert [d.id for d in listed] == [expected.id]
    assert fetched is not None and fetched.id == expected.id
    assert event is not None and event.id == expected.event_id


async def test_a_repository_that_is_neither_sql_nor_wrapping_one_is_still_refused() -> None:
    plain = cast(Any, SimpleNamespace(webhooks=object(), events=object()))

    with pytest.raises(InternalError):
        delivery_queries(plain)
    with pytest.raises(InternalError):
        event_lookup(plain)


# --- 2-4. the dispatcher wired as in production ---------------------------------------------


async def test_metered_dispatcher_sends_once_and_records_the_delivery(app: FastAPI) -> None:
    org_id, endpoint = await seed(app)
    clock, sent = FrozenClock(NOW), Transport(200)
    worker = metered_dispatcher(app, clock, sent)

    await worker.run_once()
    clock.advance(LATE)
    await worker.run_once()

    found = await only_delivery(app, org_id, endpoint.id)
    assert len(sent.requests) == 1
    assert (found.state, found.attempts, found.last_status) == ("delivered", 1, 200)
    assert len(found.attempt_history) == 1


async def test_metered_dispatcher_keeps_a_failed_attempt_pending_with_a_retry_time(
    app: FastAPI,
) -> None:
    org_id, endpoint = await seed(app)
    sent = Transport(500)

    await metered_dispatcher(app, FrozenClock(NOW), sent).run_once()

    found = await only_delivery(app, org_id, endpoint.id)
    assert len(sent.requests) == 1
    assert (found.state, found.attempts, found.last_status) == ("pending", 1, 500)
    assert found.next_attempt_at is not None
    assert len(found.attempt_history) == 1


async def test_metered_dispatcher_parks_a_delivery_whose_endpoint_is_not_usable(
    app: FastAPI,
) -> None:
    # A deleted endpoint takes its deliveries with it (foreign key plus delete_endpoint), so the
    # reachable "endpoint gone" case is a disabled one; both take the same park branch.
    org_id, endpoint = await seed(app)
    clock = FrozenClock(NOW)
    await metered_dispatcher(app, clock, Transport(500)).run_once()  # creates the delivery
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.webhooks.update_endpoint(endpoint.org_id, replace(endpoint, enabled=False))
        await uow.commit()
    clock.advance(LATE)
    sent = Transport(200)

    await metered_dispatcher(app, clock, sent).run_once()

    found = await only_delivery(app, org_id, endpoint.id)
    assert sent.requests == []
    assert (found.state, found.next_attempt_at, found.last_status) == ("disabled", None, None)
    assert [entry["kind"] for entry in found.attempt_history] == ["attempt", "parked"]


# --- 5. the wrapper still counts ------------------------------------------------------------


@pytest.mark.parametrize(("status", "outcome"), [(200, "delivered"), (500, "retrying")])
async def test_the_metrics_counter_is_incremented_once_per_recorded_state(
    app: FastAPI, status: int, outcome: str
) -> None:
    await seed(app)
    before = counted(outcome)
    clock = FrozenClock(NOW)
    worker = metered_dispatcher(app, clock, Transport(status))

    await worker.run_once()
    if status == 200:  # a second pass must not record (or send) anything again
        clock.advance(LATE)
        await worker.run_once()

    assert counted(outcome) - before == 1.0
