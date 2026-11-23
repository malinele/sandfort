"""Webhook delivery detail (round 60): migration 0022, attempt history, failure classes.

A temp SQLite database migrated to head. Name resolution is replaced by a seam returning a
public address and delivery goes to ``httpx.MockTransport``, so no test touches the network.
"""

import hashlib
import socket
import sqlite3
import ssl
from collections.abc import AsyncIterator
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.repositories.ports import WebhookDeliveryRecord, WebhookEndpointRecord
from sandfort.db.repositories.webhooks import delivery_queries
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import EventType
from sandfort.domain.org import Org
from sandfort.ids import WEBHOOK, new_id, new_org_id
from sandfort.services.events import OutboxEventPublisher
from sandfort.webhooks import signing
from sandfort.webhooks.delivery import (
    MAX_ERROR_CHARS,
    MAX_HISTORY_ENTRIES,
    append_capped,
    classify_failure,
    redeliver,
)
from sandfort.workers.webhook_attempts import AttemptOutcome, failure_text
from sandfort.workers.webhook_dispatcher import BACKOFF_SCHEDULE_S, WebhookDispatcher

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
HOOK_URL = "https://hooks.example.com/in?token=hook-url-secret"
PUBLIC_IP = "93.184.216.34"
STAMP = "2026-11-11 12:00:00"
NEW_COLUMNS = {"event_type", "payload_sha256", "last_error", "attempt_history"}
LATE = timedelta(seconds=BACKOFF_SCHEDULE_S[-1] + 1)
SEED_SQL = f"""
INSERT INTO organizations (id, name, slug, status, created_at, updated_at)
  VALUES ('org_a', 'A', 'a', 'active', '{STAMP}', '{STAMP}');
INSERT INTO webhook_endpoints (id, org_id, url, secret, enabled, failure_count, event_types,
  created_at) VALUES ('whk_a', 'org_a', 'https://h.example.com/', 's', 1, 0, '[]', '{STAMP}');
INSERT INTO outbox_events (id, org_id, event_type, payload, created_at, attempts)
  VALUES ('evt_a', 'org_a', 'sandbox.started', '{{}}', '{STAMP}', 0);
INSERT INTO webhook_deliveries (id, endpoint_id, event_id, state, attempts, created_at,
  updated_at) VALUES ('whd_a', 'whk_a', 'evt_a', 'pending', 0, '{STAMP}', '{STAMP}');
"""

type Step = int | Exception


def alembic_config(db_path: Path) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")
    return config


def delivery_columns(db_path: Path) -> set[str]:
    with closing(sqlite3.connect(db_path)) as connection:
        rows = connection.execute("PRAGMA table_info(webhook_deliveries)").fetchall()
    return {row[1] for row in rows}


def test_migration_adds_columns_with_safe_defaults_and_downgrade_drops_them(
    tmp_path: Path,
) -> None:
    pytest.importorskip("aiosqlite")
    db_path = tmp_path / "migrated.db"
    config = alembic_config(db_path)
    command.upgrade(config, "0021")
    with closing(sqlite3.connect(db_path)) as connection:
        connection.executescript(SEED_SQL)
    before = delivery_columns(db_path)

    command.upgrade(config, "0022")
    after = delivery_columns(db_path)
    with closing(sqlite3.connect(db_path)) as connection:
        row = connection.execute(
            "SELECT event_type, payload_sha256, last_error, attempt_history"
            " FROM webhook_deliveries WHERE id = 'whd_a'"
        ).fetchone()
    command.downgrade(config, "0021")
    with closing(sqlite3.connect(db_path)) as connection:
        kept = connection.execute("SELECT id, state FROM webhook_deliveries").fetchall()

    assert not NEW_COLUMNS & before
    assert NEW_COLUMNS <= after
    assert row == (None, None, None, "[]")
    assert delivery_columns(db_path) == before
    assert kept == [("whd_a", "pending")]


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    db_path = tmp_path / "detail.db"
    command.upgrade(alembic_config(db_path), "head")
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


class Script:
    """A transport that plays one step per request: a status to answer or an error to raise."""

    def __init__(self, *steps: Step) -> None:
        self._steps = list(steps)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        step = self._steps[min(len(self.requests), len(self._steps) - 1)]
        self.requests.append(request)
        if isinstance(step, Exception):
            raise step
        return httpx.Response(step)


def dispatcher(app: FastAPI, clock: FrozenClock, script: Script) -> WebhookDispatcher:
    return WebhookDispatcher(
        lambda: UnitOfWork(app.state.session_factory),
        clock,
        interval_s=1,
        transport=httpx.MockTransport(script),
    )


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
        payload = {"sandbox_id": "sbx_x", "state": "started"}
        publisher = OutboxEventPublisher(FrozenClock(NOW))
        await publisher.publish(uow, EventType.SANDBOX_STARTED, org.id, payload)
        await uow.commit()
    return org.id, endpoint


async def only_delivery(app: FastAPI, org_id: str, endpoint_id: str) -> WebhookDeliveryRecord:
    async with UnitOfWork(app.state.session_factory) as uow:
        (found,) = await delivery_queries(uow).list_deliveries(org_id, endpoint_id)
    return found


async def fail_until_dead(app: FastAPI, clock: FrozenClock) -> None:
    worker = dispatcher(app, clock, Script(500))
    for _ in range(len(BACKOFF_SCHEDULE_S) + 1):
        await worker.run_once()
        clock.advance(LATE)


async def test_delivery_row_records_event_type_event_id_created_at_and_body_digest(
    app: FastAPI,
) -> None:
    org_id, endpoint = await seed(app)
    script = Script(200)

    await dispatcher(app, FrozenClock(NOW), script).run_once()

    found = await only_delivery(app, org_id, endpoint.id)
    (request,) = script.requests
    assert found.event_type == "sandbox.started"
    assert found.created_at == NOW
    assert found.event_id.startswith("evt_")
    assert found.payload_sha256 == hashlib.sha256(request.content).hexdigest()
    assert found.last_error is None


async def test_history_gains_one_entry_per_attempt_in_the_same_update(app: FastAPI) -> None:
    org_id, endpoint = await seed(app)
    clock, script = FrozenClock(NOW), Script(500, 503, 204)
    worker = dispatcher(app, clock, script)

    seen: list[WebhookDeliveryRecord] = []
    for delay in (BACKOFF_SCHEDULE_S[0], BACKOFF_SCHEDULE_S[1], 0):
        await worker.run_once()
        seen.append(await only_delivery(app, org_id, endpoint.id))
        clock.advance(timedelta(seconds=delay))

    assert [len(d.attempt_history) for d in seen] == [1, 2, 3]
    assert [d.attempts for d in seen] == [1, 2, 3]
    assert [e["status"] for e in seen[-1].attempt_history] == [500, 503, 204]
    assert [e["error"] for e in seen[-1].attempt_history] == ["http 500", "http 503", None]
    assert [d.last_error for d in seen] == ["http 500", "http 503", None]
    assert seen[-1].state == "delivered"
    first = seen[0].attempt_history[0]
    assert first["attempted_at"] == NOW.isoformat()
    assert isinstance(first["duration_ms"], int) and first["duration_ms"] >= 0
    assert seen[-1].attempt_history[:2] == seen[1].attempt_history  # earlier entries unchanged


async def test_history_is_capped_at_the_maximum_attempt_count(app: FastAPI) -> None:
    org_id, endpoint = await seed(app)

    await fail_until_dead(app, FrozenClock(NOW))

    found = await only_delivery(app, org_id, endpoint.id)
    assert found.state == "failed"
    assert found.attempts == MAX_HISTORY_ENTRIES == len(BACKOFF_SCHEDULE_S) + 1
    assert len(found.attempt_history) == MAX_HISTORY_ENTRIES


def test_append_capped_keeps_the_newest_entries_and_does_not_mutate_the_input() -> None:
    history = tuple({"n": n} for n in range(5))

    grown = append_capped(history, {"n": 5}, cap=4)

    assert [e["n"] for e in grown] == [2, 3, 4, 5]
    assert [e["n"] for e in history] == [0, 1, 2, 3, 4]


def tls_failure() -> Exception:
    error = httpx.ConnectError("tls handshake")
    error.__cause__ = ssl.SSLError("certificate verify failed")
    return error


@pytest.mark.parametrize(
    ("step", "expected"),
    [
        (httpx.ConnectError("refused"), "connect"),
        (tls_failure(), "tls"),
        (httpx.ReadTimeout("slow"), "timeout"),
        (TimeoutError(), "timeout"),
        (503, "http 503"),
        (302, "http 302"),
        (httpx.RemoteProtocolError("Receive buffer too long"), "body too large"),
        (RuntimeError("boom"), "transport error (RuntimeError)"),
    ],
)
async def test_last_error_names_the_failure_class(
    app: FastAPI, step: Step, expected: str
) -> None:
    org_id, endpoint = await seed(app)

    await dispatcher(app, FrozenClock(NOW), Script(step)).run_once()

    found = await only_delivery(app, org_id, endpoint.id)
    (entry,) = found.attempt_history
    assert found.last_error == expected
    assert entry["error"] == expected
    assert (found.state, found.attempts) == ("pending", 1)


@pytest.mark.parametrize(
    ("addresses", "expected"),
    [(socket.gaierror(socket.EAI_NONAME, "unknown host"), "dns"), (["10.0.0.5"], "ssrf refused")],
)
async def test_resolver_failure_classes_send_no_request(
    app: FastAPI, monkeypatch: pytest.MonkeyPatch, addresses: list[str] | Exception, expected: str
) -> None:
    async def resolve(host: str) -> list[str]:
        if isinstance(addresses, Exception):
            raise addresses
        return addresses

    monkeypatch.setattr("sandfort.webhooks.ssrf.resolve_host", resolve)
    org_id, endpoint = await seed(app)
    script = Script(200)

    await dispatcher(app, FrozenClock(NOW), script).run_once()

    found = await only_delivery(app, org_id, endpoint.id)
    assert found.last_error == expected
    assert found.attempt_history[0]["status"] is None
    assert script.requests == []


async def test_stored_failure_text_never_carries_the_url_or_the_exception_text(
    app: FastAPI,
) -> None:
    org_id, endpoint = await seed(app)
    leaky = httpx.ConnectError(f"cannot reach {HOOK_URL} with {endpoint.secret}")

    await dispatcher(app, FrozenClock(NOW), Script(leaky)).run_once()

    found = await only_delivery(app, org_id, endpoint.id)
    stored = repr((found.last_error, found.attempt_history))
    assert "hook-url-secret" not in stored
    assert endpoint.secret not in stored


def test_failure_text_is_bounded_and_names_the_outcome() -> None:
    long_name = type("E" * 500, (Exception,), {})
    long_text = failure_text(AttemptOutcome(None, classify_failure(long_name()), 1))

    assert long_text is not None
    assert len(long_text) == MAX_ERROR_CHARS == 200
    assert failure_text(AttemptOutcome(204, None, 1)) is None
    assert failure_text(AttemptOutcome(404, None, 1)) == "http 404"


def failed_record(entries: int) -> WebhookDeliveryRecord:
    history = tuple(
        {"kind": "attempt", "attempted_at": NOW.isoformat(), "status": 500, "n": n}
        for n in range(entries)
    )
    return WebhookDeliveryRecord(
        id=new_id(WEBHOOK),
        endpoint_id="whk_x",
        event_id="evt_x",
        state="failed",
        attempts=entries,
        next_attempt_at=None,
        last_status=500,
        created_at=NOW,
        updated_at=NOW,
        last_error="http 500",
        attempt_history=history,
    )


def test_redeliver_resets_the_cycle_and_appends_a_marker_after_the_old_history() -> None:
    record = failed_record(3)
    later = NOW + timedelta(hours=1)

    again = redeliver(record, actor_id="usr_ana", now=later)

    assert (again.state, again.attempts, again.next_attempt_at) == ("pending", 0, None)
    assert again.updated_at == later
    assert (again.id, again.endpoint_id, again.event_id) == (
        record.id,
        record.endpoint_id,
        record.event_id,
    )
    assert (again.last_status, again.last_error) == (None, None)  # cleared together
    assert again.attempt_history[:3] == record.attempt_history
    marker = again.attempt_history[3]
    assert marker["kind"] == "redelivered"
    assert marker["actor_id"] == "usr_ana"
    assert marker["at"] == later.isoformat()
    assert len(record.attempt_history) == 3  # the input record is not changed


def test_redeliver_keeps_the_history_within_the_cap() -> None:
    again = redeliver(failed_record(MAX_HISTORY_ENTRIES), actor_id="usr_ana", now=NOW)

    assert len(again.attempt_history) == MAX_HISTORY_ENTRIES
    assert again.attempt_history[-1]["kind"] == "redelivered"
    assert again.attempt_history[0]["n"] == 1  # the oldest entry made room


async def test_redelivered_delivery_is_sent_again_and_the_history_continues(
    app: FastAPI,
) -> None:
    org_id, endpoint = await seed(app)
    clock = FrozenClock(NOW)
    await fail_until_dead(app, clock)
    dead = await only_delivery(app, org_id, endpoint.id)
    assert dead.state == "failed"

    async with UnitOfWork(app.state.session_factory) as uow:
        requeued = redeliver(dead, actor_id="usr_ana", now=clock.now())
        assert await uow.webhooks.update_delivery_state(requeued) is not None
        await uow.commit()
    healthy = Script(200)
    await dispatcher(app, clock, healthy).run_once()

    found = await only_delivery(app, org_id, endpoint.id)
    assert (found.state, found.attempts, found.last_status) == ("delivered", 1, 200)
    assert found.last_error is None
    assert [entry["kind"] for entry in found.attempt_history][-2:] == ["redelivered", "attempt"]
    assert found.attempt_history[-1]["status"] == 200
    assert len(found.attempt_history) == MAX_HISTORY_ENTRIES
    assert len(healthy.requests) == 1


# --- review fixes: in-flight redelivery, parked entries, event_type backfill ---------------


async def test_a_redelivery_during_an_attempt_keeps_its_marker_in_the_history(
    app: FastAPI,
) -> None:
    org_id, endpoint = await seed(app)
    clock = FrozenClock(NOW)

    async def redeliver_midflight(request: httpx.Request) -> httpx.Response:
        current = await only_delivery(app, org_id, endpoint.id)
        async with UnitOfWork(app.state.session_factory) as uow:
            marked = redeliver(current, actor_id="usr_ana", now=clock.now())
            assert await uow.webhooks.update_delivery_state(marked) is not None
            await uow.commit()
        return httpx.Response(500)

    worker = WebhookDispatcher(
        lambda: UnitOfWork(app.state.session_factory),
        clock,
        interval_s=1,
        transport=httpx.MockTransport(redeliver_midflight),
    )

    await worker.run_once()

    found = await only_delivery(app, org_id, endpoint.id)
    assert [entry["kind"] for entry in found.attempt_history] == ["redelivered", "attempt"]
    assert found.attempt_history[0]["actor_id"] == "usr_ana"
    assert found.last_error == "http 500"


async def disable_endpoint(app: FastAPI, endpoint: WebhookEndpointRecord) -> None:
    async with UnitOfWork(app.state.session_factory) as uow:
        stored = await uow.webhooks.get_endpoint(endpoint.org_id, endpoint.id)
        assert stored is not None
        await uow.webhooks.update_endpoint(endpoint.org_id, replace(stored, enabled=False))
        await uow.commit()


async def test_a_parked_delivery_gets_a_parked_entry_and_a_last_error(app: FastAPI) -> None:
    org_id, endpoint = await seed(app)
    clock = FrozenClock(NOW)
    await dispatcher(app, clock, Script(500)).run_once()  # one failed attempt, retry pending
    assert (await only_delivery(app, org_id, endpoint.id)).last_status == 500
    await disable_endpoint(app, endpoint)
    clock.advance(LATE)
    script = Script(200)

    await dispatcher(app, clock, script).run_once()

    found = await only_delivery(app, org_id, endpoint.id)
    assert (found.state, found.next_attempt_at) == ("disabled", None)
    assert found.last_error == "endpoint disabled"
    assert found.last_status is None  # the stale 500 of the earlier attempt is cleared
    assert [entry["kind"] for entry in found.attempt_history] == ["attempt", "parked"]
    parked = found.attempt_history[-1]
    assert parked["error"] == "endpoint disabled"
    assert parked["attempted_at"] == clock.now().isoformat()
    assert (parked["status"], parked["duration_ms"]) == (None, None)
    assert script.requests == []


async def legacy_delivery(app: FastAPI, endpoint: WebhookEndpointRecord) -> WebhookDeliveryRecord:
    """A pending delivery as written before the detail migration: no event type, no digest."""
    async with UnitOfWork(app.state.session_factory) as uow:
        (event,) = await uow.events.list_undispatched(limit=10)
        legacy = WebhookDeliveryRecord(
            id=new_id(WEBHOOK),
            endpoint_id=endpoint.id,
            event_id=event.id,
            state="pending",
            attempts=0,
            next_attempt_at=None,
            last_status=None,
            created_at=NOW,
            updated_at=NOW,
        )
        await uow.webhooks.record_delivery(legacy)
        await uow.events.mark_dispatched(event.id, NOW)
        await uow.commit()
    return legacy


async def test_a_legacy_row_gets_its_event_type_when_the_dispatcher_loads_it(
    app: FastAPI,
) -> None:
    org_id, endpoint = await seed(app)
    legacy = await legacy_delivery(app, endpoint)
    assert legacy.event_type is None
    await disable_endpoint(app, endpoint)  # parked: it is loaded but never attempted

    await dispatcher(app, FrozenClock(NOW), Script(200)).run_once()

    found = await only_delivery(app, org_id, endpoint.id)
    assert found.state == "disabled"
    assert found.event_type == "sandbox.started"


async def test_a_legacy_row_is_found_by_the_event_type_filter_after_it_is_loaded(
    app: FastAPI,
) -> None:
    org_id, endpoint = await seed(app)
    await legacy_delivery(app, endpoint)

    await dispatcher(app, FrozenClock(NOW), Script(500)).run_once()

    found = await only_delivery(app, org_id, endpoint.id)
    assert found.event_type == "sandbox.started"
    assert found.payload_sha256 is not None
    assert len(found.attempt_history) == 1
