"""WP 4.2 events and webhooks over the ASGI app and a stub HTTP transport (daemon-free).

A temp SQLite database migrated to head. Name resolution is replaced by a seam returning a
public address, so no test touches the network; delivery goes to ``httpx.MockTransport``.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
from collections.abc import AsyncIterator, Callable, Iterator, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from cryptography.fernet import Fernet
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.repositories.ports import (
    UnitOfWorkPort,
    WebhookDeliveryRecord,
    WebhookEndpointRecord,
)
from sandfort.db.repositories.webhooks import delivery_queries
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import AuditEvent, EventType
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import SandboxState
from sandfort.errors import InternalError
from sandfort.ids import WEBHOOK, new_api_key_id, new_id, new_org_id
from sandfort.preflight import WEBHOOK_KEY_MESSAGE, prod_findings, webhook_key_findings
from sandfort.services.events import OutboxEventPublisher, with_sandbox_events
from sandfort.webhooks import signing
from sandfort.webhooks.delivery import DeliveryError, deliver
from sandfort.webhooks.secret_box import SECRET_MARKER, SecretBox
from sandfort.webhooks.ssrf import UrlRejected, vet_url
from sandfort.webhooks.ssrf import configure as configure_ssrf
from sandfort.workers.webhook_dispatcher import (
    BACKOFF_SCHEDULE_S,
    DISABLE_THRESHOLD,
    WebhookDispatcher,
    round_robin,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
HOOKS = "/v1/webhooks"
SANDBOXES = "/v1/sandboxes"
HOOK_URL = "https://hooks.example.com/in"
PUBLIC_IP = "93.184.216.34"
SCOPES = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.WEBHOOKS_WRITE})


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'webhooks.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as http:
        yield http


def resolve_to(monkeypatch: pytest.MonkeyPatch, addresses: Sequence[str]) -> None:
    async def resolve(host: str) -> list[str]:
        return list(addresses)

    monkeypatch.setattr("sandfort.webhooks.ssrf.resolve_host", resolve)


@pytest.fixture(autouse=True)
def public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    resolve_to(monkeypatch, [PUBLIC_IP])


def uow_factory(app: FastAPI) -> Callable[[], UnitOfWorkPort]:
    return lambda: UnitOfWork(app.state.session_factory)


async def add_org(app: FastAPI, slug: str) -> str:
    org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def seed_key(app: FastAPI, org_id: str) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=SCOPES,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    return await add_org(app, "acme")


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id)


@pytest.fixture
async def org_id_private(private_app: FastAPI) -> str:
    return await add_org(private_app, "acme")


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


class Receiver:
    """Records every request the delivery layer makes and answers with a fixed status."""

    def __init__(self, status: int = 200, headers: dict[str, str] | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self._status = status
        self._headers = headers or {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self._status, headers=self._headers)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)


def dispatcher(
    app: FastAPI, clock: FrozenClock, transport: httpx.AsyncBaseTransport
) -> WebhookDispatcher:
    return WebhookDispatcher(uow_factory(app), clock, interval_s=1, transport=transport)


async def add_endpoint(
    app: FastAPI,
    org_id: str,
    *,
    url: str = HOOK_URL,
    event_types: Sequence[str] = (),
) -> WebhookEndpointRecord:
    endpoint = WebhookEndpointRecord(
        id=new_id(WEBHOOK),
        org_id=org_id,
        url=url,
        secret=signing.generate_secret(),
        enabled=True,
        failure_count=0,
        event_types=list(event_types),
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.webhooks.add_endpoint(endpoint)
        await uow.commit()
    return endpoint


async def publish(
    app: FastAPI, org_id: str, event_type: EventType = EventType.SANDBOX_STARTED
) -> None:
    async with UnitOfWork(app.state.session_factory) as uow:
        payload = {"sandbox_id": "sbx_x", "state": "started"}
        await OutboxEventPublisher(FrozenClock(NOW)).publish(uow, event_type, org_id, payload)
        await uow.commit()


async def deliveries(app: FastAPI, org_id: str, endpoint_id: str) -> list[WebhookDeliveryRecord]:
    async with UnitOfWork(app.state.session_factory) as uow:
        return list(await delivery_queries(uow).list_deliveries(org_id, endpoint_id, limit=200))


async def stored_endpoint(app: FastAPI, org_id: str, endpoint_id: str) -> WebhookEndpointRecord:
    async with UnitOfWork(app.state.session_factory) as uow:
        found = await uow.webhooks.get_endpoint(org_id, endpoint_id)
    assert found is not None
    return found


async def audit_actions(app: FastAPI, org_id: str) -> list[str]:
    async with UnitOfWork(app.state.session_factory) as uow:
        rows: list[AuditEvent] = list(await uow.audit.list(org_id, limit=200))
    return [row.action for row in rows]


async def outbox_types(app: FastAPI) -> list[str]:
    async with UnitOfWork(app.state.session_factory) as uow:
        return [event.event_type for event in await uow.events.list_undispatched(limit=200)]


def reference_verify(secret: str, headers: httpx.Headers, body: bytes) -> bool:
    """Standard Webhooks verifier written from the public spec, independent of ``signing``."""
    key = base64.b64decode(secret.removeprefix("whsec_"))
    message = f"{headers['webhook-id']}.{headers['webhook-timestamp']}.".encode() + body
    expected = base64.b64encode(hmac.new(key, message, hashlib.sha256).digest()).decode()
    entries = [entry.split(",", 1) for entry in headers["webhook-signature"].split(" ")]
    return any(
        version == "v1" and hmac.compare_digest(sig, expected) for version, sig in entries
    )


# --- signing and end-to-end delivery ----------------------------------------------------


async def test_signed_delivery_validates_with_the_reference_verifier(
    app: FastAPI, org_id: str
) -> None:
    clock, receiver = FrozenClock(NOW), Receiver()
    endpoint = await add_endpoint(app, org_id)
    await publish(app, org_id)
    at = int(NOW.timestamp())

    await dispatcher(app, clock, receiver.transport).run_once()

    (request,) = receiver.requests
    assert request.url.host == PUBLIC_IP  # connected to the vetted ip
    assert request.headers["host"] == "hooks.example.com"  # with the original host
    assert reference_verify(endpoint.secret, request.headers, request.content)
    assert signing.verify(endpoint.secret, request.headers, request.content, now=at)
    assert not reference_verify(endpoint.secret, request.headers, request.content + b" ")
    assert json.loads(request.content)["type"] == "sandbox.started"
    (delivery,) = await deliveries(app, org_id, endpoint.id)
    assert (delivery.state, delivery.attempts, delivery.last_status) == ("delivered", 1, 200)


async def test_event_filter_selects_the_endpoints_that_receive_an_event(
    app: FastAPI, org_id: str
) -> None:
    other = await add_endpoint(app, org_id, event_types=["snapshot.*"])
    wildcard = await add_endpoint(app, org_id, event_types=["sandbox.*"])
    await publish(app, org_id)

    await dispatcher(app, FrozenClock(NOW), Receiver().transport).run_once()

    assert await deliveries(app, org_id, other.id) == []
    assert len(await deliveries(app, org_id, wildcard.id)) == 1


async def test_a_delivered_event_is_not_redelivered_on_the_next_pass(
    app: FastAPI, org_id: str
) -> None:
    clock, receiver = FrozenClock(NOW), Receiver()
    endpoint = await add_endpoint(app, org_id)
    await publish(app, org_id)
    worker = dispatcher(app, clock, receiver.transport)

    for _ in range(3):
        await worker.run_once()
        clock.advance(timedelta(hours=1))

    assert len(receiver.requests) == 1
    assert len(await deliveries(app, org_id, endpoint.id)) == 1


# --- ssrf --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8000/hook",
        "https://[::1]/hook",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.5/hook",
        "ftp://hooks.example.com/hook",
        "https://user:pw@hooks.example.com/hook",
        "https://hooks.example.com:22/hook",
    ],
)
async def test_unsafe_urls_are_rejected_at_creation(
    client: httpx.AsyncClient, key: str, url: str
) -> None:
    response = await client.post(HOOKS, headers=auth(key), json={"url": url})

    assert response.status_code == 422


async def test_hostname_resolving_to_a_private_ip_is_rejected_at_creation(
    client: httpx.AsyncClient, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolve_to(monkeypatch, ["10.1.2.3"])

    response = await client.post(HOOKS, headers=auth(key), json={"url": HOOK_URL})

    assert response.status_code == 422


@pytest.mark.parametrize(
    ("url", "resolved"),
    [
        ("http://127.0.0.1:8000/hook", [PUBLIC_IP]),
        ("http://169.254.169.254/latest/meta-data", [PUBLIC_IP]),
        (HOOK_URL, ["10.1.2.3"]),  # rebinding: public at creation, private at delivery
    ],
)
async def test_unsafe_urls_are_rejected_at_delivery_time(
    app: FastAPI, org_id: str, monkeypatch: pytest.MonkeyPatch, url: str, resolved: list[str]
) -> None:
    receiver = Receiver()
    endpoint = await add_endpoint(app, org_id, url=url)
    await publish(app, org_id)
    resolve_to(monkeypatch, resolved)

    await dispatcher(app, FrozenClock(NOW), receiver.transport).run_once()

    assert receiver.requests == []
    (delivery,) = await deliveries(app, org_id, endpoint.id)
    assert (delivery.state, delivery.attempts, delivery.last_status) == ("pending", 1, None)


@pytest.fixture
async def private_app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'private.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(
        driver="fake",
        database_url=url,
        api_key_pepper=PEPPER,
        webhook_allow_private_networks=True,
    )
    application = create_app(settings)
    try:
        yield application
    finally:
        await application.state.engine.dispose()
        configure_ssrf(allow_private_networks=False)


async def test_private_network_opt_in_admits_loopback_but_never_metadata(
    private_app: FastAPI, org_id_private: str
) -> None:
    key_value = await seed_key(private_app, org_id_private)
    transport = httpx.ASGITransport(app=private_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        loopback = {"url": "http://127.0.0.1:8000/hook"}
        metadata = {"url": "http://169.254.169.254/latest/meta-data"}
        admitted = await http.post(HOOKS, headers=auth(key_value), json=loopback)
        rejected = await http.post(HOOKS, headers=auth(key_value), json=metadata)

    assert admitted.status_code == 201
    assert rejected.status_code == 422


async def test_private_network_opt_in_delivers_to_loopback_not_metadata(
    private_app: FastAPI, org_id_private: str
) -> None:
    receiver = Receiver()
    loopback = await add_endpoint(private_app, org_id_private, url="http://127.0.0.1:8000/hook")
    metadata = await add_endpoint(
        private_app, org_id_private, url="http://169.254.169.254/latest/meta-data"
    )
    await publish(private_app, org_id_private)

    await dispatcher(private_app, FrozenClock(NOW), receiver.transport).run_once()

    (request,) = receiver.requests
    assert request.url.host == "127.0.0.1"
    (sent,) = await deliveries(private_app, org_id_private, loopback.id)
    assert sent.state == "delivered"
    (blocked,) = await deliveries(private_app, org_id_private, metadata.id)
    assert (blocked.state, blocked.last_status) == ("pending", None)


async def test_a_redirect_is_a_failure_and_is_never_followed(app: FastAPI, org_id: str) -> None:
    receiver = Receiver(302, {"location": "http://169.254.169.254/latest"})
    endpoint = await add_endpoint(app, org_id)
    await publish(app, org_id)

    await dispatcher(app, FrozenClock(NOW), receiver.transport).run_once()

    assert len(receiver.requests) == 1
    (delivery,) = await deliveries(app, org_id, endpoint.id)
    assert (delivery.state, delivery.last_status) == ("pending", 302)
    assert (await stored_endpoint(app, org_id, endpoint.id)).failure_count == 1


# --- backoff, dead deliveries and auto-disable -------------------------------------------


async def test_backoff_schedule_is_applied_per_attempt_then_the_delivery_goes_dead(
    app: FastAPI, org_id: str
) -> None:
    clock, receiver = FrozenClock(NOW), Receiver(500)
    endpoint = await add_endpoint(app, org_id)
    await publish(app, org_id)
    worker = dispatcher(app, clock, receiver.transport)

    for attempt, delay in enumerate(BACKOFF_SCHEDULE_S, start=1):
        await worker.run_once()
        (delivery,) = await deliveries(app, org_id, endpoint.id)
        assert (delivery.state, delivery.attempts) == ("pending", attempt)
        assert delivery.next_attempt_at == clock.now() + timedelta(seconds=delay)
        clock.advance(timedelta(seconds=delay) - timedelta(milliseconds=1))
        await worker.run_once()  # not due yet: nothing is sent
        assert len(receiver.requests) == attempt
        clock.advance(timedelta(milliseconds=1))

    await worker.run_once()
    (dead,) = await deliveries(app, org_id, endpoint.id)
    assert (dead.state, dead.attempts, dead.next_attempt_at) == ("failed", 6, None)
    clock.advance(timedelta(days=1))
    await worker.run_once()
    assert len(receiver.requests) == 6


async def test_fifty_consecutive_failures_disable_the_endpoint_and_audit_it(
    app: FastAPI, org_id: str
) -> None:
    clock, receiver = FrozenClock(NOW), Receiver(500)
    endpoint = await add_endpoint(app, org_id)
    for _ in range(9):
        await publish(app, org_id)
    worker = dispatcher(app, clock, receiver.transport)

    for _ in range(7):
        await worker.run_once()
        clock.advance(timedelta(seconds=301))

    stored = await stored_endpoint(app, org_id, endpoint.id)
    assert (stored.enabled, stored.failure_count) == (False, DISABLE_THRESHOLD)
    assert len(receiver.requests) == DISABLE_THRESHOLD
    assert (await audit_actions(app, org_id)).count("webhook.endpoint_disabled") == 1
    states = [item.state for item in await deliveries(app, org_id, endpoint.id)]
    assert states.count("disabled") == 4  # parked, not sent, once the endpoint was off


# --- concurrency, per-endpoint order, org fairness and the attempt deadline --------------

SLOW_HOST = "slow.example.com"
FAST_HOSTS = ("a.example.com", "b.example.com")
BACKSTOP_S = 5.0  # delivery deadline: only a regression ever waits this long
OVERLAP_WINDOW_S = 0.05  # how long a request stays open so an overlapping one would show
STALL_DEADLINE_S = 0.05


async def test_a_slow_endpoint_does_not_hold_back_the_other_endpoints(
    app: FastAPI, org_id: str
) -> None:
    slow = await add_endpoint(app, org_id, url=f"https://{SLOW_HOST}/in")
    fast = [await add_endpoint(app, org_id, url=f"https://{host}/in") for host in FAST_HOSTS]
    for _ in range(2):
        await publish(app, org_id)
    fast_requests: list[str] = []
    released = asyncio.Event()

    async def handle(request: httpx.Request) -> httpx.Response:
        if request.headers["host"] == SLOW_HOST:
            await released.wait()  # answers only once the fast endpoints got every delivery
        else:
            fast_requests.append(request.headers["host"])
            if len(fast_requests) == 2 * len(FAST_HOSTS):
                released.set()
        return httpx.Response(200)

    worker = WebhookDispatcher(
        uow_factory(app),
        FrozenClock(NOW),
        interval_s=1,
        timeout_s=BACKSTOP_S,
        transport=httpx.MockTransport(handle),
    )
    await worker.run_once()

    assert sorted(fast_requests) == sorted(FAST_HOSTS * 2)
    for endpoint in (slow, *fast):
        states = [item.state for item in await deliveries(app, org_id, endpoint.id)]
        assert states == ["delivered", "delivered"]


async def test_deliveries_to_one_endpoint_go_out_one_at_a_time_in_batch_order(
    app: FastAPI, org_id: str
) -> None:
    endpoint = await add_endpoint(app, org_id)
    for _ in range(2):
        await publish(app, org_id)
    received: list[str] = []
    in_flight = peak = 0

    async def handle(request: httpx.Request) -> httpx.Response:
        nonlocal in_flight, peak
        received.append(json.loads(request.content)["id"])
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(OVERLAP_WINDOW_S)  # room for a second attempt to overlap, if any
        in_flight -= 1
        return httpx.Response(200)

    await dispatcher(app, FrozenClock(NOW), httpx.MockTransport(handle)).run_once()

    stored = await deliveries(app, org_id, endpoint.id)  # id order, which is the batch order
    assert received == [item.event_id for item in stored]
    assert peak == 1
    assert [item.state for item in stored] == ["delivered", "delivered"]


def test_round_robin_interleaves_orgs_and_keeps_each_orgs_order() -> None:
    batch = [("a", 1), ("a", 2), ("a", 3), ("a", 4), ("b", 1), ("c", 1), ("c", 2)]

    ordered = round_robin(batch, key=lambda item: item[0])

    assert ordered == [("a", 1), ("b", 1), ("c", 1), ("a", 2), ("c", 2), ("a", 3), ("a", 4)]
    assert round_robin([], key=str) == []


async def test_a_stalled_resolver_fails_the_attempt_at_the_delivery_deadline(
    app: FastAPI, org_id: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    receiver = Receiver()
    endpoint = await add_endpoint(app, org_id)

    async def stall(host: str) -> list[str]:
        await asyncio.Event().wait()  # a resolver that never answers
        return []

    monkeypatch.setattr("sandfort.webhooks.ssrf.resolve_host", stall)

    with pytest.raises(DeliveryError) as raised:
        await deliver(
            endpoint,
            message_id="evt_x",
            timestamp=1,
            payload=b"{}",
            timeout_s=STALL_DEADLINE_S,
            transport=receiver.transport,
        )

    assert str(raised.value) == f"{endpoint.id}:TimeoutError"
    assert receiver.requests == []


# --- lifecycle events through the outbox -------------------------------------------------


async def test_lifecycle_events_land_in_the_outbox(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    created = await client.post(SANDBOXES, headers=auth(key), json={})
    sandbox_id = created.json()["data"]["id"]
    for action in ("stop", "start"):
        await client.post(f"{SANDBOXES}/{sandbox_id}/{action}", headers=auth(key))
    await client.delete(f"{SANDBOXES}/{sandbox_id}", headers=auth(key))

    expected = ["created", "started", "stopped", "started", "deleted"]
    assert sorted(await outbox_types(app)) == sorted(f"sandbox.{name}" for name in expected)


async def test_lifecycle_event_commits_and_rolls_back_with_the_transition(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    created = await client.post(SANDBOXES, headers=auth(key), json={})
    sandbox_id = created.json()["data"]["id"]
    before = await outbox_types(app)
    factory = with_sandbox_events(uow_factory(app), OutboxEventPublisher(FrozenClock(NOW)))

    async def stop(commit: bool) -> None:
        async with factory() as uow:
            current = await uow.sandboxes.get(org_id, sandbox_id)
            assert current is not None
            moved = current.model_copy(update={"state": SandboxState.STOPPED})
            await uow.sandboxes.update(org_id, moved, expected_version=current.version)
            if commit:
                await uow.commit()

    await stop(commit=False)
    assert await outbox_types(app) == before
    await stop(commit=True)
    assert (await outbox_types(app)).count("sandbox.stopped") == 1


# --- the non-negotiable error contract ---------------------------------------------------


async def test_transport_error_never_leaks_the_secret(
    app: FastAPI, org_id: str, caplog: pytest.LogCaptureFixture
) -> None:
    endpoint = await add_endpoint(app, org_id)
    await publish(app, org_id)
    secret = endpoint.secret
    encoded = base64.b64encode(secret.encode()).decode()
    for name in ("sandfort", "httpx", "httpcore"):
        caplog.set_level(logging.DEBUG, logger=name)

    def explode(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot connect, secret={secret} b64={encoded}")

    transport = httpx.MockTransport(explode)
    with pytest.raises(DeliveryError) as raised:
        await deliver(
            endpoint, message_id="evt_x", timestamp=1, payload=b"{}", transport=transport
        )
    await dispatcher(app, FrozenClock(NOW), transport).run_once()

    error = raised.value
    assert str(error) == f"{endpoint.id}:ConnectError"
    assert error.__cause__ is None and error.__context__ is None
    assert error.__suppress_context__
    assert f"{endpoint.id}:ConnectError" in caplog.text  # the dispatcher logged the safe form
    for needle in (secret, encoded, secret.removeprefix("whsec_")):
        assert needle not in str(error)
        assert needle not in repr(error)
        assert needle not in caplog.text


# --- endpoint api --------------------------------------------------------------------------


def data(response: httpx.Response, status: int) -> Any:
    assert response.status_code == status, response.text
    return response.json()["data"]


async def test_endpoint_requests_need_authentication(client: httpx.AsyncClient) -> None:
    assert (await client.get(HOOKS)).status_code == 401
    assert (await client.post(HOOKS, json={"url": HOOK_URL})).status_code == 401


async def test_endpoint_crud_happy_path(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    headers = auth(key)
    created = data(await client.post(HOOKS, headers=headers, json={"url": HOOK_URL}), 201)
    path = f"{HOOKS}/{created['id']}"
    assert created["secret"].startswith("whsec_")
    assert "secret" not in data(await client.get(path, headers=headers), 200)
    listed = data(await client.get(HOOKS, headers=headers), 200)
    assert [item["id"] for item in listed] == [created["id"]]
    assert all("secret" not in item for item in listed)

    body = {"enabled": False, "event_types": ["sandbox.*"]}
    updated = data(await client.patch(path, headers=headers, json=body), 200)
    assert (updated["enabled"], updated["event_types"]) == (False, ["sandbox.*"])
    unsafe = await client.patch(path, headers=headers, json={"url": "http://127.0.0.1/x"})
    assert unsafe.status_code == 422
    assert data(await client.get(f"{path}/deliveries", headers=headers), 200) == []

    assert data(await client.delete(path, headers=headers), 200)["id"] == created["id"]
    assert (await client.get(path, headers=headers)).status_code == 404
    actions = await audit_actions(app, org_id)
    assert {"webhook.endpoint_created", "webhook.endpoint_deleted"} <= set(actions)


async def test_another_orgs_endpoint_is_a_404(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    endpoint = await add_endpoint(app, org_id)
    foreign = auth(await seed_key(app, await add_org(app, "globex")))
    base = f"{HOOKS}/{endpoint.id}"

    assert (await client.get(base, headers=foreign)).status_code == 404
    assert (await client.patch(base, headers=foreign, json={"enabled": False})).status_code == 404
    assert (await client.delete(base, headers=foreign)).status_code == 404
    assert (await client.get(f"{base}/deliveries", headers=foreign)).status_code == 404
    redeliver = await client.post(f"{base}/deliveries/x/redeliver", headers=foreign)
    assert redeliver.status_code == 404


async def test_failed_delivery_can_be_redelivered_but_a_delivered_one_cannot(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    clock, failing = FrozenClock(NOW), Receiver(500)
    endpoint = await add_endpoint(app, org_id)
    await publish(app, org_id)
    worker = dispatcher(app, clock, failing.transport)
    for delay in (*BACKOFF_SCHEDULE_S, 0):
        await worker.run_once()
        clock.advance(timedelta(seconds=delay + 1))
    (dead,) = await deliveries(app, org_id, endpoint.id)
    assert dead.state == "failed"
    path = f"{HOOKS}/{endpoint.id}/deliveries/{dead.id}/redeliver"

    queued = data(await client.post(path, headers=auth(key)), 200)
    assert (queued["state"], queued["attempts"]) == ("pending", 0)
    assert queued["next_attempt_at"] is None  # due at once: the API never stamps a time
    await dispatcher(app, clock, Receiver().transport).run_once()

    (done,) = await deliveries(app, org_id, endpoint.id)
    assert done.state == "delivered"
    assert (await client.post(path, headers=auth(key))).status_code == 409


# --- secrets at rest ----------------------------------------------------------------------

SECRET_KEY = Fernet.generate_key().decode()


@pytest.fixture
async def keyed_app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'keyed.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(
        driver="fake", database_url=url, api_key_pepper=PEPPER, webhook_secret_key=SECRET_KEY
    )
    application = create_app(settings)
    try:
        yield application
    finally:
        await application.state.engine.dispose()


def keyed_dispatcher(app: FastAPI, transport: httpx.AsyncBaseTransport) -> WebhookDispatcher:
    return WebhookDispatcher(
        uow_factory(app),
        FrozenClock(NOW),
        interval_s=1,
        transport=transport,
        secret_box=SecretBox(SECRET_KEY),
    )


async def mint(app: FastAPI, org_id: str) -> tuple[str, str]:
    """Create an endpoint through the API; return (endpoint id, plaintext secret)."""
    key_value = await seed_key(app, org_id)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as http:
        response = await http.post(HOOKS, headers=auth(key_value), json={"url": HOOK_URL})
    created = data(response, 201)
    return created["id"], created["secret"]


async def test_minted_secret_is_stored_sealed_and_returned_in_plaintext_once(
    keyed_app: FastAPI,
) -> None:
    org = await add_org(keyed_app, "acme")

    endpoint_id, plaintext = await mint(keyed_app, org)

    stored = (await stored_endpoint(keyed_app, org, endpoint_id)).secret
    assert plaintext.startswith("whsec_")
    assert stored.startswith(SECRET_MARKER)
    assert plaintext not in stored
    assert SecretBox(SECRET_KEY).decrypt(stored) == plaintext


async def test_delivery_signs_with_the_unsealed_secret(keyed_app: FastAPI) -> None:
    org = await add_org(keyed_app, "acme")
    receiver = Receiver()
    _, plaintext = await mint(keyed_app, org)
    await publish(keyed_app, org)

    await keyed_dispatcher(keyed_app, receiver.transport).run_once()

    (request,) = receiver.requests
    assert reference_verify(plaintext, request.headers, request.content)


async def test_legacy_plaintext_row_still_delivers_when_a_key_is_configured(
    keyed_app: FastAPI,
) -> None:
    org = await add_org(keyed_app, "acme")
    receiver = Receiver()
    legacy = await add_endpoint(keyed_app, org)  # seeded directly: unmarked plaintext
    await publish(keyed_app, org)

    await keyed_dispatcher(keyed_app, receiver.transport).run_once()

    (request,) = receiver.requests
    assert reference_verify(legacy.secret, request.headers, request.content)
    (delivery,) = await deliveries(keyed_app, org, legacy.id)
    assert delivery.state == "delivered"


async def test_updating_a_legacy_endpoint_seals_its_secret(keyed_app: FastAPI) -> None:
    org = await add_org(keyed_app, "acme")
    legacy = await add_endpoint(keyed_app, org)
    key_value = await seed_key(keyed_app, org)
    transport = httpx.ASGITransport(app=keyed_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        patched = await http.patch(
            f"{HOOKS}/{legacy.id}", headers=auth(key_value), json={"enabled": True}
        )

    assert patched.status_code == 200
    assert "secret" not in patched.json()["data"]
    stored = (await stored_endpoint(keyed_app, org, legacy.id)).secret
    assert stored.startswith(SECRET_MARKER)
    assert SecretBox(SECRET_KEY).decrypt(stored) == legacy.secret


async def test_without_a_key_the_secret_is_stored_as_before(app: FastAPI, org_id: str) -> None:
    endpoint_id, plaintext = await mint(app, org_id)
    receiver = Receiver()
    await publish(app, org_id)

    await dispatcher(app, FrozenClock(NOW), receiver.transport).run_once()

    assert (await stored_endpoint(app, org_id, endpoint_id)).secret == plaintext
    (request,) = receiver.requests
    assert reference_verify(plaintext, request.headers, request.content)


def test_loader_rejects_a_malformed_webhook_secret_key() -> None:
    with pytest.raises(ValueError, match="WEBHOOK_SECRET_KEY"):
        Settings.from_env({"SANDFORT_WEBHOOK_SECRET_KEY": "not-a-fernet-key"})

    accepted = Settings.from_env({"SANDFORT_WEBHOOK_SECRET_KEY": SECRET_KEY})
    assert accepted.webhook_secret_key == SECRET_KEY


def test_secret_box_refuses_marked_values_it_cannot_open() -> None:
    sealed = SecretBox(SECRET_KEY).encrypt("whsec_x")

    assert SecretBox("").encrypt("whsec_x") == "whsec_x"
    assert SecretBox("").decrypt("whsec_x") == "whsec_x"
    with pytest.raises(InternalError):
        SecretBox("").decrypt(sealed)
    with pytest.raises(InternalError):
        SecretBox(Fernet.generate_key().decode()).decrypt(sealed)
    with pytest.raises(InternalError):
        SecretBox("not-a-fernet-key")


# --- https requirement and prod secret key ---------------------------------------------


@pytest.fixture
def reset_ssrf() -> Iterator[None]:
    yield
    configure_ssrf(allow_private_networks=False)


def test_require_https_defaults_off_and_parses_as_a_boolean() -> None:
    assert Settings().webhook_require_https is False
    assert Settings.from_env({}).webhook_require_https is False
    enabled = Settings.from_env({"SANDFORT_WEBHOOK_REQUIRE_HTTPS": "true"})
    assert enabled.webhook_require_https is True
    disabled = Settings.from_env({"SANDFORT_WEBHOOK_REQUIRE_HTTPS": "false"})
    assert disabled.webhook_require_https is False
    with pytest.raises(ValueError, match="SANDFORT_WEBHOOK_REQUIRE_HTTPS"):
        Settings.from_env({"SANDFORT_WEBHOOK_REQUIRE_HTTPS": "maybe"})


@pytest.mark.parametrize("raw", ["false", "true"])
def test_require_https_is_forced_true_in_prod(raw: str) -> None:
    settings = Settings.from_env(
        {
            "SANDFORT_ENVIRONMENT": "prod",
            "SANDFORT_WEBHOOK_SECRET_KEY": SECRET_KEY,
            "SANDFORT_WEBHOOK_REQUIRE_HTTPS": raw,
        }
    )
    assert settings.webhook_require_https is True


def test_prod_without_the_webhook_secret_key_loads_and_the_preflight_reports_it() -> None:
    settings = Settings.from_env({"SANDFORT_ENVIRONMENT": "prod"})

    assert settings.webhook_secret_key == ""
    assert WEBHOOK_KEY_MESSAGE in prod_findings(settings)
    blank = Settings.from_env({"SANDFORT_ENVIRONMENT": "prod", "SANDFORT_WEBHOOK_SECRET_KEY": " "})
    assert webhook_key_findings(blank) == [WEBHOOK_KEY_MESSAGE]


def test_dev_without_the_webhook_secret_key_is_unchanged() -> None:
    assert Settings.from_env({"SANDFORT_ENVIRONMENT": "dev"}).webhook_secret_key == ""
    assert Settings.from_env({}).webhook_secret_key == ""


async def test_vet_url_rejects_http_only_when_https_is_required(reset_ssrf: None) -> None:
    http_url = "http://hooks.example.com/in"

    assert (await vet_url(http_url)).scheme == "http"  # default: still admitted

    configure_ssrf(allow_private_networks=False, require_https=True)
    with pytest.raises(UrlRejected, match="webhook URLs must use https on this server"):
        await vet_url(http_url)

    configure_ssrf(allow_private_networks=False, require_https=False)
    assert (await vet_url(http_url)).scheme == "http"


async def test_https_still_passes_the_ssrf_checks_when_required(
    monkeypatch: pytest.MonkeyPatch, reset_ssrf: None
) -> None:
    configure_ssrf(allow_private_networks=False, require_https=True)

    vetted = await vet_url(HOOK_URL)
    assert (vetted.scheme, vetted.ip, vetted.port) == ("https", PUBLIC_IP, 443)

    with pytest.raises(UrlRejected, match="metadata"):
        await vet_url("https://169.254.169.254/latest")
    with pytest.raises(UrlRejected, match="loopback"):
        await vet_url("https://127.0.0.1/in")
    with pytest.raises(UrlRejected, match="port"):
        await vet_url("https://hooks.example.com:22/in")
    resolve_to(monkeypatch, ["10.0.0.5"])
    with pytest.raises(UrlRejected, match="private"):
        await vet_url(HOOK_URL)
