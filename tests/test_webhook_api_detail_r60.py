"""Webhook delivery detail in the API (round 60).

The delivery list and get routes carry the stored detail (event type, payload digest, last
error, attempt history), redelivery keeps the history and answers the refreshed record, and the
list filters on ``event_type`` and ``state`` with a cursor bound to them. FakeDriver, temp
SQLite database and the ASGI client; daemon-free, deliveries are seeded straight into the
database so no test touches the network.
"""

from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.routes import webhooks as routes
from sandfort.api.schemas.webhooks import (
    AttemptEntryResponse,
    DeliveryResponse,
    delivery_response,
)
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.repositories.ports import (
    OutboxEventRecord,
    WebhookDeliveryRecord,
    WebhookEndpointRecord,
)
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import EVENT, WEBHOOK, new_api_key_id, new_id, new_org_id
from sandfort.webhooks import signing

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
BASE_MS = int(NOW.timestamp() * 1000)
PEPPER = "test-pepper"
HOOKS = "/v1/webhooks"
SCOPES = frozenset({Scope.WEBHOOKS_WRITE})
NEW_FIELDS = ("event_type", "payload_sha256", "last_error", "attempt_history")
ENTRY_FIELDS = ("kind", "attempted_at", "status", "error", "duration_ms", "actor_id")
DIGEST = "a" * 64
FIRST = {
    "kind": "attempt",
    "attempted_at": "2026-11-11T11:00:00+00:00",
    "status": 500,
    "error": "http 500",
    "duration_ms": 42,
}
SECOND = {
    "kind": "attempt",
    "attempted_at": "2026-11-11T11:05:00+00:00",
    "status": None,
    "error": "timeout",
    "duration_ms": 10000,
}
DEAD: dict[str, Any] = {
    "state": "failed",
    "attempts": 6,
    "last_status": 500,
    "last_error": "timeout",
    "event_type": "sandbox.started",
    "payload_sha256": DIGEST,
    "attempt_history": (FIRST, SECOND),
}


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'api-detail.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(
        driver="fake", database_url=url, api_key_pepper=PEPPER, rate_limit_enabled=False
    )
    application = create_app(settings)
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.fixture(autouse=True)
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(routes, "_CLOCK", FrozenClock(NOW))


async def seed_org(app: FastAPI, slug: str) -> tuple[str, str, str]:
    """An org and a key: ``(org_id, key_id, secret)``."""
    org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=SCOPES,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored)
        await uow.commit()
    return org.id, stored.id, generated.key


async def add_endpoint(app: FastAPI, org_id: str) -> WebhookEndpointRecord:
    endpoint = WebhookEndpointRecord(
        id=new_id(WEBHOOK),
        org_id=org_id,
        url="https://hooks.example.com/in",
        secret=signing.generate_secret(),
        enabled=True,
        failure_count=0,
        event_types=[],
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.webhooks.add_endpoint(endpoint)
        await uow.commit()
    return endpoint


async def add_deliveries(
    app: FastAPI, org_id: str, endpoint_id: str, rows: Sequence[dict[str, Any]]
) -> list[WebhookDeliveryRecord]:
    """One delivery per row of overrides, ids ascending in the order given."""
    made: list[WebhookDeliveryRecord] = []
    async with UnitOfWork(app.state.session_factory) as uow:
        for position, extra in enumerate(rows):
            event = OutboxEventRecord(
                id=new_id(EVENT),
                org_id=org_id,
                event_type=extra.get("event_type", "sandbox.started"),
                payload={},
                created_at=NOW,
            )
            await uow.events.append(event)
            fields: dict[str, Any] = {
                "state": "pending",
                "attempts": 0,
                "next_attempt_at": None,
                "last_status": None,
                **extra,
            }
            delivery = WebhookDeliveryRecord(
                id=new_id(WEBHOOK, now_ms=BASE_MS + position),
                endpoint_id=endpoint_id,
                event_id=event.id,
                created_at=NOW,
                updated_at=NOW,
                **fields,
            )
            await uow.webhooks.record_delivery(delivery)
            made.append(delivery)
        await uow.commit()
    return made


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def data(response: httpx.Response, status: int = 200) -> Any:
    assert response.status_code == status, response.text
    return response.json()["data"]


def moment(text: str) -> datetime:
    return datetime.fromisoformat(text)


def ids_of(response: httpx.Response) -> list[str]:
    return [item["id"] for item in data(response)]


def issue_of(response: httpx.Response) -> dict[str, Any]:
    """The single validation issue of a 422 answer."""
    assert response.status_code == 422, response.text
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_ERROR"
    (issue,) = error["details"]["errors"]
    return dict(issue)


async def audit_actions(app: FastAPI, org_id: str) -> list[str]:
    async with UnitOfWork(app.state.session_factory) as uow:
        rows = list(await uow.audit.list(org_id, limit=200))
    return [row.action for row in rows]


class Scene:
    """An org with one endpoint, its key and the delivery list path."""

    def __init__(self, org_id: str, key_id: str, key: str, endpoint_id: str) -> None:
        self.org_id, self.key_id, self.key, self.endpoint_id = org_id, key_id, key, endpoint_id
        self.base = f"{HOOKS}/{endpoint_id}/deliveries"
        self.headers = auth(key)


@pytest.fixture
async def scene(app: FastAPI) -> Scene:
    org_id, key_id, key = await seed_org(app, "acme")
    endpoint = await add_endpoint(app, org_id)
    return Scene(org_id, key_id, key, endpoint.id)


# --- the new fields on list and get --------------------------------------------------------


async def test_list_carries_the_stored_delivery_detail(
    app: FastAPI, client: httpx.AsyncClient, scene: Scene
) -> None:
    (dead,) = await add_deliveries(app, scene.org_id, scene.endpoint_id, [DEAD])

    (item,) = data(await client.get(scene.base, headers=scene.headers))

    assert item["id"] == dead.id and item["event_id"] == dead.event_id
    assert item["event_type"] == "sandbox.started"
    assert item["payload_sha256"] == DIGEST
    assert item["last_error"] == "timeout"
    assert (item["state"], item["attempts"], item["last_status"]) == ("failed", 6, 500)
    assert moment(item["created_at"]) == NOW
    first, second = item["attempt_history"]
    assert set(first) == set(ENTRY_FIELDS)
    assert (first["kind"], first["status"], first["error"]) == ("attempt", 500, "http 500")
    assert (first["duration_ms"], first["actor_id"]) == (42, None)
    assert moment(first["attempted_at"]) == moment(str(FIRST["attempted_at"]))
    assert (second["status"], second["error"], second["duration_ms"]) == (None, "timeout", 10000)


async def test_a_delivery_without_detail_reads_as_empty(
    app: FastAPI, client: httpx.AsyncClient, scene: Scene
) -> None:
    await add_deliveries(app, scene.org_id, scene.endpoint_id, [{}])

    (item,) = data(await client.get(scene.base, headers=scene.headers))

    assert item["event_type"] is None
    assert item["payload_sha256"] is None
    assert item["last_error"] is None
    assert item["attempt_history"] == []


async def test_get_returns_the_same_record_as_the_list(
    app: FastAPI, client: httpx.AsyncClient, scene: Scene
) -> None:
    (dead,) = await add_deliveries(app, scene.org_id, scene.endpoint_id, [DEAD])
    (listed,) = data(await client.get(scene.base, headers=scene.headers))

    fetched = data(await client.get(f"{scene.base}/{dead.id}", headers=scene.headers))

    assert fetched == listed
    assert all(name in fetched for name in NEW_FIELDS)


async def test_get_of_a_missing_foreign_or_misplaced_delivery_is_404(
    app: FastAPI, client: httpx.AsyncClient, scene: Scene
) -> None:
    (dead,) = await add_deliveries(app, scene.org_id, scene.endpoint_id, [DEAD])
    other = await add_endpoint(app, scene.org_id)
    _, _, foreign_key = await seed_org(app, "globex")

    missing = await client.get(f"{scene.base}/{new_id(WEBHOOK)}", headers=scene.headers)
    misplaced = await client.get(
        f"{HOOKS}/{other.id}/deliveries/{dead.id}", headers=scene.headers
    )
    foreign = await client.get(f"{scene.base}/{dead.id}", headers=auth(foreign_key))
    anonymous = await client.get(f"{scene.base}/{dead.id}")

    statuses = [r.status_code for r in (missing, misplaced, foreign, anonymous)]
    assert statuses == [404, 404, 404, 401]


async def test_get_refuses_an_unknown_query_parameter(
    app: FastAPI, client: httpx.AsyncClient, scene: Scene
) -> None:
    (dead,) = await add_deliveries(app, scene.org_id, scene.endpoint_id, [DEAD])

    response = await client.get(f"{scene.base}/{dead.id}?state=failed", headers=scene.headers)

    assert issue_of(response)["loc"] == ["query", "state"]


def test_the_new_response_fields_are_documented() -> None:
    props = DeliveryResponse.model_json_schema()["properties"]
    entry_props = AttemptEntryResponse.model_json_schema()["properties"]

    assert all(props[name].get("description") for name in NEW_FIELDS)
    assert all(entry_props[name].get("description") for name in ENTRY_FIELDS)


def test_a_malformed_stored_entry_is_read_defensively_and_extra_keys_do_not_leak() -> None:
    odd = {"kind": 5, "attempted_at": "not a time", "status": "x", "secret": "whsec_leak"}
    record = WebhookDeliveryRecord(
        id=new_id(WEBHOOK),
        endpoint_id=new_id(WEBHOOK),
        event_id=new_id(EVENT),
        state="failed",
        attempts=6,
        next_attempt_at=None,
        last_status=None,
        created_at=NOW,
        updated_at=NOW,
        attempt_history=(odd,),
    )

    (entry,) = delivery_response(record).model_dump(mode="json")["attempt_history"]

    assert entry["kind"] == "attempt"
    assert (entry["attempted_at"], entry["status"]) == (None, None)
    assert "whsec_leak" not in str(entry)
    assert set(entry) == set(ENTRY_FIELDS)


# --- redeliver -----------------------------------------------------------------------------


async def test_redeliver_answers_the_refreshed_record_and_keeps_the_history(
    app: FastAPI, client: httpx.AsyncClient, scene: Scene
) -> None:
    parked = {**DEAD, "next_attempt_at": NOW + timedelta(days=1)}
    (dead,) = await add_deliveries(app, scene.org_id, scene.endpoint_id, [parked])

    reply = data(await client.post(f"{scene.base}/{dead.id}/redeliver", headers=scene.headers))

    assert (reply["state"], reply["attempts"], reply["last_status"]) == ("pending", 0, None)
    assert reply["last_error"] is None  # cleared together with last_status
    assert reply["next_attempt_at"] is None  # due at once; the dispatcher stamps the time
    assert moment(reply["updated_at"]) == NOW
    assert (reply["event_type"], reply["payload_sha256"]) == ("sandbox.started", DIGEST)
    first, second, marker = reply["attempt_history"]
    assert (first["status"], second["error"]) == (500, "timeout")
    assert marker["kind"] == "redelivered"
    assert marker["actor_id"] == scene.key_id
    assert moment(marker["attempted_at"]) == NOW
    assert (marker["status"], marker["error"], marker["duration_ms"]) == (None, None, None)
    assert data(await client.get(f"{scene.base}/{dead.id}", headers=scene.headers)) == reply


async def test_redeliver_does_not_schedule_from_the_api_clock(
    app: FastAPI,
    client: httpx.AsyncClient,
    scene: Scene,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(routes, "_CLOCK", FrozenClock(NOW + timedelta(days=2)))  # fast clock
    (dead,) = await add_deliveries(app, scene.org_id, scene.endpoint_id, [DEAD])

    reply = data(await client.post(f"{scene.base}/{dead.id}/redeliver", headers=scene.headers))

    assert (reply["state"], reply["next_attempt_at"]) == ("pending", None)
    async with UnitOfWork(app.state.session_factory) as uow:
        due = await uow.webhooks.due_deliveries(NOW, limit=10)  # a worker clock behind the API
    assert [item.id for item in due] == [dead.id]


async def test_redeliver_of_a_parked_delivery_clears_status_and_error_together(
    app: FastAPI, client: httpx.AsyncClient, scene: Scene
) -> None:
    parked = {**DEAD, "state": "disabled", "last_status": None, "last_error": "endpoint disabled"}
    (item,) = await add_deliveries(app, scene.org_id, scene.endpoint_id, [parked])

    reply = data(await client.post(f"{scene.base}/{item.id}/redeliver", headers=scene.headers))

    assert (reply["last_status"], reply["last_error"]) == (None, None)


async def test_redeliver_writes_one_audit_event(
    app: FastAPI, client: httpx.AsyncClient, scene: Scene
) -> None:
    (dead,) = await add_deliveries(app, scene.org_id, scene.endpoint_id, [DEAD])

    data(await client.post(f"{scene.base}/{dead.id}/redeliver", headers=scene.headers))

    actions = await audit_actions(app, scene.org_id)
    assert actions.count("webhook.redelivered") == 1


async def test_a_delivered_delivery_is_refused_and_its_history_is_untouched(
    app: FastAPI, client: httpx.AsyncClient, scene: Scene
) -> None:
    done = {**DEAD, "state": "delivered", "attempts": 2, "last_status": 204, "last_error": None}
    (delivered,) = await add_deliveries(app, scene.org_id, scene.endpoint_id, [done])
    path = f"{scene.base}/{delivered.id}"

    refused = await client.post(f"{path}/redeliver", headers=scene.headers)

    assert refused.status_code == 409, refused.text
    after = data(await client.get(path, headers=scene.headers))
    assert (after["state"], after["attempts"]) == ("delivered", 2)
    assert len(after["attempt_history"]) == 2
    assert "webhook.redelivered" not in await audit_actions(app, scene.org_id)


# --- filters -------------------------------------------------------------------------------

MIXED: list[dict[str, Any]] = [
    {"state": "delivered", "event_type": "sandbox.started"},
    {"state": "failed", "event_type": "sandbox.started"},
    {"state": "failed", "event_type": "sandbox.error"},
    {"state": "pending", "event_type": "sandbox.stopped"},
    {"state": "failed", "event_type": "sandbox.started"},
    {"state": "disabled", "event_type": "sandbox.error"},
]


async def seed_mixed(app: FastAPI, scene: Scene) -> list[str]:
    made = await add_deliveries(app, scene.org_id, scene.endpoint_id, MIXED)
    return [item.id for item in made]


async def test_event_type_filters_the_list(
    app: FastAPI, client: httpx.AsyncClient, scene: Scene
) -> None:
    ids = await seed_mixed(app, scene)
    params = {"event_type": "sandbox.started"}

    response = await client.get(scene.base, params=params, headers=scene.headers)

    assert ids_of(response) == [ids[0], ids[1], ids[4]]


async def test_state_filters_the_list(
    app: FastAPI, client: httpx.AsyncClient, scene: Scene
) -> None:
    ids = await seed_mixed(app, scene)

    failed = await client.get(scene.base, params={"state": "failed"}, headers=scene.headers)
    disabled = await client.get(scene.base, params={"state": "disabled"}, headers=scene.headers)

    assert ids_of(failed) == [ids[1], ids[2], ids[4]]
    assert ids_of(disabled) == [ids[5]]


async def test_both_filters_combine_and_an_empty_match_ends_the_list(
    app: FastAPI, client: httpx.AsyncClient, scene: Scene
) -> None:
    ids = await seed_mixed(app, scene)
    both_params = {"state": "failed", "event_type": "sandbox.started"}

    both = await client.get(scene.base, params=both_params, headers=scene.headers)
    none = await client.get(
        scene.base, params={"event_type": "nothing.here"}, headers=scene.headers
    )

    assert ids_of(both) == [ids[1], ids[4]]
    assert data(none) == [] and none.json()["meta"]["next_cursor"] is None


async def test_an_unknown_state_is_422_naming_the_parameter(
    client: httpx.AsyncClient, scene: Scene
) -> None:
    response = await client.get(scene.base, params={"state": "bogus"}, headers=scene.headers)

    assert issue_of(response)["loc"] == ["query", "state"]


async def test_filters_page_through_every_match_exactly_once(
    app: FastAPI, client: httpx.AsyncClient, scene: Scene
) -> None:
    ids = await seed_mixed(app, scene)
    seen: list[str] = []
    params: dict[str, Any] = {"state": "failed", "limit": 2}

    for _ in range(len(ids)):
        response = await client.get(scene.base, params=params, headers=scene.headers)
        page = ids_of(response)
        assert len(page) <= 2
        seen.extend(page)
        cursor = response.json()["meta"]["next_cursor"]
        if cursor is None:
            break
        params = {**params, "cursor": cursor}

    assert seen == [ids[1], ids[2], ids[4]]


async def test_a_short_scan_hands_back_a_cursor_to_continue_from(
    app: FastAPI, client: httpx.AsyncClient, scene: Scene, monkeypatch: pytest.MonkeyPatch
) -> None:
    ids = await seed_mixed(app, scene)
    monkeypatch.setattr(routes, "SCAN_BATCH", 2)
    monkeypatch.setattr(routes, "SCAN_CAP", 2)
    seen: list[str] = []
    params: dict[str, Any] = {"state": "failed", "limit": 1}

    for _ in range(len(ids) + 2):
        response = await client.get(scene.base, params=params, headers=scene.headers)
        seen.extend(ids_of(response))
        cursor = response.json()["meta"]["next_cursor"]
        if cursor is None:
            break
        params = {**params, "cursor": cursor}

    assert seen == [ids[1], ids[2], ids[4]]
    assert cursor is None


# --- cursor binding ------------------------------------------------------------------------


async def first_cursor(client: httpx.AsyncClient, scene: Scene, params: dict[str, Any]) -> str:
    query = {**params, "limit": 1}
    response = await client.get(scene.base, params=query, headers=scene.headers)
    cursor = response.json()["meta"]["next_cursor"]
    assert isinstance(cursor, str)
    return cursor


async def test_a_cursor_pages_on_with_the_filter_it_was_issued_for(
    app: FastAPI, client: httpx.AsyncClient, scene: Scene
) -> None:
    ids = await seed_mixed(app, scene)
    filt = {"event_type": "sandbox.started"}
    cursor = await first_cursor(client, scene, filt)

    response = await client.get(
        scene.base, params={**filt, "cursor": cursor}, headers=scene.headers
    )

    assert ids_of(response) == [ids[1], ids[4]]


async def test_a_cursor_is_refused_for_another_event_type_or_none(
    app: FastAPI, client: httpx.AsyncClient, scene: Scene
) -> None:
    await seed_mixed(app, scene)
    cursor = await first_cursor(client, scene, {"event_type": "sandbox.started"})
    changed = {"event_type": "sandbox.error", "cursor": cursor}

    other = await client.get(scene.base, params=changed, headers=scene.headers)
    bare = await client.get(scene.base, params={"cursor": cursor}, headers=scene.headers)

    for response in (other, bare):
        issue = issue_of(response)
        assert issue["loc"] == ["query", "cursor"]
        assert issue["ctx"]["fields"] == ["event_type"]


async def test_a_cursor_is_refused_when_a_state_filter_is_added_or_changed(
    app: FastAPI, client: httpx.AsyncClient, scene: Scene
) -> None:
    await seed_mixed(app, scene)
    plain = await first_cursor(client, scene, {})
    failed = await first_cursor(client, scene, {"state": "failed"})

    added = await client.get(
        scene.base, params={"state": "failed", "cursor": plain}, headers=scene.headers
    )
    changed = await client.get(
        scene.base, params={"state": "pending", "cursor": failed}, headers=scene.headers
    )

    assert issue_of(added)["ctx"]["fields"] == ["state"]
    assert issue_of(changed)["ctx"]["fields"] == ["state"]


async def test_a_cursor_is_refused_on_another_endpoint(
    app: FastAPI, client: httpx.AsyncClient, scene: Scene
) -> None:
    await seed_mixed(app, scene)
    other = await add_endpoint(app, scene.org_id)
    cursor = await first_cursor(client, scene, {})

    response = await client.get(
        f"{HOOKS}/{other.id}/deliveries", params={"cursor": cursor}, headers=scene.headers
    )

    assert issue_of(response)["ctx"]["fields"] == ["endpoint_id"]


# --- guards --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "values"),
    [
        ("event_type", ("sandbox.started", "sandbox.error")),
        ("state", ("failed", "pending")),
        ("cursor", ("a", "b")),
        ("limit", ("1", "2")),
    ],
)
async def test_a_repeated_single_value_parameter_is_422(
    client: httpx.AsyncClient, scene: Scene, name: str, values: tuple[str, ...]
) -> None:
    response = await client.get(
        scene.base, params=[(name, value) for value in values], headers=scene.headers
    )

    issue = issue_of(response)
    assert issue["loc"] == ["query", name]
    assert issue["msg"] == f"{name} must be given once"


async def test_an_unknown_query_parameter_is_422(
    client: httpx.AsyncClient, scene: Scene
) -> None:
    response = await client.get(scene.base, params={"status": "failed"}, headers=scene.headers)

    issue = issue_of(response)
    assert (issue["type"], issue["loc"]) == ("extra_forbidden", ["query", "status"])


async def test_the_guards_answer_after_authentication_and_the_limit_is_bounded(
    client: httpx.AsyncClient, scene: Scene
) -> None:
    anonymous = await client.get(scene.base, params={"state": "bogus", "extra": "1"})
    too_small = await client.get(scene.base, params={"limit": 0}, headers=scene.headers)

    assert anonymous.status_code == 401
    assert too_small.status_code == 422
