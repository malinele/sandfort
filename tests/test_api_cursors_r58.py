"""Round 58: every list route binds its cursor to the resource and to its filter.

A cursor issued by one list is refused by another with 422 ("cursor was issued for sandboxes,
not audit-events"); the audit-events cursor is bound to its filters and the jobs and webhook
deliveries cursors to theirs, naming the differing fields. Same-filter paging still works, and
an older unbound cursor is still accepted by the list that issued it.
FakeDriver, temp SQLite migrated to head, httpx over ASGI (no network, no sockets).
"""

import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402

from sandfort.api.pagination import (  # noqa: E402
    AUDIT_EVENTS,
    JOBS,
    SNAPSHOTS,
    VOLUMES,
    WEBHOOK_DELIVERIES,
    encode_cursor,
)
from sandfort.db.repositories.ports import (  # noqa: E402
    JobRecord,
    OutboxEventRecord,
    WebhookDeliveryRecord,
    WebhookEndpointRecord,
)
from sandfort.db.unit_of_work import UnitOfWork  # noqa: E402
from sandfort.domain.events import EventType  # noqa: E402
from sandfort.domain.org import Scope  # noqa: E402
from sandfort.ids import (  # noqa: E402
    AUDIT,
    EVENT,
    JOB,
    SANDBOX,
    SNAPSHOT,
    VOLUME,
    WEBHOOK,
    new_id,
)
from test_api_sandboxes import NOW, add_org, migrated_app, seed_key, send  # noqa: E402

SCOPES = frozenset(
    {
        Scope.SANDBOXES_READ,
        Scope.SANDBOXES_WRITE,
        Scope.SNAPSHOTS_READ,
        Scope.SNAPSHOTS_WRITE,
        Scope.VOLUMES_READ,
        Scope.VOLUMES_WRITE,
        Scope.WEBHOOKS_WRITE,
        Scope.AUDIT_READ,
    }
)
COUNT = 3
AUDIT_PATH = "/v1/audit-events"
FILTER_MESSAGE = "cursor was issued for a different filter or order"
ENDPOINT_ID = new_id(WEBHOOK)  # the cursor is checked before the endpoint is looked up
PREFIX_BY_RESOURCE = {
    AUDIT_EVENTS: AUDIT,
    SNAPSHOTS: SNAPSHOT,
    VOLUMES: VOLUME,
    JOBS: JOB,
    WEBHOOK_DELIVERIES: WEBHOOK,
}
ROUTES = [
    (AUDIT_PATH, AUDIT_EVENTS),
    ("/v1/snapshots", SNAPSHOTS),
    ("/v1/volumes", VOLUMES),
    ("/v1/jobs", JOBS),
    (f"/v1/webhooks/{ENDPOINT_ID}/deliveries", WEBHOOK_DELIVERIES),
]
CROSS = [
    (path, resource, issuer)
    for path, resource in ROUTES
    for issuer in sorted(PREFIX_BY_RESOURCE)
    if issuer != resource
]


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    async with migrated_app(tmp_path) as application:
        yield application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    return await add_org(app, "cursors58")


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id, SCOPES)


def url(path: str, *parts: str) -> str:
    query = "&".join(part for part in parts if part)
    return f"{path}?{query}" if query else path


def refused(body: dict[str, Any]) -> dict[str, Any]:
    assert body["error"]["code"] == "VALIDATION_ERROR"
    issue: dict[str, Any] = body["error"]["details"]["errors"][0]
    assert issue["loc"] == ["query", "cursor"]
    assert issue["type"] == "value_error"
    return issue


async def pages(client: httpx.AsyncClient, key: str, path: str, query: str) -> list[str]:
    """Every id of the list, one per page, following ``next_cursor`` with the same query."""
    seen: list[str] = []
    cursor: str | None = None
    for _ in range(COUNT * 10):
        after = "" if cursor is None else f"cursor={cursor}"
        body = await send(client, "GET", url(path, query, "limit=1", after), key, status=200)
        seen += [item["id"] for item in body["data"]]
        cursor = body["meta"]["next_cursor"]
        if cursor is None:
            return seen
    raise AssertionError("paging did not end")


async def first_cursor(client: httpx.AsyncClient, key: str, path: str, query: str) -> str:
    body = await send(client, "GET", url(path, query, "limit=1"), key, status=200)
    cursor: str | None = body["meta"]["next_cursor"]
    assert cursor is not None
    return cursor


# -- seeding --------------------------------------------------------------------------------


async def add_volumes(client: httpx.AsyncClient, key: str) -> list[str]:
    ids: list[str] = []
    for n in range(COUNT):
        body = await send(client, "POST", "/v1/volumes", key, status=201, json={"name": f"v{n}"})
        ids.append(body["data"]["id"])
    return ids


async def add_snapshots(client: httpx.AsyncClient, key: str) -> list[str]:
    ids: list[str] = []
    for n in range(COUNT):
        payload = {"image": "alpine:3.20", "name": f"img{n}"}
        body = await send(client, "POST", "/v1/snapshots", key, status=201, json=payload)
        ids.append(body["data"]["id"])
    return ids


def job(org_id: str, state: str) -> JobRecord:
    return JobRecord(
        id=new_id(JOB),
        org_id=org_id,
        kind="test.job",
        payload={},
        state=state,
        attempts=0,
        run_after=NOW,
        lease_expires_at=None,
        last_error=None,
        created_at=NOW,
        updated_at=NOW,
    )


async def add_jobs(app: FastAPI, org_id: str, state: str) -> list[str]:
    jobs = [job(org_id, state) for _ in range(COUNT)]
    async with UnitOfWork(app.state.session_factory) as uow:
        for record in jobs:
            await uow.jobs.enqueue(record)
        await uow.commit()
    return [record.id for record in jobs]


def endpoint(org_id: str) -> WebhookEndpointRecord:
    return WebhookEndpointRecord(
        id=new_id(WEBHOOK),
        org_id=org_id,
        url="https://hooks.example.com/in",
        secret="whsec_test",
        enabled=True,
        failure_count=0,
        event_types=[],
        created_at=NOW,
    )


def delivery(endpoint_id: str, event_id: str) -> WebhookDeliveryRecord:
    return WebhookDeliveryRecord(
        id=new_id(WEBHOOK),
        endpoint_id=endpoint_id,
        event_id=event_id,
        state="delivered",
        attempts=1,
        next_attempt_at=None,
        last_status=200,
        created_at=NOW,
        updated_at=NOW,
    )


async def add_deliveries(app: FastAPI, org_id: str) -> tuple[str, list[str]]:
    target = endpoint(org_id)
    events = [
        OutboxEventRecord(
            id=new_id(EVENT),
            org_id=org_id,
            event_type=EventType.SANDBOX_STARTED.value,
            payload={},
            created_at=NOW,
        )
        for _ in range(COUNT)
    ]
    # The endpoint and the events commit first: the deliveries reference both (foreign keys).
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.webhooks.add_endpoint(target)
        for event in events:
            await uow.events.append(event)
        await uow.commit()
    records = [delivery(target.id, event.id) for event in events]
    async with UnitOfWork(app.state.session_factory) as uow:
        for record in records:
            await uow.webhooks.record_delivery(record)
        await uow.commit()
    return target.id, [record.id for record in records]


# -- 1: a cursor from another resource is refused on every list route -----------------------


@pytest.mark.parametrize(("path", "resource"), ROUTES)
async def test_a_sandbox_cursor_is_refused_on_every_other_list(
    client: httpx.AsyncClient, key: str, path: str, resource: str
) -> None:
    cursor = encode_cursor(new_id(SANDBOX), {"order": "asc"})  # as the sandbox list issues it

    body = await send(client, "GET", url(path, f"cursor={cursor}"), key, status=422)

    issue = refused(body)
    assert issue["msg"] == f"cursor was issued for sandboxes, not {resource}"
    assert issue["ctx"]["resource"] == "sandboxes"


@pytest.mark.parametrize(("path", "resource", "issuer"), CROSS)
async def test_a_labeled_cursor_is_refused_by_any_other_list(
    client: httpx.AsyncClient, key: str, path: str, resource: str, issuer: str
) -> None:
    cursor = encode_cursor(new_id(PREFIX_BY_RESOURCE[issuer]), {}, resource=issuer)

    body = await send(client, "GET", url(path, f"cursor={cursor}"), key, status=422)

    assert refused(body)["msg"] == f"cursor was issued for {issuer}, not {resource}"


async def test_a_real_volumes_cursor_is_refused_by_snapshots_and_audit(
    client: httpx.AsyncClient, key: str
) -> None:
    await add_volumes(client, key)
    cursor = await first_cursor(client, key, "/v1/volumes", "")

    snapshots = await send(client, "GET", f"/v1/snapshots?cursor={cursor}", key, status=422)
    audit = await send(client, "GET", f"{AUDIT_PATH}?cursor={cursor}", key, status=422)

    assert refused(snapshots)["msg"] == "cursor was issued for volumes, not snapshots"
    assert refused(audit)["msg"] == "cursor was issued for volumes, not audit-events"


async def test_a_label_that_does_not_match_the_id_is_an_invalid_cursor(
    client: httpx.AsyncClient, key: str
) -> None:
    cursor = encode_cursor(new_id(SANDBOX), resource=VOLUMES)

    body = await send(client, "GET", f"/v1/volumes?cursor={cursor}", key, status=422)

    assert refused(body)["msg"] == "invalid cursor"


# -- 2: the audit-events cursor is bound to its filters --------------------------------------


@pytest.mark.parametrize(
    ("issued", "reused", "fields"),
    [
        ("outcome=success", "outcome=denied", ["outcome"]),
        ("outcome=success", "", ["outcome"]),
        ("from=2000-01-01T00:00:00Z", "from=2001-01-01T00:00:00Z", ["from"]),
        ("to=2999-01-01T00:00:00Z", "", ["to"]),
        ("order=desc", "order=asc", ["order"]),
        ("outcome=success&order=desc", "outcome=error&order=asc", ["order", "outcome"]),
        ("", "target_id=vol_x", ["target_id"]),
    ],
)
async def test_audit_cursor_refused_for_another_filter(
    client: httpx.AsyncClient, key: str, issued: str, reused: str, fields: list[str]
) -> None:
    await add_volumes(client, key)
    cursor = await first_cursor(client, key, AUDIT_PATH, issued)

    body = await send(client, "GET", url(AUDIT_PATH, reused, f"cursor={cursor}"), key, status=422)

    issue = refused(body)
    assert issue["msg"] == FILTER_MESSAGE
    assert issue["ctx"]["fields"] == fields
    assert issue["ctx"]["reason"].startswith("cursor was issued with ")


async def test_audit_cursor_refused_for_another_actor_or_action(
    client: httpx.AsyncClient, key: str
) -> None:
    await add_volumes(client, key)
    row = (await send(client, "GET", AUDIT_PATH, key, status=200))["data"][0]
    action, actor = row["action"], row["actor_id"]
    by_action = await first_cursor(client, key, AUDIT_PATH, f"action={action}")
    by_actor = await first_cursor(client, key, AUDIT_PATH, f"actor_id={actor}")

    other_action = url(AUDIT_PATH, "action=other", f"cursor={by_action}")
    other_actor = url(AUDIT_PATH, "actor_id=key_other", f"cursor={by_actor}")
    action_issue = refused(await send(client, "GET", other_action, key, status=422))
    actor_issue = refused(await send(client, "GET", other_actor, key, status=422))

    assert action_issue["ctx"]["fields"] == ["action"]
    assert action_issue["ctx"]["reason"] == f"cursor was issued with action={action}, not other"
    assert actor_issue["ctx"]["fields"] == ["actor_id"]


# -- 3: same-filter paging still works on each route ----------------------------------------


@pytest.mark.parametrize("query", ["outcome=success", "order=desc&from=2000-01-01T00:00:00Z"])
async def test_audit_same_filter_pages(client: httpx.AsyncClient, key: str, query: str) -> None:
    await add_volumes(client, key)
    everything = await send(client, "GET", url(AUDIT_PATH, query), key, status=200)

    seen = await pages(client, key, AUDIT_PATH, query)

    assert len(everything["data"]) >= COUNT
    assert seen == [item["id"] for item in everything["data"]]


async def test_volumes_and_snapshots_page(client: httpx.AsyncClient, key: str) -> None:
    volumes = await add_volumes(client, key)
    snapshots = await add_snapshots(client, key)

    assert sorted(await pages(client, key, "/v1/volumes", "")) == sorted(volumes)
    assert sorted(await pages(client, key, "/v1/snapshots", "")) == sorted(snapshots)


async def test_jobs_page_and_refuse_another_state(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    dead = await add_jobs(app, org_id, "dead")
    await add_jobs(app, org_id, "queued")

    seen = await pages(client, key, "/v1/jobs", "state=dead")
    cursor = await first_cursor(client, key, "/v1/jobs", "state=dead")
    body = await send(client, "GET", f"/v1/jobs?state=queued&cursor={cursor}", key, status=422)

    assert sorted(seen) == sorted(dead)
    issue = refused(body)
    assert issue["ctx"]["fields"] == ["state"]
    assert issue["ctx"]["reason"] == "cursor was issued with state=dead, not queued"


async def test_deliveries_page_and_refuse_another_endpoint(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    endpoint_id, ids = await add_deliveries(app, org_id)
    other_id, _ = await add_deliveries(app, org_id)
    path = f"/v1/webhooks/{endpoint_id}/deliveries"

    seen = await pages(client, key, path, "")
    cursor = await first_cursor(client, key, path, "")
    other = f"/v1/webhooks/{other_id}/deliveries?cursor={cursor}"
    body = await send(client, "GET", other, key, status=422)

    assert sorted(seen) == sorted(ids)
    assert refused(body)["ctx"]["fields"] == ["endpoint_id"]


# -- 4: an older unbound cursor still pages the list that issued it --------------------------


async def test_unbound_cursor_is_accepted_by_its_own_list(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    volumes = await add_volumes(client, key)
    dead = await add_jobs(app, org_id, "dead")
    first_audit = (await send(client, "GET", AUDIT_PATH, key, status=200))["data"][0]["id"]

    by_volume = f"/v1/volumes?cursor={encode_cursor(volumes[0])}"
    by_job = f"/v1/jobs?state=dead&cursor={encode_cursor(dead[0])}"
    by_audit = f"{AUDIT_PATH}?outcome=success&cursor={encode_cursor(first_audit)}"

    assert (await send(client, "GET", by_volume, key, status=200))["success"]
    assert (await send(client, "GET", by_job, key, status=200))["success"]
    assert (await send(client, "GET", by_audit, key, status=200))["success"]
