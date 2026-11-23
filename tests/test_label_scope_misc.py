"""Remaining label-scope gaps: build logs, jobs, snapshot delete, idempotency, list filter.

Through the API on the fake driver and a temp SQLite database, plus unit tests of the scoped
repository's defense-in-depth post-filter. The scope is a ``team=red`` key against sandboxes,
snapshots and jobs that belong to ``team=blue``.
"""

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest
from fastapi import FastAPI

from sandfort.api.routes import jobs as jobs_routes
from sandfort.auth.api_keys import generate_api_key
from sandfort.auth.label_scope import set_label_scope
from sandfort.clock import SystemClock
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Scope
from sandfort.ids import new_api_key_id
from sandfort.services.image_builds import IMAGE_BUILD
from sandfort.services.label_scope import LabelScopedSandboxRepository, unscoped
from sandfort.services.snapshots import SNAPSHOT_CREATE
from sandfort.workers.jobs import SandboxStopJob, enqueue_job
from test_api_sandboxes import BASE, NOW, PEPPER, add_org, migrated_app, send
from test_snapshot_scope import (
    BLUE,
    RED,
    SNAPSHOTS,
    commit_snapshot,
    make_sandbox,
    register_image,
    seed_key,
)

BUILDS = "/v1/images/builds"
JOBS = "/v1/jobs"
IDEMPOTENCY_HEADER = "Idempotency-Key"
REPLAY_HEADER = "Idempotent-Replayed"
UNKNOWN_SNAPSHOT_ID = "snap_doesnotexist"
UNKNOWN_JOB_ID = "job_doesnotexist"
ALL_JOBS = {"limit": 100}


# --- fixtures ---------------------------------------------------------------------------


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
    return await add_org(app, "scoped-misc")


@pytest.fixture
async def unscoped_key(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id, None)


@pytest.fixture
async def red(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id, RED)


@pytest.fixture
async def blue_sandbox(client: httpx.AsyncClient, unscoped_key: str) -> str:
    return await make_sandbox(client, unscoped_key, labels=BLUE)


@pytest.fixture
async def blue_snapshot(
    app: FastAPI, client: httpx.AsyncClient, unscoped_key: str, blue_sandbox: str
) -> str:
    return await commit_snapshot(app, client, unscoped_key, blue_sandbox)


async def listed_jobs(client: httpx.AsyncClient, key: str) -> list[dict[str, Any]]:
    body = await send(client, "GET", JOBS, key, status=200, params=ALL_JOBS)
    return cast(list[dict[str, Any]], body["data"])


async def job_ids(client: httpx.AsyncClient, key: str) -> set[str]:
    return {item["id"] for item in await listed_jobs(client, key)}


async def seed_job(app: FastAPI, org_id: str, kind: str, payload: dict[str, Any]) -> str:
    """Queue a job of ``kind`` without running it."""
    async with UnitOfWork(app.state.session_factory) as uow:
        queued = await enqueue_job(uow, SystemClock(), org_id, kind, payload)
        await uow.commit()
    return queued.id


async def seed_sandbox_job(app: FastAPI, org_id: str, sandbox_id: str) -> str:
    """Queue a lifecycle job that names ``sandbox_id``, without running it."""
    job = SandboxStopJob(org_id, sandbox_id)
    return await seed_job(app, org_id, job.kind, job.payload())


async def seed_reader_key(app: FastAPI, org_id: str) -> str:
    """An unscoped key that can read sandboxes but holds no snapshot scope."""
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="reader",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset({Scope.SANDBOXES_READ}),
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


# --- 1) image build logs ----------------------------------------------------------------


async def test_build_logs_of_a_snapshot_from_another_scope_answer_not_found(
    client: httpx.AsyncClient, red: str, blue_snapshot: str
) -> None:
    hidden = await send(client, "GET", f"{BUILDS}/{blue_snapshot}/logs", red, status=404)
    absent = await send(client, "GET", f"{BUILDS}/{UNKNOWN_SNAPSHOT_ID}/logs", red, status=404)

    assert hidden["error"]["code"] == absent["error"]["code"]
    assert hidden["error"]["message"] == f"snapshot {blue_snapshot} not found"
    assert absent["error"]["message"] == f"snapshot {UNKNOWN_SNAPSHOT_ID} not found"


async def test_build_logs_are_served_to_the_unscoped_key_and_for_registered_images(
    client: httpx.AsyncClient, unscoped_key: str, red: str, blue_snapshot: str
) -> None:
    public = await register_image(client, unscoped_key)
    unscoped_headers = {"Authorization": f"Bearer {unscoped_key}"}
    red_headers = {"Authorization": f"Bearer {red}"}

    unscoped_reply = await client.get(f"{BUILDS}/{blue_snapshot}/logs", headers=unscoped_headers)
    red_reply = await client.get(f"{BUILDS}/{public}/logs", headers=red_headers)

    assert unscoped_reply.status_code == 200
    assert blue_snapshot in unscoped_reply.text
    assert red_reply.status_code == 200


# --- 2) jobs ----------------------------------------------------------------------------


async def test_jobs_list_omits_the_jobs_of_another_scope(
    app: FastAPI,
    client: httpx.AsyncClient,
    org_id: str,
    unscoped_key: str,
    red: str,
    blue_sandbox: str,
    blue_snapshot: str,
) -> None:
    blue_sandbox_job = await seed_sandbox_job(app, org_id, blue_sandbox)
    red_sandbox = await make_sandbox(client, unscoped_key, labels=RED)
    red_sandbox_job = await seed_sandbox_job(app, org_id, red_sandbox)
    everything = await job_ids(client, unscoped_key)

    visible = await listed_jobs(client, red)

    visible_ids = {item["id"] for item in visible}
    assert blue_sandbox_job in everything
    assert blue_sandbox_job not in visible_ids
    assert red_sandbox_job in visible_ids
    assert all(item["payload"].get("snapshot_id") != blue_snapshot for item in visible)
    assert len(visible_ids) < len(everything)


async def test_job_by_id_of_another_scope_answers_like_an_unknown_id(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, red: str, blue_sandbox: str
) -> None:
    hidden_id = await seed_sandbox_job(app, org_id, blue_sandbox)

    hidden = await send(client, "GET", f"{JOBS}/{hidden_id}", red, status=404)
    absent = await send(client, "GET", f"{JOBS}/{UNKNOWN_JOB_ID}", red, status=404)

    assert hidden["error"]["code"] == absent["error"]["code"]
    assert hidden["error"]["message"] == f"job {hidden_id} not found"
    assert absent["error"]["message"] == f"job {UNKNOWN_JOB_ID} not found"


async def test_snapshot_job_of_another_scope_is_hidden_by_id(
    client: httpx.AsyncClient, unscoped_key: str, red: str, blue_snapshot: str
) -> None:
    jobs = await listed_jobs(client, unscoped_key)
    snapshot_job = next(
        job["id"] for job in jobs if job["payload"].get("snapshot_id") == blue_snapshot
    )

    await send(client, "GET", f"{JOBS}/{snapshot_job}", red, status=404)
    await send(client, "GET", f"{JOBS}/{snapshot_job}", unscoped_key, status=200)


async def test_scoped_jobs_list_pages_over_hidden_jobs(
    app: FastAPI,
    client: httpx.AsyncClient,
    org_id: str,
    unscoped_key: str,
    red: str,
    blue_sandbox: str,
) -> None:
    red_sandbox = await make_sandbox(client, unscoped_key, labels=RED)
    await seed_sandbox_job(app, org_id, blue_sandbox)
    first = await seed_sandbox_job(app, org_id, red_sandbox)
    second = await seed_sandbox_job(app, org_id, red_sandbox)

    page = await send(client, "GET", JOBS, red, status=200, params={"limit": 1})
    rest = await send(
        client,
        "GET",
        JOBS,
        red,
        status=200,
        params={"limit": 5, "cursor": page["meta"]["next_cursor"]},
    )

    seen = [item["id"] for item in page["data"]] + [item["id"] for item in rest["data"]]
    assert len(seen) == 2  # ids minted in one millisecond are unordered: compare as a set
    assert set(seen) == {first, second}


async def test_build_and_snapshot_jobs_are_hidden_without_snapshots_read(
    app: FastAPI,
    client: httpx.AsyncClient,
    org_id: str,
    unscoped_key: str,
    blue_sandbox: str,
    blue_snapshot: str,
) -> None:
    reader = await seed_reader_key(app, org_id)
    build = await seed_job(app, org_id, IMAGE_BUILD, {"spec": {"base_image": "alpine:3.20"}})
    sandbox_job = await seed_sandbox_job(app, org_id, blue_sandbox)
    everything = await listed_jobs(client, unscoped_key)
    snapshot_job = next(job["id"] for job in everything if job["kind"] == SNAPSHOT_CREATE)

    visible = await job_ids(client, reader)

    assert {build, snapshot_job} <= {job["id"] for job in everything}
    assert sandbox_job in visible
    assert not {build, snapshot_job} & visible
    for hidden in (build, snapshot_job):
        await send(client, "GET", f"{JOBS}/{hidden}", reader, status=404)
        await send(client, "GET", f"{JOBS}/{hidden}", unscoped_key, status=200)


async def test_image_build_spec_is_dropped_for_a_scoped_caller_only(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, unscoped_key: str, red: str
) -> None:
    spec = {"base_image": "alpine:3.20", "env": {"TOKEN": "s3cret"}}
    build = await seed_job(app, org_id, IMAGE_BUILD, {"spec": spec, "name": "img"})

    by_id = await send(client, "GET", f"{JOBS}/{build}", red, status=200)
    listed = next(job for job in await listed_jobs(client, red) if job["id"] == build)
    full = await send(client, "GET", f"{JOBS}/{build}", unscoped_key, status=200)

    assert by_id["data"]["payload"] == {"name": "img"}
    assert listed["payload"] == {"name": "img"}
    assert "s3cret" not in str(by_id) + str(listed)
    assert full["data"]["payload"]["spec"] == spec


async def test_job_payload_snapshot_key_is_scoped_like_snapshot_id(
    app: FastAPI,
    client: httpx.AsyncClient,
    org_id: str,
    unscoped_key: str,
    red: str,
    blue_snapshot: str,
) -> None:
    hidden = await seed_job(app, org_id, IMAGE_BUILD, {"snapshot": blue_snapshot})

    await send(client, "GET", f"{JOBS}/{hidden}", red, status=404)
    await send(client, "GET", f"{JOBS}/{hidden}", unscoped_key, status=200)
    assert hidden not in await job_ids(client, red)
    assert hidden in await job_ids(client, unscoped_key)


async def test_scoped_scan_cap_returns_a_cursor_at_the_last_scanned_row(
    app: FastAPI,
    client: httpx.AsyncClient,
    org_id: str,
    unscoped_key: str,
    red: str,
    blue_sandbox: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(jobs_routes, "MAX_PAGE_SIZE", 3)
    monkeypatch.setattr(jobs_routes, "SCAN_CAP", 6)
    red_sandbox = await make_sandbox(client, unscoped_key, labels=RED)
    for _ in range(6):
        await seed_sandbox_job(app, org_id, blue_sandbox)
    await asyncio.sleep(0.01)  # a later millisecond, so the red job sorts after the blue ones
    red_job = await seed_sandbox_job(app, org_id, red_sandbox)

    first = await send(client, "GET", JOBS, red, status=200, params={"limit": 1})
    cursor = first["meta"]["next_cursor"]
    second = await send(client, "GET", JOBS, red, status=200, params={"limit": 1, "cursor": cursor})

    assert first["data"] == []  # six hidden rows used up the scan cap
    assert cursor is not None
    assert [item["id"] for item in second["data"]] == [red_job]
    assert second["meta"]["next_cursor"] is None


async def test_unscoped_key_sees_every_job(
    app: FastAPI,
    client: httpx.AsyncClient,
    org_id: str,
    unscoped_key: str,
    blue_sandbox: str,
    blue_snapshot: str,
) -> None:
    sandbox_job = await seed_sandbox_job(app, org_id, blue_sandbox)

    ids = await job_ids(client, unscoped_key)

    assert sandbox_job in ids
    assert any(
        job["payload"].get("snapshot_id") == blue_snapshot
        for job in await listed_jobs(client, unscoped_key)
    )
    await send(client, "GET", f"{JOBS}/{sandbox_job}", unscoped_key, status=200)


# --- 3) snapshot delete -----------------------------------------------------------------


async def test_scoped_delete_is_refused_while_another_scopes_sandbox_runs_from_it(
    client: httpx.AsyncClient, unscoped_key: str, red: str, blue_sandbox: str
) -> None:
    public = await register_image(client, red)  # red owns it; shared images are org-admin only
    blue_user = await make_sandbox(client, unscoped_key, labels=BLUE, snapshot=public)

    refused = await send(client, "DELETE", f"{SNAPSHOTS}/{public}", red, status=409)

    assert blue_user not in str(refused)
    assert blue_sandbox not in str(refused)
    assert refused["error"]["code"] == "CONFLICT"
    assert "sandbox_id" not in (refused["error"]["details"] or {})
    await send(client, "GET", f"{SNAPSHOTS}/{public}", red, status=200)


async def test_scoped_delete_names_a_sandbox_in_its_own_scope(
    client: httpx.AsyncClient, unscoped_key: str, red: str
) -> None:
    public = await register_image(client, red)
    red_user = await make_sandbox(client, red, snapshot=public)

    refused = await send(client, "DELETE", f"{SNAPSHOTS}/{public}", red, status=409)

    assert refused["error"]["message"] == f"snapshot {public} is used by sandbox {red_user}"


async def test_unscoped_delete_message_is_unchanged(
    client: httpx.AsyncClient, unscoped_key: str
) -> None:
    public = await register_image(client, unscoped_key)
    blue_user = await make_sandbox(client, unscoped_key, labels=BLUE, snapshot=public)

    refused = await send(client, "DELETE", f"{SNAPSHOTS}/{public}", unscoped_key, status=409)

    assert refused["error"]["message"] == f"snapshot {public} is used by sandbox {blue_user}"
    assert refused["error"]["details"] == {"reason": "in_use", "sandbox_id": blue_user}


async def test_scoped_delete_succeeds_when_no_sandbox_uses_the_snapshot(
    client: httpx.AsyncClient, unscoped_key: str, red: str
) -> None:
    public = await register_image(client, red)

    await send(client, "DELETE", f"{SNAPSHOTS}/{public}", red, status=200)


# --- 4) idempotency ---------------------------------------------------------------------


async def test_other_keys_idempotency_key_gets_a_fresh_create_while_the_first_still_replays(
    client: httpx.AsyncClient, unscoped_key: str, red: str
) -> None:
    body = {"labels": {"purpose": "idem"}}
    first_headers = {IDEMPOTENCY_HEADER: "shared-key-1", "Authorization": f"Bearer {unscoped_key}"}
    other_headers = {IDEMPOTENCY_HEADER: "shared-key-1", "Authorization": f"Bearer {red}"}
    first = await client.post(BASE, json=body, headers=first_headers)
    assert first.status_code == 201, first.text
    first_id = first.json()["data"]["id"]

    other = await client.post(BASE, json={}, headers=other_headers)
    replay = await client.post(BASE, json=body, headers=first_headers)

    assert other.status_code == 201, other.text  # no 422 mismatch, no replay
    assert REPLAY_HEADER not in other.headers
    assert other.json()["data"]["id"] != first_id
    assert replay.status_code == 201
    assert replay.headers[REPLAY_HEADER] == "true"
    assert replay.json()["data"]["id"] == first_id


async def test_same_key_replay_with_the_same_body_still_replays(
    client: httpx.AsyncClient, red: str
) -> None:
    headers = {IDEMPOTENCY_HEADER: "own-key-1", "Authorization": f"Bearer {red}"}
    first = await client.post(BASE, json={}, headers=headers)
    assert first.status_code == 201, first.text

    replay = await client.post(BASE, json={}, headers=headers)

    assert replay.status_code == 201
    assert replay.headers[REPLAY_HEADER] == "true"
    assert replay.json()["data"]["id"] == first.json()["data"]["id"]


# --- 5) defense in depth ----------------------------------------------------------------


class LeakyInner:
    """A sandbox repository whose list ignores the labels filter (a broken SQL filter)."""

    def __init__(self, rows: list[Any]) -> None:
        self.rows = rows
        self.seen_labels: Any = None

    async def list(self, org_id: str, **kwargs: Any) -> list[Any]:
        self.seen_labels = kwargs.get("labels")
        return self.rows


async def test_scoped_list_post_filters_rows_the_sql_filter_let_through() -> None:
    red_row = SimpleNamespace(id="sbx_red", labels={"team": "red", "x": "1"})
    blue_row = SimpleNamespace(id="sbx_blue", labels={"team": "blue"})
    bare_row = SimpleNamespace(id="sbx_bare", labels={})
    inner = LeakyInner([blue_row, red_row, bare_row])
    repository = LabelScopedSandboxRepository(cast(Any, inner))

    set_label_scope(RED)
    try:
        rows = await repository.list("org_1")
    finally:
        set_label_scope(None)

    assert [row.id for row in rows] == ["sbx_red"]
    assert inner.seen_labels == RED  # the SQL filter is still applied


async def test_unscoped_list_returns_every_row() -> None:
    rows = [SimpleNamespace(id="a", labels={"team": "blue"}), SimpleNamespace(id="b", labels={})]
    repository = LabelScopedSandboxRepository(cast(Any, LeakyInner(rows)))

    assert [row.id for row in await repository.list("org_1")] == ["a", "b"]


def test_unscoped_helper_unwraps_only_the_scoped_decorator() -> None:
    inner = cast(Any, LeakyInner([]))

    assert unscoped(LabelScopedSandboxRepository(inner)) is inner
    assert unscoped(inner) is inner
