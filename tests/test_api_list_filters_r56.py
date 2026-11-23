"""Round 56: the ``stop_cause`` list filter is answered in SQL, and the label filter checks keys.

FakeDriver, temp SQLite migrated to head, httpx over ASGI (no network, no sockets).

* ``GET /v1/sandboxes?stop_cause=`` matches the cause the sandbox object shows: an equality on
  the stored column inside ``stopping``/``stopped``; ``unknown`` is a NULL column inside those
  states only; ordering, ``state``, ``label`` and ``cursor`` keep working;
* a label filter key made only of whitespace answers the same 422 as a create with that key.
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

from sandfort.db.unit_of_work import UnitOfWork  # noqa: E402
from sandfort.domain.org import Scope  # noqa: E402
from sandfort.domain.sandbox import (  # noqa: E402
    STOP_CAUSE_AUTO_STOP,
    STOP_CAUSE_OOM_KILLED,
    STOP_CAUSE_REQUESTED,
    STOP_CAUSE_UNKNOWN,
)
from sandfort.services.sandbox_listing import list_by_stop_cause  # noqa: E402
from test_api_sandboxes import BASE, add_org, migrated_app, seed_key, send  # noqa: E402
from test_label_scoped_keys import TEAM_A, TEAM_B, add_key  # noqa: E402

FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})
PAGE_SIZE = 2


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
    return await add_org(app, "listfilter56")


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id, FULL_ACCESS)


async def started_sandbox(client: httpx.AsyncClient, key: str, **payload: Any) -> str:
    created = await send(client, "POST", BASE, key, status=201, json=payload)
    sandbox_id: str = created["data"]["id"]
    return sandbox_id


async def stopped_sandbox(client: httpx.AsyncClient, key: str, **payload: Any) -> str:
    sandbox_id = await started_sandbox(client, key, **payload)
    await send(client, "POST", f"{BASE}/{sandbox_id}/stop", key, status=200)
    return sandbox_id


async def set_stored_cause(app: FastAPI, org_id: str, sandbox_id: str, cause: str | None) -> None:
    async with UnitOfWork(app.state.session_factory) as uow:
        row = await uow.sandboxes.get(org_id, sandbox_id)
        assert row is not None
        changed = row.model_copy(update={"stop_cause": cause})
        await uow.sandboxes.update(org_id, changed, expected_version=row.version)
        await uow.commit()


async def listed(client: httpx.AsyncClient, key: str, query: str) -> list[str]:
    body = await send(client, "GET", f"{BASE}?{query}", key, status=200)
    return [item["id"] for item in body["data"]]


async def paged(client: httpx.AsyncClient, key: str, query: str) -> list[str]:
    """Every id of the filtered list, followed page by page through ``next_cursor``."""
    seen: list[str] = []
    cursor: str | None = None
    while True:
        page_query = f"{query}&limit={PAGE_SIZE}" + ("" if cursor is None else f"&cursor={cursor}")
        body = await send(client, "GET", f"{BASE}?{page_query}", key, status=200)
        seen += [item["id"] for item in body["data"]]
        cursor = body["meta"]["next_cursor"]
        if cursor is None:
            return seen


# -- the SQL filter ----------------------------------------------------------------------------


async def test_filter_matches_the_sandboxes_showing_that_cause(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    requested = await stopped_sandbox(client, key)
    oom = await stopped_sandbox(client, key)
    await set_stored_cause(app, org_id, oom, STOP_CAUSE_OOM_KILLED)

    assert await listed(client, key, f"stop_cause={STOP_CAUSE_REQUESTED}") == [requested]
    assert await listed(client, key, f"stop_cause={STOP_CAUSE_OOM_KILLED}") == [oom]


async def test_filter_with_no_match_answers_an_empty_page(
    client: httpx.AsyncClient, key: str
) -> None:
    await stopped_sandbox(client, key)

    body = await send(client, "GET", f"{BASE}?stop_cause={STOP_CAUSE_AUTO_STOP}", key, status=200)

    assert body["data"] == []
    assert body["meta"]["next_cursor"] is None


async def test_filter_rejects_a_value_outside_the_set(client: httpx.AsyncClient, key: str) -> None:
    body = await send(client, "GET", f"{BASE}?stop_cause=exploded", key, status=422)

    assert body["error"]["code"] == "VALIDATION_ERROR"


async def test_unknown_matches_a_null_cause_only_while_stopped(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    stopped_null = await stopped_sandbox(client, key)
    await set_stored_cause(app, org_id, stopped_null, None)
    stopped_requested = await stopped_sandbox(client, key)
    running = await started_sandbox(client, key)  # NULL cause, but it shows none
    gone = await stopped_sandbox(client, key)
    await set_stored_cause(app, org_id, gone, None)
    await send(client, "DELETE", f"{BASE}/{gone}", key, status=200)

    unknown = await listed(client, key, f"stop_cause={STOP_CAUSE_UNKNOWN}")

    assert unknown == [stopped_null]
    assert stopped_requested not in unknown and running not in unknown
    assert await listed(client, key, f"stop_cause={STOP_CAUSE_UNKNOWN}&state=destroyed") == []


async def test_a_stored_cause_on_a_running_sandbox_does_not_match(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    running = await started_sandbox(client, key)
    await set_stored_cause(app, org_id, running, STOP_CAUSE_OOM_KILLED)

    assert await listed(client, key, f"stop_cause={STOP_CAUSE_OOM_KILLED}") == []


async def test_filter_combines_with_state_and_label(client: httpx.AsyncClient, key: str) -> None:
    tagged = await stopped_sandbox(client, key, labels={"team": "a"})
    await stopped_sandbox(client, key, labels={"team": "b"})
    await started_sandbox(client, key, labels={"team": "a"})
    query = f"stop_cause={STOP_CAUSE_REQUESTED}"

    assert len(await listed(client, key, query)) == 2
    assert await listed(client, key, f"{query}&state=stopped&label=team=a") == [tagged]
    assert await listed(client, key, f"{query}&state=started") == []


async def test_filter_keeps_the_ordering_and_the_cursors(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    ids = [await stopped_sandbox(client, key) for _ in range(3)]
    await started_sandbox(client, key)  # between the matches: never listed
    ids.append(await stopped_sandbox(client, key))
    other = await stopped_sandbox(client, key)
    await set_stored_cause(app, org_id, other, STOP_CAUSE_OOM_KILLED)
    query = f"stop_cause={STOP_CAUSE_REQUESTED}&state=stopped"

    assert await paged(client, key, f"{query}&order=asc") == ids
    assert await paged(client, key, f"{query}&order=desc") == ids[::-1]
    first = await send(client, "GET", f"{BASE}?{query}&limit={PAGE_SIZE}", key, status=200)
    after = first["meta"]["next_cursor"]
    assert await listed(client, key, f"{query}&cursor={after}") == ids[PAGE_SIZE:]


# -- a label-scoped key ------------------------------------------------------------------------


async def test_scoped_key_sees_only_its_own_stopped_sandbox_by_stop_cause(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    mine = await stopped_sandbox(client, key, labels=TEAM_A)
    theirs = await stopped_sandbox(client, key, labels=TEAM_B)
    await started_sandbox(client, key, labels=TEAM_A)  # running: shows no cause
    scoped = await add_key(app, org_id, TEAM_A)

    seen = await listed(client, scoped, f"stop_cause={STOP_CAUSE_REQUESTED}")

    assert seen == [mine]
    assert theirs not in seen
    assert await listed(client, key, f"stop_cause={STOP_CAUSE_REQUESTED}") == [mine, theirs]


async def test_scoped_key_asking_for_another_label_value_gets_an_empty_stop_cause_list(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    await stopped_sandbox(client, key, labels=TEAM_A)
    theirs = await stopped_sandbox(client, key, labels=TEAM_B)
    scoped = await add_key(app, org_id, TEAM_A)
    query = f"stop_cause={STOP_CAUSE_REQUESTED}&label=team=b"

    body = await send(client, "GET", f"{BASE}?{query}", scoped, status=200)

    assert body["data"] == []
    assert body["meta"]["next_cursor"] is None
    assert theirs not in await paged(client, scoped, f"stop_cause={STOP_CAUSE_REQUESTED}")


async def test_stop_cause_listing_over_a_repository_without_the_filter_raises_type_error() -> None:
    class NoStopCauseRepository:
        async def list(self, org_id: str, *, limit: int = 50) -> None:
            raise AssertionError("the listing must not call a repository without the filter")

    repo: Any = NoStopCauseRepository()

    with pytest.raises(TypeError, match="cannot filter by stop cause"):
        await list_by_stop_cause(
            repo,
            "org_x",
            STOP_CAUSE_REQUESTED,
            state=None,
            labels=None,
            cursor=None,
            limit=PAGE_SIZE,
            order="asc",
        )


# -- the label filter key ----------------------------------------------------------------------


async def test_label_filter_with_a_whitespace_only_key_answers_422(
    client: httpx.AsyncClient, key: str
) -> None:
    created = await send(client, "POST", BASE, key, status=422, json={"labels": {"   ": "x"}})

    body = await send(client, "GET", f"{BASE}?label=%20%20%20=x", key, status=422)

    assert body["error"]["code"] == created["error"]["code"] == "VALIDATION_ERROR"
    assert "must contain a visible character" in body["error"]["message"]
    assert body["error"]["details"]["errors"][0]["loc"] == ["query", "label"]
