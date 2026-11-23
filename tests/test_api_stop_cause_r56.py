"""Round 56: stop-cause surfaces found by the persona runs.

FakeDriver, temp SQLite migrated to head, httpx over ASGI (no network, no sockets).

* a toolbox call on a sandbox without a container carries ``stop_cause`` in the 409 details
  (the value the sandbox object shows: ``unknown`` for a null cause, left out once destroyed;
  the message is unchanged);
* ``GET /v1/sandboxes?stop_cause=`` filters on the cause the sandbox object shows, together with
  ``state``, ``label``, ``order`` and ``cursor``; an unknown value answers 422;
* a label filter without ``=`` answers 422 like every other validation failure;
* the auto-stop audit row names the system as its actor.
"""

import sys
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, get_args

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402

from sandfort.api.routes.sandboxes import StopCauseFilter  # noqa: E402
from sandfort.api.wiring import ACTIVITY_TRACKER_ATTR  # noqa: E402
from sandfort.clock import FrozenClock  # noqa: E402
from sandfort.db.unit_of_work import UnitOfWork  # noqa: E402
from sandfort.domain.events import ActorType  # noqa: E402
from sandfort.domain.org import Scope  # noqa: E402
from sandfort.domain.sandbox import (  # noqa: E402
    STOP_CAUSE_AUTO_STOP,
    STOP_CAUSE_OOM_KILLED,
    STOP_CAUSE_REQUESTED,
    STOP_CAUSE_UNKNOWN,
    STOP_CAUSES,
)
from sandfort.drivers.fake import FakeDriver  # noqa: E402
from sandfort.errors import NO_CONTAINER, no_container_conflict  # noqa: E402
from sandfort.services.activity import ActivityTracker  # noqa: E402
from sandfort.workers.autostop import AUTO_STOPPED, AutoStopScanner  # noqa: E402
from test_api_sandboxes import BASE, add_org, migrated_app, seed_key, send  # noqa: E402

FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
IDLE_MINUTES = 15


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
    return await add_org(app, "stopcauser56")


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


async def exec_conflict(client: httpx.AsyncClient, key: str, sandbox_id: str) -> dict[str, Any]:
    body = await send(
        client,
        "POST",
        f"{BASE}/{sandbox_id}/toolbox/process/execute",
        key,
        status=409,
        json={"command": "echo hi"},
    )
    error: dict[str, Any] = body["error"]
    return error


# -- 1: stop_cause in the no-container conflict ------------------------------------------------


async def test_exec_on_a_stopped_sandbox_names_the_stop_cause(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await stopped_sandbox(client, key)

    error = await exec_conflict(client, key, sandbox_id)

    assert error["code"] == "CONFLICT"
    assert error["details"] == {
        "reason": NO_CONTAINER,
        "state": "stopped",
        "stop_cause": STOP_CAUSE_REQUESTED,
    }
    assert STOP_CAUSE_REQUESTED not in error["message"]


async def test_exec_on_a_stopped_sandbox_without_a_cause_shows_unknown(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    sandbox_id = await stopped_sandbox(client, key)
    with_cause = await exec_conflict(client, key, sandbox_id)
    await set_stored_cause(app, org_id, sandbox_id, None)

    error = await exec_conflict(client, key, sandbox_id)

    assert error["details"] == {
        "reason": NO_CONTAINER,
        "state": "stopped",
        "stop_cause": STOP_CAUSE_UNKNOWN,
    }
    assert error["message"] == with_cause["message"]


async def test_exec_on_a_deleted_sandbox_omits_the_stale_stop_cause(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await stopped_sandbox(client, key)
    await send(client, "DELETE", f"{BASE}/{sandbox_id}", key, status=200)

    error = await exec_conflict(client, key, sandbox_id)

    assert error["details"] == {"reason": NO_CONTAINER, "state": "destroyed"}


async def stopped_conflict(
    client: httpx.AsyncClient, key: str, method: str, path: str, **kwargs: Any
) -> dict[str, Any]:
    sandbox_id = await stopped_sandbox(client, key)
    body = await send(client, method, f"{BASE}/{sandbox_id}/{path}", key, status=409, **kwargs)
    error: dict[str, Any] = body["error"]
    return error


async def test_code_run_on_a_stopped_sandbox_names_the_stop_cause(
    client: httpx.AsyncClient, key: str
) -> None:
    error = await stopped_conflict(
        client,
        key,
        "POST",
        "toolbox/process/code-run",
        json={"language": "python", "code": "print(1)"},
    )

    assert error["details"] == {
        "reason": NO_CONTAINER,
        "state": "stopped",
        "stop_cause": STOP_CAUSE_REQUESTED,
    }


async def test_pty_create_on_a_stopped_sandbox_names_the_stop_cause(
    client: httpx.AsyncClient, key: str
) -> None:
    error = await stopped_conflict(client, key, "POST", "toolbox/pty", json={})

    assert error["details"] == {
        "reason": NO_CONTAINER,
        "state": "stopped",
        "stop_cause": STOP_CAUSE_REQUESTED,
    }


async def test_logs_without_a_container_name_the_state(client: httpx.AsyncClient, key: str) -> None:
    # A stopped sandbox keeps its container (logs stay readable); the conflict is the deleted one.
    sandbox_id = await stopped_sandbox(client, key)
    await send(client, "DELETE", f"{BASE}/{sandbox_id}", key, status=200)

    body = await send(client, "GET", f"{BASE}/{sandbox_id}/logs", key, status=409)

    assert body["error"]["details"] == {"reason": NO_CONTAINER, "state": "destroyed"}


def test_the_helper_adds_the_cause_only_when_it_is_given() -> None:
    plain = no_container_conflict("stopped")
    caused = no_container_conflict("stopped", STOP_CAUSE_OOM_KILLED)
    bare = no_container_conflict()

    assert plain.details == {"reason": NO_CONTAINER, "state": "stopped"}
    assert caused.details == {
        "reason": NO_CONTAINER,
        "state": "stopped",
        "stop_cause": STOP_CAUSE_OOM_KILLED,
    }
    assert caused.message == plain.message
    assert bare.details == {"reason": NO_CONTAINER}


# -- 2: the stop_cause list filter -------------------------------------------------------------


def test_the_filter_type_lists_every_domain_stop_cause() -> None:
    assert get_args(StopCauseFilter) == STOP_CAUSES


async def test_list_filter_matches_one_cause_and_misses_the_rest(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    requested = await stopped_sandbox(client, key)
    oom = await stopped_sandbox(client, key)
    await set_stored_cause(app, org_id, oom, STOP_CAUSE_OOM_KILLED)
    unknown = await stopped_sandbox(client, key)
    await set_stored_cause(app, org_id, unknown, None)
    running = await started_sandbox(client, key)

    assert await listed(client, key, "stop_cause=requested") == [requested]
    assert await listed(client, key, "stop_cause=oom_killed") == [oom]
    assert await listed(client, key, f"stop_cause={STOP_CAUSE_UNKNOWN}") == [unknown]
    assert await listed(client, key, f"stop_cause={STOP_CAUSE_AUTO_STOP}") == []
    everything = await listed(client, key, "limit=10")
    assert running in everything and len(everything) == 4


async def test_list_filter_rejects_a_value_outside_the_set(
    client: httpx.AsyncClient, key: str
) -> None:
    body = await send(client, "GET", f"{BASE}?stop_cause=exploded", key, status=422)

    assert body["error"]["code"] == "VALIDATION_ERROR"


async def test_list_filter_combines_with_state_and_label(
    client: httpx.AsyncClient, key: str
) -> None:
    tagged = await stopped_sandbox(client, key, labels={"team": "a"})
    await stopped_sandbox(client, key, labels={"team": "b"})
    await started_sandbox(client, key, labels={"team": "a"})

    assert len(await listed(client, key, "stop_cause=requested")) == 2
    assert await listed(client, key, "stop_cause=requested&state=stopped&label=team=a") == [tagged]
    assert await listed(client, key, "stop_cause=requested&state=started") == []
    assert await listed(client, key, "stop_cause=requested&state=destroyed") == []


async def test_list_filter_keeps_the_ordering_and_the_cursors(
    client: httpx.AsyncClient, key: str
) -> None:
    ids = [await stopped_sandbox(client, key) for _ in range(3)]
    await started_sandbox(client, key)  # between the matches: never listed
    ids.append(await stopped_sandbox(client, key))

    for order, expected in (("asc", ids), ("desc", ids[::-1])):
        seen: list[str] = []
        cursor: str | None = None
        while True:
            query = f"stop_cause=requested&order={order}&limit=3"
            query += "" if cursor is None else f"&cursor={cursor}"
            body = await send(client, "GET", f"{BASE}?{query}", key, status=200)
            seen += [item["id"] for item in body["data"]]
            cursor = body["meta"]["next_cursor"]
            if cursor is None:
                break
        assert seen == expected, order


# -- 3: a malformed label filter is a 422 ------------------------------------------------------


async def test_label_filter_without_equals_answers_422(client: httpx.AsyncClient, key: str) -> None:
    body = await send(client, "GET", f"{BASE}?label=team", key, status=422)

    assert body["error"]["message"] == (
        "request validation failed: query.label: label filter must be k=v, got 'team'"
    )


# -- 4: the auto-stop audit row names the system -----------------------------------------------


async def audit_rows(app: FastAPI, org_id: str, action: str) -> list[Any]:
    async with UnitOfWork(app.state.session_factory) as uow:
        events = await uow.audit.list(org_id, limit=200)
    return [event for event in events if event.action == action]


async def test_auto_stop_audit_row_has_the_system_as_actor(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    driver = app.state.driver
    assert isinstance(driver, FakeDriver)
    sandbox_id = await started_sandbox(client, key, auto_stop_minutes=IDLE_MINUTES)
    clock = FrozenClock(datetime.now(UTC))
    tracker = ActivityTracker(clock)
    setattr(app.state, ACTIVITY_TRACKER_ATTR, tracker)
    scanner = AutoStopScanner(app.state.uow_factory, driver, clock, tracker, interval_s=1)

    clock.advance(timedelta(minutes=IDLE_MINUTES + 1))
    await scanner.scan_once()

    rows = await audit_rows(app, org_id, AUTO_STOPPED)
    assert [row.target_id for row in rows] == [sandbox_id]
    assert rows[0].actor_type is ActorType.SYSTEM
    assert rows[0].actor_id is None


async def test_a_requested_stop_audit_row_keeps_the_api_key_actor(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    await stopped_sandbox(client, key)

    rows = await audit_rows(app, org_id, "sandbox.stop")

    assert [row.actor_type for row in rows] == [ActorType.API_KEY]
    assert rows[0].actor_id is not None
