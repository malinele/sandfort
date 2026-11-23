"""Round 58: a cursor refused for another filter names the differing field(s).

The cursor carries its filter values (compact, url-safe); the 422 keeps the round-57b message
and adds ``ctx.fields`` and ``ctx.reason`` to the issue. Older hash-only cursors still page.
FakeDriver, temp SQLite migrated to head, httpx over ASGI (no network, no sockets).
"""

import base64
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402

from sandfort.api.pagination import filter_fingerprint  # noqa: E402
from sandfort.domain.org import Scope  # noqa: E402
from test_api_sandboxes import BASE, add_org, migrated_app, seed_key, send  # noqa: E402

FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})
STOPPED_COUNT = 3
FILTER_MESSAGE = "cursor was issued for a different filter or order"
MAX_CURSOR_LENGTH = 200


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
async def key(app: FastAPI) -> str:
    org_id = await add_org(app, "listfilter58")
    return await seed_key(app, org_id, FULL_ACCESS)


async def stopped_ids(client: httpx.AsyncClient, key: str, count: int) -> list[str]:
    ids: list[str] = []
    for _ in range(count):
        created = await send(client, "POST", BASE, key, status=201, json={"labels": {"team": "a"}})
        sandbox_id: str = created["data"]["id"]
        await send(client, "POST", f"{BASE}/{sandbox_id}/stop", key, status=200)
        ids.append(sandbox_id)
    return ids


async def first_cursor(client: httpx.AsyncClient, key: str, query: str) -> str:
    body = await send(client, "GET", f"{BASE}?{query}&limit=1", key, status=200)
    cursor: str | None = body["meta"]["next_cursor"]
    assert cursor is not None
    return cursor


async def refusal(client: httpx.AsyncClient, key: str, issued: str, reused: str) -> dict[str, Any]:
    await stopped_ids(client, key, STOPPED_COUNT)
    cursor = await first_cursor(client, key, issued)
    body = await send(client, "GET", f"{BASE}?{reused}&cursor={cursor}", key, status=422)
    assert body["error"]["code"] == "VALIDATION_ERROR"
    issue: dict[str, Any] = body["error"]["details"]["errors"][0]
    assert issue["loc"] == ["query", "cursor"]
    assert issue["msg"] == FILTER_MESSAGE
    return issue


# -- 1: each field is named when it alone differs -----------------------------------------------


@pytest.mark.parametrize(
    ("issued", "reused", "field", "reason"),
    [
        ("state=stopped", "state=started", "state", "state=stopped, not started"),
        (
            "stop_cause=requested",
            "stop_cause=container_exited",
            "stop_cause",
            "stop_cause=requested, not container_exited",
        ),
        ("state=stopped", "state=stopped&stop_cause=requested", "stop_cause", "stop_cause unset"),
        ("state=stopped&order=asc", "state=stopped&order=desc", "order", "order=asc, not desc"),
        ("state=stopped", "state=stopped&label=team=a", "labels", "a different labels"),
        ("label=team=a", "label=team=b", "labels", "a different labels"),
        (
            "state=stopped",
            "state=stopped&include_destroyed=true",
            "include_destroyed",
            "include_destroyed=false, not true",
        ),
    ],
)
async def test_each_differing_field_is_named(
    client: httpx.AsyncClient, key: str, issued: str, reused: str, field: str, reason: str
) -> None:
    issue = await refusal(client, key, issued, reused)

    assert issue["ctx"]["fields"] == [field]
    assert issue["ctx"]["reason"].startswith(f"cursor was issued with {reason}")


async def test_unset_field_reads_as_unset(client: httpx.AsyncClient, key: str) -> None:
    issue = await refusal(client, key, "state=stopped", "state=stopped&stop_cause=requested")

    assert issue["ctx"]["reason"] == "cursor was issued with stop_cause unset, not requested"


async def test_two_differing_fields_are_both_named(client: httpx.AsyncClient, key: str) -> None:
    issued = "stop_cause=requested&order=asc"
    issue = await refusal(client, key, issued, "stop_cause=container_exited&order=desc")

    assert issue["ctx"]["fields"] == ["order", "stop_cause"]
    assert issue["ctx"]["reason"] == (
        "cursor was issued with order=asc, not desc; stop_cause=requested, not container_exited"
    )


# -- 2: the same filter still pages, with a cursor of reasonable length -------------------------


@pytest.mark.parametrize(
    "query",
    [
        "state=stopped",
        "stop_cause=requested&order=desc",
        "state=stopped&stop_cause=requested&label=team=a&include_destroyed=true&order=desc",
    ],
)
async def test_same_filter_still_pages(client: httpx.AsyncClient, key: str, query: str) -> None:
    expected = await stopped_ids(client, key, STOPPED_COUNT)
    seen: list[str] = []
    cursor: str | None = None
    for _ in range(STOPPED_COUNT + 1):
        page = f"{query}&limit=1" + ("" if cursor is None else f"&cursor={cursor}")
        body = await send(client, "GET", f"{BASE}?{page}", key, status=200)
        seen += [item["id"] for item in body["data"]]
        cursor = body["meta"]["next_cursor"]
        if cursor is None:
            break
        assert len(cursor) <= MAX_CURSOR_LENGTH
        assert cursor.replace("-", "").replace("_", "").isalnum()

    assert sorted(seen) == sorted(expected)
    assert cursor is None


# -- 3: older hash-only cursors behave as before ------------------------------------------------


def hash_only_cursor(last_id: str, values: dict[str, Any]) -> str:
    payload = f"{last_id}|{filter_fingerprint(values)}"
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


STOPPED_FILTER: dict[str, Any] = {
    "state": "stopped",
    "stop_cause": None,
    "labels": {},
    "order": "asc",
    "include_destroyed": False,
}


async def test_hash_only_cursor_is_accepted_for_the_same_filter(
    client: httpx.AsyncClient, key: str
) -> None:
    ids = await stopped_ids(client, key, STOPPED_COUNT)

    cursor = hash_only_cursor(ids[0], STOPPED_FILTER)
    body = await send(client, "GET", f"{BASE}?state=stopped&cursor={cursor}", key, status=200)

    assert [item["id"] for item in body["data"]] == ids[1:]


async def test_hash_only_cursor_is_refused_for_another_filter(
    client: httpx.AsyncClient, key: str
) -> None:
    ids = await stopped_ids(client, key, STOPPED_COUNT)

    cursor = hash_only_cursor(ids[0], STOPPED_FILTER)
    body = await send(client, "GET", f"{BASE}?state=started&cursor={cursor}", key, status=422)

    issue = body["error"]["details"]["errors"][0]
    assert issue["msg"] == FILTER_MESSAGE
    assert "ctx" not in issue
