"""Round 57b: one 422 shape for label-filter refusals, and a cursor bound to its list filter.

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

from sandfort.api.pagination import encode_cursor  # noqa: E402
from sandfort.domain.org import Scope  # noqa: E402
from test_api_sandboxes import BASE, add_org, migrated_app, seed_key, send  # noqa: E402

FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})
STOPPED_COUNT = 3
FILTER_MESSAGE = "cursor was issued for a different filter or order"


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
    org_id = await add_org(app, "listfilter57b")
    return await seed_key(app, org_id, FULL_ACCESS)


async def stopped_ids(client: httpx.AsyncClient, key: str, count: int) -> list[str]:
    ids: list[str] = []
    for _ in range(count):
        created = await send(client, "POST", BASE, key, status=201, json={})
        sandbox_id: str = created["data"]["id"]
        await send(client, "POST", f"{BASE}/{sandbox_id}/stop", key, status=200)
        ids.append(sandbox_id)
    return ids


async def first_cursor(client: httpx.AsyncClient, key: str, query: str) -> str:
    body = await send(client, "GET", f"{BASE}?{query}&limit=1", key, status=200)
    cursor: str | None = body["meta"]["next_cursor"]
    assert cursor is not None
    return cursor


def error_issue(body: dict[str, Any]) -> dict[str, Any]:
    issue: dict[str, Any] = body["error"]["details"]["errors"][0]
    return issue


# -- 1: every label-filter refusal has one shape ------------------------------------------------


@pytest.mark.parametrize(
    ("query", "issue_prefix"),
    [
        ("label=team", "label filter must be k=v, got 'team'"),
        ("label==a", "label filter must be k=v, got '=a'"),
        ("label=%20=a", "label names must contain a visible character"),
    ],
)
async def test_label_refusals_share_one_shape(
    client: httpx.AsyncClient, key: str, query: str, issue_prefix: str
) -> None:
    body = await send(client, "GET", f"{BASE}?{query}", key, status=422)

    issue = error_issue(body)
    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert issue["loc"] == ["query", "label"]
    assert issue["msg"].startswith(issue_prefix)
    assert body["error"]["message"] == f"request validation failed: query.label: {issue['msg']}"


# -- 2: a cursor belongs to the filter that issued it -------------------------------------------


@pytest.mark.parametrize(
    ("issued", "reused"),
    [
        ("state=stopped", "state=started"),
        ("stop_cause=requested", "stop_cause=auto_stop"),
        ("state=stopped", "state=stopped&stop_cause=requested"),
        ("state=stopped&order=asc", "state=stopped&order=desc"),
        ("state=stopped", "state=stopped&label=team=a"),
        ("state=stopped", "state=stopped&include_destroyed=true"),
        ("state=stopped&include_destroyed=true", "state=stopped"),
    ],
)
async def test_cursor_reused_with_another_filter_is_refused(
    client: httpx.AsyncClient, key: str, issued: str, reused: str
) -> None:
    await stopped_ids(client, key, STOPPED_COUNT)
    cursor = await first_cursor(client, key, issued)

    body = await send(client, "GET", f"{BASE}?{reused}&cursor={cursor}", key, status=422)

    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert body["error"]["message"] == f"request validation failed: query.cursor: {FILTER_MESSAGE}"
    assert error_issue(body)["loc"] == ["query", "cursor"]
    assert error_issue(body)["msg"] == FILTER_MESSAGE


@pytest.mark.parametrize("query", ["state=stopped", "stop_cause=requested&order=desc"])
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

    assert sorted(seen) == sorted(expected)
    assert cursor is None


async def test_cursor_without_fingerprint_is_still_accepted(
    client: httpx.AsyncClient, key: str
) -> None:
    ids = await stopped_ids(client, key, STOPPED_COUNT)

    cursor = encode_cursor(ids[0])
    body = await send(client, "GET", f"{BASE}?state=stopped&cursor={cursor}", key, status=200)

    assert [item["id"] for item in body["data"]] == ids[1:]
