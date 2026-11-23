"""Round 57: a repeated ``stop_cause`` or ``state`` list filter answers 422, not the last value.

FakeDriver, temp SQLite migrated to head, httpx over ASGI (no network, no sockets).
"""

import sys
from collections.abc import AsyncIterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402

from sandfort.domain.org import Scope  # noqa: E402
from test_api_sandboxes import BASE, add_org, migrated_app, seed_key, send  # noqa: E402

FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})


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
    org_id = await add_org(app, "listfilter57")
    return await seed_key(app, org_id, FULL_ACCESS)


@pytest.mark.parametrize(
    ("query", "name"),
    [
        ("stop_cause=requested&stop_cause=container_exited", "stop_cause"),
        ("state=started&state=stopped", "state"),
        ("order=asc&order=desc", "order"),
        ("limit=1&limit=2", "limit"),
        ("include_destroyed=true&include_destroyed=false", "include_destroyed"),
        ("cursor=a&cursor=b", "cursor"),
    ],
)
async def test_repeated_filter_answers_422(
    client: httpx.AsyncClient, key: str, query: str, name: str
) -> None:
    body = await send(client, "GET", f"{BASE}?{query}", key, status=422)

    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert f"{name} must be given once" in body["error"]["message"]
    assert body["error"]["details"]["errors"][0]["loc"] == ["query", name]


@pytest.mark.parametrize(
    "query",
    [
        "stop_cause=requested",
        "state=started",
        "order=desc",
        "limit=5",
        "include_destroyed=true",
        "",
    ],
)
async def test_single_values_still_answer_200(
    client: httpx.AsyncClient, key: str, query: str
) -> None:
    body = await send(client, "GET", f"{BASE}?{query}", key, status=200)

    assert body["data"] == []
