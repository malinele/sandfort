"""Round 58b: both label-filter refusals build one ``details.errors`` entry the same way.

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

from sandfort.domain.org import Scope  # noqa: E402
from test_api_sandboxes import BASE, add_org, migrated_app, seed_key, send  # noqa: E402

FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})
ENTRY_KEYS = ["type", "loc", "msg"]
FORM_REFUSAL = "label=team"  # no "=": refused by the k=v form check
VISIBLE_REFUSAL = "label=%20=a"  # a blank key: refused by the visible-character check
CONTROL_REFUSAL = "label=a%07b=1"  # a key with a control character


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
    org_id = await add_org(app, "listfilter58b")
    return await seed_key(app, org_id, FULL_ACCESS)


async def refusal(client: httpx.AsyncClient, key: str, query: str) -> dict[str, Any]:
    body = await send(client, "GET", f"{BASE}?{query}", key, status=422)
    errors = body["error"]["details"]["errors"]
    assert len(errors) == 1
    entry: dict[str, Any] = errors[0]
    return entry


async def test_both_refusals_have_the_same_keys_in_the_same_order(
    client: httpx.AsyncClient, key: str
) -> None:
    form = await refusal(client, key, FORM_REFUSAL)
    visible = await refusal(client, key, VISIBLE_REFUSAL)

    assert list(form) == ENTRY_KEYS
    assert list(visible) == list(form)
    assert form["type"] == visible["type"] == "value_error"
    assert form["loc"] == visible["loc"] == ["query", "label"]


@pytest.mark.parametrize("query", [VISIBLE_REFUSAL, CONTROL_REFUSAL])
async def test_visible_character_refusal_has_no_prefix_and_no_echo(
    client: httpx.AsyncClient, key: str, query: str
) -> None:
    entry = await refusal(client, key, query)

    assert entry["msg"].startswith("label names ")
    assert "Value error" not in entry["msg"]
    assert "'" not in entry["msg"]  # the repr of the raw key is not echoed
    assert "\x07" not in entry["msg"]


async def test_visible_character_refusal_keeps_its_meaning(
    client: httpx.AsyncClient, key: str
) -> None:
    blank = await refusal(client, key, VISIBLE_REFUSAL)
    control = await refusal(client, key, CONTROL_REFUSAL)

    assert blank["msg"].startswith("label names must contain a visible character")
    assert control["msg"] == "label names must not contain control characters"


async def test_top_level_message_uses_the_entry_message(
    client: httpx.AsyncClient, key: str
) -> None:
    body = await send(client, "GET", f"{BASE}?{VISIBLE_REFUSAL}", key, status=422)

    msg = body["error"]["details"]["errors"][0]["msg"]
    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert body["error"]["message"] == f"request validation failed: query.label: {msg}"


@pytest.mark.parametrize("query", ["label=k%3D", "label=a%3Db%3Dc"])
async def test_empty_or_equals_containing_value_is_accepted_and_matches_nothing(
    client: httpx.AsyncClient, key: str, query: str
) -> None:
    await send(client, "POST", BASE, key, status=201, json={"labels": {"k": "v", "a": "b"}})
    control = await send(client, "GET", f"{BASE}?label=k%3Dv", key, status=200)

    body = await send(client, "GET", f"{BASE}?{query}", key, status=200)

    assert len(control["data"]) == 1  # the sandbox is listable, so the empty list is a real miss
    assert body["data"] == []
