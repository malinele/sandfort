"""Volume labels: create with labels, list filter, label-scope merge and bounds.

Through the API on the fake driver and a temp SQLite database migrated to head; no network.
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.schemas.text_checks import (
    MAX_LABEL_KEY_LENGTH,
    MAX_LABEL_VALUE_LENGTH,
    MAX_LABELS,
)
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
VOLUMES = "/v1/volumes"
OK_STATUS = 200
CREATED_STATUS = 201
FORBIDDEN_STATUS = 403
VALIDATION_STATUS = 422
SCOPES = frozenset({Scope.VOLUMES_READ, Scope.VOLUMES_WRITE})
TEAM = {"team": "a"}


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'volume_labels.db'}"
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
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.fixture
async def org(app: FastAPI) -> Org:
    org = Org(id=new_org_id(), name="VolLabels", slug="vol-labels", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org


async def make_key(
    app: FastAPI, org: Org, name: str, scope: dict[str, str] | None = None
) -> dict[str, str]:
    generated = generate_api_key(PEPPER)
    key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name=name,
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=SCOPES,
        sandbox_labels=scope,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(key)
        await uow.commit()
    return {"Authorization": f"Bearer {generated.key}", "Content-Type": "application/json"}


@pytest.fixture
async def headers(app: FastAPI, org: Org) -> dict[str, str]:
    return await make_key(app, org, "open")


@pytest.fixture
async def scoped(app: FastAPI, org: Org) -> dict[str, str]:
    return await make_key(app, org, "scoped", TEAM)


async def create(
    client: httpx.AsyncClient, headers: dict[str, str], name: str, labels: Any = None
) -> httpx.Response:
    body: dict[str, Any] = {"name": name}
    if labels is not None:
        body["labels"] = labels
    return await client.post(VOLUMES, json=body, headers=headers)


async def create_ok(
    client: httpx.AsyncClient, headers: dict[str, str], name: str, labels: Any = None
) -> dict[str, Any]:
    response = await create(client, headers, name, labels)
    assert response.status_code == CREATED_STATUS, response.text
    data: dict[str, Any] = response.json()["data"]
    return data


async def names(client: httpx.AsyncClient, headers: dict[str, str], query: str = "") -> list[str]:
    response = await client.get(f"{VOLUMES}{query}", headers=headers)
    assert response.status_code == OK_STATUS, response.text
    return sorted(item["name"] for item in response.json()["data"])


# --- create and read --------------------------------------------------------------------------


async def test_create_without_labels_answers_an_empty_mapping(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    created = await create_ok(client, headers, "plain")

    assert created["labels"] == {}


async def test_create_with_labels_stores_and_returns_them(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    wanted = {"team": "a", "env": "dev"}

    created = await create_ok(client, headers, "tagged", wanted)

    assert created["labels"] == wanted
    fetched = await client.get(f"{VOLUMES}/{created['id']}", headers=headers)
    assert fetched.json()["data"]["labels"] == wanted


async def test_reserved_label_names_are_refused(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    response = await create(client, headers, "reserved", {"sandfort.volume_id": "x"})

    assert response.status_code == VALIDATION_STATUS
    assert "reserved" in response.text
    assert await names(client, headers) == []


# --- list filter ------------------------------------------------------------------------------


async def test_list_filters_by_one_or_more_label_pairs(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    await create_ok(client, headers, "none")
    await create_ok(client, headers, "a-dev", {"team": "a", "env": "dev"})
    await create_ok(client, headers, "a-prod", {"team": "a", "env": "prod"})
    await create_ok(client, headers, "b-dev", {"team": "b", "env": "dev"})

    assert await names(client, headers, "?label=team=a") == ["a-dev", "a-prod"]
    assert await names(client, headers, "?label=team=a&label=env=dev") == ["a-dev"]
    assert await names(client, headers, "?label=team=c") == []
    assert await names(client, headers) == ["a-dev", "a-prod", "b-dev", "none"]


@pytest.mark.parametrize("pair", ["team", "=a"])
async def test_list_refuses_a_malformed_label_filter(
    client: httpx.AsyncClient, headers: dict[str, str], pair: str
) -> None:
    response = await client.get(f"{VOLUMES}?label={pair}", headers=headers)

    assert response.status_code == VALIDATION_STATUS
    assert response.json()["error"]["details"]["errors"][0]["loc"] == ["query", "label"]


async def test_filtered_pages_continue_with_the_cursor(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    for index in range(3):
        await create_ok(client, headers, f"a{index}", TEAM)
    await create_ok(client, headers, "other", {"team": "b"})

    first = await client.get(f"{VOLUMES}?label=team=a&limit=2", headers=headers)
    cursor = first.json()["meta"]["next_cursor"]
    second = await client.get(f"{VOLUMES}?label=team=a&limit=2&cursor={cursor}", headers=headers)
    changed = await client.get(f"{VOLUMES}?label=team=b&limit=2&cursor={cursor}", headers=headers)

    assert len(first.json()["data"]) == 2
    assert [item["name"] for item in second.json()["data"]] == ["a2"]
    assert second.json()["meta"]["next_cursor"] is None
    assert changed.status_code == VALIDATION_STATUS


# --- label scope ------------------------------------------------------------------------------


async def test_scoped_key_create_merges_its_scope_into_the_labels(
    client: httpx.AsyncClient, scoped: dict[str, str]
) -> None:
    bare = await create_ok(client, scoped, "bare")
    extra = await create_ok(client, scoped, "extra", {"env": "dev"})
    same = await create_ok(client, scoped, "same", TEAM)

    assert bare["labels"] == TEAM
    assert extra["labels"] == {"team": "a", "env": "dev"}
    assert same["labels"] == TEAM


async def test_scoped_key_create_refuses_a_label_that_contradicts_its_scope(
    client: httpx.AsyncClient, scoped: dict[str, str]
) -> None:
    response = await create(client, scoped, "clash", {"team": "b"})

    assert response.status_code == FORBIDDEN_STATUS, response.text
    assert await names(client, scoped) == []


async def test_scoped_key_lists_only_volumes_carrying_its_scope(
    client: httpx.AsyncClient, headers: dict[str, str], scoped: dict[str, str]
) -> None:
    await create_ok(client, headers, "unlabelled")
    await create_ok(client, headers, "team-b", {"team": "b"})
    await create_ok(client, headers, "team-a", {"team": "a", "env": "dev"})
    await create_ok(client, scoped, "scoped-made")

    assert await names(client, scoped) == ["scoped-made", "team-a"]
    assert await names(client, scoped, "?label=env=dev") == ["team-a"]
    assert await names(client, scoped, "?label=team=b") == []
    assert await names(client, headers) == ["scoped-made", "team-a", "team-b", "unlabelled"]


# --- bounds -----------------------------------------------------------------------------------


def many_labels(count: int) -> dict[str, str]:
    return {f"k{index}": "v" for index in range(count)}


# (labels within the bound, labels one past it, the limit the refusal names)
BOUNDS = [
    pytest.param(many_labels(MAX_LABELS), many_labels(MAX_LABELS + 1), MAX_LABELS, id="count"),
    pytest.param(
        {"k" * MAX_LABEL_KEY_LENGTH: "v"},
        {"k" * (MAX_LABEL_KEY_LENGTH + 1): "v"},
        MAX_LABEL_KEY_LENGTH,
        id="key-length",
    ),
    pytest.param(
        {"team": "v" * MAX_LABEL_VALUE_LENGTH},
        {"team": "v" * (MAX_LABEL_VALUE_LENGTH + 1)},
        MAX_LABEL_VALUE_LENGTH,
        id="value-length",
    ),
]


@pytest.mark.parametrize(("fits", "too_many", "limit"), BOUNDS)
async def test_create_takes_labels_at_the_bound_and_refuses_one_past_it(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    fits: dict[str, str],
    too_many: dict[str, str],
    limit: int,
) -> None:
    refused = await create(client, headers, "too-many", too_many)

    assert refused.status_code == VALIDATION_STATUS, refused.text
    issues = refused.json()["error"]["details"]["errors"]
    assert len(issues) == 1
    assert issues[0]["loc"][:2] == ["body", "labels"]
    assert str(limit) in issues[0]["msg"]
    assert await names(client, headers) == []
    created = await create_ok(client, headers, "fits", fits)
    assert created["labels"] == fits


@pytest.mark.parametrize("key", ["bad\nkey", "\x07", "   "])
async def test_create_refuses_label_keys_that_would_show_up_blank_or_garbled(
    client: httpx.AsyncClient, headers: dict[str, str], key: str
) -> None:
    response = await create(client, headers, "garbled", {key: "v"})

    assert response.status_code == VALIDATION_STATUS, response.text
    assert await names(client, headers) == []
