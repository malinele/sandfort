"""Round 61: a repeated label filter key with different values is a 422 on both list routes.

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
from sandfort.api.label_query import parse_label_filter
from sandfort.api.pagination import QueryRefusal
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
VOLUMES = "/v1/volumes"
OK_STATUS = 200
CREATED_STATUS = 201
VALIDATION_STATUS = 422
CONFLICT_TAIL = "is given more than once with different values"
CONFLICT_MESSAGE = f"label key 'a' {CONFLICT_TAIL}"
ECHO_LIMIT = 63
LONG_KEY_LENGTH = 200
PARAMETER_SENTENCE = (
    "k=v, repeatable; all must match; a key given twice with different values is refused (422)"
)
SCOPES = frozenset(
    {Scope.SANDBOXES_WRITE, Scope.SANDBOXES_READ, Scope.VOLUMES_WRITE, Scope.VOLUMES_READ}
)
ROUTES = [pytest.param(SANDBOXES, id="sandboxes"), pytest.param(VOLUMES, id="volumes")]
CONFLICTS = ["label=a=1&label=a=2", "label=a=2&label=a=1", "label=a=1&label=b=1&label=a="]


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'labels61.db'}"
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
async def headers(app: FastAPI) -> dict[str, str]:
    org = Org(id=new_org_id(), name="Labels61", slug="labels61", created_at=NOW)
    generated = generate_api_key(PEPPER)
    key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="labels61",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=SCOPES,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(key)
        await uow.commit()
    return {"Authorization": f"Bearer {generated.key}", "Content-Type": "application/json"}


async def make(
    client: httpx.AsyncClient, headers: dict[str, str], route: str, labels: dict[str, str]
) -> None:
    body: dict[str, Any] = {"labels": labels}
    if route == VOLUMES:
        body["name"] = "vol-" + "-".join(f"{k}{v}" for k, v in sorted(labels.items()))
    response = await client.post(route, json=body, headers=headers)
    assert response.status_code == CREATED_STATUS, response.text


# --- the helper ---------------------------------------------------------------------------------


def test_helper_maps_pairs_and_keeps_an_empty_value_and_equals_in_the_value() -> None:
    assert parse_label_filter(["a=1", "b=", "c=x=y"]) == {"a": "1", "b": "", "c": "x=y"}


def test_helper_accepts_the_exact_same_pair_repeated() -> None:
    assert parse_label_filter(["a=1", "a=1", "a=1"]) == {"a": "1"}


def test_helper_refuses_one_key_with_two_values() -> None:
    with pytest.raises(QueryRefusal) as caught:
        parse_label_filter(["a=1", "b=2", "a=2"])

    issue = caught.value.details["errors"][0]
    assert issue["loc"] == ["query", "label"]
    assert issue["msg"] == CONFLICT_MESSAGE


def conflict_message(key: str) -> str:
    with pytest.raises(QueryRefusal) as caught:
        parse_label_filter([f"{key}=1", f"{key}=2"])

    message: str = caught.value.details["errors"][0]["msg"]
    return message


def test_helper_echoes_a_long_conflicting_key_capped_with_an_ellipsis() -> None:
    key = "k" * LONG_KEY_LENGTH

    message = conflict_message(key)

    assert message == f"label key {ascii('k' * ECHO_LIMIT)}... {CONFLICT_TAIL}"
    assert key not in message
    assert len(message) < LONG_KEY_LENGTH


def test_helper_echoes_a_key_at_the_cap_whole_without_an_ellipsis() -> None:
    key = "k" * ECHO_LIMIT

    assert conflict_message(key) == f"label key {ascii(key)} {CONFLICT_TAIL}"


def test_helper_echoes_an_invisible_format_character_in_a_key_escaped() -> None:
    key = "a​b"  # a zero-width space between visible characters is a valid key

    message = conflict_message(key)

    assert "​" not in message
    assert message == f"label key {ascii(key)} {CONFLICT_TAIL}"
    assert "\\u200b" in message
    assert message.isascii()


def test_helper_echoes_a_non_ascii_key_escaped() -> None:
    message = conflict_message("klúč")

    assert message.isascii()
    assert "\\xfa\\u010d" in message


@pytest.mark.parametrize("control", ["\x1b", "\x07", "\x00", "\x7f", "\n"])
def test_helper_never_echoes_a_control_character_raw(control: str) -> None:
    # The text check runs before the conflict check, so a control character is refused there
    # (without echoing the key); whichever refusal answers, no raw control character is in it.
    with pytest.raises(QueryRefusal) as caught:
        parse_label_filter([f"a{control}b=1", f"a{control}b=2"])

    message = caught.value.details["errors"][0]["msg"]
    assert control not in message
    assert message.isascii()


# --- both list routes ---------------------------------------------------------------------------


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("query", CONFLICTS)
async def test_list_refuses_one_key_with_different_values(
    client: httpx.AsyncClient, headers: dict[str, str], route: str, query: str
) -> None:
    response = await client.get(f"{route}?{query}", headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    payload = response.json()
    assert payload["error"]["code"] == "VALIDATION_ERROR"
    issues = payload["error"]["details"]["errors"]
    assert len(issues) == 1
    assert issues[0]["loc"] == ["query", "label"]
    assert issues[0]["msg"] == CONFLICT_MESSAGE


@pytest.mark.parametrize("route", ROUTES)
async def test_list_accepts_the_exact_same_pair_repeated_once(
    client: httpx.AsyncClient, headers: dict[str, str], route: str
) -> None:
    await make(client, headers, route, {"a": "1"})
    await make(client, headers, route, {"a": "2"})

    response = await client.get(f"{route}?label=a=1&label=a=1", headers=headers)

    assert response.status_code == OK_STATUS, response.text
    assert [item["labels"] for item in response.json()["data"]] == [{"a": "1"}]


@pytest.mark.parametrize("route", ROUTES)
async def test_different_keys_still_combine(
    client: httpx.AsyncClient, headers: dict[str, str], route: str
) -> None:
    await make(client, headers, route, {"a": "1", "b": "1"})
    await make(client, headers, route, {"a": "1", "b": "2"})

    response = await client.get(f"{route}?label=a=1&label=b=2", headers=headers)

    assert response.status_code == OK_STATUS, response.text
    assert [item["labels"] for item in response.json()["data"]] == [{"a": "1", "b": "2"}]


@pytest.mark.parametrize("route", ROUTES)
async def test_a_cursor_stays_bound_to_the_label_filter(
    client: httpx.AsyncClient, headers: dict[str, str], route: str
) -> None:
    for index in range(3):
        await make(client, headers, route, {"a": "1", "n": str(index)})

    first = await client.get(f"{route}?label=a=1&label=a=1&limit=2", headers=headers)
    cursor = first.json()["meta"]["next_cursor"]
    same = await client.get(f"{route}?label=a=1&limit=2&cursor={cursor}", headers=headers)
    other = await client.get(f"{route}?label=a=2&limit=2&cursor={cursor}", headers=headers)

    assert len(first.json()["data"]) == 2
    assert same.status_code == OK_STATUS, same.text
    assert len(same.json()["data"]) == 1
    assert other.status_code == VALIDATION_STATUS
    assert other.json()["error"]["details"]["errors"][0]["loc"] == ["query", "cursor"]


@pytest.mark.parametrize("route", ROUTES)
async def test_the_label_parameter_description_states_the_rules(app: FastAPI, route: str) -> None:
    operation = app.openapi()["paths"][route]["get"]
    parameter = next(item for item in operation["parameters"] if item["name"] == "label")

    assert parameter["description"] == PARAMETER_SENTENCE


@pytest.mark.parametrize("route", ROUTES)
async def test_a_long_conflicting_key_is_echoed_capped_over_http(
    client: httpx.AsyncClient, headers: dict[str, str], route: str
) -> None:
    key = "k" * LONG_KEY_LENGTH

    response = await client.get(f"{route}?label={key}=1&label={key}=2", headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    message = response.json()["error"]["details"]["errors"][0]["msg"]
    assert message == f"label key {ascii('k' * ECHO_LIMIT)}... {CONFLICT_TAIL}"
