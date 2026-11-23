"""Sandbox label bounds, null labels on PATCH and plain label messages (round 58).

Sandbox labels had no bounds: 300 labels, a 300-character key and a 2000-character value were
accepted. Create and PATCH now take at most 32 labels, keys of at most 63 characters and
values of at most 256 characters; a breach is a 422 ``VALIDATION_ERROR`` naming the limit,
and the published schema carries the bounds. ``"labels": null`` on PATCH removes every label,
an omitted ``labels`` keeps them. Label refusals read ``label names ...`` without the pydantic
``Value error, `` prefix.

Through the API on the fake driver and a temp SQLite database; no network and no sockets.
"""

from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.schemas.sandboxes import CreateSandboxRequest, UpdateSandboxRequest
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
SANDBOXES = "/v1/sandboxes"
API_KEYS = "/v1/api-keys"
OK_STATUS = 200
CREATED_STATUS = 201
VALIDATION_STATUS = 422
PYDANTIC_PREFIX = "Value error"
NULL_DESCRIPTION = "null removes all labels; omit the field to keep them"
EXPECTED_BOUNDS = (MAX_LABELS, MAX_LABEL_KEY_LENGTH, MAX_LABEL_VALUE_LENGTH)
SCOPES = frozenset(
    {Scope.SANDBOXES_WRITE, Scope.SANDBOXES_READ, Scope.TOOLBOX, Scope.API_KEYS_ADMIN}
)


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


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'labels58.db'}"
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
    org = Org(id=new_org_id(), name="Labels", slug="labels", created_at=NOW)
    generated = generate_api_key(PEPPER)
    key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="labels",
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


def refusals(response: httpx.Response) -> list[dict[str, Any]]:
    assert response.status_code == VALIDATION_STATUS, response.text
    payload: dict[str, Any] = response.json()
    assert payload["success"] is False
    assert payload["error"]["code"] == "VALIDATION_ERROR"
    issues: list[dict[str, Any]] = payload["error"]["details"]["errors"]
    assert len(issues) == 1, issues
    return issues


def assert_names_limit(response: httpx.Response, limit: int) -> None:
    issue = refusals(response)[0]
    assert issue["loc"][:2] == ["body", "labels"]
    assert str(limit) in issue["msg"]


async def create(client: httpx.AsyncClient, headers: dict[str, str], wanted: dict[str, str]) -> str:
    response = await client.post(SANDBOXES, json={"labels": wanted}, headers=headers)
    assert response.status_code == CREATED_STATUS, response.text
    sandbox_id: str = response.json()["data"]["id"]
    return sandbox_id


async def labels_of(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> dict[str, str]:
    response = await client.get(f"{SANDBOXES}/{sandbox_id}", headers=headers)
    assert response.status_code == OK_STATUS, response.text
    labels: dict[str, str] = response.json()["data"]["labels"]
    return labels


def walk(node: object) -> Iterator[dict[str, Any]]:
    """Every object in a JSON schema fragment, the fragment itself included."""
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from walk(item)


def published_bounds(labels_schema: dict[str, Any]) -> tuple[Any, Any, Any]:
    objects = [part for part in walk(labels_schema) if "maxProperties" in part]
    assert len(objects) == 1, labels_schema
    found = objects[0]
    return (
        found["maxProperties"],
        found["propertyNames"]["maxLength"],
        found["additionalProperties"]["maxLength"],
    )


# --- bounds -----------------------------------------------------------------------------------


@pytest.mark.parametrize(("fits", "too_many", "limit"), BOUNDS)
async def test_create_takes_labels_at_the_bound_and_refuses_one_past_it(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    fits: dict[str, str],
    too_many: dict[str, str],
    limit: int,
) -> None:
    refused = await client.post(SANDBOXES, json={"labels": too_many}, headers=headers)

    assert_names_limit(refused, limit)
    listed = await client.get(SANDBOXES, headers=headers)
    assert listed.json()["data"] == []
    sandbox_id = await create(client, headers, fits)
    assert await labels_of(client, headers, sandbox_id) == fits


@pytest.mark.parametrize(("fits", "too_many", "limit"), BOUNDS)
async def test_patch_takes_labels_at_the_bound_and_refuses_one_past_it(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    fits: dict[str, str],
    too_many: dict[str, str],
    limit: int,
) -> None:
    sandbox_id = await create(client, headers, {"team": "a"})
    path = f"{SANDBOXES}/{sandbox_id}"

    refused = await client.patch(path, json={"labels": too_many}, headers=headers)

    assert_names_limit(refused, limit)
    assert await labels_of(client, headers, sandbox_id) == {"team": "a"}
    accepted = await client.patch(path, json={"labels": fits}, headers=headers)
    assert accepted.status_code == OK_STATUS, accepted.text
    assert accepted.json()["data"]["labels"] == fits


@pytest.mark.parametrize("model", [CreateSandboxRequest, UpdateSandboxRequest])
def test_the_request_schema_publishes_the_label_bounds(model: type[Any]) -> None:
    labels_schema = model.model_json_schema()["properties"]["labels"]

    assert published_bounds(labels_schema) == EXPECTED_BOUNDS


def test_the_openapi_document_publishes_the_label_bounds(app: FastAPI) -> None:
    schemas = app.openapi()["components"]["schemas"]

    for name in ("CreateSandboxRequest", "UpdateSandboxRequest"):
        labels_schema = schemas[name]["properties"]["labels"]
        assert published_bounds(labels_schema) == EXPECTED_BOUNDS


# --- null labels on PATCH ---------------------------------------------------------------------


async def test_patch_with_null_labels_removes_every_label(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    sandbox_id = await create(client, headers, {"team": "a", "tier": "b"})

    response = await client.patch(
        f"{SANDBOXES}/{sandbox_id}", json={"labels": None}, headers=headers
    )

    assert response.status_code == OK_STATUS, response.text
    assert response.json()["data"]["labels"] == {}
    assert await labels_of(client, headers, sandbox_id) == {}


async def test_patch_without_labels_keeps_them(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    sandbox_id = await create(client, headers, {"team": "a"})

    response = await client.patch(
        f"{SANDBOXES}/{sandbox_id}", json={"public": True}, headers=headers
    )

    assert response.status_code == OK_STATUS, response.text
    assert response.json()["data"]["labels"] == {"team": "a"}


def test_null_labels_parse_as_an_empty_set_and_omitted_labels_as_none() -> None:
    assert UpdateSandboxRequest.model_validate({"labels": None}).labels == {}
    assert UpdateSandboxRequest.model_validate({}).labels is None


def test_the_labels_description_states_the_null_semantics(app: FastAPI) -> None:
    model_field = UpdateSandboxRequest.model_json_schema()["properties"]["labels"]
    published = app.openapi()["components"]["schemas"]["UpdateSandboxRequest"]

    assert NULL_DESCRIPTION in model_field["description"]
    assert NULL_DESCRIPTION in published["properties"]["labels"]["description"]


# --- message prefix ---------------------------------------------------------------------------


def assert_plain_label_message(response: httpx.Response, start: str) -> None:
    issue = refusals(response)[0]
    assert issue["type"] == "value_error"
    assert issue["msg"].startswith(start), issue["msg"]
    assert PYDANTIC_PREFIX not in issue["msg"]


async def test_create_blank_label_key_message_starts_with_label_names(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    response = await client.post(SANDBOXES, json={"labels": {" ": "v"}}, headers=headers)

    assert_plain_label_message(response, "label names must contain a visible character")


async def test_create_control_label_key_message_starts_with_label_names(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    response = await client.post(SANDBOXES, json={"labels": {"a\tb": "v"}}, headers=headers)

    assert_plain_label_message(response, "label names must not contain control characters")


async def test_create_reserved_label_message_starts_with_label_names(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    response = await client.post(SANDBOXES, json={"labels": {"sandfort.x": "v"}}, headers=headers)

    assert_plain_label_message(response, "label names starting with sandfort. are reserved")


async def test_patch_blank_label_key_message_starts_with_label_names(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    sandbox_id = await create(client, headers, {"team": "a"})

    response = await client.patch(
        f"{SANDBOXES}/{sandbox_id}", json={"labels": {"​": "v"}}, headers=headers
    )

    assert_plain_label_message(response, "label names must contain a visible character")


async def test_api_key_label_scope_message_starts_with_label_names(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    body = {"name": "scoped", "scopes": ["sandboxes:read"], "sandbox_labels": {" ": "a"}}

    response = await client.post(API_KEYS, json=body, headers=headers)

    assert_plain_label_message(response, "label names must contain a visible character")


async def test_a_brace_in_a_label_key_is_shown_as_sent(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    response = await client.post(SANDBOXES, json={"labels": {"{x}\t": "v"}}, headers=headers)

    issue = refusals(response)[0]
    assert issue["msg"] == "label names must not contain control characters: '{x}\\t'"
