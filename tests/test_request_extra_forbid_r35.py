"""Request bodies reject unknown fields; an unparseable body is located at ``["body"]``.

Round 34: ``POST /v1/webhooks`` with ``events`` (the field is ``event_types``) answered 201 and
subscribed the endpoint to everything. Through the API on the fake driver and a temp SQLite file.
"""

import inspect
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, get_args

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from fastapi.routing import APIRoute, iter_route_contexts
from pydantic import BaseModel

from sandfort.api.app import create_app
from sandfort.api.schemas import (
    api_keys,
    image_builds,
    orgs,
    sandboxes,
    snapshots,
    sso,
    toolbox_fs,
    toolbox_git,
    toolbox_process,
    toolbox_pty,
    toolbox_sessions,
    users,
    volumes,
    webhooks,
)
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
PUBLIC_IP = "93.184.216.34"  # a public address, so the webhook SSRF check accepts the host
WEBHOOKS = "/v1/webhooks"
SANDBOXES = "/v1/sandboxes"
SCIM_TOKENS = "/v1/org/scim-tokens"
SCOPES = frozenset(
    {Scope.WEBHOOKS_WRITE, Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.API_KEYS_ADMIN}
)
ROUTES_PACKAGE = "sandfort.api.routes"
# Modules whose request bodies stay lenient because the SCIM RFC (7643 section 3) says a
# provider ignores unknown attributes of a resource. The SCIM token admin body is not one.
LENIENT_BY_RFC_MODULES = frozenset({"sandfort.api.routes.scim"})
REQUEST_MODULES = (
    api_keys,
    image_builds,
    orgs,
    sandboxes,
    snapshots,
    sso,
    toolbox_fs,
    toolbox_git,
    toolbox_process,
    toolbox_pty,
    toolbox_sessions,
    users,
    volumes,
    webhooks,
)


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'extra_forbid.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(driver="fake", database_url=url, api_key_pepper=PEPPER, scim_enabled=True)
    application = create_app(settings)
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
async def key(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=SCOPES,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def error_of(response: httpx.Response) -> dict[str, Any]:
    body: dict[str, Any] = response.json()
    assert body["success"] is False, body
    error: dict[str, Any] = body["error"]
    assert error["code"] == "VALIDATION_ERROR", error
    return error


async def test_webhook_create_with_events_instead_of_event_types_is_422_naming_events(
    client: httpx.AsyncClient, key: str
) -> None:
    payload = {"url": "https://hooks.example.com/sandfort", "events": ["sandbox.error"]}

    response = await client.post(WEBHOOKS, headers=auth(key), json=payload)

    assert response.status_code == 422, response.text
    error = error_of(response)
    assert error["details"]["errors"][0]["loc"] == ["body", "events"]
    assert error["details"]["errors"][0]["type"] == "extra_forbidden"
    assert "body.events" in error["message"]


async def test_sandbox_create_with_an_unknown_field_is_422_naming_it(
    client: httpx.AsyncClient, key: str
) -> None:
    response = await client.post(SANDBOXES, headers=auth(key), json={"name": "demo", "cpus": 2})

    assert response.status_code == 422, response.text
    assert error_of(response)["details"]["errors"][0]["loc"] == ["body", "cpus"]


async def test_sandbox_update_with_an_unknown_field_is_422_naming_it(
    client: httpx.AsyncClient, key: str
) -> None:
    created = await client.post(SANDBOXES, headers=auth(key), json={"name": "demo"})
    assert created.status_code == 201, created.text
    sandbox_id = created.json()["data"]["id"]

    response = await client.patch(
        f"{SANDBOXES}/{sandbox_id}", headers=auth(key), json={"label": {"a": "b"}}
    )

    assert response.status_code == 422, response.text
    assert error_of(response)["details"]["errors"][0]["loc"] == ["body", "label"]


async def test_valid_sandbox_create_still_works(client: httpx.AsyncClient, key: str) -> None:
    response = await client.post(
        SANDBOXES, headers=auth(key), json={"name": "demo", "labels": {"team": "a"}}
    )

    assert response.status_code == 201, response.text
    assert response.json()["data"]["name"] == "demo"


async def test_valid_webhook_create_still_works(
    client: httpx.AsyncClient, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def resolve(host: str) -> list[str]:
        return [PUBLIC_IP]

    monkeypatch.setattr("sandfort.webhooks.ssrf.resolve_host", resolve)
    payload = {"url": "https://hooks.example.com/sandfort", "event_types": ["sandbox.error"]}

    response = await client.post(WEBHOOKS, headers=auth(key), json=payload)

    assert response.status_code == 201, response.text
    assert response.json()["data"]["event_types"] == ["sandbox.error"]


async def test_invalid_json_is_located_at_the_body_alone(
    client: httpx.AsyncClient, key: str
) -> None:
    headers = {**auth(key), "Content-Type": "application/json"}

    response = await client.post(SANDBOXES, headers=headers, content=b'{"name": ')

    assert response.status_code == 422, response.text
    issue = error_of(response)["details"]["errors"][0]
    assert issue["type"] == "json_invalid"
    assert issue["loc"] == ["body"]


def request_models() -> list[type[BaseModel]]:
    found: list[type[BaseModel]] = []
    for module in REQUEST_MODULES:
        for name, member in inspect.getmembers(module, inspect.isclass):
            is_own = member.__module__ == module.__name__
            if is_own and issubclass(member, BaseModel) and name.endswith("Request"):
                found.append(member)
    return found


def test_every_request_model_forbids_extra_fields() -> None:
    models = request_models()

    assert len(models) >= 25  # the sweep must actually find the request models
    lax = [model.__name__ for model in models if model.model_config.get("extra") != "forbid"]
    assert lax == []


def body_models(annotation: object) -> list[type[BaseModel]]:
    """The models a body annotation names, looking through ``X | None`` and similar unions."""
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return [annotation]
    return [model for arg in get_args(annotation) for model in body_models(arg)]


def route_body_models(app: FastAPI) -> list[type[BaseModel]]:
    found: dict[str, type[BaseModel]] = {}
    # Included routers are flattened by iter_route_contexts; the SCIM routes are out of the spec
    # but still mounted, so no include_in_schema filter here.
    for context in iter_route_contexts(app.routes):
        route = context.original_route
        if not isinstance(route, APIRoute):
            continue
        for field in route.dependant.body_params:
            for model in body_models(field.field_info.annotation):
                found[f"{model.__module__}.{model.__qualname__}"] = model
    return list(found.values())


async def test_every_route_request_body_under_the_routes_package_forbids_extra_fields(
    app: FastAPI,
) -> None:
    models = [
        model
        for model in route_body_models(app)
        if model.__module__.startswith(ROUTES_PACKAGE) and model.__name__.endswith("Request")
    ]
    names = {model.__name__ for model in models}
    checked = [model for model in models if model.__module__ not in LENIENT_BY_RFC_MODULES]

    # The sweep must actually reach the route-level bodies, including the SCIM token one.
    assert {"MintPreviewTokenRequest", "CreateScimTokenRequest", "CodeContextRunRequest"} <= names
    assert "sandfort.api.routes.scim_tokens" not in LENIENT_BY_RFC_MODULES
    lax = [model.__name__ for model in checked if model.model_config.get("extra") != "forbid"]
    assert lax == []


async def test_preview_token_mint_with_an_unknown_field_is_422_naming_it(
    client: httpx.AsyncClient, key: str
) -> None:
    created = await client.post(SANDBOXES, headers=auth(key), json={"name": "demo"})
    assert created.status_code == 201, created.text
    sandbox_id = created.json()["data"]["id"]

    response = await client.post(
        f"{SANDBOXES}/{sandbox_id}/preview-tokens",
        headers=auth(key),
        json={"port": 3000, "ttl": 600},
    )

    assert response.status_code == 422, response.text
    issue = error_of(response)["details"]["errors"][0]
    assert issue["loc"] == ["body", "ttl"]
    assert issue["type"] == "extra_forbidden"


async def test_scim_token_create_with_an_unknown_field_is_422_naming_it(
    client: httpx.AsyncClient, key: str
) -> None:
    response = await client.post(
        SCIM_TOKENS,
        headers=auth(key),
        json={"name": "okta", "max_role": "viewer", "role": "admin"},
    )

    assert response.status_code == 422, response.text
    issue = error_of(response)["details"]["errors"][0]
    assert issue["loc"] == ["body", "role"]
    assert issue["type"] == "extra_forbidden"
