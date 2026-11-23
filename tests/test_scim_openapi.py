"""The SCIM wire contract and the OpenAPI export policy (phase 10, slice 9).

SCIM is described by its own discovery documents and media type, not by the exported spec
(docs/scim-design.md, OpenAPI export policy): no ``/scim/v2`` and no ``/v1/org/scim-tokens`` path
is exported, with SCIM off (the export default) or on, so the pinned ``openapi/sandfort.v1.json``
and its drift test stay valid with no regeneration. With SCIM off nothing is mounted at all. The
wire side: discovery, ``application/scim+json`` in both directions, ``invalidSyntax`` and
``invalidValue`` for bad input, and the ordinary 404 for an unknown path under ``/scim/v2``.
"""

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.routing import APIRoute

from sandfort.api.openapi import OPENAPI_PATH, build_document, render_spec
from sandfort.api.routes import scim, scim_tokens
from sandfort.api.routes.scim import SCIM_PREFIX, ScimRoute, scim_principal
from test_scim_api import (
    SCIM,
    SCIM_TYPE,
    USER_SCHEMA,
    USERS,
    World,
    assert_scim_error,
    bearer,
    open_world,
    send,
    user_body,
)

EXCLUDED_PREFIXES = ("/scim", "/v1/org/scim-tokens")
USER_ITEM = f"{USERS}/{{user_id}}"
EXPECTED_OPERATIONS = {
    ("GET", f"{SCIM}/ServiceProviderConfig"),
    ("GET", f"{SCIM}/ResourceTypes"),
    ("GET", f"{SCIM}/Schemas"),
    ("GET", USERS),
    ("POST", USERS),
    ("GET", USER_ITEM),
    ("PUT", USER_ITEM),
    ("PATCH", USER_ITEM),
    ("DELETE", USER_ITEM),
}


@pytest.fixture
async def world(tmp_path: Path) -> AsyncIterator[World]:
    async with open_world(tmp_path) as opened:
        yield opened


def exported_scim_paths(document: dict[str, Any]) -> list[str]:
    return [path for path in document["paths"] if path.startswith(EXCLUDED_PREFIXES)]


def api_routes(routes: list[Any]) -> list[APIRoute]:
    return [route for route in routes if isinstance(route, APIRoute)]


# --- the export policy --------------------------------------------------------------------


async def test_the_default_export_has_no_scim_path() -> None:
    document = build_document()

    assert exported_scim_paths(document) == []


async def test_an_export_with_scim_enabled_has_no_scim_path(world: World) -> None:
    served = await send(world, "GET", USERS)

    document = build_document(world.app)

    assert served.status_code == 200
    assert exported_scim_paths(document) == []


async def test_enabling_scim_leaves_the_committed_spec_byte_identical(world: World) -> None:
    exported = render_spec(build_document(world.app)).encode("utf-8")

    assert exported == OPENAPI_PATH.read_bytes()


def test_every_scim_route_is_unexported_scim_shaped_and_token_guarded() -> None:
    routes = api_routes(scim.router.routes)

    operations = {(method, route.path) for route in routes for method in route.methods}

    assert EXPECTED_OPERATIONS <= operations
    assert len(routes) == len(scim.router.routes)
    for route in routes:
        assert isinstance(route, ScimRoute)
        assert route.path.startswith(SCIM_PREFIX)
        assert route.include_in_schema is False
        assert any(depends.dependency is scim_principal for depends in route.dependencies)


def test_every_scim_token_route_is_unexported() -> None:
    routes = api_routes(scim_tokens.router.routes)

    assert routes
    assert all(route.include_in_schema is False for route in routes)


async def test_nothing_is_mounted_when_scim_is_off(tmp_path: Path) -> None:
    async with open_world(tmp_path, scim_enabled=False) as off:
        users = await off.client.get(USERS, headers=bearer(off.admin_key))
        discovery = await off.client.get(f"{SCIM}/ServiceProviderConfig")

    for response in (users, discovery):
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "NOT_FOUND"


# --- the wire contract --------------------------------------------------------------------


async def test_discovery_documents_are_served_with_the_scim_type(world: World) -> None:
    config = await send(world, "GET", f"{SCIM}/ServiceProviderConfig")
    resource_types = await send(world, "GET", f"{SCIM}/ResourceTypes")
    schemas = await send(world, "GET", f"{SCIM}/Schemas")

    for response in (config, resource_types, schemas):
        assert response.status_code == 200
        assert response.headers["content-type"] == SCIM_TYPE
    assert config.json()["patch"]["supported"] is True
    assert config.json()["bulk"]["supported"] is False
    assert config.json()["meta"]["location"] == f"http://test{SCIM}/ServiceProviderConfig"
    assert [item["endpoint"] for item in resource_types.json()["Resources"]] == ["/Users"]
    assert [item["id"] for item in schemas.json()["Resources"]] == [USER_SCHEMA]


async def test_a_plain_json_body_is_accepted_and_answered_as_scim(world: World) -> None:
    body = user_body("ada@example.com")

    response = await send(world, "POST", USERS, body, content_type="application/json")

    assert response.status_code == 201
    assert response.headers["content-type"] == SCIM_TYPE


async def test_bad_bodies_and_parameters_are_400_in_scim_terms(world: World) -> None:
    body = user_body("ada@example.com")

    malformed = await send(world, "POST", USERS, "{not json")
    plain_text = await send(world, "POST", USERS, body, content_type="text/plain")
    no_schema = await send(world, "POST", USERS, {"userName": "ada@example.com"})
    inactive = await send(world, "POST", USERS, user_body("ada@example.com", active=False))
    bad_index = await send(world, "GET", USERS, params={"startIndex": "first"})

    for response in (malformed, plain_text, no_schema):
        assert_scim_error(response, 400, "invalidSyntax")
    assert_scim_error(inactive, 400, "invalidValue")
    assert_scim_error(bad_index, 400, "invalidValue")


async def test_an_unknown_scim_path_is_the_ordinary_404(world: World) -> None:
    response = await send(world, "GET", f"{SCIM}/Groups")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"
