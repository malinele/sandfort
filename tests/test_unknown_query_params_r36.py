"""Unknown query parameters answer 422 on every guarded GET list route (not only audit).

Through the API on the fake driver and a temp SQLite database, with a key holding every scope.
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
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute, RouteContext, iter_route_contexts

from sandfort.api.app import create_app
from sandfort.api.query_guard import known_query_params
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
USAGE_WINDOW = {"from": "2026-11-01T00:00:00Z", "to": "2026-11-08T00:00:00Z"}
MISSING_ENDPOINT = "/v1/webhooks/whe_missing/deliveries"

# (path, query parameters that route accepts, expected status with them)
ROUTES: list[tuple[str, dict[str, str], int]] = [
    ("/v1/sandboxes", {"limit": "1"}, 200),
    ("/v1/isolation", {}, 200),
    ("/v1/snapshots", {"limit": "1"}, 200),
    ("/v1/volumes", {"limit": "1"}, 200),
    ("/v1/api-keys", {}, 200),
    ("/v1/webhooks", {}, 200),
    (MISSING_ENDPOINT, {"limit": "1"}, 404),  # past the guard: the endpoint does not exist
    ("/v1/nodes", {}, 200),
    ("/v1/jobs", {"limit": "1"}, 200),
    ("/v1/org/usage", USAGE_WINDOW, 200),
    ("/v1/org/members", {}, 200),
    ("/v1/org/quota", {}, 200),
    ("/v1/org/quota/recount", {}, 200),
    ("/v1/org/scim-tokens", {}, 200),
]
PATHS = [path for path, _, _ in ROUTES]


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'unknown_query.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(
        Settings(driver="fake", database_url=url, api_key_pepper=PEPPER, scim_enabled=True)
    )
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
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset(Scope),
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored)
        await uow.commit()
    return {"Authorization": f"Bearer {generated.key}"}


def _error(response: httpx.Response) -> dict[str, Any]:
    body: dict[str, Any] = response.json()
    error: dict[str, Any] = body["error"]
    return error


@pytest.mark.parametrize("path", PATHS)
async def test_unknown_parameter_is_422_validation_error_naming_it(
    client: httpx.AsyncClient, headers: dict[str, str], path: str
) -> None:
    response = await client.get(path, params={"bogus": "1"}, headers=headers)

    assert response.status_code == 422, response.text
    error = _error(response)
    assert error["code"] == "VALIDATION_ERROR"
    assert "`bogus`" in error["message"]
    assert error["details"]["errors"] == [
        {
            "type": "extra_forbidden",
            "loc": ["query", "bogus"],
            "msg": "Extra inputs are not permitted",
        }
    ]


@pytest.mark.parametrize(("path", "params", "status"), ROUTES)
async def test_known_parameters_still_work(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    path: str,
    params: dict[str, str],
    status: int,
) -> None:
    response = await client.get(path, params=params, headers=headers)

    assert response.status_code == status, response.text


@pytest.mark.parametrize("path", PATHS)
async def test_unauthenticated_unknown_parameter_is_401(
    client: httpx.AsyncClient, path: str
) -> None:
    response = await client.get(path, params={"bogus": "1"})

    assert response.status_code == 401, response.text


@pytest.mark.parametrize("path", ["/v1/sandboxes", "/v1/snapshots"])
@pytest.mark.parametrize("cursor", ["", "!!", "bm90LWFuLWlk"])
async def test_empty_or_malformed_cursor_is_422_located_at_query_cursor(
    client: httpx.AsyncClient, headers: dict[str, str], path: str, cursor: str
) -> None:
    response = await client.get(path, params={"cursor": cursor}, headers=headers)

    assert response.status_code == 422, response.text
    error = _error(response)
    assert error["code"] == "VALIDATION_ERROR"
    assert [issue["loc"] for issue in error["details"]["errors"]] == [["query", "cursor"]]


async def test_misspelt_filter_on_sandbox_list_is_rejected_not_ignored(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    response = await client.get("/v1/sandboxes", params={"sate": "started"}, headers=headers)

    assert response.status_code == 422, response.text
    assert _error(response)["details"]["errors"][0]["loc"] == ["query", "sate"]


async def test_two_unknown_parameters_give_two_entries(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    response = await client.get("/v1/volumes", params={"zzz": "1", "aaa": "2"}, headers=headers)

    assert response.status_code == 422, response.text
    errors = _error(response)["details"]["errors"]
    assert [entry["loc"] for entry in errors] == [["query", "aaa"], ["query", "zzz"]]


async def test_pagination_names_are_accepted_only_where_the_route_declares_them(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    listed = await client.get("/v1/sandboxes", params={"order": "desc"}, headers=headers)
    snapshots = await client.get("/v1/snapshots", params={"order": "desc"}, headers=headers)

    assert listed.status_code == 200, listed.text
    assert snapshots.status_code == 422, snapshots.text


# -- toolbox lists -----------------------------------------------------------------------------
# A sandbox that does not exist passes the router-level visibility guard for an unscoped key, so
# the query guard is reached; the handler then answers 404, which proves the request got past it.

TOOLBOX = "/v1/sandboxes/sbx_missing/toolbox"
COMMAND = f"{TOOLBOX}/process/sessions/ses_missing/commands/cmd_missing"
TOOLBOX_ROUTES: list[tuple[str, dict[str, str]]] = [
    (f"{TOOLBOX}/process/sessions", {}),
    (f"{COMMAND}/logs", {"offset": "0", "limit": "1"}),
    (f"{COMMAND}/logs/follow", {"offset": "0"}),
    (f"{TOOLBOX}/pty", {}),
    (f"{TOOLBOX}/code-contexts", {"name": "main"}),
    (f"{TOOLBOX}/fs/list", {"path": "/"}),
    (f"{TOOLBOX}/git/status", {"path": "/work"}),
    (f"{TOOLBOX}/fs/stat", {"path": "/"}),
    (f"{TOOLBOX}/fs/download", {"path": "/", "inline": "true", "max_bytes": "10"}),
    ("/v1/sandboxes/sbx_missing", {"wait_for": "started", "timeout_s": "0"}),
    ("/v1/sandboxes/sbx_missing/logs", {"tail": "10", "follow": "false", "since": "0"}),
]
TOOLBOX_PATHS = [path for path, _ in TOOLBOX_ROUTES]


@pytest.mark.parametrize("path", TOOLBOX_PATHS)
async def test_toolbox_unknown_parameter_is_422_before_the_sandbox_lookup(
    client: httpx.AsyncClient, headers: dict[str, str], path: str
) -> None:
    response = await client.get(path, params={"pth": "/"}, headers=headers)

    assert response.status_code == 422, response.text
    error = _error(response)
    assert error["code"] == "VALIDATION_ERROR"
    assert error["details"]["errors"][0]["loc"] == ["query", "pth"]


@pytest.mark.parametrize(("path", "params"), TOOLBOX_ROUTES)
async def test_toolbox_known_parameters_reach_the_handler(
    client: httpx.AsyncClient, headers: dict[str, str], path: str, params: dict[str, str]
) -> None:
    response = await client.get(path, params=params, headers=headers)

    assert response.status_code == 404, response.text


@pytest.mark.parametrize("path", TOOLBOX_PATHS)
async def test_toolbox_unauthenticated_unknown_parameter_is_401(
    client: httpx.AsyncClient, path: str
) -> None:
    response = await client.get(path, params={"bogus": "1"})

    assert response.status_code == 401, response.text


# -- drift guard -------------------------------------------------------------------------------
# Every GET route must carry the guard or be listed here with the reason it does not. A new route
# that is neither fails ``test_every_get_route_is_guarded_or_allowlisted``. Paths are the full
# route templates (prefix included), as FastAPI reports them.

SCIM_PREFIX = "/scim/v2/"  # RFC 7644 parameters (filter, startIndex, count) are accepted there
HEALTH_AND_PAGES = frozenset(
    {
        "/healthz",
        "/readyz",
        "/v1/status",
        "/metrics",
        "/console",
        "/docs",
        "/redoc",
        "/docs/init.js",
    }
)
_SESSION = "/v1/sandboxes/{sandbox_id}/toolbox/process/sessions/{session_id}"
STREAMING = frozenset(
    {
        "/v1/images/builds/{snapshot_id}/logs",
        "/v1/snapshots/{snapshot_id}/export",
    }
)
# Reads of one resource by id (or one record under a session): not lists, so no filter to
# misspell. ``test_allowlisted_routes_declare_no_query_parameter`` fails when one of them gains a
# query parameter: add the guard to it and drop it from here.
ITEM_READS = frozenset(
    {
        "/v1/snapshots/{snapshot_id}",
        "/v1/volumes/{volume_id}",
        "/v1/webhooks/{endpoint_id}",
        "/v1/jobs/{job_id}",
        _SESSION,
        f"{_SESSION}/commands/{{command_id}}",
        "/v1/sandboxes/{sandbox_id}/toolbox/pty/{pty_id}",
    }
)
UNGUARDED_ALLOWLIST = HEALTH_AND_PAGES | STREAMING | ITEM_READS


def _calls(dependant: Dependant) -> list[object]:
    found: list[object] = [dependant.call]
    for sub in dependant.dependencies:
        found.extend(_calls(sub))
    return found


def _has_query_guard(route: RouteContext) -> bool:
    for call in _calls(route.dependant):
        if call is known_query_params:
            return True
        if getattr(call, "__qualname__", "").startswith("only_params."):
            return True
    return False


def _get_routes(application: FastAPI) -> list[RouteContext]:
    """The GET routes with their effective path and dependencies (included routers flattened)."""
    return [
        route
        for route in iter_route_contexts(application.routes)
        if isinstance(route.original_route, APIRoute) and "GET" in (route.methods or set())
    ]


def _path(route: RouteContext) -> str:
    return route.path or ""


def _is_exempt(path: str) -> bool:
    return path.startswith(SCIM_PREFIX) or path in UNGUARDED_ALLOWLIST


def _query_names(dependant: Dependant) -> set[str]:
    names = {field.alias for field in dependant.query_params}
    for sub in dependant.dependencies:
        names |= _query_names(sub)
    return names


def test_walk_sees_the_guarded_routes_it_polices(app: FastAPI) -> None:
    guarded = {_path(route) for route in _get_routes(app) if _has_query_guard(route)}
    templates = {
        path.replace("sbx_missing", "{sandbox_id}")
        .replace("ses_missing", "{session_id}")
        .replace("cmd_missing", "{command_id}")
        for path in TOOLBOX_PATHS
    }

    assert templates <= guarded
    assert "/v1/org/members" in guarded
    assert "/v1/org/quota" in guarded
    assert "/v1/org/quota/recount" in guarded
    assert "/v1/org/scim-tokens" in guarded


def test_every_get_route_is_guarded_or_allowlisted(app: FastAPI) -> None:
    drifted = sorted(
        _path(route)
        for route in _get_routes(app)
        if not _has_query_guard(route) and not _is_exempt(_path(route))
    )

    assert drifted == [], (
        "GET routes without the unknown-query guard (add `_known: KnownQuery` after the auth "
        f"dependency, or list them in UNGUARDED_ALLOWLIST with a reason): {drifted}"
    )


def test_allowlisted_routes_do_not_carry_the_guard(app: FastAPI) -> None:
    redundant = sorted(
        _path(route)
        for route in _get_routes(app)
        if _has_query_guard(route) and _path(route) in UNGUARDED_ALLOWLIST
    )

    assert redundant == [], f"drop these from UNGUARDED_ALLOWLIST, they are guarded: {redundant}"


def test_allowlisted_routes_declare_no_query_parameter(app: FastAPI) -> None:
    """The allowlist cannot hide a filter: an exempt route has no non-path query parameter."""
    declaring = {
        _path(route): sorted(_query_names(route.dependant))
        for route in _get_routes(app)
        if _path(route) in UNGUARDED_ALLOWLIST and _query_names(route.dependant)
    }

    assert declaring == {}, f"guard these routes instead of allowlisting them: {declaring}"


def test_scim_resource_routes_stay_unguarded(app: FastAPI) -> None:
    scim_routes = [route for route in _get_routes(app) if _path(route).startswith(SCIM_PREFIX)]

    assert scim_routes, "SCIM is enabled in this app: its GET routes must be mounted"
    assert [_path(route) for route in scim_routes if _has_query_guard(route)] == []
