"""Meta test: every mutating route is audited or sits on a reasoned exemption list (B7).

``docs/governance.md`` promises one audit row for what a mutating call did. Nothing used to walk
the routes, so ``POST .../preview-tokens`` and ``PATCH /v1/webhooks/{id}`` shipped without one.

``COVERAGE`` has one entry per non-GET, non-HEAD, non-OPTIONS route that ``create_app`` registers
(SCIM and the internal egress route switched on) and per WebSocket route:

* ``exercised``: the scenario below calls the route over HTTP and requires a new success row with
  that action in the caller's org, and no secret from the response in any new row;
* ``proven``: a call needs infrastructure this suite builds elsewhere (scripted shells, jobs, a
  git remote). The entry names the test that asserts the row; this file checks that the test
  still exists and still mentions the action, so deleting the proof fails here;
* ``exempt``: a short reason why the route writes no row.

A route the app registers without an entry fails ``test_every_mutating_route_has_a_coverage_entry``;
an entry for a route that no longer exists fails it too. That is the guard for new routes.
"""

import ast
import json
from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from fastapi.routing import iter_route_contexts

import test_code_contexts_api
from audit_coverage_table_r96 import COVERAGE, WEBSOCKET_EXEMPT, Entry
from sandfort.api.app import create_app
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import AuditEvent, AuditOutcome
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
NOW = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
NOT_MUTATING = frozenset({"GET", "HEAD", "OPTIONS"})
SECRET_KEYS = frozenset({"key", "secret", "token"})  # response fields that hold a credential


# --- the app and its keys -----------------------------------------------------------


@pytest.fixture(autouse=True)
def public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolve(host: str) -> Sequence[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr("sandfort.webhooks.ssrf.resolve_host", resolve)


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'coverage.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(
        driver="fake",
        database_url=url,
        api_key_pepper=PEPPER,
        scim_enabled=True,  # mounts the SCIM routes the inventory has to see
        egress_secret="e" * 40,
        egress_policy_route_enabled=True,
    )
    application = create_app(settings)
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as http:
        yield http


async def seed_admin(app: FastAPI) -> tuple[str, str, str]:
    """A platform-admin key with every scope: ``(raw key, key id, org id)``."""
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="meta",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset(Scope),
        is_platform_admin=True,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key, stored.id, org.id


async def rows(app: FastAPI, org_id: str) -> list[AuditEvent]:
    async with UnitOfWork(app.state.session_factory) as uow:
        return list(await uow.audit.list(org_id, limit=500))


def secrets_in(body: Any) -> set[str]:
    """Credential values a response hands out (``key``, ``secret`` or ``token`` fields)."""
    found: set[str] = set()
    if isinstance(body, dict):
        for name, value in body.items():
            if name in SECRET_KEYS and isinstance(value, str) and value:
                found.add(value)
            found |= secrets_in(value)
    elif isinstance(body, list):
        for item in body:
            found |= secrets_in(item)
    return found


# --- 1. the inventory: no route without an entry ------------------------------------


def registered_routes(app: FastAPI) -> tuple[set[tuple[str, str]], set[str]]:
    mutating: set[tuple[str, str]] = set()
    websockets: set[str] = set()
    for context in iter_route_contexts(app.routes):
        if context.methods is None:
            websockets.add(context.path)
            continue
        mutating |= {(m, context.path) for m in context.methods if m not in NOT_MUTATING}
    return mutating, websockets


def test_every_mutating_route_has_a_coverage_entry(app: FastAPI) -> None:
    mutating, websockets = registered_routes(app)

    missing = sorted(mutating - set(COVERAGE))
    stale = sorted(set(COVERAGE) - mutating)
    assert not missing, (
        f"mutating routes with no audit coverage entry (add an audited case or a reasoned "
        f"exemption in tests/audit_coverage_table_r96.py): {missing}"
    )
    assert not stale, f"coverage entries for routes the app no longer registers: {stale}"
    differing = sorted(websockets ^ set(WEBSOCKET_EXEMPT))
    assert websockets == set(WEBSOCKET_EXEMPT), (
        f"WebSocket routes and exemptions differ: {differing}"
    )
    assert all(WEBSOCKET_EXEMPT.values())
    assert all(entry.reason for entry in COVERAGE.values() if entry.kind == "exempt")


def test_a_new_mutating_route_without_an_entry_is_reported(app: FastAPI) -> None:
    async def handler() -> dict[str, bool]:
        return {"ok": True}

    app.add_api_route("/v1/new-thing", handler, methods=["POST", "GET"])
    app.add_api_websocket_route("/v1/new-socket", handler)

    mutating, websockets = registered_routes(app)

    assert sorted(mutating - set(COVERAGE)) == [("POST", "/v1/new-thing")]
    assert "/v1/new-socket" in websockets - set(WEBSOCKET_EXEMPT)


def test_the_exemption_list_stays_small() -> None:
    exemptions = [key for key, entry in COVERAGE.items() if entry.kind == "exempt"]

    assert exemptions == [("POST", "/internal/egress/v1/policies")]


# --- 2. proofs: the named tests still exist and still mention the action ------------


def function_source(path: Path, name: str) -> str | None:
    text = path.read_text()
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == name:
            return ast.get_source_segment(text, node)
    return None


@pytest.mark.parametrize(
    ("route", "entry"),
    [(route, entry) for route, entry in COVERAGE.items() if entry.kind == "proven"],
    ids=lambda value: " ".join(value) if isinstance(value, tuple) else "",
)
def test_a_proven_route_names_a_test_that_exists_and_mentions_its_action(
    route: tuple[str, str], entry: Entry
) -> None:
    file_name, _, function = entry.proof.partition("::")
    source = function_source(TESTS / file_name, function)

    assert source is not None, f"{entry.proof} does not exist (route {route})"
    literal = f'"{entry.action}"'  # the string itself: a constant's name would survive its removal
    assert literal in source, f"{entry.proof} no longer mentions the literal {literal}"
    assert file_name != Path(__file__).name


def test_code_context_actions_proven_by_the_api_test_are_members_of_its_action_set() -> None:
    """That proof asserts against the set ``AUDIT_ACTIONS``; the table's actions must be in it."""
    proved = [
        entry.action
        for entry in COVERAGE.values()
        if entry.proof.startswith("test_code_contexts_api.py::test_every_mutating_call")
    ]

    assert sorted(proved) == ["toolbox.code_contexts.delete", "toolbox.code_contexts.run"]
    assert set(proved) <= set(test_code_contexts_api.AUDIT_ACTIONS)


# --- 3. the exercise: call the routes and read the rows -----------------------------


def concrete(template: str, context: dict[str, str]) -> str:
    return template.format(**context)


async def test_every_exercised_route_writes_a_success_row_without_secrets(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    key, key_id, org_id = await seed_admin(app)
    context: dict[str, str] = {}
    seen = {event.id for event in await rows(app, org_id)}
    done: set[tuple[str, str]] = set()
    handed_out: set[str] = set()

    for route, entry in COVERAGE.items():
        if entry.kind != "exercised":
            continue
        method, template = route
        step = dict(entry.step)
        status, capture = step.pop("status"), step.pop("capture")
        response = await client.request(
            method,
            concrete(template, context),
            headers={"Authorization": f"Bearer {key}"},
            **step,
        )
        assert response.status_code == status, f"{route}: {response.status_code} {response.text}"
        body = response.json() if response.content else {}
        handed_out |= secrets_in(body)
        if capture:
            name, _, field_name = capture.partition(":")
            assert field_name in body["data"], f"{route} returned no {field_name}: {body['data']}"
            context[name] = body["data"][field_name]

        fresh = [e for e in await rows(app, org_id) if e.id not in seen]
        seen |= {e.id for e in fresh}
        mine = [e for e in fresh if e.action == entry.action]
        assert mine, f"{route} wrote no {entry.action} row; new rows: {[e.action for e in fresh]}"
        assert all(e.outcome is AuditOutcome.SUCCESS for e in fresh), f"{route}: {fresh}"
        assert all(e.org_id == org_id and e.actor_id == key_id for e in mine), route
        done.add(route)

    exercised_routes = {route for route, entry in COVERAGE.items() if entry.kind == "exercised"}
    assert done == exercised_routes
    everything = json.dumps([vars(e) for e in await rows(app, org_id)], default=str)
    leaked = sorted(secret for secret in handed_out if secret in everything)
    assert not leaked, "a credential returned to the caller is stored in an audit row"
