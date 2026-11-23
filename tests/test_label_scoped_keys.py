"""A label-scoped API key sees and changes only sandboxes that carry its labels.

Through the API on the fake driver and a temp SQLite database. Snapshots, volumes, keys and usage
are not scoped; only sandboxes are. A label-scoped key cannot read audit events.
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
from sandfort.auth.api_keys import generate_api_key
from sandfort.auth.label_scope import set_label_scope
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
TEAM_A = {"team": "a"}
TEAM_B = {"team": "b"}
REFUSAL = "this API key is limited to sandboxes labelled team=a"


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'scoped.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(driver="fake", database_url=url, api_key_pepper=PEPPER)
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


async def add_org(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def add_key(app: FastAPI, org_id: str, labels: dict[str, str] | None) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=FULL_ACCESS,
        created_at=NOW,
        sandbox_labels=labels,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    return await add_org(app)


@pytest.fixture
async def unscoped(app: FastAPI, org_id: str) -> str:
    return await add_key(app, org_id, None)


@pytest.fixture
async def scoped(app: FastAPI, org_id: str) -> str:
    return await add_key(app, org_id, TEAM_A)


async def send(
    client: httpx.AsyncClient, method: str, path: str, key: str, *, status: int, **kwargs: Any
) -> dict[str, Any]:
    response = await client.request(
        method, path, headers={"Authorization": f"Bearer {key}"}, **kwargs
    )
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    assert body["success"] is (status < 400)
    return body


async def create(client: httpx.AsyncClient, key: str, **payload: Any) -> dict[str, Any]:
    body = await send(client, "POST", BASE, key, status=201, json=payload)
    data: dict[str, Any] = body["data"]
    return data


async def listed_ids(client: httpx.AsyncClient, key: str, **params: Any) -> set[str]:
    body = await send(client, "GET", BASE, key, status=200, params=params)
    return {item["id"] for item in body["data"]}


@pytest.fixture
async def team_b_id(client: httpx.AsyncClient, unscoped: str) -> str:
    """A running sandbox labelled team=b, created by the unscoped key."""
    return str((await create(client, unscoped, labels=TEAM_B))["id"])


# --- create ------------------------------------------------------------------------


async def test_create_adds_the_scope_labels_to_the_sandbox(
    client: httpx.AsyncClient, scoped: str
) -> None:
    plain = await create(client, scoped)
    mixed = await create(client, scoped, labels={"env": "ci"})

    assert plain["labels"]["team"] == "a"
    assert mixed["labels"]["team"] == "a"
    assert mixed["labels"]["env"] == "ci"


async def test_create_with_a_label_that_contradicts_the_scope_is_forbidden(
    client: httpx.AsyncClient, scoped: str
) -> None:
    body = await send(client, "POST", BASE, scoped, status=403, json={"labels": TEAM_B})

    assert body["error"]["code"] == "FORBIDDEN"
    assert body["error"]["message"] == REFUSAL
    assert await listed_ids(client, scoped) == set()


async def test_create_with_the_scope_label_itself_is_accepted(
    client: httpx.AsyncClient, scoped: str
) -> None:
    sandbox = await create(client, scoped, labels=TEAM_A)

    assert sandbox["labels"]["team"] == "a"


# --- reads -------------------------------------------------------------------------


async def test_list_shows_only_sandboxes_in_the_scope(
    client: httpx.AsyncClient, scoped: str, unscoped: str, team_b_id: str
) -> None:
    own = (await create(client, scoped))["id"]
    unlabelled = (await create(client, unscoped))["id"]

    assert await listed_ids(client, scoped) == {own}
    assert {own, unlabelled, team_b_id} <= await listed_ids(client, unscoped)


async def test_list_filtered_to_another_value_of_the_scope_key_is_empty(
    client: httpx.AsyncClient, scoped: str, team_b_id: str
) -> None:
    await create(client, scoped)

    assert await listed_ids(client, scoped, label="team=b") == set()


async def test_list_filtered_by_an_extra_label_stays_inside_the_scope(
    client: httpx.AsyncClient, scoped: str, unscoped: str
) -> None:
    own = (await create(client, scoped, labels={"env": "ci"}))["id"]
    await create(client, scoped, labels={"env": "dev"})
    await create(client, unscoped, labels={"env": "ci", "team": "b"})

    assert await listed_ids(client, scoped, label="env=ci") == {own}


async def test_get_of_a_sandbox_outside_the_scope_is_not_found(
    client: httpx.AsyncClient, scoped: str, unscoped: str, team_b_id: str
) -> None:
    own = (await create(client, scoped))["id"]

    await send(client, "GET", f"{BASE}/{team_b_id}", scoped, status=404)
    await send(client, "GET", f"{BASE}/{own}", scoped, status=200)
    await send(client, "GET", f"{BASE}/{team_b_id}", unscoped, status=200)


# --- changes -----------------------------------------------------------------------


async def test_exec_in_a_sandbox_outside_the_scope_is_not_found(
    client: httpx.AsyncClient, scoped: str, team_b_id: str
) -> None:
    own = (await create(client, scoped))["id"]

    def execute(sandbox_id: str) -> str:
        return f"{BASE}/{sandbox_id}/toolbox/process/execute"

    payload = {"command": "true"}
    await send(client, "POST", execute(team_b_id), scoped, status=404, json=payload)
    await send(client, "POST", execute(own), scoped, status=200, json=payload)


async def test_stop_of_a_sandbox_outside_the_scope_is_not_found(
    client: httpx.AsyncClient, scoped: str, unscoped: str, team_b_id: str
) -> None:
    own = (await create(client, scoped))["id"]

    await send(client, "POST", f"{BASE}/{team_b_id}/stop", scoped, status=404)
    stopped = await send(client, "POST", f"{BASE}/{own}/stop", scoped, status=200)

    assert stopped["data"]["state"] == "stopped"
    other = await send(client, "GET", f"{BASE}/{team_b_id}", unscoped, status=200)
    assert other["data"]["state"] == "started"


async def test_delete_of_a_sandbox_outside_the_scope_is_not_found(
    client: httpx.AsyncClient, scoped: str, unscoped: str, team_b_id: str
) -> None:
    own = (await create(client, scoped))["id"]

    await send(client, "DELETE", f"{BASE}/{team_b_id}", scoped, status=404)
    await send(client, "DELETE", f"{BASE}/{own}", scoped, status=200)

    other = await send(client, "GET", f"{BASE}/{team_b_id}", unscoped, status=200)
    assert other["data"]["state"] == "started"


async def test_patching_labels_out_of_the_scope_is_forbidden(
    client: httpx.AsyncClient, scoped: str
) -> None:
    own = (await create(client, scoped))["id"]
    path = f"{BASE}/{own}"

    moved = await send(client, "PATCH", path, scoped, status=403, json={"labels": TEAM_B})
    dropped = await send(client, "PATCH", path, scoped, status=403, json={"labels": {}})

    assert moved["error"]["message"] == REFUSAL
    assert dropped["error"]["message"] == REFUSAL
    kept = await send(client, "GET", path, scoped, status=200)
    assert kept["data"]["labels"]["team"] == "a"


async def test_patching_labels_inside_the_scope_is_allowed(
    client: httpx.AsyncClient, scoped: str
) -> None:
    own = (await create(client, scoped))["id"]
    labels = {"team": "a", "env": "ci"}

    body = await send(client, "PATCH", f"{BASE}/{own}", scoped, status=200, json={"labels": labels})

    assert body["data"]["labels"]["env"] == "ci"


async def test_patch_of_a_sandbox_outside_the_scope_is_not_found(
    client: httpx.AsyncClient, scoped: str, team_b_id: str
) -> None:
    path = f"{BASE}/{team_b_id}"

    await send(client, "PATCH", path, scoped, status=404, json={"labels": TEAM_A})


async def test_an_unscoped_key_may_move_labels_freely(
    client: httpx.AsyncClient, unscoped: str, team_b_id: str
) -> None:
    body = await send(
        client, "PATCH", f"{BASE}/{team_b_id}", unscoped, status=200, json={"labels": TEAM_A}
    )

    assert body["data"]["labels"]["team"] == "a"


# --- system paths ------------------------------------------------------------------


async def test_the_reconciler_listing_is_not_filtered_by_a_scope(
    app: FastAPI, client: httpx.AsyncClient, scoped: str, team_b_id: str
) -> None:
    own = (await create(client, scoped))["id"]

    token = set_label_scope(TEAM_A)
    try:
        async with app.state.uow_factory() as uow:
            seen = {item.id for item in await uow.sandboxes.list_for_reconciler()}
    finally:
        set_label_scope(None)
        del token

    assert {own, team_b_id} <= seen


async def test_without_a_scope_the_repository_passes_every_call_through(
    app: FastAPI, client: httpx.AsyncClient, scoped: str, team_b_id: str, org_id: str
) -> None:
    own = (await create(client, scoped))["id"]
    # The in-process ASGI transport runs requests in this task, so the scoped request above
    # left its scope set; a worker starts in a context where it was never set.
    set_label_scope(None)

    async with app.state.uow_factory() as uow:
        found = await uow.sandboxes.get(org_id, team_b_id)
        everything = {item.id for item in await uow.sandboxes.list(org_id)}

    assert found is not None
    assert {own, team_b_id} <= everything
