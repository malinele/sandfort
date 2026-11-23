"""Round 35: label-scoped keys see no internal ids; node counts are per caller org.

1) ``source_sandbox_id`` on snapshots and ``node_id`` / ``job_id`` on sandboxes are null for a
   ``team=red`` key and filled in for an org-wide key.
2) ``GET /v1/nodes`` counts only the caller org's started sandboxes on each node.
"""

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from sandfort.auth.api_keys import generate_api_key
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.node import DEFAULT_NODE_ID, Node
from sandfort.domain.org import ApiKey, Scope
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.ids import new_api_key_id, new_sandbox_id
from test_api_sandboxes import BASE, NOW, PEPPER, add_org, migrated_app, send
from test_snapshot_scope import RED, SNAPSHOTS, commit_snapshot, make_sandbox, seed_key

NODES = "/v1/nodes"
NODE_A = "node-a"
NODE_B = "node-b"


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    async with migrated_app(tmp_path) as application:
        yield application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


async def seed_org_reader(app: FastAPI, org_id: str) -> str:
    """An org-wide key with ``org:read``, the scope ``GET /v1/nodes`` needs."""
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="nodes",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset({Scope.ORG_READ}),
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


async def seed_nodes(app: FastAPI, *node_ids: str) -> None:
    async with UnitOfWork(app.state.session_factory) as uow:
        for node_id in node_ids:
            await uow.nodes.upsert_heartbeat(
                Node(id=node_id, name=node_id, last_heartbeat_at=NOW)
            )
        await uow.commit()


async def seed_sandboxes(
    app: FastAPI, org_id: str, node_id: str, state: SandboxState, count: int
) -> None:
    async with UnitOfWork(app.state.session_factory) as uow:
        for _ in range(count):
            sandbox_id = new_sandbox_id()
            await uow.sandboxes.add(
                Sandbox(
                    id=sandbox_id,
                    org_id=org_id,
                    name=f"sbx-{sandbox_id}",
                    image_ref="python:3.12-slim",
                    driver="fake",
                    state=state,
                    desired_state=state,
                    created_at=NOW,
                    updated_at=NOW,
                )
            )
            await uow.nodes.assign_sandbox(sandbox_id, node_id)
        await uow.commit()


async def running_by_node(client: httpx.AsyncClient, key: str) -> dict[str, int]:
    body = await send(client, "GET", NODES, key, status=200)
    return {item["id"]: item["running_sandboxes"] for item in body["data"]}


# --- 1) internal ids are withheld from a label-scoped caller ----------------------------


async def test_scoped_key_sees_null_node_and_job_ids_on_a_sandbox(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    org_id = await add_org(app, "internals-sbx")
    unscoped = await seed_key(app, org_id, None)
    red = await seed_key(app, org_id, RED)
    sandbox_id = await make_sandbox(client, unscoped, labels=RED)

    scoped = (await send(client, "GET", f"{BASE}/{sandbox_id}", red, status=200))["data"]
    listed = (await send(client, "GET", BASE, red, status=200))["data"]

    assert (scoped["node_id"], scoped["job_id"]) == (None, None)
    assert [item["id"] for item in listed] == [sandbox_id]
    assert (listed[0]["node_id"], listed[0]["job_id"]) == (None, None)


async def test_org_wide_key_sees_the_node_id_on_a_sandbox(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    org_id = await add_org(app, "internals-wide")
    unscoped = await seed_key(app, org_id, None)
    sandbox_id = await make_sandbox(client, unscoped, labels=RED)

    data = (await send(client, "GET", f"{BASE}/{sandbox_id}", unscoped, status=200))["data"]

    assert data["node_id"] == DEFAULT_NODE_ID


async def test_scoped_key_sees_a_null_source_sandbox_id_on_a_snapshot(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    org_id = await add_org(app, "internals-snap")
    unscoped = await seed_key(app, org_id, None)
    red = await seed_key(app, org_id, RED)
    sandbox_id = await make_sandbox(client, unscoped, labels=RED)
    snapshot_id = await commit_snapshot(app, client, unscoped, sandbox_id)
    path = f"{SNAPSHOTS}/{snapshot_id}"

    scoped = (await send(client, "GET", path, red, status=200))["data"]
    wide = (await send(client, "GET", path, unscoped, status=200))["data"]

    assert scoped["source_sandbox_id"] is None
    assert wide["source_sandbox_id"] == sandbox_id


async def test_scoped_key_sees_null_image_ref_and_digest_on_a_snapshot(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    org_id = await add_org(app, "internals-ref")
    unscoped = await seed_key(app, org_id, None)
    red = await seed_key(app, org_id, RED)
    sandbox_id = await make_sandbox(client, unscoped, labels=RED)
    snapshot_id = await commit_snapshot(app, client, unscoped, sandbox_id)
    path = f"{SNAPSHOTS}/{snapshot_id}"

    scoped = (await send(client, "GET", path, red, status=200))["data"]
    wide = (await send(client, "GET", path, unscoped, status=200))["data"]
    listed = (await send(client, "GET", SNAPSHOTS, red, status=200))["data"]

    assert (scoped["image_ref"], scoped["digest"]) == (None, None)
    assert [(item["image_ref"], item["digest"]) for item in listed] == [(None, None)]
    assert wide["image_ref"]
    assert wide["digest"]


# --- 2) node counts are per caller org --------------------------------------------------


async def test_two_orgs_on_shared_nodes_each_see_only_their_own_count(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    acme = await add_org(app, "nodes-acme")
    globex = await add_org(app, "nodes-globex")
    await seed_nodes(app, NODE_A, NODE_B)
    await seed_sandboxes(app, acme, NODE_A, SandboxState.STARTED, 2)
    await seed_sandboxes(app, acme, NODE_A, SandboxState.STOPPED, 1)
    await seed_sandboxes(app, globex, NODE_A, SandboxState.STARTED, 1)
    await seed_sandboxes(app, globex, NODE_B, SandboxState.STARTED, 3)

    acme_counts = await running_by_node(client, await seed_org_reader(app, acme))
    globex_counts = await running_by_node(client, await seed_org_reader(app, globex))

    assert (acme_counts[NODE_A], acme_counts[NODE_B]) == (2, 0)
    assert (globex_counts[NODE_A], globex_counts[NODE_B]) == (1, 3)


async def test_an_org_with_no_sandboxes_sees_zero_on_a_busy_node(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    busy = await add_org(app, "nodes-busy")
    idle = await add_org(app, "nodes-idle")
    await seed_nodes(app, NODE_A)
    await seed_sandboxes(app, busy, NODE_A, SandboxState.STARTED, 2)

    counts = await running_by_node(client, await seed_org_reader(app, idle))

    assert counts[NODE_A] == 0
