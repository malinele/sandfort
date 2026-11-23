"""The sandbox ``snapshot`` field is withheld from label-scoped callers; pull classifier.

Through the API on the fake driver and a temp SQLite database. An admin (org-wide key) creates a
``team=red`` sandbox from a snapshot committed from a ``team=blue`` sandbox, so the snapshot is
out of scope for the ``team=red`` key that can still see the sandbox. That key must not learn the
snapshot id from the ``snapshot`` response field (round-31 rule).
"""

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from sandfort.drivers.docker.images import _is_pull_denied
from test_api_sandboxes import BASE, add_org, migrated_app, send
from test_snapshot_scope import BLUE, RED, commit_snapshot, make_sandbox, seed_key

PULL_DENIED_MESSAGES = (
    "pull access denied for x, repository does not exist or may require 'docker login'",
    "repository does not exist",
    "Error response from daemon: manifest unknown",
    'MANIFEST UNKNOWN: manifest tagged by "nope" is not found',
    "manifest unknown: manifest unknown",
)
NOT_DENIED_MESSAGES = (
    "failed to resolve reference: dial tcp: lookup registry.example.com: no such host",
    "unexpected EOF",
    "",
)


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
async def org_id(app: FastAPI) -> str:
    return await add_org(app, "scoped-r34")


@pytest.fixture
async def admin(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id, None)


@pytest.fixture
async def red(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id, RED)


@pytest.fixture
async def blue_snapshot(app: FastAPI, client: httpx.AsyncClient, admin: str) -> str:
    """A ready snapshot committed from a ``team=blue`` sandbox, out of the red scope."""
    blue_sandbox = await make_sandbox(client, admin, labels=BLUE)
    return await commit_snapshot(app, client, admin, blue_sandbox)


@pytest.fixture
async def red_sandbox(client: httpx.AsyncClient, admin: str, blue_snapshot: str) -> str:
    """A ``team=red`` sandbox the admin created from the blue snapshot."""
    return await make_sandbox(client, admin, labels=RED, snapshot=blue_snapshot)


async def listed(client: httpx.AsyncClient, key: str, sandbox_id: str) -> dict[str, Any]:
    body = await send(client, "GET", BASE, key, status=200)
    matches = [item for item in body["data"] if item["id"] == sandbox_id]
    assert len(matches) == 1
    return dict(matches[0])


async def fetched(client: httpx.AsyncClient, key: str, sandbox_id: str) -> dict[str, Any]:
    body = await send(client, "GET", f"{BASE}/{sandbox_id}", key, status=200)
    return dict(body["data"])


async def test_org_wide_key_sees_snapshot_on_get(
    client: httpx.AsyncClient, admin: str, red_sandbox: str, blue_snapshot: str
) -> None:
    assert (await fetched(client, admin, red_sandbox))["snapshot"] == blue_snapshot


async def test_org_wide_key_sees_snapshot_on_list(
    client: httpx.AsyncClient, admin: str, red_sandbox: str, blue_snapshot: str
) -> None:
    assert (await listed(client, admin, red_sandbox))["snapshot"] == blue_snapshot


async def test_label_scoped_key_sees_null_snapshot_on_get(
    client: httpx.AsyncClient, red: str, red_sandbox: str
) -> None:
    sandbox = await fetched(client, red, red_sandbox)

    assert sandbox["id"] == red_sandbox
    assert sandbox["snapshot"] is None


async def test_label_scoped_key_sees_null_snapshot_on_list(
    client: httpx.AsyncClient, red: str, red_sandbox: str
) -> None:
    assert (await listed(client, red, red_sandbox))["snapshot"] is None


async def test_label_scoped_key_response_never_contains_the_snapshot_id(
    client: httpx.AsyncClient, red: str, red_sandbox: str, blue_snapshot: str
) -> None:
    response = await client.get(f"{BASE}/{red_sandbox}", headers={"Authorization": f"Bearer {red}"})

    assert response.status_code == 200
    assert blue_snapshot not in response.text


@pytest.mark.parametrize("message", PULL_DENIED_MESSAGES)
def test_pull_classifier_maps_denied_and_unknown_manifest_to_not_found(message: str) -> None:
    assert _is_pull_denied(message) is True


@pytest.mark.parametrize("message", NOT_DENIED_MESSAGES)
def test_pull_classifier_leaves_other_failures_alone(message: str) -> None:
    assert _is_pull_denied(message) is False
