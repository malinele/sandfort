"""r31: sandbox API objects carry created_at/updated_at; the SDK create cleanup relies on them."""

import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from sandfort.domain.org import Scope
from test_api_sandboxes import BASE, add_org, migrated_app, seed_key, send
from test_sdk_r30 import (
    ONE_SANDBOX,
    SANDBOXES,
    WAIT_S,
    SandboxTimeoutError,
    create_times_out,
    fresh_listing,
    listing,
    sandbox_json,
    sync_client,
)

READ_WRITE = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})
TIMESTAMPS = ("created_at", "updated_at")


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
async def key(app: FastAPI) -> str:
    return await seed_key(app, await add_org(app, "acme"), READ_WRITE)


def parse(value: Any) -> datetime:
    """The datetime in ``value`` (an ISO 8601 string), which must carry a UTC offset."""
    assert isinstance(value, str)
    parsed = datetime.fromisoformat(value)
    assert parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0)
    return parsed


def assert_timestamps(sandbox: dict[str, Any]) -> tuple[datetime, datetime]:
    created, updated = (parse(sandbox[name]) for name in TIMESTAMPS)
    assert created <= updated
    return created, updated


async def create(client: httpx.AsyncClient, key: str) -> dict[str, Any]:
    body = await send(client, "POST", BASE, key, status=201, json={})
    data: dict[str, Any] = body["data"]
    return data


# --- API ----------------------------------------------------------------------------------


async def test_create_returns_timezone_aware_created_at_and_updated_at(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox = await create(client, key)

    assert_timestamps(sandbox)


async def test_get_returns_the_same_created_at_as_create(
    client: httpx.AsyncClient, key: str
) -> None:
    created = await create(client, key)

    body = await send(client, "GET", f"{BASE}/{created['id']}", key, status=200)

    assert_timestamps(body["data"])
    assert body["data"]["created_at"] == created["created_at"]


async def test_list_returns_the_timestamps_of_every_sandbox(
    client: httpx.AsyncClient, key: str
) -> None:
    first, second = await create(client, key), await create(client, key)

    body = await send(client, "GET", BASE, key, status=200)

    by_id = {item["id"]: item for item in body["data"]}
    assert set(by_id) == {first["id"], second["id"]}
    for item in by_id.values():
        assert_timestamps(item)


async def test_stop_moves_updated_at_forward_and_keeps_created_at(
    client: httpx.AsyncClient, key: str
) -> None:
    created = await create(client, key)
    before_created, before_updated = assert_timestamps(created)

    stopped = await send(client, "POST", f"{BASE}/{created['id']}/stop", key, status=200)

    after_created, after_updated = assert_timestamps(stopped["data"])
    assert after_created == before_created
    assert after_updated > before_updated


async def test_start_keeps_created_at_and_carries_both_timestamps(
    client: httpx.AsyncClient, key: str
) -> None:
    created = await create(client, key)
    await send(client, "POST", f"{BASE}/{created['id']}/stop", key, status=200)

    started = await send(client, "POST", f"{BASE}/{created['id']}/start", key, status=200)

    after_created, _ = assert_timestamps(started["data"])
    assert after_created == parse(created["created_at"])


# --- SDK create cleanup --------------------------------------------------------------------


def test_cleanup_deletes_a_sandbox_created_after_the_pre_post_moment() -> None:
    router = create_times_out(found=[listing(), fresh_listing(state="pending")])
    client, _ = sync_client(router)

    with pytest.raises(SandboxTimeoutError):
        client.create_sandbox(name="demo", wait_timeout_s=WAIT_S)

    assert len(router.seen("DELETE", ONE_SANDBOX)) == 1


def test_cleanup_without_created_at_names_the_sandbox_and_does_not_delete(
    caplog: pytest.LogCaptureFixture,
) -> None:
    router = create_times_out(found=[listing(), listing(sandbox_json(state="pending"))])
    client, _ = sync_client(router)

    with caplog.at_level(logging.WARNING, logger="sandfort_sdk"):
        with pytest.raises(SandboxTimeoutError):
            client.create_sandbox(name="demo", wait_timeout_s=WAIT_S)

    sandbox_id = ONE_SANDBOX.removeprefix(f"{SANDBOXES}/")
    assert router.seen("DELETE", ONE_SANDBOX) == []
    assert "did not report created_at" in caplog.text
    assert f"sandfort sandbox rm {sandbox_id}" in caplog.text
    assert "created at an unknown time" not in caplog.text


def test_cleanup_leaves_a_sandbox_created_before_the_create_alone(
    caplog: pytest.LogCaptureFixture,
) -> None:
    old = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    router = create_times_out(found=[listing(), listing(sandbox_json(created_at=old))])
    client, _ = sync_client(router)

    with caplog.at_level(logging.WARNING, logger="sandfort_sdk"):
        with pytest.raises(SandboxTimeoutError):
            client.create_sandbox(name="demo", wait_timeout_s=WAIT_S)

    assert router.seen("DELETE", ONE_SANDBOX) == []
    assert "not by this create" in caplog.text
