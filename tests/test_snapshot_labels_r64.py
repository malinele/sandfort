"""Snapshot labels (round 64): create, register, response, list filter, scoped keys, migration.

Through the API on the fake driver and a temp SQLite database migrated to head; no network.
Labels follow the volume rules: same bounds, the shared content rule, the reserved ``sandfort.``
prefix refused, scope labels merged into what a label-scoped key creates.
"""

import sqlite3
from collections.abc import AsyncIterator
from contextlib import closing
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.schemas.text_checks import (
    MAX_LABEL_KEY_LENGTH,
    MAX_LABEL_VALUE_LENGTH,
    MAX_LABELS,
)
from test_api_sandboxes import BASE, add_org, migrated_app, send
from test_snapshot_scope import BLUE, RED, commit_snapshot, make_sandbox, seed_key
from test_snapshots import run_jobs

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOTS = "/v1/snapshots"
FROM_SANDBOX = f"{SNAPSHOTS}/from-sandbox"
IMAGE = "alpine:3.20"
VALIDATION_STATUS = 422
FORBIDDEN_STATUS = 403
STAMP = "2026-11-11 12:00:00"
SEED_SQL = f"""
INSERT INTO organizations (id, name, slug, status, created_at, updated_at)
  VALUES ('org_a', 'A', 'a', 'active', '{STAMP}', '{STAMP}');
INSERT INTO snapshots (id, org_id, name, image_ref, digest, layer_count, state, created_at)
  VALUES ('snap_a', 'org_a', 'old', 'alpine@sha256:ab', 'sha256:ab', 1, 'ready', '{STAMP}');
"""


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
    return await add_org(app, "snapshot-labels")


@pytest.fixture
async def admin(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id, None)


@pytest.fixture
async def red(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id, RED)


async def register(
    client: httpx.AsyncClient, key: str, name: str, labels: Any = None, status: int = 201
) -> dict[str, Any]:
    payload: dict[str, Any] = {"image": IMAGE, "name": name}
    if labels is not None:
        payload["labels"] = labels
    body = await send(client, "POST", SNAPSHOTS, key, status=status, json=payload)
    return dict(body["data"] if status < 400 else body)


async def from_sandbox(
    client: httpx.AsyncClient,
    key: str,
    sandbox_id: str,
    name: str,
    labels: Any = None,
    status: int = 202,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"sandbox_id": sandbox_id, "name": name}
    if labels is not None:
        payload["labels"] = labels
    body = await send(client, "POST", FROM_SANDBOX, key, status=status, json=payload)
    return dict(body["data"] if status < 400 else body)


async def names(client: httpx.AsyncClient, key: str, query: str = "") -> list[str]:
    body = await send(client, "GET", f"{SNAPSHOTS}{query}", key, status=200)
    return sorted(item["name"] for item in body["data"])


# --- create, register and read -----------------------------------------------------------------


async def test_register_without_labels_answers_an_empty_mapping(
    client: httpx.AsyncClient, admin: str
) -> None:
    created = await register(client, admin, "plain")

    assert created["labels"] == {}


async def test_register_with_labels_stores_and_returns_them(
    client: httpx.AsyncClient, admin: str
) -> None:
    wanted = {"team": "a", "env": "dev"}

    created = await register(client, admin, "tagged", wanted)

    assert created["labels"] == wanted
    fetched = await send(client, "GET", f"{SNAPSHOTS}/{created['id']}", admin, status=200)
    assert fetched["data"]["labels"] == wanted
    listed = await send(client, "GET", SNAPSHOTS, admin, status=200)
    assert [item["labels"] for item in listed["data"]] == [wanted]


async def test_create_from_sandbox_takes_labels_through_the_commit(
    app: FastAPI, client: httpx.AsyncClient, admin: str
) -> None:
    sandbox_id = await make_sandbox(client, admin)
    wanted = {"release": "1.2"}

    pending = await from_sandbox(client, admin, sandbox_id, "committed", wanted)
    assert await run_jobs(app) == 1

    assert pending["labels"] == wanted
    fetched = await send(client, "GET", f"{SNAPSHOTS}/{pending['id']}", admin, status=200)
    assert fetched["data"]["state"] == "ready"
    assert fetched["data"]["labels"] == wanted


async def test_create_from_sandbox_without_labels_answers_an_empty_mapping(
    client: httpx.AsyncClient, admin: str
) -> None:
    sandbox_id = await make_sandbox(client, admin)

    pending = await from_sandbox(client, admin, sandbox_id, "bare")

    assert pending["labels"] == {}


async def test_delete_answers_the_labels(client: httpx.AsyncClient, admin: str) -> None:
    created = await register(client, admin, "doomed", {"team": "a"})

    body = await send(client, "DELETE", f"{SNAPSHOTS}/{created['id']}", admin, status=200)

    assert body["data"]["labels"] == {"team": "a"}


# --- content rules -----------------------------------------------------------------------------


@pytest.mark.parametrize("path", [SNAPSHOTS, FROM_SANDBOX])
async def test_reserved_label_names_are_refused(
    client: httpx.AsyncClient, admin: str, path: str
) -> None:
    sandbox_id = await make_sandbox(client, admin)
    payload = {"name": "reserved", "labels": {"sandfort.snapshot_id": "x"}}
    payload |= {"image": IMAGE} if path == SNAPSHOTS else {"sandbox_id": sandbox_id}

    body = await send(client, "POST", path, admin, status=VALIDATION_STATUS, json=payload)

    assert "reserved" in body["error"]["message"]
    assert await names(client, admin) == []


@pytest.mark.parametrize("key", ["bad\nkey", "\x07", "   ", "zero​width"])
async def test_label_keys_that_would_show_up_blank_or_garbled_are_refused(
    client: httpx.AsyncClient, admin: str, key: str
) -> None:
    await register(client, admin, "garbled", {key: "v"}, status=VALIDATION_STATUS)

    assert await names(client, admin) == []


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


@pytest.mark.parametrize(("fits", "too_many", "limit"), BOUNDS)
async def test_register_takes_labels_at_the_bound_and_refuses_one_past_it(
    client: httpx.AsyncClient,
    admin: str,
    fits: dict[str, str],
    too_many: dict[str, str],
    limit: int,
) -> None:
    refused = await register(client, admin, "too-many", too_many, status=VALIDATION_STATUS)

    issues = refused["error"]["details"]["errors"]
    assert len(issues) == 1
    assert issues[0]["loc"][:2] == ["body", "labels"]
    assert str(limit) in issues[0]["msg"]
    assert await names(client, admin) == []
    assert (await register(client, admin, "fits", fits))["labels"] == fits


async def test_from_sandbox_refuses_labels_past_the_bound(
    client: httpx.AsyncClient, admin: str
) -> None:
    sandbox_id = await make_sandbox(client, admin)

    refused = await from_sandbox(
        client, admin, sandbox_id, "many", many_labels(MAX_LABELS + 1), VALIDATION_STATUS
    )

    assert refused["error"]["details"]["errors"][0]["loc"][:2] == ["body", "labels"]


# --- list filter -------------------------------------------------------------------------------


async def test_list_filters_by_one_or_more_label_pairs(
    client: httpx.AsyncClient, admin: str
) -> None:
    await register(client, admin, "none")
    await register(client, admin, "a-dev", {"team": "a", "env": "dev"})
    await register(client, admin, "a-prod", {"team": "a", "env": "prod"})
    await register(client, admin, "b-dev", {"team": "b", "env": "dev"})

    assert await names(client, admin, "?label=team=a") == ["a-dev", "a-prod"]
    assert await names(client, admin, "?label=team=a&label=env=dev") == ["a-dev"]
    assert await names(client, admin, "?label=team=c") == []
    assert await names(client, admin) == ["a-dev", "a-prod", "b-dev", "none"]


@pytest.mark.parametrize("pair", ["team", "=a"])
async def test_list_refuses_a_malformed_label_filter(
    client: httpx.AsyncClient, admin: str, pair: str
) -> None:
    body = await send(
        client, "GET", f"{SNAPSHOTS}?label={pair}", admin, status=VALIDATION_STATUS
    )

    assert body["error"]["details"]["errors"][0]["loc"] == ["query", "label"]


async def test_list_refuses_one_key_with_two_values(
    client: httpx.AsyncClient, admin: str
) -> None:
    body = await send(
        client, "GET", f"{SNAPSHOTS}?label=team=a&label=team=b", admin, status=VALIDATION_STATUS
    )

    issue = body["error"]["details"]["errors"][0]
    assert issue["loc"] == ["query", "label"]
    assert "more than once" in issue["msg"]


async def test_filtered_pages_continue_with_the_cursor_and_bind_to_the_filter(
    client: httpx.AsyncClient, admin: str
) -> None:
    for index in range(3):
        await register(client, admin, f"a{index}", {"team": "a"})
    await register(client, admin, "other", {"team": "b"})

    first = await send(client, "GET", f"{SNAPSHOTS}?label=team=a&limit=2", admin, status=200)
    cursor = first["meta"]["next_cursor"]
    second = await send(
        client, "GET", f"{SNAPSHOTS}?label=team=a&limit=2&cursor={cursor}", admin, status=200
    )
    await send(
        client,
        "GET",
        f"{SNAPSHOTS}?label=team=b&limit=2&cursor={cursor}",
        admin,
        status=VALIDATION_STATUS,
    )
    await send(
        client, "GET", f"{SNAPSHOTS}?limit=2&cursor={cursor}", admin, status=VALIDATION_STATUS
    )

    assert len(first["data"]) == 2
    assert [item["name"] for item in second["data"]] == ["a2"]
    assert second["meta"]["next_cursor"] is None


# --- label-scoped keys -------------------------------------------------------------------------


async def test_scoped_register_merges_the_scope_into_the_labels(
    client: httpx.AsyncClient, red: str
) -> None:
    bare = await register(client, red, "bare")
    extra = await register(client, red, "extra", {"env": "dev"})
    same = await register(client, red, "same", RED)

    assert bare["labels"] == RED
    assert extra["labels"] == {"team": "red", "env": "dev"}
    assert same["labels"] == RED


async def test_scoped_create_from_sandbox_merges_the_scope_into_the_labels(
    app: FastAPI, client: httpx.AsyncClient, red: str
) -> None:
    sandbox_id = await make_sandbox(client, red)

    pending = await from_sandbox(client, red, sandbox_id, "scoped", {"env": "dev"})
    assert await run_jobs(app) == 1

    assert pending["labels"] == {"team": "red", "env": "dev"}
    fetched = await send(client, "GET", f"{SNAPSHOTS}/{pending['id']}", red, status=200)
    assert fetched["data"]["labels"] == {"team": "red", "env": "dev"}


async def test_scoped_register_refuses_a_label_that_contradicts_the_scope(
    client: httpx.AsyncClient, red: str
) -> None:
    await register(client, red, "clash", BLUE, status=FORBIDDEN_STATUS)

    assert await names(client, red) == []


async def test_scoped_key_sees_snapshots_that_carry_its_scope(
    client: httpx.AsyncClient, admin: str, red: str
) -> None:
    await register(client, admin, "by-admin-red", {"team": "red", "env": "dev"})
    await register(client, admin, "by-admin-blue", BLUE)
    await register(client, admin, "by-admin-other", {"env": "dev"})
    await register(client, red, "by-red")

    assert await names(client, red) == ["by-admin-red", "by-red"]
    assert await names(client, red, "?label=env=dev") == ["by-admin-red"]
    assert await names(client, red, "?label=team=blue") == []
    assert await names(client, red, "?label=team=red&label=env=dev") == ["by-admin-red"]
    everything = ["by-admin-blue", "by-admin-other", "by-admin-red", "by-red"]
    assert await names(client, admin) == everything


async def test_scoped_key_reads_creates_from_and_deletes_only_snapshots_in_its_scope(
    client: httpx.AsyncClient, admin: str, red: str
) -> None:
    mine = await register(client, admin, "mine", RED)
    theirs = await register(client, admin, "theirs", BLUE)

    await send(client, "GET", f"{SNAPSHOTS}/{mine['id']}", red, status=200)
    created = await send(client, "POST", BASE, red, status=201, json={"snapshot": mine["id"]})
    await send(client, "GET", f"{SNAPSHOTS}/{theirs['id']}", red, status=404)
    await send(client, "POST", BASE, red, status=404, json={"snapshot": theirs["id"]})
    await send(client, "DELETE", f"{SNAPSHOTS}/{theirs['id']}", red, status=404)

    assert created["data"]["labels"] == RED
    assert await names(client, admin) == ["mine", "theirs"]


async def test_labelled_snapshot_decides_over_an_out_of_scope_source_sandbox(
    app: FastAPI, client: httpx.AsyncClient, admin: str, red: str
) -> None:
    """Labels set on the snapshot win when the source sandbox is outside the scope."""
    sandbox_id = await make_sandbox(client, admin, labels=BLUE)
    mine = await from_sandbox(client, admin, sandbox_id, "relabelled", RED)
    other = await from_sandbox(client, admin, sandbox_id, "stays-blue", BLUE)
    assert await run_jobs(app) == 2

    await send(client, "GET", f"{SNAPSHOTS}/{mine['id']}", red, status=200)
    await send(client, "GET", f"{SNAPSHOTS}/{other['id']}", red, status=404)
    assert await names(client, red) == ["relabelled"]


async def test_unlabelled_snapshots_keep_following_their_source_sandbox(
    app: FastAPI, client: httpx.AsyncClient, admin: str, red: str
) -> None:
    red_sandbox = await make_sandbox(client, admin, labels=RED)
    blue_sandbox = await make_sandbox(client, admin, labels=BLUE)
    visible = await commit_snapshot(app, client, admin, red_sandbox)
    hidden = await commit_snapshot(app, client, admin, blue_sandbox)
    public = await register(client, admin, "public")

    seen = {item["id"] for item in (await send(client, "GET", SNAPSHOTS, red, status=200))["data"]}

    assert seen == {visible, public["id"]}
    assert hidden not in seen


# --- migration ---------------------------------------------------------------------------------


def alembic_config(db_path: Path) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")
    return config


def snapshot_columns(db_path: Path) -> set[str]:
    with closing(sqlite3.connect(db_path)) as connection:
        rows = connection.execute("PRAGMA table_info(snapshots)").fetchall()
    return {row[1] for row in rows}


def test_migration_adds_the_labels_column_and_downgrade_drops_it(tmp_path: Path) -> None:
    pytest.importorskip("aiosqlite")
    db_path = tmp_path / "migrated.db"
    config = alembic_config(db_path)
    command.upgrade(config, "0023")
    with closing(sqlite3.connect(db_path)) as connection:
        connection.executescript(SEED_SQL)
    before = snapshot_columns(db_path)

    command.upgrade(config, "0024")
    after = snapshot_columns(db_path)
    with closing(sqlite3.connect(db_path)) as connection:
        row = connection.execute("SELECT labels FROM snapshots WHERE id = 'snap_a'").fetchone()
    command.downgrade(config, "0023")
    with closing(sqlite3.connect(db_path)) as connection:
        kept = connection.execute("SELECT id, name FROM snapshots").fetchall()

    assert "labels" not in before
    assert "labels" in after
    assert row == ("{}",)
    assert snapshot_columns(db_path) == before
    assert kept == [("snap_a", "old")]
