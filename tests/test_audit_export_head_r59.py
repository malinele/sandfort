"""The REST audit export ends with a trailer; ``cascade`` on key revoke is single-valued (r59).

Through the API on the fake driver and a temp SQLite database. ``GET /v1/audit-events/export``
appends, as its last line, the signed ``audit_head`` the operator ``audit-export`` writes when
the chain key is set and the export reaches the chain's last row; otherwise (a filter cuts the
chain, or no key) a plain ``export_summary`` line with the row count and the filter names.
``DELETE /v1/api-keys/{id}`` answers 422 when ``cascade`` is repeated.
"""

import json
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
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.audit_chain_head import HEAD_TYPE, parse_heads

ROOT = Path(__file__).resolve().parents[1]
PEPPER = "test-pepper"
KEYS = "/v1/api-keys"
EXPORT = "/v1/audit-events/export"
KEY_ENV = "SANDFORT_AUDIT_CHAIN_KEY"
CHAIN_KEY = "c" * 40
SUMMARY_TYPE = "export_summary"
SCOPES = [Scope.API_KEYS_ADMIN.value, Scope.AUDIT_READ.value]
MINTED = 3


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'export.db'}"
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
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as http:
        yield http


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="School", slug="school", created_at=datetime.now(UTC))
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


@pytest.fixture
async def root(app: FastAPI, org_id: str) -> tuple[str, str]:
    """A seeded admin key with ``audit:read``; returns (key id, plaintext key)."""
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="root",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset(Scope(value) for value in SCOPES),
        created_at=datetime.now(UTC),
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return stored.id, generated.key


def bearer(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def mint(client: httpx.AsyncClient, caller: str, name: str) -> dict[str, Any]:
    response = await client.post(
        KEYS, json={"name": name, "scopes": SCOPES}, headers=bearer(caller)
    )
    assert response.status_code == 201
    data: dict[str, Any] = response.json()["data"]
    return data


async def seeded(client: httpx.AsyncClient, caller: str) -> None:
    """Write a few audit rows (one per minted key)."""
    for index in range(MINTED):
        await mint(client, caller, f"child-{index}")


async def export(
    client: httpx.AsyncClient, caller: str, params: dict[str, str] | None = None
) -> list[dict[str, Any]]:
    response = await client.get(EXPORT, params=params or {}, headers=bearer(caller))
    assert response.status_code == 200
    assert response.text.endswith("\n")
    return [json.loads(line) for line in response.text.splitlines() if line.strip()]


async def last_chain_row(app: FastAPI, org_id: str) -> tuple[str, str | None]:
    async with UnitOfWork(app.state.session_factory) as uow:
        rows = await uow.audit.list_chained(org_id, cursor=None, limit=500)
    last = rows[-1]
    return last.event.id, last.entry_hash


async def test_full_export_with_key_ends_with_signed_head(
    app: FastAPI,
    client: httpx.AsyncClient,
    org_id: str,
    root: tuple[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(KEY_ENV, CHAIN_KEY)
    await seeded(client, root[1])
    last_id, last_hash = await last_chain_row(app, org_id)

    records = await export(client, root[1])

    *rows, trailer = records
    assert len(rows) == MINTED
    assert trailer["type"] == HEAD_TYPE
    (head,) = parse_heads([json.dumps(trailer)])
    assert head.valid(CHAIN_KEY.encode())
    assert not head.valid(b"x" * 40)
    assert head.org_id == org_id
    assert head.row_id == last_id == rows[-1]["id"]
    assert head.entry_hash == last_hash == rows[-1]["hash"]


async def test_from_bound_alone_still_ends_with_signed_head(
    client: httpx.AsyncClient, root: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV, CHAIN_KEY)
    await seeded(client, root[1])

    records = await export(client, root[1], {"from": "2000-01-01T00:00:00Z"})

    assert records[-1]["type"] == HEAD_TYPE
    assert records[-1]["row_id"] == records[-2]["id"]


async def test_to_bound_including_last_row_ends_with_signed_head(
    client: httpx.AsyncClient, root: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV, CHAIN_KEY)
    await seeded(client, root[1])

    records = await export(client, root[1], {"to": "9999-01-01T00:00:00Z"})

    assert records[-1]["type"] == HEAD_TYPE
    assert len(records) == MINTED + 1


async def test_to_bound_before_last_row_ends_with_summary(
    client: httpx.AsyncClient, root: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV, CHAIN_KEY)
    await seeded(client, root[1])

    records = await export(client, root[1], {"to": "2000-01-01T00:00:00Z"})

    assert records == [{"type": SUMMARY_TYPE, "rows": 0, "filters": ["to"]}]


async def test_outcome_filter_ends_with_summary_even_with_key(
    client: httpx.AsyncClient, root: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV, CHAIN_KEY)
    await seeded(client, root[1])

    records = await export(client, root[1], {"outcome": "success", "request_id": "nope"})

    assert records == [{"type": SUMMARY_TYPE, "rows": 0, "filters": ["outcome", "request_id"]}]


async def test_filtered_export_counts_its_rows_and_trailer_is_last(
    client: httpx.AsyncClient, root: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV, CHAIN_KEY)
    await seeded(client, root[1])

    records = await export(client, root[1], {"outcome": "success"})

    *rows, trailer = records
    assert len(rows) == MINTED
    assert all("type" not in row for row in rows)
    # Since r63 a filtered export is signed too: a head marked filtered, binding the content.
    assert trailer["type"] == HEAD_TYPE
    assert trailer["filtered"] is True and trailer["filters"] == {"outcome": "success"}
    assert trailer["row_count"] == MINTED and trailer["row_id"] == rows[-1]["id"]


async def test_no_key_full_export_ends_with_summary_only(
    client: httpx.AsyncClient, root: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV, raising=False)
    await seeded(client, root[1])

    records = await export(client, root[1])

    *rows, trailer = records
    assert len(rows) == MINTED
    assert trailer == {"type": SUMMARY_TYPE, "rows": MINTED, "filters": []}
    assert all(record.get("type") != HEAD_TYPE for record in records)


async def test_empty_chain_with_key_ends_with_summary(
    client: httpx.AsyncClient, root: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV, CHAIN_KEY)

    records = await export(client, root[1])

    assert records == [{"type": SUMMARY_TYPE, "rows": 0, "filters": []}]


async def test_repeated_cascade_answers_422(
    client: httpx.AsyncClient, root: tuple[str, str]
) -> None:
    child = await mint(client, root[1], "child")

    response = await client.delete(
        f"{KEYS}/{child['id']}?cascade=true&cascade=false", headers=bearer(root[1])
    )

    assert response.status_code == 422
    assert "cascade must be given once" in response.text
    listed = await client.get(KEYS, headers=bearer(root[1]))
    revoked = [row for row in listed.json()["data"] if row["revoked_at"] is not None]
    assert revoked == []


async def test_single_cascade_still_revokes(
    client: httpx.AsyncClient, root: tuple[str, str]
) -> None:
    child = await mint(client, root[1], "child")

    response = await client.delete(f"{KEYS}/{child['id']}?cascade=true", headers=bearer(root[1]))

    assert response.status_code == 200
    assert response.json()["data"]["status"] == "revoked"
