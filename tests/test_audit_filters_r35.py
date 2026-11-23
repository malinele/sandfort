"""Audit listing: ``request_id`` and ``outcome`` filters; unknown query parameters answer 422.

Through the API on the fake driver and a temp SQLite database. Rows are seeded straight into the
audit repository, so each test controls request ids and outcomes exactly.
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
from sqlalchemy import Index

from sandfort.api.app import create_app
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.models.audit import AuditRow
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import ActorType, AuditEvent, AuditOutcome
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import AUDIT, new_api_key_id, new_id, new_org_id
from sandfort.services.audit_chain import ChainPolicy
from sandfort.services.audit_chain_head import HEAD_TYPE, SUMMARY_TYPE

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
AUDIT_PATH = "/v1/audit-events"
EXPORT_PATH = f"{AUDIT_PATH}/export"
VERIFY_PATH = f"{AUDIT_PATH}/verify"
ALL_PATHS = (AUDIT_PATH, EXPORT_PATH, VERIFY_PATH)


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'audit_filters.db'}"
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
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset({Scope.AUDIT_READ}),
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


async def seed(
    app: FastAPI,
    org_id: str,
    *,
    request_id: str | None,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    action: str = "sandbox.create",
) -> str:
    event = AuditEvent(
        id=new_id(AUDIT),
        org_id=org_id,
        actor_type=ActorType.API_KEY,
        actor_id="key_1",
        action=action,
        outcome=outcome,
        request_id=request_id,
        occurred_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.audit.add(event)
        await uow.commit()
    return event.id


@pytest.fixture
async def rows(app: FastAPI, org_id: str) -> dict[str, str]:
    """Four rows: two share request id ``req-a``; one is denied; one has no request id."""
    return {
        "a_ok": await seed(app, org_id, request_id="req-a"),
        "a_denied": await seed(
            app, org_id, request_id="req-a", outcome=AuditOutcome.DENIED, action="sandbox.delete"
        ),
        "b_error": await seed(app, org_id, request_id="req-b", outcome=AuditOutcome.ERROR),
        "none": await seed(app, org_id, request_id=None),
    }


async def get(client: httpx.AsyncClient, path: str, key: str, **params: Any) -> httpx.Response:
    return await client.get(path, headers={"Authorization": f"Bearer {key}"}, params=params)


def ids(response: httpx.Response) -> set[str]:
    assert response.status_code == 200, response.text
    return {event["id"] for event in response.json()["data"]}


def split_export(response: httpx.Response, *, summary: bool) -> list[dict[str, Any]]:
    """The event rows of an export; the last line is the trailer, told apart by `type`.

    The trailer is a signed head only for an unfiltered, unbounded export on a server with a
    chain key; a filtered or bounded export, or a server without a key, gets a summary.
    """
    assert response.status_code == 200, response.text
    lines = [json.loads(line) for line in response.text.splitlines() if line]
    assert lines, "an export always ends with a trailer"
    *rows, trailer = lines
    head_expected = ChainPolicy.from_env().key is not None and not summary
    assert trailer["type"] == (HEAD_TYPE if head_expected else SUMMARY_TYPE)
    assert all("type" not in row for row in rows)
    return rows


def export_ids(response: httpx.Response, *, summary: bool = True) -> set[str]:
    return {row["id"] for row in split_export(response, summary=summary)}


async def test_request_id_filter_returns_only_matching_rows(
    client: httpx.AsyncClient, key: str, rows: dict[str, str]
) -> None:
    response = await get(client, AUDIT_PATH, key, request_id="req-a")

    assert ids(response) == {rows["a_ok"], rows["a_denied"]}
    assert {event["request_id"] for event in response.json()["data"]} == {"req-a"}


async def test_request_id_filter_with_no_match_returns_empty_list(
    client: httpx.AsyncClient, key: str, rows: dict[str, str]
) -> None:
    response = await get(client, AUDIT_PATH, key, request_id="req-missing")

    assert ids(response) == set()


async def test_outcome_filter_returns_only_matching_rows(
    client: httpx.AsyncClient, key: str, rows: dict[str, str]
) -> None:
    denied = await get(client, AUDIT_PATH, key, outcome="denied")
    errors = await get(client, AUDIT_PATH, key, outcome="error")

    assert ids(denied) == {rows["a_denied"]}
    assert ids(errors) == {rows["b_error"]}


async def test_outcome_with_unknown_value_is_422(
    client: httpx.AsyncClient, key: str, rows: dict[str, str]
) -> None:
    response = await get(client, AUDIT_PATH, key, outcome="bogus")

    assert response.status_code == 422, response.text


async def test_request_id_and_outcome_combine(
    client: httpx.AsyncClient, key: str, rows: dict[str, str]
) -> None:
    response = await get(client, AUDIT_PATH, key, request_id="req-a", outcome="success")

    assert ids(response) == {rows["a_ok"]}


@pytest.mark.parametrize("param", ["reason", "actor", "requestid", "Outcome"])
async def test_unknown_parameter_is_422_naming_it_and_the_accepted_ones(
    client: httpx.AsyncClient, key: str, rows: dict[str, str], param: str
) -> None:
    response = await get(client, AUDIT_PATH, key, **{param: "x"})

    assert response.status_code == 422, response.text
    body = response.json()
    assert body["success"] is False
    message = body["error"]["message"]
    assert f"`{param}`" in message
    for accepted in ("actor_id", "action", "target_id", "request_id", "outcome", "from", "to"):
        assert accepted in message


async def test_every_unknown_parameter_is_named(
    client: httpx.AsyncClient, key: str, rows: dict[str, str]
) -> None:
    response = await get(client, AUDIT_PATH, key, reason="x", actor="y", request_id="req-a")

    assert response.status_code == 422, response.text
    named = response.json()["error"]["message"].split("accepted:")[0]
    assert "`reason`" in named
    assert "`actor`" in named
    assert "`request_id`" not in named


@pytest.mark.parametrize("path", [EXPORT_PATH, VERIFY_PATH])
async def test_export_and_verify_reject_unknown_parameters(
    client: httpx.AsyncClient, key: str, rows: dict[str, str], path: str
) -> None:
    response = await get(client, path, key, reason="x")

    assert response.status_code == 422, response.text
    assert "`reason`" in response.json()["error"]["message"]


async def test_export_rejects_list_only_filter(
    client: httpx.AsyncClient, key: str, rows: dict[str, str]
) -> None:
    response = await get(client, EXPORT_PATH, key, actor_id="key_1")

    assert response.status_code == 422, response.text
    assert "`actor_id`" in response.json()["error"]["message"]


@pytest.mark.parametrize("path", ALL_PATHS)
async def test_unauthenticated_unknown_parameter_is_not_422(
    client: httpx.AsyncClient, rows: dict[str, str], path: str
) -> None:
    response = await client.get(path, params={"reason": "x"})

    assert response.status_code in (401, 403), response.text


async def test_documented_parameters_still_work(
    client: httpx.AsyncClient, key: str, rows: dict[str, str]
) -> None:
    params = {
        "actor_id": "key_1",
        "action": "sandbox.create",
        "from": "2026-11-07T00:00:00Z",
        "to": "2026-11-08T00:00:00Z",
        "order": "desc",
        "limit": "10",
    }

    response = await get(client, AUDIT_PATH, key, **params)

    assert ids(response) == {rows["a_ok"], rows["none"], rows["b_error"]}

    first_page = await get(client, AUDIT_PATH, key, limit="2")
    cursor = first_page.json()["meta"]["next_cursor"]
    assert cursor is not None
    assert (await get(client, AUDIT_PATH, key, cursor=cursor)).status_code == 200
    assert (await get(client, AUDIT_PATH, key, target_id="sbx_none")).status_code == 200


async def test_export_honours_request_id_filter(
    client: httpx.AsyncClient, key: str, rows: dict[str, str]
) -> None:
    response = await get(client, EXPORT_PATH, key, request_id="req-a")

    assert export_ids(response) == {rows["a_ok"], rows["a_denied"]}


async def test_export_honours_outcome_filter(
    client: httpx.AsyncClient, key: str, rows: dict[str, str]
) -> None:
    response = await get(client, EXPORT_PATH, key, outcome="error")

    assert export_ids(response) == {rows["b_error"]}


async def test_export_without_filters_and_with_time_bounds_still_works(
    client: httpx.AsyncClient, key: str, rows: dict[str, str]
) -> None:
    everything = await get(client, EXPORT_PATH, key)
    bounded = await get(
        client, EXPORT_PATH, key, **{"from": "2026-11-07T00:00:00Z", "to": "2026-11-08T00:00:00Z"}
    )

    assert export_ids(everything, summary=False) == set(rows.values())
    assert export_ids(bounded) == set(rows.values())


async def test_verify_with_documented_parameter_is_not_rejected(
    client: httpx.AsyncClient, key: str, rows: dict[str, str]
) -> None:
    response = await get(client, VERIFY_PATH, key, from_id=rows["a_ok"])

    assert response.status_code in (200, 404), response.text


@pytest.mark.parametrize("path", ALL_PATHS)
async def test_unknown_parameter_422_has_the_validation_error_shape(
    client: httpx.AsyncClient, key: str, rows: dict[str, str], path: str
) -> None:
    response = await get(client, path, key, bogus="x")

    assert response.status_code == 422, response.text
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert "`bogus`" in error["message"]
    assert error["details"]["errors"] == [
        {
            "type": "extra_forbidden",
            "loc": ["query", "bogus"],
            "msg": "Extra inputs are not permitted",
        }
    ]


async def test_two_unknown_parameters_give_two_entries(
    client: httpx.AsyncClient, key: str, rows: dict[str, str]
) -> None:
    response = await get(client, AUDIT_PATH, key, bogus="x", zzz="y")

    assert response.status_code == 422, response.text
    errors = response.json()["error"]["details"]["errors"]
    assert [entry["loc"] for entry in errors] == [["query", "bogus"], ["query", "zzz"]]
    assert all(set(entry) == {"type", "loc", "msg"} for entry in errors)


def test_model_declares_the_org_request_id_index() -> None:
    table_args: tuple[object, ...] = AuditRow.__table_args__  # type: ignore[assignment]
    index_names = {item.name for item in table_args if isinstance(item, Index)}

    assert "ix_audit_events_org_id_request_id" in index_names
