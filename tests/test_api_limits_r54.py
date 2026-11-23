"""Two validation findings of round 54.

* ``POST /v1/org/members`` stored a display name made only of whitespace (the CLI refuses it
  locally), only of invisible format characters, or holding a control character. Such a name now
  answers 422 ``VALIDATION_ERROR`` naming ``display_name``; nothing is created. Visible names in
  any script are accepted as before.
* ``GET /v1/sandboxes/{id}/logs?since=nan`` answered that the value should be less than the
  upper bound. A non-finite ``since`` now answers the same 422 at ``["query", "since"]`` with a
  message saying it must be a finite number of seconds.

Through the API on the fake driver and a temp SQLite database; no network and no sockets.
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
from sandfort.api.openapi import OPENAPI_PATH, build_document, render_spec
from sandfort.api.routes.sandbox_logs import NOT_FINITE_MESSAGE, SINCE_LIMIT_S
from sandfort.api.schemas.users import check_display_name
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
MEMBERS = "/v1/org/members"
SANDBOXES = "/v1/sandboxes"
OK_STATUS = 200
CREATED_STATUS = 201
VALIDATION_STATUS = 422
SCOPES = frozenset(Scope)  # granting a role needs every scope the role carries

WHITESPACE_ONLY = [
    pytest.param(" ", id="space"),
    pytest.param("     ", id="spaces"),
    pytest.param(" ", id="no-break-space"),
    pytest.param("　", id="ideographic-space"),
    pytest.param(" ​ ", id="spaces-around-zero-width"),
    pytest.param("​ ⁠", id="space-between-invisibles"),
]
INVISIBLE_ONLY = [
    pytest.param("​", id="zero-width-space"),
    pytest.param("​‌‍﻿", id="zero-width-run"),
    pytest.param("‮⁦⁩", id="bidi-controls"),
    pytest.param("\U000e0041\U000e0062\U000e007f", id="tag-characters"),
    pytest.param("­", id="soft-hyphen"),
    pytest.param("ㅤ", id="hangul-filler"),
    pytest.param("⠀", id="braille-blank"),
]
WITH_CONTROL = [
    pytest.param("Ana\x1b[31m", id="esc"),
    pytest.param("Ana\x07", id="bel"),
    pytest.param("Ana\x85", id="c1-nel"),
    pytest.param("Ana\x7f", id="del"),
    pytest.param("Ana\tB", id="tab"),
    pytest.param("Ana\nB", id="newline"),
]
REJECTED = [*WHITESPACE_ONLY, *INVISIBLE_ONLY, *WITH_CONTROL]
ORDINARY = [
    pytest.param("Ana Petrović", id="latin-diacritics"),
    pytest.param("Ана Петровић", id="cyrillic"),
    pytest.param("山田 太郎", id="cjk-with-space"),
    pytest.param("ทดสอบ", id="thai"),
    pytest.param("👨‍👩‍👧 family", id="emoji-with-joiners"),
    pytest.param("deploy​bot", id="joiner-between-visible"),
]
NON_FINITE = ["nan", "NaN", "inf", "-inf", "Infinity", "-Infinity", "1e309"]


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'limits54.db'}"
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
async def headers(app: FastAPI) -> dict[str, str]:
    org = Org(id=new_org_id(), name="Limits", slug="limits", created_at=NOW)
    generated = generate_api_key(PEPPER)
    key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="limits",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=SCOPES,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(key)
        await uow.commit()
    return {"Authorization": f"Bearer {generated.key}"}


def validation_errors(response: httpx.Response) -> list[dict[str, Any]]:
    assert response.status_code == VALIDATION_STATUS, response.text
    payload: dict[str, Any] = response.json()
    assert payload["success"] is False
    assert payload["error"]["code"] == "VALIDATION_ERROR"
    errors: list[dict[str, Any]] = payload["error"]["details"]["errors"]
    return errors


async def member_emails(client: httpx.AsyncClient, headers: dict[str, str]) -> list[str]:
    response = await client.get(MEMBERS, headers=headers)
    assert response.status_code == OK_STATUS, response.text
    return [item["email"] for item in response.json()["data"]]


def member_body(display_name: str) -> dict[str, str]:
    return {"email": "ana@example.com", "display_name": display_name, "role": "developer"}


# --- the display name check -------------------------------------------------------------


@pytest.mark.parametrize("name", REJECTED)
def test_blank_invisible_or_control_display_name_is_refused(name: str) -> None:
    with pytest.raises(ValueError):
        check_display_name(name)


@pytest.mark.parametrize("name", ORDINARY)
def test_visible_display_name_is_returned_unchanged(name: str) -> None:
    assert check_display_name(name) == name


# --- member creation --------------------------------------------------------------------


@pytest.mark.parametrize("name", REJECTED)
async def test_member_display_name_without_visible_text_answers_422_and_creates_nothing(
    client: httpx.AsyncClient, headers: dict[str, str], name: str
) -> None:
    before = await member_emails(client, headers)

    response = await client.post(MEMBERS, json=member_body(name), headers=headers)

    assert ["body", "display_name"] in [issue["loc"] for issue in validation_errors(response)]
    assert await member_emails(client, headers) == before


@pytest.mark.parametrize("name", ORDINARY)
async def test_member_display_name_in_any_visible_script_is_created(
    client: httpx.AsyncClient, headers: dict[str, str], name: str
) -> None:
    response = await client.post(MEMBERS, json=member_body(name), headers=headers)

    assert response.status_code == CREATED_STATUS, response.text
    assert response.json()["data"]["display_name"] == name
    assert "ana@example.com" in await member_emails(client, headers)


# --- sandbox logs: since ----------------------------------------------------------------


@pytest.fixture
async def sandbox_id(client: httpx.AsyncClient, headers: dict[str, str]) -> str:
    response = await client.post(SANDBOXES, json={}, headers=headers)
    assert response.status_code == CREATED_STATUS, response.text
    value: str = response.json()["data"]["id"]
    return value


@pytest.mark.parametrize("since", NON_FINITE)
async def test_logs_since_non_finite_answers_422_with_the_finite_number_message(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, since: str
) -> None:
    response = await client.get(
        f"{SANDBOXES}/{sandbox_id}/logs", params={"since": since}, headers=headers
    )

    issues = [issue for issue in validation_errors(response) if issue["loc"] == ["query", "since"]]
    assert [issue["msg"] for issue in issues] == [NOT_FINITE_MESSAGE]
    assert "less than" not in response.text


async def test_logs_since_that_is_not_a_number_keeps_the_parse_error(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    response = await client.get(
        f"{SANDBOXES}/{sandbox_id}/logs", params={"since": "soon"}, headers=headers
    )

    issues = [issue for issue in validation_errors(response) if issue["loc"] == ["query", "since"]]
    assert issues
    assert NOT_FINITE_MESSAGE not in [issue["msg"] for issue in issues]


async def test_logs_since_finite_value_still_streams(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    response = await client.get(
        f"{SANDBOXES}/{sandbox_id}/logs", params={"since": "0.5"}, headers=headers
    )

    assert response.status_code == OK_STATUS, response.text


# --- published spec ---------------------------------------------------------------------


def test_the_published_since_keeps_its_bounds() -> None:
    operation = build_document()["paths"]["/v1/sandboxes/{sandbox_id}/logs"]["get"]
    since = next(item for item in operation["parameters"] if item["name"] == "since")
    number = {"exclusiveMaximum": SINCE_LIMIT_S, "minimum": 0, "type": "number"}

    assert since["schema"]["anyOf"] == [number, {"type": "null"}], since


def test_the_committed_spec_matches_the_application() -> None:
    expected = render_spec(build_document())

    assert OPENAPI_PATH.read_bytes().decode("utf-8") == expected
