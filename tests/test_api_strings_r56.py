"""Whitespace-only label keys (round 56, persona findings).

A label key made only of whitespace (ASCII space, no-break space, em space, ideographic space or
any other Unicode White_Space character, alone or mixed with invisible format characters)
passed the invisible-text check, so a sandbox (create and PATCH) or an API key label scope
could carry a blank key. Such a key now answers 422 ``VALIDATION_ERROR`` naming the field, and
nothing is stored. Keys with whitespace between visible characters are accepted as before.

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
from sandfort.api.schemas.text_checks import invisible_text_problem
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
API_KEYS = "/v1/api-keys"
OK_STATUS = 200
CREATED_STATUS = 201
VALIDATION_STATUS = 422
VALUE_ERROR_TYPE = "value_error"
BLANK_MESSAGE = "must contain a visible character"
SCOPES = frozenset(
    {Scope.SANDBOXES_WRITE, Scope.SANDBOXES_READ, Scope.TOOLBOX, Scope.API_KEYS_ADMIN}
)

WHITESPACE_KEYS = [
    pytest.param(" ", id="ascii-space"),
    pytest.param("   ", id="ascii-spaces"),
    pytest.param(" ", id="no-break-space"),
    pytest.param(" ", id="em-space"),
    pytest.param("　", id="ideographic-space"),
    pytest.param(" ", id="ogham-space-mark"),
    pytest.param("  ", id="en-quad-hair-space"),
    pytest.param("  ", id="narrow-nbsp-math-space"),
    pytest.param("  ", id="line-paragraph-separators"),
    pytest.param("   　", id="mixed-whitespace"),
    pytest.param("​ ⁠", id="space-between-invisibles"),
    pytest.param("　‍﻿", id="ideographic-space-with-format"),
]
BLANK_LOOKING_KEYS = [
    pytest.param("ㅤ", id="hangul-filler"),
    pytest.param("ᅟ", id="hangul-choseong-filler"),
    pytest.param("ᅠ", id="hangul-jungseong-filler"),
    pytest.param("⠀", id="braille-blank"),
    pytest.param("͏", id="combining-grapheme-joiner"),
    pytest.param("︀", id="variation-selector-1"),
    pytest.param("️", id="variation-selector-16"),
    pytest.param("ﾠ", id="halfwidth-hangul-filler"),
    pytest.param("឴", id="khmer-inherent-vowel-aq"),
    pytest.param("឵", id="khmer-inherent-vowel-aa"),
    pytest.param("᠋", id="mongolian-fvs-1"),
    pytest.param("᠌", id="mongolian-fvs-2"),
    pytest.param("᠍", id="mongolian-fvs-3"),
    pytest.param("᠏", id="mongolian-fvs-4"),
    pytest.param("\U000e0100", id="variation-selector-17"),
    pytest.param("\U000e01ef", id="variation-selector-256"),
    pytest.param("ﾠ឴᠋\U000e0100", id="mixed-new-blank-looking"),
    pytest.param("ㅤ⠀͏️", id="mixed-blank-looking"),
    pytest.param(" ㅤ​⠀", id="blank-looking-with-space-and-format"),
]
VISIBLE_KEYS = [
    pytest.param("team name", id="inner-ascii-space"),
    pytest.param("a　b", id="inner-ideographic-space"),
    pytest.param(" x ", id="no-break-spaces-around-visible"),
    pytest.param("名 前", id="cjk-with-space"),
    pytest.param("👨‍👩‍👧", id="emoji-with-joiners"),
    pytest.param("aㅤb", id="hangul-filler-between-visible"),
    pytest.param("⠀x", id="braille-blank-before-visible"),
    pytest.param("❤️", id="emoji-with-variation-selector"),
]
# Round 63: a label key holds no whitespace and no format character (ZWJ included), so only the
# keys without either are still stored; the function-level check above keeps all of VISIBLE_KEYS.
STORED_KEYS = [
    param
    for param in VISIBLE_KEYS
    if param.id in {"hangul-filler-between-visible", "braille-blank-before-visible"}
    or param.id == "emoji-with-variation-selector"
]


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'strings56.db'}"
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
async def headers(app: FastAPI) -> dict[str, str]:
    org = Org(id=new_org_id(), name="Strings", slug="strings", created_at=NOW)
    generated = generate_api_key(PEPPER)
    key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="strings",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=SCOPES,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(key)
        await uow.commit()
    return {"Authorization": f"Bearer {generated.key}", "Content-Type": "application/json"}


def assert_refused(response: httpx.Response, loc: list[str]) -> None:
    assert response.status_code == VALIDATION_STATUS, response.text
    payload: dict[str, Any] = response.json()
    assert payload["success"] is False
    assert payload["error"]["code"] == "VALIDATION_ERROR"
    issues = payload["error"]["details"]["errors"]
    assert [(issue["type"], issue["loc"]) for issue in issues] == [(VALUE_ERROR_TYPE, loc)]
    assert BLANK_MESSAGE in issues[0]["msg"]


async def listed(client: httpx.AsyncClient, headers: dict[str, str], path: str) -> list[Any]:
    response = await client.get(path, headers=headers)
    assert response.status_code == OK_STATUS, response.text
    rows: list[Any] = response.json()["data"]
    return rows


# --- the shared check -------------------------------------------------------------------------


@pytest.mark.parametrize("key", [*WHITESPACE_KEYS, *BLANK_LOOKING_KEYS])
def test_whitespace_only_text_is_named_as_blank(key: str) -> None:
    problem = invisible_text_problem(key)

    assert problem is not None
    assert BLANK_MESSAGE in problem


@pytest.mark.parametrize("key", VISIBLE_KEYS)
def test_whitespace_between_visible_characters_is_fine(key: str) -> None:
    assert invisible_text_problem(key) is None


def test_a_control_character_is_still_named_as_such() -> None:
    assert invisible_text_problem(" \t ") == "must not contain control characters"


# --- sandbox labels ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", BLANK_LOOKING_KEYS)
async def test_sandbox_create_with_a_blank_looking_label_key_is_refused(
    client: httpx.AsyncClient, headers: dict[str, str], key: str
) -> None:
    response = await client.post(SANDBOXES, json={"labels": {key: "v"}}, headers=headers)

    assert_refused(response, ["body", "labels"])
    assert await listed(client, headers, SANDBOXES) == []


@pytest.mark.parametrize("key", WHITESPACE_KEYS)
async def test_sandbox_create_with_a_whitespace_label_key_is_refused(
    client: httpx.AsyncClient, headers: dict[str, str], key: str
) -> None:
    response = await client.post(SANDBOXES, json={"labels": {key: "v"}}, headers=headers)

    assert_refused(response, ["body", "labels"])
    assert await listed(client, headers, SANDBOXES) == []


@pytest.mark.parametrize("key", WHITESPACE_KEYS)
async def test_sandbox_label_patch_with_a_whitespace_key_is_refused(
    client: httpx.AsyncClient, headers: dict[str, str], key: str
) -> None:
    created = await client.post(SANDBOXES, json={"labels": {"team": "a"}}, headers=headers)
    assert created.status_code == CREATED_STATUS, created.text
    sandbox_id = created.json()["data"]["id"]

    response = await client.patch(
        f"{SANDBOXES}/{sandbox_id}", json={"labels": {key: "v"}}, headers=headers
    )

    assert_refused(response, ["body", "labels"])
    current = await client.get(f"{SANDBOXES}/{sandbox_id}", headers=headers)
    assert current.json()["data"]["labels"] == {"team": "a"}


@pytest.mark.parametrize("key", STORED_KEYS)
async def test_sandbox_label_key_with_inner_whitespace_is_stored(
    client: httpx.AsyncClient, headers: dict[str, str], key: str
) -> None:
    response = await client.post(SANDBOXES, json={"labels": {key: "v"}}, headers=headers)

    assert response.status_code == CREATED_STATUS, response.text
    assert response.json()["data"]["labels"] == {key: "v"}


# --- api key label scope ----------------------------------------------------------------------


def key_body(labels: dict[str, str]) -> dict[str, Any]:
    return {"name": "scoped", "scopes": ["sandboxes:read"], "sandbox_labels": labels}


@pytest.mark.parametrize("key", BLANK_LOOKING_KEYS)
async def test_api_key_with_a_blank_looking_label_key_is_refused(
    client: httpx.AsyncClient, headers: dict[str, str], key: str
) -> None:
    response = await client.post(API_KEYS, json=key_body({key: "a"}), headers=headers)

    assert_refused(response, ["body", "sandbox_labels"])
    names = [row["name"] for row in await listed(client, headers, API_KEYS)]
    assert names == ["strings"]


@pytest.mark.parametrize("key", WHITESPACE_KEYS)
async def test_api_key_with_a_whitespace_label_key_is_refused(
    client: httpx.AsyncClient, headers: dict[str, str], key: str
) -> None:
    response = await client.post(API_KEYS, json=key_body({key: "a"}), headers=headers)

    assert_refused(response, ["body", "sandbox_labels"])
    names = [row["name"] for row in await listed(client, headers, API_KEYS)]
    assert names == ["strings"]


@pytest.mark.parametrize("key", STORED_KEYS)
async def test_api_key_label_key_with_inner_whitespace_is_stored(
    client: httpx.AsyncClient, headers: dict[str, str], key: str
) -> None:
    response = await client.post(API_KEYS, json=key_body({key: "a"}), headers=headers)

    assert response.status_code == CREATED_STATUS, response.text
    assert response.json()["data"]["sandbox_labels"] == {key: "a"}
