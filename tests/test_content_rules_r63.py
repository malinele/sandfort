"""One content rule for every stored string (round 63, API-contract review).

Label keys and values, env keys and values, egress allowlist entries, exec / session / context
working directories, API key names and mount paths accepted control characters, bidi controls,
zero-width and other invisible format characters, line separators, private-use code points
and look-alikes. They are now refused with a 422 ``VALIDATION_ERROR`` that names the field and
the offending code point (``U+XXXX``, never the raw character), before anything is stored.
Normal text, including letters of any script in values, is still accepted.

Through the API on the fake driver and a temp SQLite database; no network and no sockets.
"""

import re
import shutil
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.schemas.text_checks import check_egress_hosts
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
VOLUMES = "/v1/volumes"
API_KEYS = "/v1/api-keys"
USAGE = "/v1/org/usage"
OK_STATUS = 200
CREATED_STATUS = 201
VALIDATION_STATUS = 422
SCOPES = frozenset(
    {
        Scope.SANDBOXES_WRITE,
        Scope.SANDBOXES_READ,
        Scope.TOOLBOX,
        Scope.VOLUMES_READ,
        Scope.VOLUMES_WRITE,
        Scope.API_KEYS_ADMIN,
        Scope.USAGE_READ,
    }
)

# Refused in every field below (tab is its own case: only env values take it).
BAD_EVERYWHERE = [
    pytest.param("\x1b", id="esc"),
    pytest.param("\n", id="newline"),
    pytest.param("\r", id="carriage-return"),
    pytest.param("\x07", id="bel"),
    pytest.param("\x7f", id="del"),
    pytest.param("\x85", id="c1-nel"),
    pytest.param("\x9b", id="c1-csi"),
    pytest.param("‮", id="rlo"),
    pytest.param("‪", id="lre"),
    pytest.param("⁦", id="lri"),
    pytest.param("⁩", id="pdi"),
    pytest.param("‎", id="lrm"),
    pytest.param("؜", id="arabic-letter-mark"),
    pytest.param("​", id="zwsp"),
    pytest.param("‌", id="zwnj"),
    pytest.param("‍", id="zwj"),
    pytest.param("⁠", id="word-joiner"),
    pytest.param("­", id="soft-hyphen"),
    pytest.param("﻿", id="bom"),
    pytest.param(" ", id="line-separator"),
    pytest.param(" ", id="paragraph-separator"),
    pytest.param("\U000e0041", id="tag-a"),
    pytest.param("\U000e007f", id="cancel-tag"),
    pytest.param("", id="private-use-bmp"),
    pytest.param("\U000f0000", id="private-use-plane-15"),
    pytest.param("﷐", id="noncharacter-fdd0"),
    pytest.param("￿", id="noncharacter-ffff"),
    pytest.param("\U0001fffe", id="noncharacter-1fffe"),
]
# NUL never reaches the schemas: the body guard (``text_guard``) refuses it first, on every field.
# A variation selector is refused as the first character only (emoji keep theirs).
LEADING_VARIATION_SELECTORS = [
    pytest.param("️", id="vs16"),
    pytest.param("︀", id="vs1"),
    pytest.param("\U000e0100", id="vs17"),
]
# Refused in label values and keys (a plain space stays fine in values).
NON_ASCII_SPACES = [
    pytest.param(" ", id="nbsp"),
    pytest.param(" ", id="en-space"),
    pytest.param(" ", id="narrow-nbsp"),
    pytest.param("　", id="ideographic-space"),
]
TAB = "\t"


def in_value(char: str) -> str:
    """``char`` in a value; a joiner goes last, as between visible characters it is accepted."""
    return f"a{char}" if char in "\u200c\u200d" else f"a{char}b"


def code_point(char: str) -> str:
    return f"U+{ord(char[0]):04X}"


@pytest.fixture(scope="session")
def migrated_db(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One migrated SQLite file, copied per test (the migration is the slow part)."""
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    template = tmp_path_factory.mktemp("content63") / "template.db"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{template}")
    command.upgrade(config, "head")
    return template


@pytest.fixture
async def app(tmp_path: Path, migrated_db: Path) -> AsyncIterator[FastAPI]:
    database = tmp_path / "content63.db"
    shutil.copyfile(migrated_db, database)
    url = f"sqlite+aiosqlite:///{database}"
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
    org = Org(id=new_org_id(), name="Content", slug="content", created_at=NOW)
    generated = generate_api_key(PEPPER)
    key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="content",
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


async def rows(client: httpx.AsyncClient, headers: dict[str, str], path: str) -> list[Any]:
    response = await client.get(path, headers=headers)
    assert response.status_code == OK_STATUS, response.text
    found: list[Any] = response.json()["data"]
    return found


def assert_refused(response: httpx.Response, loc: list[Any], char: str) -> None:
    assert response.status_code == VALIDATION_STATUS, response.text
    payload: dict[str, Any] = response.json()
    assert payload["success"] is False
    assert payload["error"]["code"] == "VALIDATION_ERROR"
    issues = payload["error"]["details"]["errors"]
    assert [issue["loc"] for issue in issues] == [loc], issues
    assert not issues[0]["msg"].startswith("Value error")
    # A control character refused before round 63 (label key, key name) keeps its wording.
    legacy = ("label names", "must not contain control characters")
    if not issues[0]["msg"].startswith(legacy):
        assert code_point(char) in issues[0]["msg"], issues[0]["msg"]
    assert char.isprintable() or char not in issues[0]["msg"]


# --- creates: refused, and nothing is stored -------------------------------------------------

Send = Callable[[httpx.AsyncClient, dict[str, str], str], Any]


def sandbox_create(body: Callable[[str], dict[str, Any]], loc: list[Any]) -> Callable[..., Any]:
    async def run(client: httpx.AsyncClient, headers: dict[str, str], char: str) -> None:
        response = await client.post(SANDBOXES, json=body(char), headers=headers)
        assert_refused(response, loc, char)
        assert await rows(client, headers, SANDBOXES) == []

    return run


def volume_create(body: Callable[[str], dict[str, Any]], loc: list[Any]) -> Callable[..., Any]:
    async def run(client: httpx.AsyncClient, headers: dict[str, str], char: str) -> None:
        response = await client.post(VOLUMES, json={"name": "data", **body(char)}, headers=headers)
        assert_refused(response, loc, char)
        assert await rows(client, headers, VOLUMES) == []

    return run


def key_create(body: Callable[[str], dict[str, Any]], loc: list[Any]) -> Callable[..., Any]:
    async def run(client: httpx.AsyncClient, headers: dict[str, str], char: str) -> None:
        full = {"name": "k", "scopes": ["sandboxes:read"], **body(char)}
        response = await client.post(API_KEYS, json=full, headers=headers)
        assert_refused(response, loc, char)
        names = [row["name"] for row in await rows(client, headers, API_KEYS)]
        assert names == ["content"]

    return run


def label_value(char: str) -> dict[str, Any]:
    return {"labels": {"team": in_value(char)}}


def label_key(char: str) -> dict[str, Any]:
    return {"labels": {f"te{char}am": "v"}}


GENERAL_FIELDS = {
    "sandbox-label-value": sandbox_create(label_value, ["body", "labels"]),
    "sandbox-label-key": sandbox_create(label_key, ["body", "labels"]),
    "sandbox-env-key": sandbox_create(lambda c: {"env": {f"K{c}": "v"}}, ["body", "env"]),
    "sandbox-env-value": sandbox_create(lambda c: {"env": {"K": in_value(c)}}, ["body", "env"]),
    "sandbox-egress": sandbox_create(
        lambda c: {"egress_allowlist": [f"exa{c}mple.com"]}, ["body", "egress_allowlist"]
    ),
    "volume-label-value": volume_create(label_value, ["body", "labels"]),
    "volume-label-key": volume_create(label_key, ["body", "labels"]),
    "api-key-label-value": key_create(
        lambda c: {"sandbox_labels": {"team": in_value(c)}}, ["body", "sandbox_labels"]
    ),
    "api-key-label-key": key_create(
        lambda c: {"sandbox_labels": {f"te{c}am": "v"}}, ["body", "sandbox_labels"]
    ),
    "api-key-name": key_create(lambda c: {"name": f"ci{c}key"}, ["body", "name"]),
}


@pytest.mark.parametrize("char", BAD_EVERYWHERE)
@pytest.mark.parametrize("field", sorted(GENERAL_FIELDS))
async def test_create_refuses_a_bad_character(
    client: httpx.AsyncClient, headers: dict[str, str], field: str, char: str
) -> None:
    await GENERAL_FIELDS[field](client, headers, char)


@pytest.mark.parametrize("char", [TAB])
@pytest.mark.parametrize(
    "field",
    [
        "sandbox-label-value",
        "sandbox-label-key",
        "sandbox-env-key",
        "sandbox-egress",
        "volume-label-value",
        "volume-label-key",
        "api-key-label-value",
        "api-key-label-key",
        "api-key-name",
    ],
)
async def test_tab_is_refused_everywhere_but_env_values(
    client: httpx.AsyncClient, headers: dict[str, str], field: str, char: str
) -> None:
    await GENERAL_FIELDS[field](client, headers, char)


@pytest.mark.parametrize("char", LEADING_VARIATION_SELECTORS)
@pytest.mark.parametrize(
    "field", ["sandbox-label-value", "sandbox-label-key", "sandbox-env-key", "api-key-name"]
)
async def test_a_leading_variation_selector_is_refused(
    client: httpx.AsyncClient, headers: dict[str, str], field: str, char: str
) -> None:
    run = {
        "sandbox-label-value": sandbox_create(
            lambda c: {"labels": {"team": f"{c}x"}}, ["body", "labels"]
        ),
        "sandbox-label-key": sandbox_create(
            lambda c: {"labels": {f"{c}team": "v"}}, ["body", "labels"]
        ),
        "sandbox-env-key": sandbox_create(lambda c: {"env": {f"{c}K": "v"}}, ["body", "env"]),
        "api-key-name": key_create(lambda c: {"name": f"{c}ci"}, ["body", "name"]),
    }[field]
    await run(client, headers, char)


@pytest.mark.parametrize("char", NON_ASCII_SPACES)
@pytest.mark.parametrize(
    "field",
    [
        "sandbox-label-value",
        "sandbox-label-key",
        "volume-label-value",
        "volume-label-key",
        "api-key-label-value",
        "api-key-label-key",
    ],
)
async def test_labels_refuse_non_ascii_spaces(
    client: httpx.AsyncClient, headers: dict[str, str], field: str, char: str
) -> None:
    await GENERAL_FIELDS[field](client, headers, char)


@pytest.mark.parametrize("char", [" ", *[p.values[0] for p in NON_ASCII_SPACES]])
@pytest.mark.parametrize("field", ["sandbox-label-key", "volume-label-key", "api-key-label-key"])
async def test_label_keys_refuse_any_whitespace(
    client: httpx.AsyncClient, headers: dict[str, str], field: str, char: str
) -> None:
    run = GENERAL_FIELDS[field]
    # A plain space has no code point to name beyond U+0020; it is named all the same.
    await run(client, headers, char)


@pytest.mark.parametrize("host", ["exa mple.com", "example.com ", "ex ample.com"])
async def test_egress_hosts_with_whitespace_are_refused(
    client: httpx.AsyncClient, headers: dict[str, str], host: str
) -> None:
    response = await client.post(SANDBOXES, json={"egress_allowlist": [host]}, headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert await rows(client, headers, SANDBOXES) == []


# --- PATCH labels ----------------------------------------------------------------------------


@pytest.mark.parametrize("char", [*[p.values[0] for p in BAD_EVERYWHERE], TAB, " "])
@pytest.mark.parametrize("part", ["value", "key"])
async def test_patch_labels_refuses_a_bad_character(
    client: httpx.AsyncClient, headers: dict[str, str], part: str, char: str
) -> None:
    created = await client.post(SANDBOXES, json={"labels": {"team": "a"}}, headers=headers)
    assert created.status_code == CREATED_STATUS, created.text
    sandbox_id = created.json()["data"]["id"]
    labels = label_value(char) if part == "value" else label_key(char)

    response = await client.patch(f"{SANDBOXES}/{sandbox_id}", json=labels, headers=headers)

    assert_refused(response, ["body", "labels"], char)
    current = await client.get(f"{SANDBOXES}/{sandbox_id}", headers=headers)
    assert current.json()["data"]["labels"] == {"team": "a"}


# --- exec, code-run, sessions, contexts ------------------------------------------------------

TOOLBOX_ROUTES = {
    "exec": ("process/execute", {"command": "true"}),
    "code-run": ("process/code-run", {"language": "python", "code": "1"}),
    "session": ("process/sessions", {}),
    "context": ("code-contexts", {}),
}


@pytest.mark.parametrize("char", [*[p.values[0] for p in BAD_EVERYWHERE], TAB])
@pytest.mark.parametrize("route", sorted(TOOLBOX_ROUTES))
@pytest.mark.parametrize("field", ["cwd", "env-key"])
async def test_toolbox_requests_refuse_a_bad_character(
    client: httpx.AsyncClient, headers: dict[str, str], route: str, field: str, char: str
) -> None:
    if route == "context" and field == "env-key":
        pytest.skip("code contexts take no env")
    created = await client.post(SANDBOXES, json={}, headers=headers)
    assert created.status_code == CREATED_STATUS, created.text
    sandbox_id = created.json()["data"]["id"]
    suffix, base = TOOLBOX_ROUTES[route]
    body = dict(base)
    if field == "cwd":
        body["cwd"] = f"/work{char}dir"
        loc = ["body", "cwd"]
    else:
        body["env"] = {f"K{char}": "v"}
        loc = ["body", "env"]

    response = await client.post(
        f"{SANDBOXES}/{sandbox_id}/toolbox/{suffix}", json=body, headers=headers
    )

    assert_refused(response, loc, char)


@pytest.mark.parametrize("char", [p.values[0] for p in BAD_EVERYWHERE])
@pytest.mark.parametrize("route", ["exec", "code-run", "session"])
async def test_toolbox_env_values_refuse_everything_but_tab(
    client: httpx.AsyncClient, headers: dict[str, str], route: str, char: str
) -> None:
    created = await client.post(SANDBOXES, json={}, headers=headers)
    sandbox_id = created.json()["data"]["id"]
    suffix, base = TOOLBOX_ROUTES[route]

    response = await client.post(
        f"{SANDBOXES}/{sandbox_id}/toolbox/{suffix}",
        json={**base, "env": {"K": in_value(char)}},
        headers=headers,
    )

    assert_refused(response, ["body", "env"], char)
    if route == "session":
        listing = await rows(client, headers, f"{SANDBOXES}/{sandbox_id}/toolbox/{suffix}")
        assert listing == []


async def test_a_tab_in_an_env_value_is_accepted(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    response = await client.post(SANDBOXES, json={"env": {"K": "a\tb"}}, headers=headers)

    assert response.status_code == CREATED_STATUS, response.text


# --- mount paths -----------------------------------------------------------------------------

BAD_MOUNT_PATHS = [
    pytest.param("/data x", " ", id="en-space"),
    pytest.param("/data x", " ", id="narrow-nbsp"),
    pytest.param("/data x", " ", id="ogham-space"),
    pytest.param("/data x", " ", id="nbsp"),
    pytest.param("/data͏x", "͏", id="cgj"),
    pytest.param("/data️x", "️", id="vs16"),
    pytest.param("/data／x", "／", id="fullwidth-solidus"),
    pytest.param("/data：x", "：", id="fullwidth-colon"),
    pytest.param("/data，x", "，", id="fullwidth-comma"),
    pytest.param("/data∕x", "∕", id="division-slash"),
    pytest.param("/data‥x", "‥", id="two-dot-leader"),
    pytest.param("/datax", "", id="private-use"),
    pytest.param("/data﷐x", "﷐", id="noncharacter"),
    pytest.param("/data￼x", "￼", id="object-replacement"),
    pytest.param("/data�x", "�", id="replacement-char"),
    pytest.param("/data͸x", "͸", id="unassigned"),
    pytest.param("/data​x", "​", id="zwsp"),
    pytest.param("/data\x1bx", "\x1b", id="esc"),
]


@pytest.mark.parametrize(("path", "char"), BAD_MOUNT_PATHS)
async def test_mount_path_look_alikes_are_refused(
    client: httpx.AsyncClient, headers: dict[str, str], path: str, char: str
) -> None:
    body = {"volumes": [{"volume_id": "vol_x", "mount_path": path}]}

    response = await client.post(SANDBOXES, json=body, headers=headers)

    assert_refused(response, ["body", "volumes", "0", "mount_path"], char)
    assert await rows(client, headers, SANDBOXES) == []


@pytest.mark.parametrize(
    "path",
    ["/var/run/docker.sock", "/run/docker.sock", "/data/.../x", "/..."],
)
async def test_docker_socket_and_dots_segments_are_refused(
    client: httpx.AsyncClient, headers: dict[str, str], path: str
) -> None:
    body = {"volumes": [{"volume_id": "vol_x", "mount_path": path}]}

    response = await client.post(SANDBOXES, json=body, headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    issues = response.json()["error"]["details"]["errors"]
    assert [issue["loc"] for issue in issues] == [["body", "volumes", "0", "mount_path"]]
    assert not issues[0]["msg"].startswith("Value error")
    assert await rows(client, headers, SANDBOXES) == []


# --- normal values stay accepted -------------------------------------------------------------


@pytest.mark.parametrize(
    "value", ["café", "名前", "Привет", "a b", "émile zola", "x" * 10, "ok-1_2.3", "naïve 🙂"]
)
async def test_normal_label_values_are_stored(
    client: httpx.AsyncClient, headers: dict[str, str], value: str
) -> None:
    response = await client.post(SANDBOXES, json={"labels": {"team": value}}, headers=headers)

    assert response.status_code == CREATED_STATUS, response.text
    assert response.json()["data"]["labels"] == {"team": value}


async def test_normal_values_in_every_field_are_stored(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    body = {
        "labels": {"team": "café", "env": "prod"},
        "env": {"GREETING": "héllo wörld\tok", "PATH_X": "/usr/bin"},
        "volumes": [],
    }

    sandbox = await client.post(SANDBOXES, json=body, headers=headers)
    volume = await client.post(
        VOLUMES, json={"name": "data", "labels": {"owner": "zoë"}}, headers=headers
    )
    key = await client.post(
        API_KEYS,
        json={
            "name": "ci key é",
            "scopes": ["sandboxes:read"],
            "sandbox_labels": {"team": "café"},
        },
        headers=headers,
    )

    assert sandbox.status_code == CREATED_STATUS, sandbox.text
    assert volume.status_code == CREATED_STATUS, volume.text
    assert key.status_code == CREATED_STATUS, key.text


@pytest.mark.parametrize("host", ["example.com", ".example.org", "xn--bcher-kva.de", "a-b.io"])
def test_normal_egress_hosts_pass_the_content_rule(host: str) -> None:
    assert check_egress_hosts([host]) == [host]


async def test_normal_cwd_and_env_pass_validation(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    created = await client.post(SANDBOXES, json={}, headers=headers)
    sandbox_id = created.json()["data"]["id"]

    response = await client.post(
        f"{SANDBOXES}/{sandbox_id}/toolbox/process/sessions",
        json={"cwd": "/work space/é", "env": {"A": "x\ty"}},
        headers=headers,
    )

    assert response.status_code == CREATED_STATUS, response.text


# --- usage route -----------------------------------------------------------------------------

PERIOD = {"from": "2026-11-01T00:00:00Z", "to": "2026-11-02T00:00:00Z"}


async def test_usage_group_by_message_has_no_value_error_prefix(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    response = await client.get(USAGE, params={**PERIOD, "group_by": "nonsense"}, headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    issues = response.json()["error"]["details"]["errors"]
    assert [issue["loc"] for issue in issues] == [["query", "group_by"]]
    assert issues[0]["msg"] == "group_by must be 'sandbox' or 'label:<key>'"


async def test_usage_date_range_message_has_no_value_error_prefix(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    response = await client.get(
        USAGE,
        params={"from": "9999-12-31T23:00:00-23:00", "to": "9999-12-31T23:59:00Z"},
        headers=headers,
    )

    assert response.status_code == VALIDATION_STATUS, response.text
    issues = response.json()["error"]["details"]["errors"]
    assert issues[0]["loc"] == ["query", "from"]
    assert issues[0]["msg"] == "datetime is out of range once converted to UTC"


@pytest.mark.parametrize("char", [p.values[0] for p in BAD_EVERYWHERE])
async def test_usage_group_by_label_key_refuses_a_bad_character(
    client: httpx.AsyncClient, headers: dict[str, str], char: str
) -> None:
    response = await client.get(
        USAGE, params={**PERIOD, "group_by": f"label:te{char}am"}, headers=headers
    )

    assert_refused(response, ["query", "group_by"], char)


@pytest.mark.parametrize("key", ["team name", "team name", "a" * 64, "a" * 3000])
async def test_usage_group_by_label_key_refuses_whitespace_and_long_keys(
    client: httpx.AsyncClient, headers: dict[str, str], key: str
) -> None:
    response = await client.get(
        USAGE, params={**PERIOD, "group_by": f"label:{key}"}, headers=headers
    )

    assert response.status_code == VALIDATION_STATUS, response.text
    issues = response.json()["error"]["details"]["errors"]
    assert [issue["loc"] for issue in issues] == [["query", "group_by"]]
    assert not issues[0]["msg"].startswith("Value error")
    assert key not in response.text


@pytest.mark.parametrize("value", ["label:team,sandbox", "label:a,b", "label:,"])
async def test_usage_group_by_refuses_two_groupings_in_one_call(
    client: httpx.AsyncClient, headers: dict[str, str], value: str
) -> None:
    response = await client.get(USAGE, params={**PERIOD, "group_by": value}, headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    issues = response.json()["error"]["details"]["errors"]
    assert [issue["loc"] for issue in issues] == [["query", "group_by"]]
    assert "one grouping per call" in issues[0]["msg"]


@pytest.mark.parametrize("value", ["sandbox", "label:team", "label:" + "a" * 63, "label:équipe"])
async def test_usage_group_by_valid_forms_still_work(
    client: httpx.AsyncClient, headers: dict[str, str], value: str
) -> None:
    response = await client.get(USAGE, params={**PERIOD, "group_by": value}, headers=headers)

    assert response.status_code == OK_STATUS, response.text
    assert re.fullmatch(r"\[.*\]", str(response.json()["data"]).replace("\n", ""))
