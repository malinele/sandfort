"""Query guards on the remaining routes (round 59): repeated single values and unknown names.

Each single-value parameter given twice answers 422 on its route, one value still works, an
unknown query name answers 422 naming it (the key revoke route included), and the volume delete
409 names only the sandboxes the caller's label scope can see, counting the rest in
``hidden_sandboxes``. Through the API on the fake driver and a temp SQLite database.
"""

import asyncio
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
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
from sandfort.drivers.base import ExecRequest, ExecResult
from sandfort.drivers.fake import FakeDriver
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
ACCEPTED_STATUS = 202
CONFLICT_STATUS = 409
VALIDATION_STATUS = 422
WINDOW = {"from": "2026-11-01T00:00:00Z", "to": "2026-11-08T00:00:00Z"}
TEAM_A = {"team": "a"}
TEAM_B = {"team": "b"}
Pairs = list[tuple[str, str]]


@dataclass(frozen=True)
class Targets:
    """Ids of one sandbox with an exited async command, for the session routes."""

    sandbox_id: str
    session_id: str
    command_id: str

    @property
    def sessions(self) -> str:
        return f"{SANDBOXES}/{self.sandbox_id}/toolbox/process/sessions"

    @property
    def commands(self) -> str:
        return f"{self.sessions}/{self.session_id}/commands"

    @property
    def logs(self) -> str:
        return f"{self.commands}/{self.command_id}/logs"


def _exec_handler(env: Mapping[str, str], request: ExecRequest) -> ExecResult:
    return ExecResult(exit_code=0, stdout=b"hello\n")


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'query_guard_r59.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))
    driver = application.state.driver
    assert isinstance(driver, FakeDriver)
    driver.exec_handler = _exec_handler
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
async def org(app: FastAPI) -> Org:
    org = Org(id=new_org_id(), name="Guard", slug="guard-r59", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org


async def make_key(
    app: FastAPI, org: Org, name: str, scope: dict[str, str] | None = None
) -> tuple[str, dict[str, str]]:
    """A stored key with every scope; returns its id and the bearer header."""
    generated = generate_api_key(PEPPER)
    key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name=name,
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset(Scope),
        sandbox_labels=scope,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(key)
        await uow.commit()
    return key.id, {"Authorization": f"Bearer {generated.key}"}


@pytest.fixture
async def headers(app: FastAPI, org: Org) -> dict[str, str]:
    return (await make_key(app, org, "open"))[1]


@pytest.fixture
async def scoped(app: FastAPI, org: Org) -> dict[str, str]:
    return (await make_key(app, org, "scoped", TEAM_A))[1]


async def new_sandbox(client: httpx.AsyncClient, headers: dict[str, str], **payload: Any) -> str:
    response = await client.post(SANDBOXES, json=payload, headers=headers)
    assert response.status_code == CREATED_STATUS, response.text
    sandbox_id: str = response.json()["data"]["id"]
    return sandbox_id


@pytest.fixture
async def targets(client: httpx.AsyncClient, headers: dict[str, str]) -> Targets:
    sandbox_id = await new_sandbox(client, headers)
    base = f"{SANDBOXES}/{sandbox_id}/toolbox/process/sessions"
    session = await client.post(base, json={}, headers=headers)
    assert session.status_code == CREATED_STATUS, session.text
    session_id: str = session.json()["data"]["id"]
    started = await client.post(
        f"{base}/{session_id}/commands",
        params={"async": "true"},
        json={"command": "echo hello"},
        headers=headers,
    )
    assert started.status_code == ACCEPTED_STATUS, started.text
    command_id: str = started.json()["data"]["command"]["id"]
    found = Targets(sandbox_id, session_id, command_id)
    for _ in range(300):
        status = await client.get(f"{found.commands}/{command_id}", headers=headers)
        if status.json()["data"]["state"] == "exited":
            return found
        await asyncio.sleep(0.01)
    raise AssertionError("the async command never exited")


async def new_volume(
    client: httpx.AsyncClient, headers: dict[str, str], name: str, labels: dict[str, str]
) -> str:
    response = await client.post(VOLUMES, json={"name": name, "labels": labels}, headers=headers)
    assert response.status_code == CREATED_STATUS, response.text
    volume_id: str = response.json()["data"]["id"]
    return volume_id


def _repeated(name: str, *values: str) -> Pairs:
    return [(name, value) for value in values]


def _assert_repeat_refused(response: httpx.Response, name: str) -> None:
    assert response.status_code == VALIDATION_STATUS, response.text
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert f"{name} must be given once" in response.text


def _assert_unknown_refused(response: httpx.Response, name: str) -> None:
    assert response.status_code == VALIDATION_STATUS, response.text
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert f"`{name}`" in error["message"]
    assert error["details"]["errors"][0]["loc"] == ["query", name]


# --- GET sandbox by id ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "values"), [("wait_for", ("started", "stopped")), ("timeout_s", ("1", "2"))]
)
async def test_get_sandbox_with_a_repeated_parameter_answers_422(
    client: httpx.AsyncClient, headers: dict[str, str], name: str, values: tuple[str, ...]
) -> None:
    sandbox_id = await new_sandbox(client, headers)

    response = await client.get(
        f"{SANDBOXES}/{sandbox_id}", params=_repeated(name, *values), headers=headers
    )

    _assert_repeat_refused(response, name)


async def test_get_sandbox_with_single_values_still_works(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    sandbox_id = await new_sandbox(client, headers)
    path = f"{SANDBOXES}/{sandbox_id}"
    both = {"wait_for": "started", "timeout_s": "1"}

    timed = await client.get(path, params={"timeout_s": "1"}, headers=headers)
    waited = await client.get(path, params=both, headers=headers)

    assert timed.status_code == OK_STATUS, timed.text
    assert waited.status_code == OK_STATUS, waited.text


# --- command log and follow routes ------------------------------------------------------------


@pytest.mark.parametrize("name", ["offset", "limit"])
async def test_command_logs_with_a_repeated_parameter_answers_422(
    client: httpx.AsyncClient, headers: dict[str, str], targets: Targets, name: str
) -> None:
    response = await client.get(targets.logs, params=_repeated(name, "1", "2"), headers=headers)

    _assert_repeat_refused(response, name)


async def test_command_logs_with_single_values_still_work(
    client: httpx.AsyncClient, headers: dict[str, str], targets: Targets
) -> None:
    params = {"offset": "0", "limit": "1024"}

    response = await client.get(targets.logs, params=params, headers=headers)

    assert response.status_code == OK_STATUS, response.text
    assert response.json()["data"]["complete"] is True


async def test_command_follow_with_a_repeated_offset_answers_422(
    client: httpx.AsyncClient, headers: dict[str, str], targets: Targets
) -> None:
    response = await client.get(
        f"{targets.logs}/follow", params=_repeated("offset", "0", "1"), headers=headers
    )

    _assert_repeat_refused(response, "offset")


async def test_command_follow_with_a_single_offset_still_streams(
    client: httpx.AsyncClient, headers: dict[str, str], targets: Targets
) -> None:
    response = await client.get(f"{targets.logs}/follow", params={"offset": "0"}, headers=headers)

    assert response.status_code == OK_STATUS, response.text
    assert "event: exit" in response.text


# --- org usage --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "values"),
    [
        ("from", ("2026-11-01T00:00:00Z", "2026-10-01T00:00:00Z")),
        ("to", ("2026-11-08T00:00:00Z", "2026-11-09T00:00:00Z")),
        ("group_by", ("sandbox", "sandbox")),
    ],
)
async def test_usage_with_a_repeated_parameter_answers_422(
    client: httpx.AsyncClient, headers: dict[str, str], name: str, values: tuple[str, ...]
) -> None:
    params: Pairs = [(key, value) for key, value in WINDOW.items() if key != name]
    params.extend(_repeated(name, *values))

    response = await client.get(USAGE, params=params, headers=headers)

    _assert_repeat_refused(response, name)


async def test_usage_with_single_values_still_works(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    plain = await client.get(USAGE, params=WINDOW, headers=headers)
    grouped = await client.get(USAGE, params={**WINDOW, "group_by": "sandbox"}, headers=headers)

    assert plain.status_code == OK_STATUS, plain.text
    assert grouped.status_code == OK_STATUS, grouped.text


# --- session command route (async flag) -------------------------------------------------------


async def test_session_command_with_a_repeated_async_flag_answers_422(
    client: httpx.AsyncClient, headers: dict[str, str], targets: Targets
) -> None:
    response = await client.post(
        targets.commands,
        params=_repeated("async", "true", "false"),
        json={"command": "echo hello"},
        headers=headers,
    )

    _assert_repeat_refused(response, "async")


async def test_session_command_with_a_single_async_flag_still_works(
    client: httpx.AsyncClient, headers: dict[str, str], targets: Targets
) -> None:
    body = {"command": "echo hello"}

    started = await client.post(
        targets.commands, params={"async": "true"}, json=body, headers=headers
    )
    plain = await client.post(targets.commands, json=body, headers=headers)

    assert started.status_code == ACCEPTED_STATUS, started.text
    assert plain.status_code == OK_STATUS, plain.text


# --- key revoke route -------------------------------------------------------------------------


async def test_revoke_with_a_repeated_cascade_answers_422_and_revokes_nothing(
    app: FastAPI, client: httpx.AsyncClient, org: Org, headers: dict[str, str]
) -> None:
    victim_id, _ = await make_key(app, org, "victim")

    response = await client.delete(
        f"{API_KEYS}/{victim_id}", params=_repeated("cascade", "true", "false"), headers=headers
    )
    listed = await client.get(API_KEYS, params={"status": "revoked"}, headers=headers)

    _assert_repeat_refused(response, "cascade")
    assert listed.json()["data"] == []


@pytest.mark.parametrize("name", ["Cascade", "casade", "CASCADE"])
async def test_revoke_with_an_unknown_query_name_answers_422_and_revokes_nothing(
    app: FastAPI, client: httpx.AsyncClient, org: Org, headers: dict[str, str], name: str
) -> None:
    victim_id, _ = await make_key(app, org, "victim")

    response = await client.delete(
        f"{API_KEYS}/{victim_id}", params={name: "true"}, headers=headers
    )
    listed = await client.get(API_KEYS, params={"status": "revoked"}, headers=headers)

    _assert_unknown_refused(response, name)
    assert listed.json()["data"] == []


async def test_revoke_with_a_single_cascade_still_works(
    app: FastAPI, client: httpx.AsyncClient, org: Org, headers: dict[str, str]
) -> None:
    victim_id, _ = await make_key(app, org, "victim")

    response = await client.delete(
        f"{API_KEYS}/{victim_id}", params={"cascade": "true"}, headers=headers
    )

    assert response.status_code == OK_STATUS, response.text


# --- unknown names on the other touched routes ------------------------------------------------


async def test_unknown_query_names_answer_422_on_the_touched_routes(
    client: httpx.AsyncClient, headers: dict[str, str], targets: Targets
) -> None:
    gets = [
        (f"{SANDBOXES}/{targets.sandbox_id}", {"bogus": "1"}),
        (targets.logs, {"bogus": "1"}),
        (f"{targets.logs}/follow", {"bogus": "1"}),
        (USAGE, {**WINDOW, "bogus": "1"}),
    ]
    for path, params in gets:
        _assert_unknown_refused(await client.get(path, params=params, headers=headers), "bogus")

    posted = await client.post(
        targets.commands, params={"asnyc": "true"}, json={"command": "echo hi"}, headers=headers
    )

    _assert_unknown_refused(posted, "asnyc")


# --- volume delete 409: only visible sandbox ids ----------------------------------------------


async def _delete_conflict(
    client: httpx.AsyncClient, caller: dict[str, str], volume_id: str
) -> dict[str, Any]:
    response = await client.delete(f"{VOLUMES}/{volume_id}", headers=caller)
    assert response.status_code == CONFLICT_STATUS, response.text
    body: dict[str, Any] = response.json()
    error: dict[str, Any] = body["error"]
    return error


async def test_conflict_names_a_visible_sandbox_and_no_hidden_count(
    client: httpx.AsyncClient, headers: dict[str, str], scoped: dict[str, str]
) -> None:
    volume_id = await new_volume(client, headers, "shared", TEAM_A)
    mount = [{"volume_id": volume_id, "mount_path": "/data"}]
    visible = await new_sandbox(client, headers, labels=TEAM_A, volumes=mount)

    error = await _delete_conflict(client, scoped, volume_id)

    assert error["details"] == {"reason": "in_use", "sandbox_id": visible}
    assert visible in error["message"]


async def test_conflict_counts_hidden_sandboxes_without_naming_them(
    client: httpx.AsyncClient, headers: dict[str, str], scoped: dict[str, str]
) -> None:
    volume_id = await new_volume(client, headers, "shared", TEAM_A)
    mount = [{"volume_id": volume_id, "mount_path": "/data"}]
    hidden = await new_sandbox(client, headers, labels=TEAM_B, volumes=mount)

    error = await _delete_conflict(client, scoped, volume_id)

    assert error["details"] == {"reason": "in_use", "hidden_sandboxes": 1}
    assert hidden not in str(error)


async def test_conflict_with_visible_and_hidden_sandboxes_names_only_the_visible_one(
    client: httpx.AsyncClient, headers: dict[str, str], scoped: dict[str, str]
) -> None:
    volume_id = await new_volume(client, headers, "shared", TEAM_A)
    mount = [{"volume_id": volume_id, "mount_path": "/data"}]
    hidden = await new_sandbox(client, headers, labels=TEAM_B, volumes=mount)
    visible = await new_sandbox(client, headers, labels=TEAM_A, volumes=mount)

    error = await _delete_conflict(client, scoped, volume_id)

    assert error["details"] == {"reason": "in_use", "sandbox_id": visible, "hidden_sandboxes": 1}
    assert hidden not in str(error)


async def test_unscoped_conflict_names_the_sandbox_and_has_no_hidden_count(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    volume_id = await new_volume(client, headers, "shared", TEAM_A)
    mount = [{"volume_id": volume_id, "mount_path": "/data"}]
    user = await new_sandbox(client, headers, labels=TEAM_B, volumes=mount)

    error = await _delete_conflict(client, headers, volume_id)

    assert error["details"] == {"reason": "in_use", "sandbox_id": user}
