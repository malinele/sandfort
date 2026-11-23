"""A label-scoped key cannot read a hidden sandbox's session, command or pty records.

Five toolbox GET routes look records up by id without loading the sandbox; the router-level
``require_visible_sandbox`` guard makes them answer 404 like every other toolbox route. Through
the API on the fake driver and a temp SQLite database, on Starlette's ``TestClient`` because the
pty websocket needs it.
"""

import time
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from starlette.testclient import TestClient

from sandfort.api.app import create_app
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
RED = {"team": "red"}
BLUE = {"team": "blue"}
MISSING_SANDBOX_ID = "sbx_doesnotexist"
FINISH_POLLS = 200
FINISH_POLL_S = 0.05


@dataclass(frozen=True)
class Records:
    """One sandbox with an exec session, a finished async command and an open pty."""

    sandbox_id: str
    session_id: str
    command_id: str
    pty: dict[str, Any]

    def get_paths(self, sandbox_id: str | None = None) -> list[str]:
        """The five GET routes, addressed through ``sandbox_id`` (default: the owner)."""
        root = f"{BASE}/{sandbox_id or self.sandbox_id}/toolbox"
        session = f"{root}/process/sessions/{self.session_id}"
        command_path = f"{session}/commands/{self.command_id}"
        return [
            session,
            command_path,
            f"{command_path}/logs",
            f"{command_path}/logs/follow",
            f"{root}/pty/{self.pty['pty_id']}",
        ]


# --- fixtures ---------------------------------------------------------------------


@pytest.fixture
def app(tmp_path: Path) -> FastAPI:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'toolbox-scope.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    return create_app(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:  # lifespan disposes the engine on exit
        yield test_client


def run[T](client: TestClient, func: Callable[..., Awaitable[T]], *args: Any) -> T:
    """Run a coroutine function on the TestClient's event loop."""
    portal = client.portal
    assert portal is not None
    return portal.call(func, *args)


async def add_org(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def add_key(app: FastAPI, org_id: str, labels: dict[str, str] | None) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=FULL_ACCESS,
        created_at=NOW,
        sandbox_labels=labels,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


@pytest.fixture
def org_id(app: FastAPI, client: TestClient) -> str:
    return run(client, add_org, app)


@pytest.fixture
def unscoped(app: FastAPI, client: TestClient, org_id: str) -> str:
    return run(client, add_key, app, org_id, None)


@pytest.fixture
def red(app: FastAPI, client: TestClient, org_id: str) -> str:
    return run(client, add_key, app, org_id, RED)


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def send(
    client: TestClient, method: str, path: str, key: str, *, status: int, **kwargs: Any
) -> dict[str, Any]:
    response = client.request(method, path, headers=auth(key), **kwargs)
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    assert body["success"] is (status < 400)
    return body


def build_records(client: TestClient, key: str, **sandbox: Any) -> Records:
    """Create a sandbox and its session, command (waited until finished) and pty with ``key``."""
    sandbox_id = send(client, "POST", BASE, key, status=201, json=sandbox)["data"]["id"]
    root = f"{BASE}/{sandbox_id}/toolbox"
    sessions = f"{root}/process/sessions"
    session_id = send(client, "POST", sessions, key, status=201, json={})["data"]["id"]
    started = send(
        client,
        "POST",
        f"{sessions}/{session_id}/commands?async=true",
        key,
        status=202,
        json={"command": "echo hi"},
    )
    command_id = started["data"]["command"]["id"]
    wait_until_finished(client, key, f"{sessions}/{session_id}/commands/{command_id}")
    pty = send(client, "POST", f"{root}/pty", key, status=201, json={})["data"]
    return Records(sandbox_id, session_id, command_id, pty)


def wait_until_finished(client: TestClient, key: str, status_path: str) -> None:
    """Poll until the async command left ``running``, so the log follow stream ends."""
    for _ in range(FINISH_POLLS):
        if send(client, "GET", status_path, key, status=200)["data"]["state"] != "running":
            return
        time.sleep(FINISH_POLL_S)
    pytest.fail("the async command did not finish")


@pytest.fixture
def blue(client: TestClient, unscoped: str) -> Records:
    """Records of a team=blue sandbox, all created by the unscoped key."""
    return build_records(client, unscoped, labels=BLUE)


def comparable(error: dict[str, Any], sandbox_id: str, placeholder: str) -> dict[str, Any]:
    """The error without its per-request id, the sandbox id in the message replaced."""
    return {
        "code": error["code"],
        "message": error["message"].replace(sandbox_id, placeholder),
        "details": error["details"],
    }


# --- the five routes --------------------------------------------------------------


def test_red_key_gets_the_not_found_of_a_missing_sandbox_on_blue_records(
    client: TestClient, red: str, blue: Records
) -> None:
    hidden = blue.get_paths()
    missing = blue.get_paths(MISSING_SANDBOX_ID)

    for hidden_path, missing_path in zip(hidden, missing, strict=True):
        refused = send(client, "GET", hidden_path, red, status=404)
        absent = send(client, "GET", missing_path, red, status=404)

        assert blue.sandbox_id in refused["error"]["message"]
        assert comparable(refused["error"], blue.sandbox_id, "<id>") == comparable(
            absent["error"], MISSING_SANDBOX_ID, "<id>"
        ), hidden_path


def test_red_key_still_reads_the_records_of_its_own_sandbox(client: TestClient, red: str) -> None:
    own = build_records(client, red)

    for path in own.get_paths():
        response = client.get(path, headers=auth(red))
        assert response.status_code == 200, path


def test_unscoped_key_still_reads_blue_records(
    client: TestClient, unscoped: str, blue: Records
) -> None:
    for path in blue.get_paths():
        response = client.get(path, headers=auth(unscoped))
        assert response.status_code == 200, path


# --- the websocket ----------------------------------------------------------------


def test_pty_websocket_connect_with_a_valid_token_needs_no_key(
    client: TestClient, blue: Records
) -> None:
    created = blue.pty
    url = f"{BASE}/{blue.sandbox_id}/toolbox/pty/{created['pty_id']}/connect"

    with client.websocket_connect(f"{url}?token={created['token']}") as ws:
        ws.send_bytes(b"echo hi\n")
        assert ws.receive_bytes() == b"echo hi\n"
