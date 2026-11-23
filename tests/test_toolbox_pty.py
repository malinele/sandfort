"""Interactive terminals over FakeDriver: REST routes, the websocket bridge and connect tokens.

Daemon-free: temp SQLite and Starlette's ``TestClient``, whose websocket support drives the
bridge. Everything runs on the TestClient's event loop (setup coroutines go through its
portal), so the fake terminal's queue and the database pool see a single loop. Routes are only
exercised through HTTP and websocket traffic, never by inspecting route tables.
"""

import json
from collections.abc import Awaitable, Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from sandfort.api.app import create_app
from sandfort.api.routes.toolbox import pty as pty_routes
from sandfort.api.wiring import CONNECT_TOKENS_ATTR, PTY_REGISTRY_ATTR
from sandfort.auth.api_keys import generate_api_key
from sandfort.auth.connect_tokens import ConnectTokenInvalid, InMemoryConnectTokenStore
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import AuditEvent
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.drivers.base import PtySessionHandle
from sandfort.drivers.errors import DriverConflict
from sandfort.drivers.fake import FakeDriver, FakePty
from sandfort.errors import CapacityExceeded
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.toolbox.pty import LivePty, PtyRegistry

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
UNAUTHORIZED_CLOSE = 4401
NORMAL_CLOSE = 1000


# --- fixtures ---------------------------------------------------------------------


@pytest.fixture
def app(tmp_path: Path, request: pytest.FixtureRequest) -> FastAPI:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'pty.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    overrides: dict[str, Any] = getattr(request, "param", {})  # indirect settings overrides
    return create_app(
        Settings(driver="fake", database_url=url, api_key_pepper=PEPPER, **overrides)
    )


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:  # lifespan disposes the engine on exit
        yield test_client


def run[T](client: TestClient, func: Callable[..., Awaitable[T]], *args: Any) -> T:
    """Run a coroutine function on the TestClient's event loop."""
    portal = client.portal
    assert portal is not None
    return portal.call(func, *args)


async def add_org(app: FastAPI, slug: str) -> str:
    org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def add_key(app: FastAPI, org_id: str, scopes: frozenset[Scope]) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=scopes,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


async def list_audit(app: FastAPI, org_id: str) -> list[AuditEvent]:
    async with UnitOfWork(app.state.session_factory) as uow:
        return list(await uow.audit.list(org_id, limit=200))


@pytest.fixture
def org_id(app: FastAPI, client: TestClient) -> str:
    return run(client, add_org, app, "acme")


@pytest.fixture
def key(app: FastAPI, client: TestClient, org_id: str) -> str:
    return run(client, add_key, app, org_id, FULL_ACCESS)


@pytest.fixture
def driver(app: FastAPI) -> FakeDriver:
    fake = app.state.driver
    assert isinstance(fake, FakeDriver)
    return fake


@pytest.fixture
def registry(app: FastAPI) -> PtyRegistry:
    live = app.state.pty_registry
    assert isinstance(live, PtyRegistry)
    return live


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


def create_sandbox(client: TestClient, key: str) -> str:
    body = send(client, "POST", BASE, key, status=201, json={})
    sandbox_id: str = body["data"]["id"]
    return sandbox_id


def pty_path(sandbox_id: str, *parts: str) -> str:
    return "/".join([f"{BASE}/{sandbox_id}/toolbox/pty", *parts])


def create_pty(client: TestClient, key: str, sandbox_id: str, **payload: Any) -> dict[str, Any]:
    body = send(client, "POST", pty_path(sandbox_id), key, status=201, json=payload)
    data: dict[str, Any] = body["data"]
    return data


def connect_url(sandbox_id: str, created: dict[str, Any], token: str | None = None) -> str:
    path = pty_path(sandbox_id, created["pty_id"], "connect")
    return f"{path}?token={token or created['token']}"


def assert_rejected(client: TestClient, url: str) -> None:
    with client.websocket_connect(url) as ws, pytest.raises(WebSocketDisconnect) as closed:
        ws.receive_bytes()
    assert closed.value.code == UNAUTHORIZED_CLOSE


def fake_pty(driver: FakeDriver, registry: PtyRegistry, pty_id: str) -> FakePty:
    live = registry.get(pty_id)
    assert live is not None
    return driver._get_pty(live.handle)


# --- registry unit ----------------------------------------------------------------


def test_registry_scopes_live_terminals_by_org_and_sandbox() -> None:
    registry = PtyRegistry()
    registry.add(LivePty("org_a", "sbx_1", "pty_1", PtySessionHandle("h1")))
    registry.add(LivePty("org_a", "sbx_2", "pty_2", PtySessionHandle("h2")))
    registry.add(LivePty("org_b", "sbx_1", "pty_3", PtySessionHandle("h3")))

    assert [live.pty_id for live in registry.for_sandbox("org_a", "sbx_1")] == ["pty_1"]
    assert registry.pop("pty_1") is not None
    assert registry.pop("pty_1") is None
    assert len(registry) == 2


def test_registry_caps_terminals_per_org_and_zero_lifts_the_cap() -> None:
    registry = PtyRegistry(max_per_org=2)
    registry.reserve("org_a", "pty_1")
    registry.add(LivePty("org_a", "sbx_1", "pty_2", PtySessionHandle("h2")))

    with pytest.raises(CapacityExceeded):
        registry.reserve("org_a", "pty_3")
    registry.reserve("org_b", "pty_4")  # the cap is per org
    registry.pop("pty_1")
    registry.reserve("org_a", "pty_3")  # popping gave the slot back
    unlimited = PtyRegistry(max_per_org=0)
    for index in range(20):
        unlimited.reserve("org_a", f"pty_{index}")


def test_caps_default_to_eight_and_sixteen_and_load_from_the_environment() -> None:
    defaults = Settings()
    loaded = Settings.from_env(
        {"SANDFORT_MAX_PTYS_PER_ORG": "0", "SANDFORT_MAX_ASYNC_COMMANDS_PER_ORG": "3"}
    )

    assert (defaults.max_ptys_per_org, defaults.max_async_commands_per_org) == (8, 16)
    assert (loaded.max_ptys_per_org, loaded.max_async_commands_per_org) == (0, 3)
    with pytest.raises(ValueError, match="MAX_PTYS_PER_ORG"):
        Settings.from_env({"SANDFORT_MAX_PTYS_PER_ORG": "-1"})


# --- create, websocket echo, resize -------------------------------------------------


def test_create_returns_token_and_websocket_echoes_bytes(
    client: TestClient, key: str, registry: PtyRegistry
) -> None:
    sandbox_id = create_sandbox(client, key)

    created = create_pty(client, key, sandbox_id, rows=30, cols=100)

    pty_id = created["pty_id"]
    assert pty_id.startswith("pty_") and created["token"]
    expected_path = pty_path(sandbox_id, pty_id, "connect")
    assert created["websocket_url"] == f"ws://testserver{expected_path}"
    detail = send(client, "GET", pty_path(sandbox_id, pty_id), key, status=200)["data"]
    assert (detail["state"], detail["rows"], detail["cols"]) == ("open", 30, 100)
    with client.websocket_connect(connect_url(sandbox_id, created)) as ws:
        ws.send_bytes(b"echo hi\n")
        assert ws.receive_bytes() == b"echo hi\n"
        ws.send_text("ls\n")
        assert ws.receive_bytes() == b"ls\n"
    # the client went away and its spent token cannot reattach: the terminal is torn down
    assert len(registry) == 0
    closed = send(client, "GET", pty_path(sandbox_id, pty_id), key, status=200)["data"]
    assert closed["state"] == "closed"


def test_server_closes_the_websocket_normally_when_the_pty_ends(
    client: TestClient, key: str
) -> None:
    sandbox_id = create_sandbox(client, key)
    created = create_pty(client, key, sandbox_id)

    with client.websocket_connect(connect_url(sandbox_id, created)) as ws:
        ws.send_bytes(b"x")
        assert ws.receive_bytes() == b"x"
        body = send(client, "DELETE", pty_path(sandbox_id, created["pty_id"]), key, status=200)
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_bytes()

    assert body["data"]["state"] == "closed"
    assert closed.value.code == NORMAL_CLOSE


def report_exit_codes(
    monkeypatch: pytest.MonkeyPatch, *codes: int | None
) -> list[PtySessionHandle]:
    """Give the fake driver the exit code capability: each read yields the next of ``codes``."""
    queue = list(codes)
    reads: list[PtySessionHandle] = []

    async def pty_exit_code(self: FakeDriver, handle: PtySessionHandle) -> int | None:
        reads.append(handle)
        return queue.pop(0) if len(queue) > 1 else queue[0]

    monkeypatch.setattr(FakeDriver, "pty_exit_code", pty_exit_code, raising=False)
    return reads


def close_code_after_the_terminal_ends(client: TestClient, key: str) -> int:
    sandbox_id = create_sandbox(client, key)
    created = create_pty(client, key, sandbox_id)
    with client.websocket_connect(connect_url(sandbox_id, created)) as ws:
        ws.send_bytes(b"x")
        assert ws.receive_bytes() == b"x"
        send(client, "DELETE", pty_path(sandbox_id, created["pty_id"]), key, status=200)
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_bytes()
    return closed.value.code


@pytest.mark.parametrize(
    ("exit_code", "expected"),
    [(3, 4003), (0, 4000), (255, 4255), (256, NORMAL_CLOSE), (-1, NORMAL_CLOSE)],
)
def test_server_closes_with_4000_plus_the_exit_code_of_the_ended_terminal(
    client: TestClient, key: str, monkeypatch: pytest.MonkeyPatch, exit_code: int, expected: int
) -> None:
    reads = report_exit_codes(monkeypatch, exit_code)

    assert close_code_after_the_terminal_ends(client, key) == expected
    assert len(reads) == 1


def test_server_retries_until_the_exit_code_is_recorded(
    client: TestClient, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pty_routes, "EXIT_CODE_POLL_S", 0.01)
    reads = report_exit_codes(monkeypatch, None, None, 5)

    assert close_code_after_the_terminal_ends(client, key) == pty_routes.PTY_EXIT_CLOSE_BASE + 5
    assert len(reads) == 3


def test_server_closes_normally_when_the_exit_code_stays_unknown(
    client: TestClient, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pty_routes, "EXIT_CODE_WAIT_S", 0.1)
    monkeypatch.setattr(pty_routes, "EXIT_CODE_POLL_S", 0.01)
    reads = report_exit_codes(monkeypatch, None)

    assert close_code_after_the_terminal_ends(client, key) == NORMAL_CLOSE
    assert len(reads) > 1  # it tried more than once before giving up


def test_server_closes_normally_without_waiting_when_the_driver_lacks_the_capability(
    client: TestClient, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pty_routes, "EXIT_CODE_WAIT_S", 30.0)  # would time the test out if waited

    assert not hasattr(FakeDriver, "pty_exit_code")
    assert close_code_after_the_terminal_ends(client, key) == NORMAL_CLOSE


def test_server_ignores_the_exit_code_when_the_client_goes_away(
    client: TestClient, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    reads = report_exit_codes(monkeypatch, 3)
    sandbox_id = create_sandbox(client, key)
    created = create_pty(client, key, sandbox_id)

    with client.websocket_connect(connect_url(sandbox_id, created)) as ws:
        ws.send_bytes(b"x")
        assert ws.receive_bytes() == b"x"

    assert reads == []


def test_resize_propagates_to_the_fake_handle_and_the_row(
    client: TestClient, key: str, driver: FakeDriver, registry: PtyRegistry
) -> None:
    sandbox_id = create_sandbox(client, key)
    pty_id = create_pty(client, key, sandbox_id)["pty_id"]
    handle = fake_pty(driver, registry, pty_id)
    assert (handle.rows, handle.cols) == (24, 80)

    body = send(
        client,
        "POST",
        pty_path(sandbox_id, pty_id, "resize"),
        key,
        status=200,
        json={"rows": 33, "cols": 107},
    )

    assert (body["data"]["rows"], body["data"]["cols"]) == (33, 107)
    assert (handle.rows, handle.cols) == (33, 107)
    detail = send(client, "GET", pty_path(sandbox_id, pty_id), key, status=200)["data"]
    assert (detail["rows"], detail["cols"], detail["state"]) == (33, 107, "open")


def test_resize_of_a_closed_pty_conflicts(client: TestClient, key: str) -> None:
    sandbox_id = create_sandbox(client, key)
    pty_id = create_pty(client, key, sandbox_id)["pty_id"]
    send(client, "DELETE", pty_path(sandbox_id, pty_id), key, status=200)

    body = send(
        client,
        "POST",
        pty_path(sandbox_id, pty_id, "resize"),
        key,
        status=409,
        json={"rows": 10, "cols": 10},
    )

    assert body["error"]["code"] == "CONFLICT"


def test_create_rejects_reserved_env(client: TestClient, key: str) -> None:
    sandbox_id = create_sandbox(client, key)

    body = send(
        client, "POST", pty_path(sandbox_id), key, status=422, json={"env": {"SANDFORT_X": "1"}}
    )

    assert body["error"]["code"] == "UNPROCESSABLE"


def test_driver_failure_on_create_closes_the_row(
    client: TestClient,
    key: str,
    driver: FakeDriver,
    registry: PtyRegistry,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def refuse(*args: Any, **kwargs: Any) -> PtySessionHandle:
        raise DriverConflict("no tty available")

    monkeypatch.setattr(driver, "create_pty", refuse)
    sandbox_id = create_sandbox(client, key)

    send(client, "POST", pty_path(sandbox_id), key, status=409, json={})

    listing = send(client, "GET", pty_path(sandbox_id), key, status=200)["data"]
    assert [item["state"] for item in listing] == ["closed"]
    assert len(registry) == 0


# --- connect tokens -----------------------------------------------------------------


def test_connect_token_is_single_use(client: TestClient, key: str) -> None:
    sandbox_id = create_sandbox(client, key)
    created = create_pty(client, key, sandbox_id)
    url = connect_url(sandbox_id, created)

    with client.websocket_connect(url) as first:
        first.send_bytes(b"a")
        assert first.receive_bytes() == b"a"
        assert_rejected(client, url)
        first.send_bytes(b"b")  # the first bridge is unaffected
        assert first.receive_bytes() == b"b"


def test_expired_connect_token_is_rejected(app: FastAPI, client: TestClient, key: str) -> None:
    clock = FrozenClock(NOW)
    store = InMemoryConnectTokenStore(clock=clock, ttl=timedelta(seconds=30))
    setattr(app.state, CONNECT_TOKENS_ATTR, store)
    sandbox_id = create_sandbox(client, key)
    created = create_pty(client, key, sandbox_id)

    clock.advance(timedelta(seconds=30))

    assert_rejected(client, connect_url(sandbox_id, created))


def test_garbage_missing_and_misdirected_tokens_are_rejected(
    client: TestClient, key: str
) -> None:
    sandbox_id = create_sandbox(client, key)
    first = create_pty(client, key, sandbox_id)
    second = create_pty(client, key, sandbox_id)

    assert_rejected(client, connect_url(sandbox_id, first, token="garbage"))
    assert_rejected(client, pty_path(sandbox_id, first["pty_id"], "connect"))
    # a real token presented for another terminal is refused and spent
    assert_rejected(client, connect_url(sandbox_id, second, token=first["token"]))
    assert_rejected(client, connect_url(sandbox_id, first))


async def test_a_later_mint_sweeps_expired_connect_tokens() -> None:
    clock = FrozenClock(NOW)
    store = InMemoryConnectTokenStore(clock=clock, ttl=timedelta(seconds=30))
    stale = await store.mint("org_a", "sbx_1", "pty_1")
    clock.advance(timedelta(seconds=30))
    assert len(store) == 1

    fresh = await store.mint("org_a", "sbx_1", "pty_2")

    assert len(store) == 1
    assert await store.pending_pty_ids() == frozenset({"pty_2"})
    with pytest.raises(ConnectTokenInvalid):
        await store.redeem(stale)
    assert (await store.redeem(fresh)).pty_id == "pty_2"


# --- per-org terminal cap and reaping -----------------------------------------------


def test_ninth_terminal_is_refused_while_another_org_can_still_create(
    app: FastAPI, client: TestClient, key: str
) -> None:
    sandbox_id = create_sandbox(client, key)
    for _ in range(8):
        create_pty(client, key, sandbox_id)

    refused = send(client, "POST", pty_path(sandbox_id), key, status=503, json={})

    assert refused["error"]["code"] == "CAPACITY"
    listing = send(client, "GET", pty_path(sandbox_id), key, status=200)["data"]
    assert [item["state"] for item in listing] == ["open"] * 8  # the refusal wrote no row
    other = run(client, add_key, app, run(client, add_org, app, "globex"), FULL_ACCESS)
    assert create_pty(client, other, create_sandbox(client, other))["pty_id"]


@pytest.mark.parametrize("app", [{"max_ptys_per_org": 0}], indirect=True)
def test_a_zero_terminal_cap_admits_a_ninth_terminal(client: TestClient, key: str) -> None:
    sandbox_id = create_sandbox(client, key)

    created = [create_pty(client, key, sandbox_id) for _ in range(9)]

    assert len({item["pty_id"] for item in created}) == 9


def test_unconnected_terminal_is_reaped_once_its_token_lapses(
    app: FastAPI, client: TestClient, key: str, driver: FakeDriver
) -> None:
    clock = FrozenClock(NOW)
    store = InMemoryConnectTokenStore(clock=clock, ttl=timedelta(seconds=30))
    registry = PtyRegistry(max_per_org=2)
    setattr(app.state, CONNECT_TOKENS_ATTR, store)
    setattr(app.state, PTY_REGISTRY_ATTR, registry)
    sandbox_id = create_sandbox(client, key)
    idle = create_pty(client, key, sandbox_id)
    bridged = create_pty(client, key, sandbox_id)
    idle_terminal = fake_pty(driver, registry, idle["pty_id"])

    with client.websocket_connect(connect_url(sandbox_id, bridged)) as ws:
        ws.send_bytes(b"x")
        assert ws.receive_bytes() == b"x"
        send(client, "POST", pty_path(sandbox_id), key, status=503, json={})  # both slots held
        clock.advance(timedelta(seconds=30))
        fresh = create_pty(client, key, sandbox_id)  # reaps the idle terminal, takes its slot
        ws.send_bytes(b"y")
        assert ws.receive_bytes() == b"y"  # the bridged terminal is never reaped

    assert idle_terminal.exit_code is not None
    assert registry.get(idle["pty_id"]) is None
    assert registry.get(fresh["pty_id"]) is not None
    detail = send(client, "GET", pty_path(sandbox_id, idle["pty_id"]), key, status=200)["data"]
    assert detail["state"] == "closed"
    assert_rejected(client, connect_url(sandbox_id, idle))


# --- sandbox stop -------------------------------------------------------------------


def test_stopping_the_sandbox_closes_live_ptys(
    client: TestClient, key: str, driver: FakeDriver, registry: PtyRegistry
) -> None:
    sandbox_id = create_sandbox(client, key)
    first = create_pty(client, key, sandbox_id)
    second = create_pty(client, key, sandbox_id)
    terminals = [fake_pty(driver, registry, item["pty_id"]) for item in (first, second)]
    assert len(registry) == 2

    with client.websocket_connect(connect_url(sandbox_id, first)) as ws:
        ws.send_bytes(b"x")
        assert ws.receive_bytes() == b"x"
        stopped = send(client, "POST", f"{BASE}/{sandbox_id}/stop", key, status=200)
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_bytes()

    assert stopped["data"]["state"] == "stopped"
    assert closed.value.code == NORMAL_CLOSE
    assert len(registry) == 0
    assert all(terminal.exit_code is not None for terminal in terminals)
    listing = send(client, "GET", pty_path(sandbox_id), key, status=200)["data"]
    assert sorted(item["state"] for item in listing) == ["closed", "closed"]


# --- access control and audit -------------------------------------------------------


def test_unauthenticated_rest_calls_are_rejected(client: TestClient) -> None:
    calls = [
        ("POST", pty_path("sbx_missing"), {}),
        ("GET", pty_path("sbx_missing"), None),
        ("POST", pty_path("sbx_missing", "pty_x", "resize"), {"rows": 1, "cols": 1}),
        ("DELETE", pty_path("sbx_missing", "pty_x"), None),
    ]
    for method, path, payload in calls:
        response = client.request(method, path, json=payload)
        assert response.status_code == 401, path
        assert response.json()["success"] is False


def test_another_orgs_sandbox_and_pty_are_not_found(
    app: FastAPI, client: TestClient, key: str
) -> None:
    sandbox_id = create_sandbox(client, key)
    pty_id = create_pty(client, key, sandbox_id)["pty_id"]
    other = run(client, add_key, app, run(client, add_org, app, "globex"), FULL_ACCESS)

    calls = [
        ("POST", pty_path(sandbox_id), {}),
        ("GET", pty_path(sandbox_id), None),
        ("GET", pty_path(sandbox_id, pty_id), None),
        ("POST", pty_path(sandbox_id, pty_id, "resize"), {"rows": 10, "cols": 10}),
        ("DELETE", pty_path(sandbox_id, pty_id), None),
    ]
    for method, path, payload in calls:
        body = send(client, method, path, other, status=404, json=payload)
        assert body["error"]["code"] == "NOT_FOUND", path
    detail = send(client, "GET", pty_path(sandbox_id, pty_id), key, status=200)["data"]
    assert detail["state"] == "open"


def test_actions_are_audited_without_terminal_content(
    app: FastAPI, client: TestClient, org_id: str, key: str
) -> None:
    sandbox_id = create_sandbox(client, key)
    created = create_pty(client, key, sandbox_id, env={"TOKEN": "hunter2"})
    pty_id = created["pty_id"]
    resize = {"rows": 40, "cols": 120}
    send(client, "POST", pty_path(sandbox_id, pty_id, "resize"), key, status=200, json=resize)
    with client.websocket_connect(connect_url(sandbox_id, created)) as ws:
        ws.send_bytes(b"SECRET-INPUT\n")
        assert ws.receive_bytes() == b"SECRET-INPUT\n"
    send(client, "DELETE", pty_path(sandbox_id, pty_id), key, status=200)

    events = run(client, list_audit, app, org_id)

    ordered = sorted(events, key=lambda event: event.occurred_at)
    pty_events = [e for e in ordered if e.action.startswith("toolbox.pty.")]
    assert [e.action for e in pty_events] == [
        "toolbox.pty.create",
        "toolbox.pty.resize",
        "toolbox.pty.close",
    ]
    assert all(e.target_id == sandbox_id for e in pty_events)
    assert all(e.details["pty_id"] == pty_id for e in pty_events)
    dumped = json.dumps([dict(e.details) for e in pty_events])
    for leaked in ("SECRET-INPUT", "hunter2", created["token"]):
        assert leaked not in dumped
