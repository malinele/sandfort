"""Phase 9 slice 6: terminal websockets forwarded from the edge node to the owner.

Same two-app idiom as ``test_routing_http.py`` (nodes ``alpha`` and ``beta``, one SQLite
database, one routing secret, a fake driver each), except that both apps are served by real
uvicorn servers on loopback ports: the websocket client dials alpha, alpha dials beta. A
recorder in front of beta logs every request or websocket that reaches it.
"""

import asyncio
import socket
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

from sandfort.api.app import create_app
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import MIN_SESSION_SECRET_CHARS, Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.node import Node
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.drivers.fake import FakeDriver, FakePty
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.routing.forward import FORWARDED_HEADER, ROUTE_TOKEN_HEADER
from sandfort.routing.tokens import verify_route_token

ROOT = Path(__file__).resolve().parents[1]
PEPPER = "test-pepper"
SECRET = "r" * MIN_SESSION_SECRET_CHARS
LOOPBACK = "127.0.0.1"
BASE = "/v1/sandboxes"
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
STARTUP_TIMEOUT_S = 5.0
DEADLINE_S = 10.0
POLL_S = 0.02
TRY_AGAIN_LATER = 1013
UNAUTHORIZED = 4401

type Seen = dict[str, Any]


class Recorder:
    """ASGI wrapper logging type, path and headers of every request that reaches the app."""

    def __init__(self, app: FastAPI, seen: list[Seen]) -> None:
        self.app = app
        self.seen = seen

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] in ("http", "websocket"):
            headers = {key.decode(): value.decode() for key, value in scope["headers"]}
            self.seen.append({"type": scope["type"], "path": scope["path"], "headers": headers})
        await self.app(scope, receive, send)


@dataclass
class Cluster:
    alpha: FastAPI
    beta: FastAPI
    alpha_client: httpx.AsyncClient
    auth: dict[str, str]
    sandbox_id: str  # owned by beta
    alpha_port: int
    beta_url: str
    seen: list[Seen] = field(default_factory=list)

    @property
    def toolbox(self) -> str:
        return f"{BASE}/{self.sandbox_id}/toolbox"

    async def create_pty(self) -> tuple[str, str]:
        """Create a terminal through alpha; returns its id and single-use connect token."""
        response = await self.alpha_client.post(f"{self.toolbox}/pty", headers=self.auth, json={})
        assert response.status_code == 201, response.text
        data = response.json()["data"]
        return data["pty_id"], data["token"]

    def ws_url(self, pty_id: str, token: str | None) -> str:
        query = f"?token={token}" if token else ""
        return f"ws://{LOOPBACK}:{self.alpha_port}{self.toolbox}/pty/{pty_id}/connect{query}"

    def beta_pty(self, pty_id: str) -> FakePty | None:
        live = self.beta.state.pty_registry.get(pty_id)
        driver = self.beta.state.driver
        assert isinstance(driver, FakeDriver)
        return None if live is None else driver._get_pty(live.handle)

    async def wait_until_beta_forgets(self, pty_id: str) -> None:
        async with asyncio.timeout(DEADLINE_S):
            while self.beta.state.pty_registry.get(pty_id) is not None:
                await asyncio.sleep(POLL_S)

    async def beat_beta(self, url: str) -> None:
        node = Node(id="beta", name="beta", last_heartbeat_at=datetime.now(UTC), internal_url=url)
        async with UnitOfWork(self.alpha.state.session_factory) as uow:
            await uow.nodes.upsert_heartbeat(node)
            await uow.commit()


def migrate(tmp_path: Path) -> str:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'routing-ws.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    return url


def make_app(url: str, node_id: str, internal_url: str) -> FastAPI:
    settings = Settings(
        driver="fake",
        database_url=url,
        api_key_pepper=PEPPER,
        node_id=node_id,
        node_internal_url=internal_url,
        routing_secret=SECRET,
    )
    return create_app(settings)


async def seed_key(app: FastAPI) -> dict[str, str]:
    now = datetime.now(UTC)
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=now)
    generated = generate_api_key(PEPPER)
    key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=FULL_ACCESS,
        created_at=now,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(key)
        await uow.commit()
    return {"Authorization": f"Bearer {generated.key}"}


def listener() -> socket.socket:
    sock = socket.socket()
    sock.bind((LOOPBACK, 0))
    sock.listen()
    return sock


def closed_port() -> int:
    with socket.socket() as probe:
        probe.bind((LOOPBACK, 0))
        port: int = probe.getsockname()[1]
    return port


async def wait_started(server: uvicorn.Server) -> None:
    async with asyncio.timeout(STARTUP_TIMEOUT_S):
        while not server.started:
            await asyncio.sleep(POLL_S)


@pytest.fixture
async def cluster(tmp_path: Path) -> AsyncIterator[Cluster]:
    url = migrate(tmp_path)
    alpha_sock, beta_sock = listener(), listener()
    alpha_port, beta_port = (s.getsockname()[1] for s in (alpha_sock, beta_sock))
    beta_url = f"http://{LOOPBACK}:{beta_port}"
    alpha = make_app(url, "alpha", f"http://{LOOPBACK}:{alpha_port}")
    beta = make_app(url, "beta", beta_url)
    seen: list[Seen] = []
    servers = [
        (uvicorn.Server(uvicorn.Config(app, log_level="warning", lifespan="off")), sock)
        for app, sock in ((alpha, alpha_sock), (Recorder(beta, seen), beta_sock))
    ]
    tasks = [asyncio.create_task(server.serve(sockets=[sock])) for server, sock in servers]
    alpha_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=alpha), base_url="http://test"
    )
    beta_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=beta), base_url="http://test")
    try:
        for server, _ in servers:
            await wait_started(server)
        auth = await seed_key(alpha)
        for app in (alpha, beta):
            await app.state.node_registry.heartbeat()
        created = await beta_client.post(BASE, headers=auth, json={})
        assert created.status_code == 201, created.text
        sandbox_id: str = created.json()["data"]["id"]
        yield Cluster(alpha, beta, alpha_client, auth, sandbox_id, alpha_port, beta_url, seen)
    finally:
        for server, _ in servers:
            server.should_exit = True
        await asyncio.gather(*tasks)
        for sock in (alpha_sock, beta_sock):
            sock.close()
        for client in (alpha_client, beta_client):
            await client.aclose()
        for app in (alpha, beta):
            await app.state.engine.dispose()


async def test_terminal_echoes_both_ways_and_honors_a_resize(cluster: Cluster) -> None:
    pty_id, token = await cluster.create_pty()
    assert cluster.alpha.state.pty_registry.get(pty_id) is None  # the terminal lives on beta

    async with asyncio.timeout(DEADLINE_S):
        async with connect(cluster.ws_url(pty_id, token), proxy=None) as ws:
            await ws.send(b"echo hi\n")
            assert await ws.recv() == b"echo hi\n"
            await ws.send(b"second")
            assert await ws.recv() == b"second"
            resized = await cluster.alpha_client.post(
                f"{cluster.toolbox}/pty/{pty_id}/resize",
                headers=cluster.auth,
                json={"rows": 33, "cols": 107},
            )
            assert resized.status_code == 200, resized.text
            handle = cluster.beta_pty(pty_id)
            assert handle is not None
            assert (handle.rows, handle.cols) == (33, 107)

    [create, hop, resize] = cluster.seen
    assert (create["type"], hop["type"], resize["type"]) == ("http", "websocket", "http")
    assert hop["headers"][FORWARDED_HEADER] == "1"
    verify_route_token(
        SECRET,
        hop["headers"][ROUTE_TOKEN_HEADER],
        node_id="beta",
        sandbox_id=cluster.sandbox_id,
        now=datetime.now(UTC),
    )


async def test_a_redeemed_connect_token_closes_with_the_owners_4401(cluster: Cluster) -> None:
    pty_id, token = await cluster.create_pty()
    url = cluster.ws_url(pty_id, token)

    async with asyncio.timeout(DEADLINE_S):
        async with connect(url, proxy=None) as first:
            await first.send(b"x")
            assert await first.recv() == b"x"
        async with connect(url, proxy=None) as second:
            with pytest.raises(ConnectionClosed) as closed:
                await second.recv()

    assert closed.value.rcvd is not None
    assert closed.value.rcvd.code == UNAUTHORIZED


async def test_an_owner_address_with_nothing_listening_closes_with_1013(
    cluster: Cluster,
) -> None:
    pty_id, token = await cluster.create_pty()
    await cluster.beat_beta(f"http://{LOOPBACK}:{closed_port()}")
    cluster.seen.clear()

    async with asyncio.timeout(DEADLINE_S):
        async with connect(cluster.ws_url(pty_id, token), proxy=None) as ws:
            with pytest.raises(ConnectionClosed) as closed:
                await ws.recv()

    assert closed.value.rcvd is not None
    assert closed.value.rcvd.code == TRY_AGAIN_LATER
    assert cluster.seen == []


async def test_a_client_close_ends_the_upstream_connection(cluster: Cluster) -> None:
    pty_id, token = await cluster.create_pty()

    async with connect(cluster.ws_url(pty_id, token), proxy=None) as ws:
        await ws.send(b"ping")
        assert await ws.recv() == b"ping"
        assert cluster.beta_pty(pty_id) is not None

    await cluster.wait_until_beta_forgets(pty_id)  # beta saw its side of the hop go away


async def test_a_connect_without_a_token_is_served_locally_and_not_forwarded(
    cluster: Cluster,
) -> None:
    pty_id, _ = await cluster.create_pty()
    cluster.seen.clear()

    async with asyncio.timeout(DEADLINE_S):
        async with connect(cluster.ws_url(pty_id, None), proxy=None) as ws:
            with pytest.raises(ConnectionClosed) as closed:
                await ws.recv()

    assert closed.value.rcvd is not None
    assert closed.value.rcvd.code == UNAUTHORIZED  # alpha's own answer, not beta's
    assert cluster.seen == []
