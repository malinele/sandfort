"""Phase 9 slice 5: HTTP forwarding and the owner guard over two in-process nodes.

Two apps (nodes ``alpha`` and ``beta``) share one SQLite database and a routing secret; each has
its own fake driver. Beta is exposed to alpha by a real uvicorn server on a loopback port (its
address is registered by heartbeat); alpha is driven in process. A recorder in front of beta
logs every request that reaches it, which is how "no connection" and "one hop" are proven.
"""

import asyncio
import re
import socket
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from sqlalchemy import event

from sandfort.api.app import create_app
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import MIN_SESSION_SECRET_CHARS, Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.node import Node
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.drivers.base import ExecRequest, ExecResult
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.routing.forward import FORWARDED_HEADER, ROUTE_TOKEN_HEADER
from sandfort.routing.guard import RouteGuardMiddleware
from sandfort.routing.middleware import RouteForwardMiddleware
from sandfort.routing.tokens import mint_route_token, verify_route_token

ROOT = Path(__file__).resolve().parents[1]
PEPPER = "test-pepper"
SECRET = "r" * MIN_SESSION_SECRET_CHARS
OTHER_SECRET = "o" * MIN_SESSION_SECRET_CHARS
LOOPBACK = "127.0.0.1"
ALPHA_URL = f"http://{LOOPBACK}:9"  # alpha owns nothing in these tests: never dialed
BASE = "/v1/sandboxes"
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
STARTUP_TIMEOUT_S = 5.0
NODES_TABLE = re.compile(r"\bnodes\b")

type Seen = dict[str, Any]


class Script:
    """Exec handler: answers the cwd read-back and everything else with fixed stdout."""

    def __init__(self, stdout: bytes) -> None:
        self.stdout = stdout
        self.calls = 0

    def __call__(self, env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        self.calls += 1
        if request.argv[0] == "cat":
            return ExecResult(exit_code=0, stdout=b"/work\n")
        return ExecResult(exit_code=0, stdout=self.stdout)


class Recorder:
    """ASGI wrapper logging path and headers of every http request that reaches the app."""

    def __init__(self, app: FastAPI, seen: list[Seen]) -> None:
        self.app = app
        self.seen = seen

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            headers = {key.decode(): value.decode() for key, value in scope["headers"]}
            self.seen.append({"path": scope["path"], "headers": headers})
        await self.app(scope, receive, send)


@dataclass
class Cluster:
    alpha: FastAPI
    beta: FastAPI
    alpha_client: httpx.AsyncClient
    beta_client: httpx.AsyncClient
    auth: dict[str, str]
    sandbox_id: str  # owned by beta
    beta_url: str
    seen: list[Seen] = field(default_factory=list)

    @property
    def toolbox(self) -> str:
        return f"{BASE}/{self.sandbox_id}/toolbox"

    @property
    def alpha_script(self) -> Script:
        return script_of(self.alpha)

    @property
    def beta_script(self) -> Script:
        return script_of(self.beta)

    async def beat_beta(self, *, at: datetime | None = None, url: str | None = None) -> None:
        """Rewrite beta's registry row, as a heartbeat (or its absence) would."""
        node = Node(
            id="beta",
            name="beta",
            last_heartbeat_at=at or datetime.now(UTC),
            internal_url=self.beta_url if url is None else url,
        )
        async with UnitOfWork(self.alpha.state.session_factory) as uow:
            await uow.nodes.upsert_heartbeat(node)
            await uow.commit()

    async def execute(self, client: httpx.AsyncClient, headers: dict[str, str]) -> httpx.Response:
        return await client.post(
            f"{self.toolbox}/process/execute", headers=headers, json={"command": "id"}
        )


def script_of(app: FastAPI) -> Script:
    driver = app.state.driver
    assert isinstance(driver, FakeDriver)
    assert isinstance(driver.exec_handler, Script)
    return driver.exec_handler


def migrate(tmp_path: Path, name: str) -> str:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / name}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    return url


def make_app(url: str, node_id: str, internal_url: str = "", secret: str = SECRET) -> FastAPI:
    settings = Settings(
        driver="fake",
        database_url=url,
        api_key_pepper=PEPPER,
        node_id=node_id,
        node_internal_url=internal_url,
        routing_secret=secret,
    )
    app = create_app(settings)
    assert isinstance(app.state.driver, FakeDriver)
    app.state.driver.exec_handler = Script(f"from-{node_id}\n".encode())
    return app


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


def in_process(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def create_sandbox(client: httpx.AsyncClient, auth: dict[str, str]) -> str:
    response = await client.post(BASE, headers=auth, json={})
    assert response.status_code == 201, response.text
    sandbox_id: str = response.json()["data"]["id"]
    return sandbox_id


def closed_port() -> int:
    with socket.socket() as probe:
        probe.bind((LOOPBACK, 0))
        port: int = probe.getsockname()[1]
    return port


async def wait_started(server: uvicorn.Server) -> None:
    async with asyncio.timeout(STARTUP_TIMEOUT_S):
        while not server.started:
            await asyncio.sleep(0.01)


@pytest.fixture
async def cluster(tmp_path: Path) -> AsyncIterator[Cluster]:
    url = migrate(tmp_path, "routing.db")
    listener = socket.socket()
    listener.bind((LOOPBACK, 0))
    listener.listen()
    beta_url = f"http://{LOOPBACK}:{listener.getsockname()[1]}"
    alpha, beta = make_app(url, "alpha", ALPHA_URL), make_app(url, "beta", beta_url)
    seen: list[Seen] = []
    config = uvicorn.Config(Recorder(beta, seen), log_level="warning", lifespan="off")
    server = uvicorn.Server(config)
    serving = asyncio.create_task(server.serve(sockets=[listener]))
    alpha_client, beta_client = in_process(alpha), in_process(beta)
    try:
        await wait_started(server)
        auth = await seed_key(alpha)
        for app in (alpha, beta):
            await app.state.node_registry.heartbeat()
        sandbox_id = await create_sandbox(beta_client, auth)
        yield Cluster(alpha, beta, alpha_client, beta_client, auth, sandbox_id, beta_url, seen)
    finally:
        server.should_exit = True
        await serving
        listener.close()
        for client in (alpha_client, beta_client):
            await client.aclose()
        for app in (alpha, beta):
            await app.state.engine.dispose()


def error_of(response: httpx.Response) -> dict[str, Any]:
    body = response.json()
    assert body["success"] is False
    error: dict[str, Any] = body["error"]
    return error


def parse_sse(text: str) -> list[dict[str, str]]:
    blocks = [block for block in text.split("\n\n") if block.strip() and not block.startswith(":")]
    return [dict(line.split(": ", 1) for line in block.split("\n")) for block in blocks]


# -- forwarding: the beta result comes back through alpha ----------------------------------


async def test_exec_sent_to_alpha_runs_on_beta_in_one_hop(cluster: Cluster) -> None:
    response = await cluster.execute(cluster.alpha_client, cluster.auth)

    assert response.status_code == 200, response.text
    assert response.json()["data"]["stdout"] == "from-beta\n"
    assert [hop["path"] for hop in cluster.seen] == [f"{cluster.toolbox}/process/execute"]
    assert (cluster.alpha_script.calls, cluster.beta_script.calls) == (0, 1)


async def test_upload_and_download_round_trip_through_alpha(cluster: Cluster) -> None:
    payload = bytes(range(256)) * 1200
    upload_path, download_path = f"{cluster.toolbox}/fs/upload", f"{cluster.toolbox}/fs/download"
    params = {"path": "/work/data.bin"}

    uploaded = await cluster.alpha_client.put(
        upload_path, headers=cluster.auth, params=params, content=payload
    )
    downloaded = await cluster.alpha_client.get(download_path, headers=cluster.auth, params=params)
    direct = await cluster.beta_client.get(download_path, headers=cluster.auth, params=params)

    assert uploaded.status_code == 200, uploaded.text
    assert downloaded.status_code == 200
    assert downloaded.content == payload == direct.content
    assert downloaded.headers["content-type"] == direct.headers["content-type"]
    assert [hop["path"] for hop in cluster.seen] == [upload_path, download_path]


async def test_followed_logs_arrive_as_the_beta_event_stream(cluster: Cluster) -> None:
    sessions = f"{cluster.toolbox}/process/sessions"
    client, auth = cluster.alpha_client, cluster.auth
    session = await client.post(sessions, headers=auth, json={})
    session_id = session.json()["data"]["id"]
    started = await client.post(
        f"{sessions}/{session_id}/commands?async=true", headers=auth, json={"command": "make"}
    )
    assert started.status_code == 202, started.text
    command_path = f"{sessions}/{session_id}/commands/{started.json()['data']['command']['id']}"
    for _ in range(500):
        status = await client.get(command_path, headers=auth)
        if status.json()["data"]["state"] == "exited":
            break
        await asyncio.sleep(0.02)

    followed = await client.get(f"{command_path}/logs/follow?offset=0", headers=auth)
    direct = await cluster.beta_client.get(f"{command_path}/logs/follow?offset=0", headers=auth)

    assert followed.status_code == 200
    assert followed.headers["content-type"].startswith("text/event-stream")
    assert followed.headers["cache-control"] == "no-cache"
    assert followed.text == direct.text
    assert [frame["event"] for frame in parse_sse(followed.text)] == ["stdout", "exit"]
    assert cluster.seen[-1]["path"] == f"{command_path}/logs/follow"


async def test_hop_headers_carry_a_valid_token_and_drop_client_internals(
    cluster: Cluster,
) -> None:
    headers = {
        **cluster.auth,
        "X-Request-Id": "req-hop-1",
        "Idempotency-Key": "idem-1",
        "X-Sandfort-Evil": "1",
        "X-Forwarded-For": "6.6.6.6",
    }

    response = await cluster.execute(cluster.alpha_client, headers)

    assert response.status_code == 200, response.text
    [hop] = cluster.seen
    sent = hop["headers"]
    assert sent[FORWARDED_HEADER] == "1"
    assert "x-sandfort-evil" not in sent
    assert (sent["x-request-id"], sent["idempotency-key"]) == ("req-hop-1", "idem-1")
    assert sent["x-forwarded-for"] == LOOPBACK
    assert sent["host"] == cluster.beta_url.removeprefix("http://")
    verify_route_token(
        SECRET,
        sent[ROUTE_TOKEN_HEADER],
        node_id="beta",
        sandbox_id=cluster.sandbox_id,
        now=datetime.now(UTC),
    )


# -- refusals made by the edge ---------------------------------------------------------------


async def test_no_credential_gets_the_usual_401_and_no_forward(cluster: Cluster) -> None:
    response = await cluster.execute(cluster.alpha_client, {})

    assert response.status_code == 401
    assert error_of(response)["code"] != "NODE_UNAVAILABLE"
    assert cluster.seen == []


@pytest.mark.parametrize(
    ("reason", "age_minutes", "keep_url"), [("stale", 10, True), ("no_address", 0, False)]
)
async def test_unusable_owner_is_a_retryable_503_without_a_connection(
    cluster: Cluster, reason: str, age_minutes: int, keep_url: bool
) -> None:
    beat = datetime.now(UTC) - timedelta(minutes=age_minutes)
    await cluster.beat_beta(at=beat, url=None if keep_url else "")

    response = await cluster.execute(cluster.alpha_client, cluster.auth)

    assert response.status_code == 503
    error = error_of(response)
    assert (error["code"], error["details"]["reason"]) == ("NODE_UNAVAILABLE", reason)
    assert error["details"]["node_id"] == "beta"
    assert "retry-after" in response.headers
    assert cluster.seen == []
    assert cluster.alpha_script.calls == 0


async def test_an_address_with_nothing_listening_is_unreachable(cluster: Cluster) -> None:
    await cluster.beat_beta(url=f"http://{LOOPBACK}:{closed_port()}")

    response = await cluster.execute(cluster.alpha_client, cluster.auth)

    assert response.status_code == 503
    assert error_of(response)["details"]["reason"] == "unreachable"
    assert "retry-after" in response.headers
    assert cluster.seen == []


# -- the owner guard -------------------------------------------------------------------------


def hop_headers(cluster: Cluster, token: str | None) -> dict[str, str]:
    headers = {**cluster.auth, FORWARDED_HEADER: "1"}
    return headers if token is None else {**headers, ROUTE_TOKEN_HEADER: token}


def token_for(secret: str, sandbox_id: str, node_id: str) -> str:
    return mint_route_token(secret, sandbox_id=sandbox_id, node_id=node_id, now=datetime.now(UTC))


@pytest.mark.parametrize("kind", ["forged", "wrong_node", "wrong_sandbox", "missing"])
async def test_owner_rejects_a_hop_without_a_genuine_token(cluster: Cluster, kind: str) -> None:
    sid = cluster.sandbox_id
    tokens = {
        "forged": token_for(OTHER_SECRET, sid, "beta"),
        "wrong_node": token_for(SECRET, sid, "alpha"),
        "wrong_sandbox": token_for(SECRET, "sbx_other", "beta"),
        "missing": None,
    }

    response = await cluster.execute(cluster.beta_client, hop_headers(cluster, tokens[kind]))

    assert response.status_code == 503  # never 401: that reads as a bad API key
    assert error_of(response)["details"] == {"reason": "rejected", "node_id": "beta"}
    assert cluster.beta_script.calls == 0


async def test_a_genuine_token_sent_to_a_non_owner_is_misrouted(cluster: Cluster) -> None:
    token = token_for(SECRET, cluster.sandbox_id, "alpha")

    response = await cluster.execute(cluster.alpha_client, hop_headers(cluster, token))

    assert response.status_code == 503
    assert error_of(response)["details"]["reason"] == "misrouted"
    assert cluster.seen == []  # a request that carries the hop marker is never forwarded again


async def test_a_genuine_hop_is_served_locally_by_the_owner(cluster: Cluster) -> None:
    token = token_for(SECRET, cluster.sandbox_id, "beta")

    response = await cluster.execute(cluster.beta_client, hop_headers(cluster, token))

    assert response.status_code == 200, response.text
    assert response.json()["data"]["stdout"] == "from-beta\n"


# -- single node and the default -------------------------------------------------------------


@pytest.mark.parametrize(
    ("secret", "installed", "node_queries"), [("", False, 0), (SECRET, True, 1)]
)
async def test_default_installs_nothing_and_a_local_call_costs_one_lookup_at_most(
    tmp_path: Path, secret: str, installed: bool, node_queries: int
) -> None:
    app = make_app(migrate(tmp_path, "solo.db"), "solo", secret=secret)
    client = in_process(app)
    statements: list[str] = []

    def record(conn: Any, cursor: Any, statement: str, *rest: Any) -> None:
        statements.append(statement)

    try:
        auth = await seed_key(app)
        await app.state.node_registry.heartbeat()
        sandbox_id = await create_sandbox(client, auth)
        event.listen(app.state.engine.sync_engine, "before_cursor_execute", record)
        response = await client.post(
            f"{BASE}/{sandbox_id}/toolbox/process/execute", headers=auth, json={"command": "id"}
        )
    finally:
        await client.aclose()
        await app.state.engine.dispose()

    classes = {middleware.cls for middleware in app.user_middleware}
    assert response.status_code == 200, response.text
    assert (RouteForwardMiddleware in classes, RouteGuardMiddleware in classes) == (installed,) * 2
    assert sum(1 for sql in statements if NODES_TABLE.search(sql)) == node_queries
