"""WP 5.1: the preview proxy over the fake driver, with in-process upstreams.

The proxy is driven through httpx's ASGI transport with a preview ``Host`` header, or with raw
ASGI messages for websockets (httpx's transport speaks HTTP only). Its HTTP upstream is an ASGI
echo app behind an injected httpx client; websocket upstreams are real ``websockets`` servers
on a loopback port, because the proxy bridges with the ``websockets`` client library.
"""

import asyncio
import json
import socket
from collections.abc import AsyncIterator
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from websockets.asyncio.server import ServerConnection, serve

from sandfort.api.app import create_app
from sandfort.api.routes.sandbox_preview import preview_url
from sandfort.api.wiring import sandbox_lookup
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.resources import ResourceSpec
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.drivers.base import SandboxSpec
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id, new_sandbox_id
from sandfort.main import create_proxy_app as create_shared_proxy_app
from sandfort.proxy.app import create_proxy_app
from sandfort.proxy.routing import PreviewTarget, parse_preview_host, preview_host
from sandfort.proxy.tokens import (
    COOKIE_NAME,
    TOKEN_PARAM,
    InMemoryPreviewTokenStore,
    token_cookie,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
PORT = 8080
LOOPBACK = "127.0.0.1"
UNUSED_UPSTREAM_PORT = 9  # the injected HTTP client never dials it
TIMEOUT_S = 5.0
SETTINGS = Settings(driver="fake")
DOMAIN = SETTINGS.preview_domain

type Message = dict[str, Any]


def host_for(sandbox_id: str, port: int = PORT) -> str:
    return f"{port}-{sandbox_id.lower().replace('_', '-', 1)}.{DOMAIN}"


def closed_port() -> int:
    """A loopback port nothing listens on (bound once, then released)."""
    with socket.socket() as probe:
        probe.bind((LOOPBACK, 0))
        port: int = probe.getsockname()[1]
    return port


class EchoApp:
    """ASGI upstream answering with what it received; the body goes out in two chunks."""

    def __init__(self) -> None:
        self.calls = 0

    async def __call__(self, scope: Message, receive: Any, send: Any) -> None:
        assert scope["type"] == "http"
        self.calls += 1
        body = b""
        more_body = True
        while more_body:
            message = await receive()
            body += message.get("body", b"")
            more_body = message.get("more_body", False)
        echoed = {
            "method": scope["method"],
            "path": scope["path"],
            "query": scope["query_string"].decode(),
            "body": body.decode(),
            "headers": {key.decode(): value.decode() for key, value in scope["headers"]},
        }
        payload = json.dumps(echoed).encode()
        middle = len(payload) // 2
        headers = [
            (b"content-type", b"application/json"),
            (b"set-cookie", b"a=1"),
            (b"set-cookie", b"b=2"),
        ]
        if scope["path"] == "/domain-cookie":
            headers.append((b"set-cookie", b"c=3; Domain=preview.test; Path=/; Secure"))
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": payload[:middle], "more_body": True})
        await send({"type": "http.response.body", "body": payload[middle:]})


@dataclass
class World:
    """Sandboxes the proxy can see, the fake driver behind them and one token store."""

    driver: FakeDriver = field(default_factory=FakeDriver)
    tokens: InMemoryPreviewTokenStore = field(default_factory=InMemoryPreviewTokenStore)
    sandboxes: dict[str, Sandbox] = field(default_factory=dict)
    org_id: str = field(default_factory=new_org_id)

    async def add(
        self,
        *,
        public: bool = False,
        state: SandboxState = SandboxState.STARTED,
        endpoint: tuple[str, int] | None = (LOOPBACK, UNUSED_UPSTREAM_PORT),
    ) -> Sandbox:
        sandbox_id = new_sandbox_id()
        spec = SandboxSpec(
            sandbox_id=sandbox_id,
            org_id=self.org_id,
            name=f"sf-{sandbox_id}",
            image="echo",
            resources=ResourceSpec(),
        )
        info = await self.driver.create(spec)
        await self.driver.start(info.ref)
        if endpoint is not None:
            self.driver.register_endpoint(info.ref, *endpoint)
        sandbox = Sandbox(
            id=sandbox_id,
            org_id=self.org_id,
            name=spec.name,
            state=state,
            image_ref="echo",
            driver="fake",
            driver_ref=info.ref,
            public=public,
            created_at=NOW,
            updated_at=NOW,
        )
        self.sandboxes[sandbox_id] = sandbox
        return sandbox

    async def lookup(self, sandbox_id: str) -> Sandbox | None:
        return self.sandboxes.get(sandbox_id)

    def proxy(self, http_client: httpx.AsyncClient | None = None) -> Any:
        return create_proxy_app(
            SETTINGS,
            tokens=self.tokens,
            lookup=self.lookup,
            driver=self.driver,
            http_client=http_client,
        )


class AsgiWebSocket:
    """Drives one websocket connection into an ASGI app with raw messages."""

    def __init__(
        self,
        app: Any,
        host: str,
        path: str = "/",
        *,
        headers: dict[str, str] | None = None,
        **extensions: Any,
    ) -> None:
        self.app = app
        self.inbound: asyncio.Queue[Message] = asyncio.Queue()
        self.outbound: asyncio.Queue[Message] = asyncio.Queue()
        self.scope: Message = {
            "type": "websocket",
            "asgi": {"version": "3.0"},
            "scheme": "ws",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [(b"host", host.encode())]
            + [(key.encode(), value.encode()) for key, value in (headers or {}).items()],
            "subprotocols": [],
            "client": (LOOPBACK, 50000),
            "server": ("proxy.test", 80),
            "extensions": extensions,
        }
        self.task: asyncio.Task[None] | None = None

    async def connect(self) -> None:
        await self.inbound.put({"type": "websocket.connect"})
        running = self.app(self.scope, self.inbound.get, self.outbound.put)
        self.task = asyncio.create_task(running)

    async def push(self, message: Message) -> None:
        await self.inbound.put(message)

    async def next(self) -> Message:
        return await asyncio.wait_for(self.outbound.get(), TIMEOUT_S)

    async def finish(self) -> None:
        assert self.task is not None
        await asyncio.wait_for(self.task, TIMEOUT_S)


async def call(
    app: Any, method: str, host: str, path: str = "/", **kwargs: Any
) -> httpx.Response:
    headers = {"host": host, **kwargs.pop("headers", {})}
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://proxy.test") as client:
        return await client.request(method, path, headers=headers, **kwargs)


def error_code(response: httpx.Response) -> str:
    body = response.json()
    assert body["success"] is False
    code: str = body["error"]["code"]
    return code


@pytest.fixture
def world() -> World:
    return World()


@pytest.fixture
def echo() -> EchoApp:
    return EchoApp()


@pytest.fixture
async def upstream(echo: EchoApp) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=echo)) as client:
        yield client


# -- HTTP streaming ------------------------------------------------------------------------


async def test_get_round_trips_through_the_proxy(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=True)

    response = await call(world.proxy(upstream), "GET", host_for(sandbox.id), "/a/b?x=1&y=two")

    assert response.status_code == 200, response.text
    echoed = response.json()
    assert (echoed["method"], echoed["path"], echoed["query"]) == ("GET", "/a/b", "x=1&y=two")
    assert echoed["body"] == ""
    assert echoed["headers"]["x-forwarded-host"] == host_for(sandbox.id)
    assert echoed["headers"]["x-forwarded-proto"] == "http"
    assert response.headers.get_list("set-cookie") == ["a=1", "b=2"]


async def test_post_streams_the_request_body_both_ways(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=True)

    async def chunks() -> AsyncIterator[bytes]:
        for part in (b"first-", b"second-", b"third"):
            yield part

    response = await call(
        world.proxy(upstream), "POST", host_for(sandbox.id), "/submit", content=chunks()
    )

    assert response.status_code == 200, response.text
    echoed = response.json()  # the upstream answered in two chunks
    assert (echoed["method"], echoed["path"]) == ("POST", "/submit")
    assert echoed["body"] == "first-second-third"


# -- access control ------------------------------------------------------------------------


async def test_public_sandbox_passes_without_a_token(
    world: World, upstream: httpx.AsyncClient, echo: EchoApp
) -> None:
    sandbox = await world.add(public=True)

    response = await call(world.proxy(upstream), "GET", host_for(sandbox.id))

    assert response.status_code == 200, response.text
    assert echo.calls == 1


async def test_private_sandbox_needs_a_token_before_any_upstream_call(
    world: World, upstream: httpx.AsyncClient, echo: EchoApp
) -> None:
    sandbox = await world.add(public=False)

    denied = await call(world.proxy(upstream), "GET", host_for(sandbox.id))

    assert denied.status_code == 401
    assert error_code(denied) == "UNAUTHORIZED"
    assert echo.calls == 0


async def test_minted_token_passes_by_query_then_by_cookie(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=False)
    proxy = world.proxy(upstream)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)

    by_query = await call(proxy, "GET", host_for(sandbox.id), f"/p?keep=1&{TOKEN_PARAM}={token}")
    cookie = f"{COOKIE_NAME}={token}; theme=dark"
    by_cookie = await call(proxy, "GET", host_for(sandbox.id), "/p", headers={"cookie": cookie})

    assert by_query.status_code == 200, by_query.text
    assert by_query.json()["query"] == "keep=1"  # the token never reaches the sandbox
    assert any(
        value.startswith(f"{COOKIE_NAME}={token};") and "HttpOnly" in value and "Secure" in value
        for value in by_query.headers.get_list("set-cookie")
    )
    assert by_cookie.status_code == 200, by_cookie.text
    assert by_cookie.json()["headers"]["cookie"] == "theme=dark"


# -- cross-site requests, cookie hygiene ---------------------------------------------------


async def cookie_call(
    world: World, upstream: httpx.AsyncClient, extra: dict[str, str]
) -> tuple[httpx.Response, str]:
    sandbox = await world.add(public=False)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)
    headers = {"cookie": f"{COOKIE_NAME}={token}", **extra}
    host = host_for(sandbox.id)
    return await call(world.proxy(upstream), "GET", host, "/p", headers=headers), host


async def test_cookie_auth_with_foreign_origin_is_refused(
    world: World, upstream: httpx.AsyncClient, echo: EchoApp
) -> None:
    denied, _ = await cookie_call(world, upstream, {"origin": "http://evil.preview.test"})

    assert denied.status_code == 401
    assert error_code(denied) == "UNAUTHORIZED"
    assert echo.calls == 0


async def test_cookie_auth_passes_with_matching_origin_or_none(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=False)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)
    host = host_for(sandbox.id)
    proxy = world.proxy(upstream)
    base = {"cookie": f"{COOKIE_NAME}={token}"}

    matching = await call(proxy, "GET", host, headers={**base, "origin": f"http://{host}"})
    direct = await call(proxy, "GET", host, headers={**base, "sec-fetch-site": "none"})
    same = await call(proxy, "GET", host, headers={**base, "sec-fetch-site": "same-origin"})
    bare = await call(proxy, "GET", host, headers=base)

    assert [r.status_code for r in (matching, direct, same, bare)] == [200, 200, 200, 200]


@pytest.mark.parametrize("site", ["cross-site", "same-site"])
async def test_cookie_auth_with_cross_site_fetch_metadata_is_refused(
    world: World, upstream: httpx.AsyncClient, site: str
) -> None:
    denied, _ = await cookie_call(world, upstream, {"sec-fetch-site": site})

    assert denied.status_code == 401


async def test_query_token_is_unaffected_by_foreign_origin(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=False)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)
    headers = {"origin": "http://evil.preview.test", "sec-fetch-site": "cross-site"}

    path = f"/p?{TOKEN_PARAM}={token}"

    response = await call(world.proxy(upstream), "GET", host_for(sandbox.id), path, headers=headers)

    assert response.status_code == 200, response.text


async def test_malformed_query_token_sets_no_cookie(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=True)
    path = f"/p?{TOKEN_PARAM}=x%3B%20Domain%3Dpreview.test"

    response = await call(world.proxy(upstream), "GET", host_for(sandbox.id), path)

    assert response.status_code == 200, response.text
    cookies = response.headers.get_list("set-cookie")
    assert not any(TOKEN_PARAM in value for value in cookies)
    assert token_cookie("x; Domain=preview.test", secure=False) is None
    assert token_cookie("a" * 129, secure=False) is None
    assert token_cookie("a" * 128, secure=False) is not None


async def test_valid_query_token_still_sets_the_cookie(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=False)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)

    response = await call(
        world.proxy(upstream), "GET", host_for(sandbox.id), f"/p?{TOKEN_PARAM}={token}"
    )

    expected = f"{COOKIE_NAME}={token}; Path=/; Secure; HttpOnly; SameSite=Lax"
    assert expected in response.headers.get_list("set-cookie")


async def test_upstream_set_cookie_domain_attribute_is_dropped(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=True)

    response = await call(world.proxy(upstream), "GET", host_for(sandbox.id), "/domain-cookie")

    assert response.headers.get_list("set-cookie") == ["a=1", "b=2", "c=3; Path=/; Secure"]


async def test_token_for_another_port_or_org_is_rejected(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=False)
    proxy = world.proxy(upstream)
    other_port = await world.tokens.mint(world.org_id, sandbox.id, PORT + 1)
    other_org = await world.tokens.mint(new_org_id(), sandbox.id, PORT)

    for token in (other_port, other_org, "garbage"):
        response = await call(proxy, "GET", host_for(sandbox.id), f"/?{TOKEN_PARAM}={token}")
        assert response.status_code == 401, token


# -- routing -------------------------------------------------------------------------------


async def test_port_below_1024_is_not_found(
    world: World, upstream: httpx.AsyncClient, echo: EchoApp
) -> None:
    sandbox = await world.add(public=True)

    response = await call(world.proxy(upstream), "GET", host_for(sandbox.id, port=1023))

    assert response.status_code == 404
    assert error_code(response) == "NOT_FOUND"
    assert echo.calls == 0


@pytest.mark.parametrize(
    "host", ["localhost", f"{PORT}-sbx_x.{DOMAIN}", "{port}-{sid}.preview.example.com"]
)
async def test_unparseable_or_foreign_hosts_are_not_found(
    world: World, upstream: httpx.AsyncClient, host: str
) -> None:
    sandbox = await world.add(public=True)
    resolved = host.format(port=PORT, sid=sandbox.id.lower())

    response = await call(world.proxy(upstream), "GET", resolved)

    assert response.status_code == 404
    assert error_code(response) == "NOT_FOUND"


async def test_stopped_or_unknown_sandbox_is_not_found(
    world: World, upstream: httpx.AsyncClient
) -> None:
    stopped = await world.add(public=True, state=SandboxState.STOPPED)
    proxy = world.proxy(upstream)

    for sandbox_id in (stopped.id, new_sandbox_id()):
        response = await call(proxy, "GET", host_for(sandbox_id))
        assert response.status_code == 404
        assert error_code(response) == "NOT_FOUND"


async def test_host_header_port_suffix_is_ignored(
    world: World, upstream: httpx.AsyncClient
) -> None:
    sandbox = await world.add(public=True)

    response = await call(world.proxy(upstream), "GET", f"{host_for(sandbox.id)}:8001")

    assert response.status_code == 200, response.text


def test_preview_host_builder_emits_hyphenated_label_without_underscore() -> None:
    sandbox_id = new_sandbox_id()
    body = sandbox_id.split("_", 1)[1]

    host = preview_host(PORT, sandbox_id, DOMAIN)

    assert "_" not in host
    assert host == f"{PORT}-sbx-{body.lower()}.{DOMAIN}"


def test_preview_host_round_trips_to_the_canonical_id() -> None:
    sandbox_id = new_sandbox_id()

    target = parse_preview_host(preview_host(PORT, sandbox_id, DOMAIN))

    assert target == PreviewTarget(port=PORT, sandbox_id=sandbox_id)


def test_legacy_underscore_host_parses_to_the_same_id() -> None:
    sandbox_id = new_sandbox_id()
    legacy = f"{PORT}-{sandbox_id.lower()}.{DOMAIN}"
    hyphenated = preview_host(PORT, sandbox_id, DOMAIN)

    assert parse_preview_host(legacy) == parse_preview_host(hyphenated)
    assert parse_preview_host(legacy) == PreviewTarget(port=PORT, sandbox_id=sandbox_id)


@pytest.mark.parametrize(
    "label",
    [
        "org-{body}",  # wrong prefix
        "org_{body}",
        "sbx--{body}",  # hyphen run where the separator position is ambiguous
        "sbx-_{body}",
        "sbx_-{body}",
        "sbx__{body}",
        "sbx-{body}-x",  # extra hyphen part after the body
        "sbx-",  # empty body
        "sbx_",
        "sbx",
        "{body}",  # no prefix at all
        "-{body}",
    ],
)
def test_near_miss_preview_hosts_are_not_parsed(label: str) -> None:
    body = new_sandbox_id().split("_", 1)[1].lower()

    assert parse_preview_host(f"{PORT}-{label.format(body=body)}.{DOMAIN}") is None


# -- upstream failures ---------------------------------------------------------------------


async def test_upstream_connection_refused_is_bad_gateway(world: World) -> None:
    sandbox = await world.add(public=True, endpoint=(LOOPBACK, closed_port()))
    proxy = world.proxy()  # a real httpx client: the connection is actually refused
    try:
        response = await call(proxy, "GET", host_for(sandbox.id))
    finally:
        await proxy.aclose()

    assert response.status_code == 502
    assert error_code(response) == "BAD_GATEWAY"


async def test_missing_endpoint_is_bad_gateway(world: World, upstream: httpx.AsyncClient) -> None:
    sandbox = await world.add(public=True, endpoint=None)

    response = await call(world.proxy(upstream), "GET", host_for(sandbox.id))

    assert response.status_code == 502
    assert error_code(response) == "BAD_GATEWAY"


# -- websockets ----------------------------------------------------------------------------


async def test_websocket_echo_bridges_both_directions(world: World) -> None:
    paths: list[str] = []

    async def greet_then_echo(connection: ServerConnection) -> None:
        paths.append(connection.request.path if connection.request else "")
        await connection.send("welcome")
        async for message in connection:
            await connection.send(f"echo:{message}" if isinstance(message, str) else message)

    async with serve(greet_then_echo, LOOPBACK, 0) as server:
        upstream_port: int = server.sockets[0].getsockname()[1]
        sandbox = await world.add(public=True, endpoint=(LOOPBACK, upstream_port))
        session = AsgiWebSocket(world.proxy(), host_for(sandbox.id), "/socket")
        await session.connect()

        accepted = await session.next()
        greeting = await session.next()
        await session.push({"type": "websocket.receive", "text": "hello"})
        text_echo = await session.next()
        await session.push({"type": "websocket.receive", "bytes": b"\x00\x01"})
        bytes_echo = await session.next()
        await session.push({"type": "websocket.disconnect", "code": 1000})
        await session.finish()

    assert accepted["type"] == "websocket.accept"
    assert greeting == {"type": "websocket.send", "text": "welcome"}  # upstream to client
    assert text_echo == {"type": "websocket.send", "text": "echo:hello"}  # and back
    assert bytes_echo == {"type": "websocket.send", "bytes": b"\x00\x01"}
    assert paths == ["/socket"]


async def test_private_websocket_without_token_is_rejected_with_401(world: World) -> None:
    sandbox = await world.add(public=False)
    extensions: dict[str, Any] = {"websocket.http.response": {}}
    session = AsgiWebSocket(world.proxy(), host_for(sandbox.id), **extensions)
    await session.connect()

    start = await session.next()
    body = await session.next()
    await session.finish()

    assert start["type"] == "websocket.http.response.start"
    assert start["status"] == 401
    assert json.loads(body["body"])["error"]["code"] == "UNAUTHORIZED"


async def test_websocket_cookie_auth_with_foreign_origin_is_refused(world: World) -> None:
    sandbox = await world.add(public=False)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)
    headers = {"cookie": f"{COOKIE_NAME}={token}", "origin": "http://evil.preview.test"}
    extensions: dict[str, Any] = {"websocket.http.response": {}}
    session = AsgiWebSocket(world.proxy(), host_for(sandbox.id), headers=headers, **extensions)
    await session.connect()

    start = await session.next()
    await session.next()
    await session.finish()

    assert start["type"] == "websocket.http.response.start"
    assert start["status"] == 401


async def test_websocket_cookie_auth_foreign_origin_closes_without_http_extension(
    world: World,
) -> None:
    sandbox = await world.add(public=False)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)
    headers = {"cookie": f"{COOKIE_NAME}={token}", "sec-fetch-site": "cross-site"}
    session = AsgiWebSocket(world.proxy(), host_for(sandbox.id), headers=headers)
    await session.connect()

    closed = await session.next()
    await session.finish()

    assert closed == {"type": "websocket.close", "code": 1008}


async def test_websocket_upstream_refused_is_bad_gateway(world: World) -> None:
    sandbox = await world.add(public=True, endpoint=(LOOPBACK, closed_port()))
    session = AsgiWebSocket(world.proxy(), host_for(sandbox.id))
    await session.connect()

    closed = await session.next()
    await session.finish()

    assert closed == {"type": "websocket.close", "code": 1011}


# -- the mint route and the shared wiring --------------------------------------------------


@pytest.fixture
async def api(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'preview.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def auth(api: FastAPI) -> dict[str, str]:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    async with UnitOfWork(api.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    generated = generate_api_key(PEPPER)
    key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE}),
        created_at=NOW,
    )
    async with UnitOfWork(api.state.session_factory) as uow:
        await uow.api_keys.add(key)
        await uow.commit()
    return {"Authorization": f"Bearer {generated.key}"}


async def api_call(
    api: FastAPI, method: str, path: str, auth: dict[str, str], body: Any = None
) -> httpx.Response:
    transport = httpx.ASGITransport(app=api)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.request(method, path, headers=auth, json=body)


async def private_sandbox(api: FastAPI, auth: dict[str, str]) -> tuple[str, str]:
    """Create a private sandbox through the API; return its id and its fake-driver ref."""
    created = await api_call(api, "POST", "/v1/sandboxes", auth, {"public": False})
    assert created.status_code == 201, created.text
    sandbox_id: str = created.json()["data"]["id"]
    driver: FakeDriver = api.state.driver
    [info] = [item for item in await driver.list_managed() if item.sandbox_id == sandbox_id]
    return sandbox_id, info.ref


async def mint(api: FastAPI, auth: dict[str, str], sandbox_id: str, port: int) -> httpx.Response:
    path = f"/v1/sandboxes/{sandbox_id}/preview-tokens"
    return await api_call(api, "POST", path, auth, {"port": port})


async def test_mint_route_returns_token_and_url_honoured_by_the_proxy(
    api: FastAPI, auth: dict[str, str], upstream: httpx.AsyncClient
) -> None:
    sandbox_id, ref = await private_sandbox(api, auth)
    driver: FakeDriver = api.state.driver
    driver.register_endpoint(ref, LOOPBACK, UNUSED_UPSTREAM_PORT)

    minted = await mint(api, auth, sandbox_id, PORT)

    assert minted.status_code == 201, minted.text
    data = minted.json()["data"]
    settings: Settings = api.state.settings
    query = f"?{TOKEN_PARAM}={data['token']}"
    assert data["url"] == f"http://{host_for(sandbox_id)}:{settings.proxy_port}{query}"
    assert data["port"] == PORT
    proxy = create_proxy_app(
        settings,
        tokens=api.state.preview_tokens,
        lookup=sandbox_lookup(api.state.session_factory),
        driver=driver,
        http_client=upstream,
    )
    denied = await call(proxy, "GET", host_for(sandbox_id))
    allowed = await call(proxy, "GET", host_for(sandbox_id), f"/?{TOKEN_PARAM}={data['token']}")
    assert denied.status_code == 401
    assert allowed.status_code == 200, allowed.text


PUBLIC_PREVIEW_ENV = "SANDFORT_PUBLIC_PREVIEW_URL"
PREVIEW_TOKEN = "tok_abc-123_XYZ"
TOKEN_QUERY = f"?{TOKEN_PARAM}={PREVIEW_TOKEN}"


def preview_settings(public_preview_url: str | None = None) -> Settings:
    """Settings loaded through ``from_env``, with the public preview origin when given."""
    environ = {"SANDFORT_DRIVER": "fake"}
    if public_preview_url is not None:
        environ[PUBLIC_PREVIEW_ENV] = public_preview_url
    return Settings.from_env(environ)


def test_preview_url_default_mode_is_http_on_the_proxy_port() -> None:
    sandbox_id = new_sandbox_id()
    settings = preview_settings()

    url = preview_url(settings, sandbox_id, PORT, PREVIEW_TOKEN)

    assert settings.public_preview_url == ""
    assert url == f"http://{host_for(sandbox_id)}:{settings.proxy_port}{TOKEN_QUERY}"
    assert preview_url(preview_settings(""), sandbox_id, PORT, PREVIEW_TOKEN) == url


def test_preview_url_default_mode_omits_the_default_http_port() -> None:
    sandbox_id = new_sandbox_id()
    settings = replace(SETTINGS, proxy_port=80)

    url = preview_url(settings, sandbox_id, PORT, PREVIEW_TOKEN)

    assert url == f"http://{host_for(sandbox_id)}{TOKEN_QUERY}"


def test_preview_url_https_origin_without_port_has_no_port_suffix() -> None:
    sandbox_id = new_sandbox_id()
    settings = preview_settings(f"https://{DOMAIN}")

    url = preview_url(settings, sandbox_id, PORT, PREVIEW_TOKEN)

    assert url == f"https://{host_for(sandbox_id)}{TOKEN_QUERY}"


def test_preview_url_query_parameter_is_the_one_the_proxy_parses() -> None:
    url = preview_url(SETTINGS, new_sandbox_id(), PORT, PREVIEW_TOKEN)

    query = parse_qs(urlsplit(url).query)

    assert query == {TOKEN_PARAM: [PREVIEW_TOKEN]}
    assert url.endswith(f"?{TOKEN_PARAM}={PREVIEW_TOKEN}")


@pytest.mark.parametrize(
    ("origin", "expected_suffix"),
    [
        (f"https://{DOMAIN}:8443", ":8443"),
        (f"https://{DOMAIN}:443", ":443"),
        (f"http://{DOMAIN}:80", ":80"),
        (f"http://{DOMAIN}:8001/", ":8001"),
    ],
)
def test_preview_url_keeps_an_explicit_port(origin: str, expected_suffix: str) -> None:
    sandbox_id = new_sandbox_id()
    scheme = origin.split("://")[0]

    url = preview_url(preview_settings(origin), sandbox_id, PORT, PREVIEW_TOKEN)

    assert url == f"{scheme}://{host_for(sandbox_id)}{expected_suffix}{TOKEN_QUERY}"


@pytest.mark.parametrize(
    ("raw", "stored"),
    [
        (f"https://{DOMAIN}", f"https://{DOMAIN}"),
        (f"https://{DOMAIN}/", f"https://{DOMAIN}"),
        (f"  https://{DOMAIN}:8443/ ", f"https://{DOMAIN}:8443"),
        (f"HTTPS://{DOMAIN.upper()}", f"https://{DOMAIN}"),
        (f"http://{DOMAIN}:8001", f"http://{DOMAIN}:8001"),
    ],
)
def test_public_preview_url_is_stored_normalized(raw: str, stored: str) -> None:
    assert preview_settings(raw).public_preview_url == stored


@pytest.mark.parametrize(
    "invalid",
    [
        pytest.param(f"ftp://{DOMAIN}", id="unsupported-scheme"),
        pytest.param(f"ws://{DOMAIN}", id="websocket-scheme"),
        pytest.param(DOMAIN, id="no-scheme"),
        pytest.param("https://example.com", id="other-host"),
        pytest.param(f"https://api.{DOMAIN}", id="subdomain-of-the-preview-domain"),
        pytest.param(f"https://{DOMAIN}.evil.test", id="preview-domain-as-a-prefix"),
        pytest.param(f"https://user@{DOMAIN}", id="userinfo"),
        pytest.param(f"https://{DOMAIN}/app", id="path"),
        pytest.param(f"https://{DOMAIN}//", id="more-than-one-trailing-slash"),
        pytest.param(f"https://{DOMAIN}?a=1", id="query"),
        pytest.param(f"https://{DOMAIN}/?a=1", id="slash-and-query"),
        pytest.param(f"https://{DOMAIN}#frag", id="fragment"),
        pytest.param(f"https://{DOMAIN}:abc", id="non-numeric-port"),
        pytest.param(f"https://{DOMAIN}:", id="empty-port"),
        pytest.param(f"https://{DOMAIN}:-1", id="negative-port"),
        pytest.param(f"https://{DOMAIN}:0", id="port-zero"),
        pytest.param(f"https://{DOMAIN}:65536", id="port-too-large"),
    ],
)
def test_public_preview_url_rejects_anything_but_an_origin_on_the_preview_domain(
    invalid: str,
) -> None:
    with pytest.raises(ValueError, match=PUBLIC_PREVIEW_ENV):
        preview_settings(invalid)


def test_public_preview_url_host_is_compared_with_the_configured_preview_domain() -> None:
    environ = {"SANDFORT_DRIVER": "fake", "SANDFORT_PREVIEW_DOMAIN": "preview.example.com"}

    accepted = Settings.from_env({**environ, PUBLIC_PREVIEW_ENV: "https://preview.example.com"})
    with pytest.raises(ValueError, match=PUBLIC_PREVIEW_ENV):
        Settings.from_env({**environ, PUBLIC_PREVIEW_ENV: f"https://{DOMAIN}"})

    assert accepted.public_preview_url == "https://preview.example.com"


async def test_shared_proxy_factory_reads_the_api_token_store(
    api: FastAPI, auth: dict[str, str]
) -> None:
    sandbox_id, ref = await private_sandbox(api, auth)
    driver: FakeDriver = api.state.driver
    driver.register_endpoint(ref, LOOPBACK, closed_port())
    token = (await mint(api, auth, sandbox_id, PORT)).json()["data"]["token"]
    proxy = create_shared_proxy_app(api.state.settings, api_app=api)
    try:
        denied = await call(proxy, "GET", host_for(sandbox_id))
        passed = await call(proxy, "GET", host_for(sandbox_id), f"/?{TOKEN_PARAM}={token}")
    finally:
        await proxy.aclose()

    assert denied.status_code == 401
    assert passed.status_code == 502  # past access control; nothing listens upstream


async def test_mint_route_rejects_privileged_ports_and_unknown_sandboxes(
    api: FastAPI, auth: dict[str, str]
) -> None:
    sandbox_id, _ = await private_sandbox(api, auth)

    low = await mint(api, auth, sandbox_id, 80)
    unknown = await mint(api, auth, new_sandbox_id(), PORT)

    assert low.status_code == 422
    assert unknown.status_code == 404
    assert error_code(unknown) == "NOT_FOUND"
