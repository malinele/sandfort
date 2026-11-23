"""SDK and CLI member administration plus the single sign-on exchange, through the real routes.

The application is the real one (FakeDriver, a migrated temp SQLite database); no socket is
opened. The async SDK client talks to it over an ASGI transport. The sync SDK client talks to
it through a small bridge that hops onto the test's event loop, so both clients exercise the
same routes. RSA keys are generated here and respx serves the identity provider's key set.
"""

import asyncio
import inspect
import json
import sys
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))
sys.path.insert(0, str(ROOT / "src"))

import httpx  # noqa: E402
import jwt  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from jwt.algorithms import RSAAlgorithm  # noqa: E402
from sandfort_cli import members as members_cli  # noqa: E402
from sandfort_cli.main import create_app as create_cli_app  # noqa: E402
from sandfort_sdk import (  # noqa: E402
    AsyncClient,
    Client,
    Conflict,
    InvalidState,
    Member,
    NotFound,
    SsoSession,
    Unauthorized,
)
from sandfort_sdk._transport import client_kwargs  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

from sandfort.api.app import create_app  # noqa: E402
from sandfort.auth.api_keys import generate_api_key  # noqa: E402
from sandfort.config import Settings  # noqa: E402
from sandfort.db.unit_of_work import UnitOfWork  # noqa: E402
from sandfort.domain.org import ApiKey, Org, Scope  # noqa: E402
from sandfort.domain.user import OrgMembership, OrgRole, User  # noqa: E402
from sandfort.ids import new_api_key_id, new_org_id  # noqa: E402

BASE = "http://sandfort.test"
TIMEOUT_S = 30.0
PEPPER = "test-pepper"
SECRET = "session-secret-for-sdk-user-tests"
TTL_S = 900
ISSUER = "https://idp.example.test"
AUDIENCE = "sandfort-web"
JWKS_URL = "https://idp.example.test/.well-known/jwks.json"
KID = "signing-key-1"
T0 = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)
ADA_ID = "usr_ada"
ADA_EMAIL = "ada@example.com"
GRACE_EMAIL = "grace@example.com"
RUNNER = CliRunner()
SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
HOP_HEADERS = frozenset({"content-length", "content-encoding", "transfer-encoding"})


@dataclass(frozen=True)
class World:
    app: FastAPI
    http: httpx.AsyncClient
    org_id: str
    admin_key: str


class LoopBridge(httpx.BaseTransport):
    """Run a sync SDK request on the event loop that owns the app and its database."""

    def __init__(self, http: httpx.AsyncClient, loop: asyncio.AbstractEventLoop) -> None:
        self._http = http
        self._loop = loop

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        future = asyncio.run_coroutine_threadsafe(self._send(request), self._loop)
        return future.result(timeout=TIMEOUT_S)

    async def _send(self, request: httpx.Request) -> httpx.Response:
        response = await self._http.request(
            request.method, str(request.url), headers=request.headers, content=request.content
        )
        pairs = response.headers.multi_items()
        headers = [(name, value) for name, value in pairs if name.lower() not in HOP_HEADERS]
        return httpx.Response(response.status_code, headers=headers, content=response.content)


def key_set() -> dict[str, Any]:
    public = RSAAlgorithm.to_jwk(SIGNING_KEY.public_key(), as_dict=True)
    return {"keys": [{**public, "kid": KID, "alg": "RS256", "use": "sig"}]}


def identity_token(email: str = ADA_EMAIL) -> str:
    """A valid identity token; the application runs on the system clock, so mint against it."""
    issued = datetime.now(UTC)
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "idp-subject-ada",
        "email": email,
        "email_verified": True,
        "iat": int(issued.timestamp()),
        "exp": int((issued + timedelta(minutes=5)).timestamp()),
    }
    return jwt.encode(claims, SIGNING_KEY, algorithm="RS256", headers={"kid": KID, "typ": "JWT"})


async def seed(app: FastAPI, org_id: str) -> str:
    """One org, an all-scopes admin key, and Ada as a developer member (the sign-on user)."""
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="seed",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset(Scope),
        created_at=T0,
    )
    ada = User(id=ADA_ID, email=ADA_EMAIL, display_name="Ada", created_at=T0)
    membership = OrgMembership(
        user_id=ADA_ID, org_id=org_id, role=OrgRole.DEVELOPER, created_at=T0
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(Org(id=org_id, name="Acme", slug="acme", created_at=T0))
        await uow.api_keys.add(stored)
        await uow.users.add(ada)
        await uow.memberships.add(membership)
        await uow.commit()
    return generated.key


@pytest.fixture
async def world(tmp_path: Path) -> AsyncIterator[World]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'sdk-users.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    org_id = new_org_id()
    settings = Settings(
        driver="fake",
        database_url=url,
        api_key_pepper=PEPPER,
        session_secret=SECRET,
        session_ttl_s=TTL_S,
        oidc_issuer=ISSUER,
        oidc_audience=AUDIENCE,
        oidc_jwks_url=JWKS_URL,
        oidc_org_id=org_id,
    )
    app = create_app(settings)
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            admin_key = await seed(app, org_id)
            yield World(app, http, org_id, admin_key)
    finally:
        await app.state.engine.dispose()


@pytest.fixture
def provider() -> Iterator[respx.MockRouter]:
    """The identity provider's key set endpoint; nothing else may leave the process."""
    with respx.mock(assert_all_called=False) as router:
        router.get(JWKS_URL).mock(return_value=httpx.Response(200, json=key_set()))
        yield router


def sync_client(world: World, api_key: str, loop: asyncio.AbstractEventLoop) -> Client:
    client = Client(BASE, api_key)
    client._transport._http.close()
    bridge = LoopBridge(world.http, loop)
    kwargs = client_kwargs(BASE, api_key, TIMEOUT_S)
    client._transport._http = httpx.Client(transport=bridge, **kwargs)
    return client


async def async_client(world: World, api_key: str) -> AsyncClient:
    client = AsyncClient(BASE, api_key)
    await client._transport._http.aclose()
    asgi = httpx.ASGITransport(app=world.app)
    kwargs = client_kwargs(BASE, api_key, TIMEOUT_S)
    client._transport._http = httpx.AsyncClient(transport=asgi, **kwargs)
    return client


async def open_sdk(kind: str, world: World, api_key: str) -> Client | AsyncClient:
    if kind == "sync":
        return sync_client(world, api_key, asyncio.get_running_loop())
    return await async_client(world, api_key)


async def close_sdk(client: Client | AsyncClient) -> None:
    if isinstance(client, Client):
        client.close()
    else:
        await client.aclose()


async def run(fn: Callable[..., Any], *args: Any) -> Any:
    """Call a sync SDK method off the loop thread, or await an async one."""
    if inspect.iscoroutinefunction(fn):
        return await fn(*args)
    return await asyncio.to_thread(fn, *args)


@pytest.fixture(params=["sync", "async"])
async def sdk(request: pytest.FixtureRequest, world: World) -> AsyncIterator[Client | AsyncClient]:
    client = await open_sdk(request.param, world, world.admin_key)
    try:
        yield client
    finally:
        await close_sdk(client)


# --- members through the SDK -------------------------------------------------------------


async def test_member_roundtrip_create_list_set_role_remove(sdk: Client | AsyncClient) -> None:
    created = await run(sdk.members.create, GRACE_EMAIL, "Grace Hopper", "developer")
    assert isinstance(created, Member)
    assert (created.email, created.display_name, created.role) == (
        GRACE_EMAIL,
        "Grace Hopper",
        "developer",
    )
    assert created.user_id.startswith("usr_")

    listed = await run(sdk.members.list)
    assert [member.email for member in listed] == [ADA_EMAIL, GRACE_EMAIL]
    assert listed[1].user_id == created.user_id
    assert listed[1].display_name == "Grace Hopper"

    changed = await run(sdk.members.set_role, created.user_id, "viewer")
    assert (changed.user_id, changed.role) == (created.user_id, "viewer")
    roles = {member.email: member.role for member in await run(sdk.members.list)}
    assert roles == {ADA_EMAIL: "developer", GRACE_EMAIL: "viewer"}

    assert await run(sdk.members.remove, created.user_id) is None
    remaining = await run(sdk.members.list)
    assert [member.email for member in remaining] == [ADA_EMAIL]


async def test_member_errors_surface_as_typed_sdk_errors(sdk: Client | AsyncClient) -> None:
    admin = await run(sdk.members.create, "root@example.com", "Root", "admin")
    with pytest.raises(Conflict):
        await run(sdk.members.create, "ROOT@example.com", "Root Again", "viewer")
    with pytest.raises(NotFound):
        await run(sdk.members.set_role, "usr_missing", "viewer")
    with pytest.raises(NotFound):
        await run(sdk.members.remove, "usr_missing")
    with pytest.raises(InvalidState):  # the only admin can neither be demoted nor removed
        await run(sdk.members.set_role, admin.user_id, "viewer")
    with pytest.raises(InvalidState):
        await run(sdk.members.remove, admin.user_id)


async def test_member_arguments_are_checked_before_any_request(sdk: Client | AsyncClient) -> None:
    with pytest.raises(ValueError, match="email"):
        await run(sdk.members.create, " ", "Nobody", "viewer")
    with pytest.raises(ValueError, match="role"):
        await run(sdk.members.set_role, ADA_ID, "")


# --- single sign-on exchange -------------------------------------------------------------


@pytest.mark.parametrize("kind", ["sync", "async"])
async def test_exchange_sso_returns_a_session_that_authenticates(
    world: World, provider: respx.MockRouter, kind: str
) -> None:
    client = await open_sdk(kind, world, world.admin_key)
    try:
        session = await run(client.exchange_sso, identity_token())
    finally:
        await close_sdk(client)

    assert isinstance(session, SsoSession)
    assert session.role == "developer"
    assert session.expires_at > datetime.now(UTC)
    assert session.session_token not in repr(session)

    signed_in = await open_sdk(kind, world, session.session_token)
    try:
        members = await run(signed_in.members.list)
    finally:
        await close_sdk(signed_in)
    assert [member.email for member in members] == [ADA_EMAIL]


@pytest.mark.parametrize("kind", ["sync", "async"])
async def test_exchange_sso_refusal_is_unauthorized(
    world: World, provider: respx.MockRouter, kind: str
) -> None:
    client = await open_sdk(kind, world, world.admin_key)
    try:
        with pytest.raises(Unauthorized):
            await run(client.exchange_sso, "not-a-jwt")
        with pytest.raises(Unauthorized):  # a valid token for an email that is no member
            await run(client.exchange_sso, identity_token("nobody@example.com"))
        with pytest.raises(ValueError, match="id_token"):
            await run(client.exchange_sso, "")
    finally:
        await close_sdk(client)


# --- CLI ---------------------------------------------------------------------------------


async def invoke(*args: str) -> Any:
    return await asyncio.to_thread(RUNNER.invoke, create_cli_app(), list(args))


@pytest.fixture
async def cli_world(world: World, monkeypatch: pytest.MonkeyPatch) -> World:
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(
        members_cli, "open_client", lambda: sync_client(world, world.admin_key, loop)
    )
    return world


async def test_cli_members_list_prints_json_and_table(cli_world: World) -> None:
    listed = await invoke("--json", "members", "list")
    assert listed.exit_code == 0, listed.output
    rows = json.loads(listed.stdout)
    assert [(row["user_id"], row["email"], row["role"]) for row in rows] == [
        (ADA_ID, ADA_EMAIL, "developer")
    ]
    assert set(rows[0]) == {"user_id", "email", "display_name", "role", "created_at"}

    table = await invoke("members", "list")
    assert table.exit_code == 0, table.output
    assert ADA_EMAIL in table.stdout
    assert "developer" in table.stdout


async def test_cli_members_add_set_role_remove(cli_world: World) -> None:
    add = ("--json", "members", "add", GRACE_EMAIL, "Grace Hopper", "--role", "viewer")
    added = await invoke(*add)
    assert added.exit_code == 0, added.output
    member = json.loads(added.stdout)
    assert (member["email"], member["display_name"], member["role"]) == (
        GRACE_EMAIL,
        "Grace Hopper",
        "viewer",
    )
    user_id = member["user_id"]

    changed = await invoke("--json", "members", "set-role", user_id, "--role", "developer")
    assert changed.exit_code == 0, changed.output
    assert json.loads(changed.stdout)["role"] == "developer"

    removed = await invoke("--json", "members", "remove", user_id)
    assert removed.exit_code == 0, removed.output
    assert json.loads(removed.stdout) == {"removed": user_id}


async def test_cli_members_reports_failures_and_bad_roles(cli_world: World) -> None:
    missing = await invoke("members", "remove", "usr_missing")
    assert missing.exit_code == 1
    assert "error:" in missing.stderr

    bad_role = await invoke("members", "add", GRACE_EMAIL, "Grace", "--role", "owner")
    assert bad_role.exit_code == 2
