"""User session tokens: mint/verify roundtrip, rejection paths and the Bearer dependency.

Daemon-free. The Bearer dependency re-checks the user and membership on every request, so those
tests run against a migrated temp SQLite database seeded like tests/test_sso.py.
"""

import base64
import json
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from sandfort.auth.authenticate import AuthContext, authenticate, install_auth
from sandfort.auth.principal import Principal
from sandfort.auth.session_tokens import (
    SESSION_PREFIX,
    mint_session_token,
    verify_session_token,
)
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import Org
from sandfort.domain.user import OrgMembership, OrgRole, User, role_scopes
from sandfort.errors import SandfortError, Unauthorized

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)
SECRET = "session-secret-for-tests"
OTHER_SECRET = "a-different-secret"
TTL_S = 3600
USER_ID = "usr_0123456789ABCDEFGHJKMNPQRS"
ORG_ID = "org_0123456789ABCDEFGHJKMNPQRS"
OTHER_ORG_ID = "org_ZZZZZZZZZZZZZZZZZZZZZZZZZZ"
ROOT = Path(__file__).resolve().parents[1]
GOOD_SECRET = "s" * 32


def mint(secret: str = SECRET, role: OrgRole = OrgRole.DEVELOPER) -> str:
    return mint_session_token(
        secret, user_id=USER_ID, org_id=ORG_ID, role=role, now=NOW, ttl_s=TTL_S
    )


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def no_database() -> UnitOfWorkPort:
    raise AssertionError("this path must not touch the database")


class Database:
    def __init__(self, engine: AsyncEngine) -> None:
        self.engine = engine
        self.session_factory: async_sessionmaker[Any] = create_session_factory(engine)

    def uow(self) -> UnitOfWorkPort:
        return UnitOfWork(self.session_factory)

    async def seed(
        self, role: OrgRole | None = OrgRole.DEVELOPER, *, disabled: bool = False
    ) -> None:
        """One user in ORG_ID with ``role`` (no membership when ``None``), plus a second org."""
        user = User(
            id=USER_ID,
            email="ada@example.com",
            display_name="Ada",
            created_at=NOW,
            disabled_at=NOW if disabled else None,
        )
        async with UnitOfWork(self.session_factory) as uow:
            for org_id, slug in ((ORG_ID, "acme"), (OTHER_ORG_ID, "globex")):
                await uow.orgs.add(Org(id=org_id, name=slug.title(), slug=slug, created_at=NOW))
            await uow.users.add(user)
            if role is not None:
                membership = OrgMembership(
                    user_id=USER_ID, org_id=ORG_ID, role=role, created_at=NOW
                )
                await uow.memberships.add(membership)
            await uow.commit()


@pytest.fixture
async def database(tmp_path: Path) -> AsyncIterator[Database]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'sessions.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    engine = create_engine(Settings(driver="fake", database_url=url))
    try:
        yield Database(engine)
    finally:
        await engine.dispose()


def build_app(context: AuthContext) -> FastAPI:
    app = FastAPI()
    install_auth(app, context)

    @app.exception_handler(SandfortError)
    async def handle(_request: Request, exc: SandfortError) -> JSONResponse:
        body = {"code": exc.code, "message": exc.message, "details": exc.details}
        return JSONResponse(status_code=exc.status, content=body)

    @app.get("/whoami")
    async def whoami(principal: Annotated[Principal, Depends(authenticate)]) -> dict[str, Any]:
        return {
            "org_id": principal.org_id,
            "key_id": principal.key_id,
            "user_id": principal.user_id,
            "scopes": sorted(scope.value for scope in principal.scopes),
            "is_platform_admin": principal.is_platform_admin,
        }

    return app


def open_client(
    session_secret: str,
    uow_factory: Callable[[], UnitOfWorkPort] = no_database,
    sso_org_id: str = "",
) -> httpx.AsyncClient:
    context = AuthContext(
        pepper="test-pepper",
        uow_factory=uow_factory,
        clock=FrozenClock(NOW + timedelta(seconds=10)),
        session_secret=session_secret,
        sso_org_id=sso_org_id,
    )
    transport = httpx.ASGITransport(app=build_app(context))
    return httpx.AsyncClient(transport=transport, base_url="http://test")


# --- mint / verify ------------------------------------------------------------


def test_roundtrip_preserves_every_claim() -> None:
    token = mint(role=OrgRole.VIEWER)

    claims = verify_session_token(SECRET, token, NOW)

    assert claims.user_id == USER_ID
    assert claims.org_id == ORG_ID
    assert claims.role is OrgRole.VIEWER
    assert claims.issued_at == NOW
    assert claims.expires_at == NOW + timedelta(seconds=TTL_S)
    assert claims.token_id.startswith("ses_")


def test_token_has_session_prefix_distinct_from_api_keys() -> None:
    token = mint()

    assert token.startswith(SESSION_PREFIX)
    assert not token.startswith("sf_")


def test_each_minted_token_gets_a_fresh_id() -> None:
    first = verify_session_token(SECRET, mint(), NOW)
    second = verify_session_token(SECRET, mint(), NOW)

    assert first.token_id != second.token_id


def test_tampered_payload_is_rejected() -> None:
    token = mint(role=OrgRole.VIEWER)
    payload, _, signature = token[len(SESSION_PREFIX) :].partition(".")
    body = json.loads(unb64(payload))
    body["role"] = OrgRole.ADMIN.value
    forged_payload = b64(json.dumps(body, separators=(",", ":")).encode())

    with pytest.raises(Unauthorized):
        verify_session_token(SECRET, f"{SESSION_PREFIX}{forged_payload}.{signature}", NOW)


def test_signature_from_a_different_secret_is_rejected() -> None:
    token = mint(secret=OTHER_SECRET)

    with pytest.raises(Unauthorized):
        verify_session_token(SECRET, token, NOW)


@pytest.mark.parametrize(
    "token",
    [
        "",
        "sfs_",
        "sfs_nodot",
        "sfs_a.b.c",
        "sfs_!!!.???",
        "sfs_%%%.AAAA",
        "sf_live_abcdefgh_" + "a" * 43,
        "sfs_" + b64(b"not json") + "." + b64(b"x" * 32),
    ],
)
def test_malformed_token_is_rejected(token: str) -> None:
    with pytest.raises(Unauthorized):
        verify_session_token(SECRET, token, NOW)


def test_expired_token_is_rejected_at_and_after_expiry() -> None:
    token = mint()

    verify_session_token(SECRET, token, NOW + timedelta(seconds=TTL_S - 1))
    with pytest.raises(Unauthorized):
        verify_session_token(SECRET, token, NOW + timedelta(seconds=TTL_S))
    with pytest.raises(Unauthorized):
        verify_session_token(SECRET, token, NOW + timedelta(days=1))


def test_verify_with_empty_secret_is_rejected() -> None:
    with pytest.raises(Unauthorized):
        verify_session_token("", mint(), NOW)


def test_minting_with_empty_secret_is_refused() -> None:
    with pytest.raises(ValueError):
        mint(secret="")


def test_minting_with_non_positive_ttl_is_refused() -> None:
    with pytest.raises(ValueError):
        mint_session_token(
            SECRET, user_id=USER_ID, org_id=ORG_ID, role=OrgRole.ADMIN, now=NOW, ttl_s=0
        )


# --- Bearer dependency --------------------------------------------------------


@pytest.mark.parametrize("role", list(OrgRole))
async def test_session_token_yields_role_derived_principal(
    role: OrgRole, database: Database
) -> None:
    await database.seed(role)
    token = mint(role=role)

    async with open_client(SECRET, database.uow) as client:
        response = await client.get("/whoami", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    body = response.json()
    assert body["org_id"] == ORG_ID
    assert body["user_id"] == USER_ID
    assert body["key_id"].startswith("ses_")
    assert body["is_platform_admin"] is False
    assert body["scopes"] == sorted(scope.value for scope in role_scopes(role))


async def test_session_auth_is_rejected_when_secret_is_unset() -> None:
    token = mint()

    async with open_client("") as client:
        response = await client.get("/whoami", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert response.json()["code"] == "UNAUTHORIZED"
    assert token not in response.text


async def test_session_token_signed_with_another_secret_is_rejected_over_http(
    database: Database,
) -> None:
    await database.seed()
    token = mint(secret=OTHER_SECRET)

    async with open_client(SECRET, database.uow) as client:
        response = await client.get("/whoami", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert token not in response.text


async def get_status(client: httpx.AsyncClient, token: str) -> httpx.Response:
    return await client.get("/whoami", headers={"Authorization": f"Bearer {token}"})


async def test_disabled_user_with_a_valid_token_is_rejected(database: Database) -> None:
    await database.seed(disabled=True)
    token = mint()

    async with open_client(SECRET, database.uow) as client:
        response = await get_status(client, token)

    assert response.status_code == 401
    assert response.json()["message"] == "invalid API key"


async def test_unknown_user_with_a_valid_token_is_rejected(database: Database) -> None:
    token = mint()

    async with open_client(SECRET, database.uow) as client:
        response = await get_status(client, token)

    assert response.status_code == 401


async def test_removed_membership_is_rejected(database: Database) -> None:
    await database.seed(role=None)
    token = mint()

    async with open_client(SECRET, database.uow) as client:
        response = await get_status(client, token)

    assert response.status_code == 401
    assert response.json()["message"] == "invalid API key"


async def test_stale_role_is_rejected_and_the_current_role_passes(database: Database) -> None:
    await database.seed(role=OrgRole.VIEWER)
    stale = mint(role=OrgRole.ADMIN)
    current = mint(role=OrgRole.VIEWER)

    async with open_client(SECRET, database.uow) as client:
        rejected = await get_status(client, stale)
        accepted = await get_status(client, current)

    assert rejected.status_code == 401
    assert accepted.status_code == 200
    assert accepted.json()["scopes"] == sorted(s.value for s in role_scopes(OrgRole.VIEWER))


async def test_token_for_another_org_than_the_sso_org_is_rejected(database: Database) -> None:
    await database.seed()
    token = mint()

    async with open_client(SECRET, database.uow, sso_org_id=OTHER_ORG_ID) as client:
        response = await get_status(client, token)

    assert response.status_code == 401


async def test_token_for_the_configured_sso_org_passes(database: Database) -> None:
    await database.seed()
    token = mint()

    async with open_client(SECRET, database.uow, sso_org_id=ORG_ID) as client:
        response = await get_status(client, token)

    assert response.status_code == 200


# --- settings loader ----------------------------------------------------------

SSO_ENV = {
    "SANDFORT_SESSION_SECRET": GOOD_SECRET,
    "SANDFORT_SESSION_TTL_S": "3600",
    "SANDFORT_OIDC_ISSUER": "https://idp.example.test",
    "SANDFORT_OIDC_JWKS_URL": "https://idp.example.test/jwks.json",
    "SANDFORT_OIDC_JWKS_CACHE_S": "300",
}


def test_valid_session_and_sso_settings_load() -> None:
    settings = Settings.from_env(SSO_ENV)

    assert settings.session_secret == GOOD_SECRET
    assert settings.session_ttl_s == 3600


def test_empty_session_secret_and_no_issuer_still_load() -> None:
    assert Settings.from_env({}).session_secret == ""


def test_localhost_http_key_set_url_is_allowed_for_development() -> None:
    env = {**SSO_ENV, "SANDFORT_OIDC_JWKS_URL": "http://localhost:8080/jwks.json"}

    assert Settings.from_env(env).oidc_jwks_url.startswith("http://localhost")


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("SANDFORT_SESSION_SECRET", "x", "SESSION_SECRET"),
        ("SANDFORT_SESSION_SECRET", "s" * 31, "SESSION_SECRET"),
        ("SANDFORT_OIDC_JWKS_URL", "http://idp.example.test/jwks.json", "OIDC_JWKS_URL"),
        ("SANDFORT_OIDC_JWKS_URL", "", "OIDC_JWKS_URL"),
        ("SANDFORT_OIDC_JWKS_CACHE_S", "0", "OIDC_JWKS_CACHE_S"),
        ("SANDFORT_OIDC_JWKS_CACHE_S", "-5", "OIDC_JWKS_CACHE_S"),
        ("SANDFORT_SESSION_TTL_S", "59", "SESSION_TTL_S"),
        ("SANDFORT_SESSION_TTL_S", "86401", "SESSION_TTL_S"),
    ],
)
def test_weak_session_settings_are_rejected_at_load(name: str, value: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        Settings.from_env({**SSO_ENV, name: value})
