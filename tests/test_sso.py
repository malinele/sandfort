"""OIDC single sign-on: an identity token is exchanged for a short-lived platform session.

Fully hermetic: RSA keys are generated here, identity tokens are minted with pyjwt, and respx
serves the key set at the configured url. Storage is a migrated temp SQLite database behind
the real application (FakeDriver); service-level cases run on a frozen clock.
"""

from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
import respx
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from jwt.algorithms import RSAAlgorithm

from sandfort.api.app import create_app
from sandfort.api.middleware.rate_limit import (
    EXCHANGE_BURST,
    EXCHANGE_LIMITER_ATTR,
    TokenBucketRateLimiter,
)
from sandfort.auth.oidc import OidcVerifier
from sandfort.auth.session_tokens import verify_session_token
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import AuditEvent
from sandfort.domain.org import Org
from sandfort.domain.user import OrgMembership, OrgRole, User
from sandfort.errors import Unauthorized
from sandfort.ids import new_org_id
from sandfort.services.sso import SESSION_CREATED, SsoService, SsoSession

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SECRET = "session-secret-for-sso-tests"
TTL_S = 900
ISSUER = "https://idp.example.test"
AUDIENCE = "sandfort-web"
JWKS_URL = "https://idp.example.test/.well-known/jwks.json"
KID = "signing-key-1"
EXCHANGE = "/v1/auth/sso/exchange"
MEMBERS = "/v1/org/members"
ADA_ID = "usr_ada"
ADA_EMAIL = "ada@example.com"
BOB_ID = "usr_bob"
BOB_EMAIL = "bob@example.com"
TOKEN_LIFETIME = timedelta(minutes=5)

SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
FOREIGN_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


@dataclass(frozen=True)
class World:
    app: FastAPI
    client: httpx.AsyncClient
    url: str
    org_id: str
    other_org_id: str


def key_set(private_key: rsa.RSAPrivateKey, kid: str = KID) -> dict[str, Any]:
    public = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    return {"keys": [{**public, "kid": kid, "alg": "RS256", "use": "sig"}]}


def identity_token(
    *,
    key: rsa.RSAPrivateKey = SIGNING_KEY,
    kid: str = KID,
    issued: datetime = NOW,
    typ: str = "JWT",
    omit: tuple[str, ...] = (),
    **overrides: Any,
) -> str:
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "idp-subject-ada",
        "email": "Ada@Example.COM",
        "email_verified": True,
        "iat": int(issued.timestamp()),
        "exp": int((issued + TOKEN_LIFETIME).timestamp()),
    }
    merged = {k: v for k, v in {**claims, **overrides}.items() if k not in omit}
    headers = {"kid": kid, "typ": typ}
    return jwt.encode(merged, key, algorithm="RS256", headers=headers)


def sso_settings(url: str, org_id: str, **overrides: Any) -> Settings:
    base = Settings(
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
    return replace(base, **overrides)


def make_org(org_id: str, slug: str) -> Org:
    return Org(id=org_id, name=slug.title(), slug=slug, created_at=NOW)


def make_user(user_id: str, email: str) -> User:
    return User(id=user_id, email=email, display_name=user_id.title(), created_at=NOW)


def make_membership(user_id: str, org_id: str, role: OrgRole) -> OrgMembership:
    return OrgMembership(user_id=user_id, org_id=org_id, role=role, created_at=NOW)


async def seed(app: FastAPI, org_id: str, other_org_id: str) -> None:
    """Ada is a developer in the single sign-on org; Bob only belongs to another org."""
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(make_org(org_id, "acme"))
        await uow.orgs.add(make_org(other_org_id, "globex"))
        await uow.users.add(make_user(ADA_ID, ADA_EMAIL))
        await uow.users.add(make_user(BOB_ID, BOB_EMAIL))
        await uow.memberships.add(make_membership(ADA_ID, org_id, OrgRole.DEVELOPER))
        await uow.memberships.add(make_membership(BOB_ID, other_org_id, OrgRole.ADMIN))
        await uow.commit()


@pytest.fixture
async def world(tmp_path: Path) -> AsyncIterator[World]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'sso.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    org_id, other_org_id = new_org_id(), new_org_id()
    app = create_app(sso_settings(url, org_id))
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            await seed(app, org_id, other_org_id)
            yield World(app, client, url, org_id, other_org_id)
    finally:
        await app.state.engine.dispose()


@pytest.fixture
def provider() -> Iterator[respx.MockRouter]:
    """The identity provider's key set endpoint; nothing else may leave the process."""
    with respx.mock(assert_all_called=False) as router:
        router.get(JWKS_URL).mock(return_value=httpx.Response(200, json=key_set(SIGNING_KEY)))
        yield router


def build_service(
    world: World, *, clock: FrozenClock | None = None, **overrides: Any
) -> SsoService:
    settings = sso_settings(world.url, world.org_id, **overrides)
    tick = clock or FrozenClock(NOW)

    def uow_factory() -> UnitOfWorkPort:
        return UnitOfWork(world.app.state.session_factory)

    return SsoService(uow_factory, OidcVerifier(settings, tick), tick, settings)


async def audit_rows(world: World, org_id: str) -> list[AuditEvent]:
    async with UnitOfWork(world.app.state.session_factory) as uow:
        return list(await uow.audit.list(org_id, limit=200))


async def refused(service: SsoService, token: str) -> Unauthorized:
    with pytest.raises(Unauthorized) as caught:
        await service.exchange(token)
    return caught.value


# --- success -----------------------------------------------------------------------------


async def test_valid_token_for_member_mints_session(
    world: World, provider: respx.MockRouter
) -> None:
    session: SsoSession = await build_service(world).exchange(identity_token())

    claims = verify_session_token(SECRET, session.token, NOW)
    assert claims.user_id == ADA_ID
    assert claims.org_id == world.org_id
    assert claims.role is OrgRole.DEVELOPER
    assert session.role is OrgRole.DEVELOPER
    assert session.expires_at == NOW + timedelta(seconds=TTL_S)
    assert claims.expires_at == session.expires_at

    rows = await audit_rows(world, world.org_id)
    created = [row for row in rows if row.action == SESSION_CREATED]
    assert len(created) == 1
    assert created[0].target_id == ADA_ID
    assert created[0].actor_id == claims.token_id
    assert created[0].details["email"] == ADA_EMAIL
    assert session.token not in str(created[0].details)


async def test_exchange_route_session_authenticates_requests(
    world: World, provider: respx.MockRouter
) -> None:
    # The application runs on the system clock, so this token is minted against it.
    token = identity_token(issued=datetime.now(UTC))

    exchanged = await world.client.post(EXCHANGE, json={"id_token": token})
    assert exchanged.status_code == 200, exchanged.text
    body = exchanged.json()
    assert body["success"] is True
    assert body["data"]["role"] == OrgRole.DEVELOPER.value
    session_token = body["data"]["session_token"]

    headers = {"Authorization": f"Bearer {session_token}"}
    members = await world.client.get(MEMBERS, headers=headers)
    assert members.status_code == 200, members.text
    assert [member["email"] for member in members.json()["data"]] == [ADA_EMAIL]


async def test_exchange_flood_is_answered_429_after_the_burst(
    world: World, provider: respx.MockRouter
) -> None:
    clock = FrozenClock(NOW)  # deterministic refill: the real limiter only differs in its clock
    limiter = TokenBucketRateLimiter(clock, refill_per_s=1, burst=EXCHANGE_BURST)
    setattr(world.app.state, EXCHANGE_LIMITER_ATTR, limiter)
    body = {"id_token": identity_token()}

    first = [await world.client.post(EXCHANGE, json=body) for _ in range(EXCHANGE_BURST)]
    flooded = await world.client.post(EXCHANGE, json=body)

    assert all(response.status_code != 429 for response in first)
    assert flooded.status_code == 429
    assert flooded.json()["error"]["code"] == "RATE_LIMITED"
    assert flooded.headers["Retry-After"].isdigit()
    assert (await world.client.get("/healthz")).status_code == 200  # only the exchange is guarded
    clock.advance(timedelta(seconds=2))
    assert (await world.client.post(EXCHANGE, json=body)).status_code != 429


async def test_key_set_is_cached_for_the_configured_window(
    world: World, provider: respx.MockRouter
) -> None:
    clock = FrozenClock(NOW)
    service = build_service(world, clock=clock, oidc_jwks_cache_s=60)

    await service.exchange(identity_token())
    clock.advance(timedelta(seconds=30))
    await service.exchange(identity_token(issued=clock.now()))
    assert provider.calls.call_count == 1

    clock.advance(timedelta(seconds=31))
    await service.exchange(identity_token(issued=clock.now()))
    assert provider.calls.call_count == 2


# --- rejected identity tokens ------------------------------------------------------------


@pytest.mark.parametrize("kid", [KID, "unknown-key"], ids=["same-kid", "unknown-kid"])
async def test_token_signed_by_unknown_key_is_rejected(
    world: World, provider: respx.MockRouter, kid: str
) -> None:
    await refused(build_service(world), identity_token(key=FOREIGN_KEY, kid=kid))


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "someone-else"},
        {"iss": "https://evil.example.test"},
        {"email_verified": False},
        {"email": "   "},
        {"email_verified": "false"},
        {"email": "\u212aate@example.com"},
        {"aud": [AUDIENCE, "other-client"], "azp": "other-client"},
        {"aud": [AUDIENCE, "other-client"]},
        {"typ": "at+jwt"},
        {"omit": ("email_verified",)},
        {"omit": ("iat",)},
        {"iat": int((NOW - timedelta(seconds=301)).timestamp())},
    ],
    ids=[
        "wrong-audience",
        "wrong-issuer",
        "unverified-email",
        "blank-email",
        "string-false-email-verified",
        "kelvin-sign-email",
        "foreign-authorized-party",
        "list-audience-without-azp",
        "access-token-type",
        "missing-email-verified",
        "missing-iat",
        "stale-iat",
    ],
)
async def test_token_with_wrong_claims_is_rejected(
    world: World, provider: respx.MockRouter, overrides: dict[str, Any]
) -> None:
    await refused(build_service(world), identity_token(**overrides))


async def test_expired_token_is_rejected(world: World, provider: respx.MockRouter) -> None:
    expired = int((NOW - timedelta(seconds=61)).timestamp())
    await refused(build_service(world), identity_token(exp=expired))


async def test_token_expiring_at_the_end_of_the_leeway_is_rejected(
    world: World, provider: respx.MockRouter
) -> None:
    expired = int((NOW - timedelta(seconds=60)).timestamp())
    await refused(build_service(world), identity_token(exp=expired))


async def test_token_issued_in_the_future_beyond_leeway_is_rejected(
    world: World, provider: respx.MockRouter
) -> None:
    await refused(build_service(world), identity_token(issued=NOW + timedelta(seconds=61)))


async def test_strict_token_with_list_audience_and_matching_azp_exchanges(
    world: World, provider: respx.MockRouter
) -> None:
    token = identity_token(aud=[AUDIENCE, "other-client"], azp=AUDIENCE, typ="jwt")
    session = await build_service(world).exchange(token)
    assert session.role is OrgRole.DEVELOPER


async def test_malformed_token_is_rejected_without_fetching_keys(
    world: World, provider: respx.MockRouter
) -> None:
    await refused(build_service(world), "not-a-jwt")
    assert provider.calls.call_count == 0


# --- rejected identities -----------------------------------------------------------------


async def test_unknown_email_is_rejected(world: World, provider: respx.MockRouter) -> None:
    await refused(build_service(world), identity_token(email="nobody@example.com"))


async def test_member_of_a_different_org_is_rejected(
    world: World, provider: respx.MockRouter
) -> None:
    await refused(build_service(world), identity_token(email=BOB_EMAIL))


async def test_refusals_do_not_reveal_which_lookup_failed(
    world: World, provider: respx.MockRouter
) -> None:
    service = build_service(world)

    unknown = await refused(service, identity_token(email="nobody@example.com"))
    foreign = await refused(service, identity_token(email=BOB_EMAIL))

    assert unknown.message == foreign.message
    for org_id in (world.org_id, world.other_org_id):
        rows = await audit_rows(world, org_id)
        assert [row for row in rows if row.action == SESSION_CREATED] == []


# --- configuration -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "setting", ["oidc_issuer", "oidc_audience", "oidc_jwks_url", "oidc_org_id"]
)
async def test_exchange_is_refused_when_oidc_is_unconfigured(
    world: World, provider: respx.MockRouter, setting: str
) -> None:
    await refused(build_service(world, **{setting: ""}), identity_token())
    assert provider.calls.call_count == 0


async def test_exchange_route_is_refused_with_default_settings(world: World) -> None:
    app = create_app(Settings(driver="fake", database_url=world.url, api_key_pepper=PEPPER))
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(EXCHANGE, json={"id_token": identity_token()})
    finally:
        await app.state.engine.dispose()
    assert response.status_code == 401
    assert response.json()["success"] is False


async def test_exchange_is_refused_without_a_session_secret(
    world: World, provider: respx.MockRouter
) -> None:
    await refused(build_service(world, session_secret=""), identity_token())


async def test_unreachable_key_set_is_unauthorized_without_echoing_the_url(
    world: World,
) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(JWKS_URL).mock(return_value=httpx.Response(500))
        error = await refused(build_service(world), identity_token())
    assert JWKS_URL not in error.message
    assert "idp.example.test" not in error.message


def test_settings_read_oidc_from_the_environment() -> None:
    settings = Settings.from_env(
        {
            "SANDFORT_OIDC_ISSUER": ISSUER,
            "SANDFORT_OIDC_AUDIENCE": AUDIENCE,
            "SANDFORT_OIDC_JWKS_URL": JWKS_URL,
            "SANDFORT_OIDC_ORG_ID": "org_x",
            "SANDFORT_OIDC_JWKS_CACHE_S": "120",
        }
    )
    defaults = Settings.from_env({})

    assert (settings.oidc_issuer, settings.oidc_audience) == (ISSUER, AUDIENCE)
    assert (settings.oidc_jwks_url, settings.oidc_org_id) == (JWKS_URL, "org_x")
    assert settings.oidc_jwks_cache_s == 120
    assert defaults.oidc_issuer == ""
    assert defaults.oidc_jwks_cache_s == 300
