"""Egress token lifetime at create, and a fresh token on reset (audit r58 follow-up).

A create mints the token with the settings lifetime (``egress_token_ttl_s``), shortened to the
sandbox's auto-delete horizon plus one day. A reset recreates the container, so it re-mints the
token into the row and the new container. A start keeps the container and so keeps its token.
Through ``SandboxService`` on the fake driver, a frozen clock and a temp SQLite database.
"""

from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import Org
from sandfort.drivers.base import ExecRequest
from sandfort.drivers.fake import FakeDriver
from sandfort.egress.tokens_v2 import EgressClaimsV2, verify_egress_token_v2
from sandfort.ids import new_org_id
from sandfort.services.sandboxes import CreateSandboxCommand, SandboxService

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 12, 9, 0, tzinfo=UTC)
PEPPER = "test-pepper"
ACTOR = "key_test"
PROXY_ADDRESS = "proxy.internal:3128"
EGRESS_SECRET = "e" * 40
ALLOWED = ("api.example-provider.com",)
DAY_S = 24 * 3600
TTL_S = 2 * DAY_S  # differs from the 7-day minter default
HOUR_MINUTES = 60


@dataclass(frozen=True)
class Harness:
    service: SandboxService
    driver: FakeDriver
    clock: FrozenClock
    org_id: str


@pytest.fixture
async def harness(tmp_path: Path) -> AsyncIterator[Harness]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'egress-ttl.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(
        driver="fake",
        database_url=url,
        api_key_pepper=PEPPER,
        autostop_enabled=False,
        egress_proxy_address=PROXY_ADDRESS,
        egress_secret=EGRESS_SECRET,
        egress_token_ttl_s=TTL_S,
    )
    app: FastAPI = create_app(settings)
    clock = FrozenClock(NOW)
    driver = FakeDriver(clock)
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    service = SandboxService(lambda: UnitOfWork(app.state.session_factory), driver, settings, clock)
    try:
        yield Harness(service, driver, clock, org.id)
    finally:
        await app.state.engine.dispose()


def token_of(env: dict[str, str]) -> str:
    password = urlsplit(env["https_proxy"]).password
    assert password is not None
    return unquote(password)


def claims_of(env: dict[str, str], now: datetime) -> EgressClaimsV2:
    return verify_egress_token_v2(EGRESS_SECRET, token_of(env), now)


def lifetime_of(env: dict[str, str], now: datetime) -> timedelta:
    claims = claims_of(env, now)
    return claims.expires_at - claims.issued_at


async def container_env(harness: Harness, ref: str | None) -> dict[str, str]:
    """The environment the container was created with, read through the driver."""
    assert ref is not None
    result = await harness.driver.exec(ref, ExecRequest(argv=["env"]))
    pairs = (line.split("=", 1) for line in result.stdout.decode().splitlines() if "=" in line)
    return {name: value for name, value in pairs}


async def create(harness: Harness, auto_delete_minutes: int = -1) -> str:
    request = CreateSandboxCommand(
        name="egress", egress_allowlist=ALLOWED, auto_delete_minutes=auto_delete_minutes
    )
    created = await harness.service.create(harness.org_id, ACTOR, request)
    return created.id


async def stored_env(harness: Harness, sandbox_id: str) -> dict[str, str]:
    sandbox = await harness.service.get(harness.org_id, sandbox_id)
    return dict(sandbox.env)


# ---- create ----------------------------------------------------------------------------------


async def test_create_without_auto_delete_uses_the_settings_lifetime(harness: Harness) -> None:
    sandbox_id = await create(harness)

    env = await stored_env(harness, sandbox_id)

    assert lifetime_of(env, NOW) == timedelta(seconds=TTL_S)


async def test_create_follows_the_auto_delete_horizon(harness: Harness) -> None:
    sandbox_id = await create(harness, auto_delete_minutes=HOUR_MINUTES)

    env = await stored_env(harness, sandbox_id)

    assert lifetime_of(env, NOW) == timedelta(hours=1, days=1)


async def test_create_caps_a_long_horizon_at_the_settings_lifetime(harness: Harness) -> None:
    sandbox_id = await create(harness, auto_delete_minutes=10 * DAY_S // 60)

    env = await stored_env(harness, sandbox_id)

    assert lifetime_of(env, NOW) == timedelta(seconds=TTL_S)


# ---- reset and start -------------------------------------------------------------------------


async def test_reset_mints_a_new_token_into_the_row_and_the_container(harness: Harness) -> None:
    sandbox_id = await create(harness, auto_delete_minutes=HOUR_MINUTES)
    before = await stored_env(harness, sandbox_id)
    later = harness.clock.advance(timedelta(minutes=5))

    reset = await harness.service.reset(harness.org_id, ACTOR, sandbox_id)

    after = dict(reset.env)
    assert token_of(after) != token_of(before)
    assert claims_of(after, later).issued_at == later
    assert lifetime_of(after, later) == timedelta(hours=1, days=1)
    assert token_of(await container_env(harness, reset.driver_ref)) == token_of(after)


async def test_start_keeps_the_token_the_container_was_created_with(harness: Harness) -> None:
    sandbox_id = await create(harness, auto_delete_minutes=HOUR_MINUTES)
    before = await stored_env(harness, sandbox_id)
    await harness.service.stop(harness.org_id, ACTOR, sandbox_id)
    harness.clock.advance(timedelta(minutes=5))

    started = await harness.service.start(harness.org_id, ACTOR, sandbox_id)

    assert token_of(dict(started.env)) == token_of(before)
    assert token_of(await container_env(harness, started.driver_ref)) == token_of(before)
