"""Egress v2 round 3: create and reset mint ``sfe2_`` tokens (docs/egress-v2-design.md 5.1).

A create with an allowlist mints a v2 token with epoch 0 and stores ``egress_policy_generation``
1 (a ``[]`` create stores 1 but mints nothing, an absent allowlist stores 0). A reset raises
``egress_credential_epoch`` by 1 and mints with the new epoch, and lifts a legacy row (generation
0) to at least 1. ``Lifecycle.refresh_egress`` persists epoch, generation and env in one update.
The env layout and the lifetime rule are the v1 ones. Through ``SandboxService`` on the fake
driver, a frozen clock and a temp SQLite database; the refresh case uses an in-memory unit of work.
"""

import sqlite3
from collections.abc import AsyncIterator
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
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
from sandfort.domain.sandbox import ERROR_RESET_FAILED, NetworkPolicy, Sandbox, SandboxState
from sandfort.drivers.base import ExecRequest
from sandfort.drivers.errors import DriverError
from sandfort.drivers.fake import FakeDriver
from sandfort.egress.env import (
    NO_PROXY_HOSTS,
    NO_PROXY_VARIABLES,
    PROXY_VARIABLES,
    EgressReminting,
    compose_proxy_env,
)
from sandfort.egress.tokens import EGRESS_PREFIX, InvalidEgressToken, verify_egress_token
from sandfort.egress.tokens_v2 import EGRESS_V2_PREFIX, EgressClaimsV2, verify_egress_token_v2
from sandfort.ids import new_org_id
from sandfort.services.sandbox_jobs import Lifecycle
from sandfort.services.sandboxes import CreateSandboxCommand, SandboxService

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 24, 9, 0, tzinfo=UTC)
PEPPER = "test-pepper"
ACTOR = "key_test"
PROXY_ADDRESS = "proxy.internal:3128"
EGRESS_SECRET = "e" * 40
ALLOWED = ("api.example-provider.com",)
DAY_S = 24 * 3600
TTL_S = 2 * DAY_S  # differs from the 7-day minter default
HOUR_MINUTES = 60
ORG = "org_mint"
SANDBOX = "sbx_mint"


@dataclass(frozen=True)
class Harness:
    service: SandboxService
    driver: FakeDriver
    clock: FrozenClock
    org_id: str
    db_path: Path


@pytest.fixture
async def harness(tmp_path: Path) -> AsyncIterator[Harness]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    db_path = tmp_path / "egress-mint.db"
    url = f"sqlite+aiosqlite:///{db_path}"
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
        yield Harness(service, driver, clock, org.id, db_path)
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


async def create(
    harness: Harness,
    allowlist: tuple[str, ...] | None = ALLOWED,
    auto_delete_minutes: int = -1,
) -> Sandbox:
    request = CreateSandboxCommand(
        name="egress", egress_allowlist=allowlist, auto_delete_minutes=auto_delete_minutes
    )
    return await harness.service.create(harness.org_id, ACTOR, request)


async def stored(harness: Harness, sandbox_id: str) -> Sandbox:
    return await harness.service.get(harness.org_id, sandbox_id)


def force_generation(harness: Harness, sandbox_id: str, generation: int) -> None:
    """Write the generation straight into the table, as a pre-r0027 row would carry it."""
    with closing(sqlite3.connect(harness.db_path)) as connection:
        connection.execute(
            "UPDATE sandboxes SET egress_policy_generation = ? WHERE id = ?",
            (generation, sandbox_id),
        )
        connection.commit()


# ---- create ----------------------------------------------------------------------------------


async def test_create_with_an_allowlist_mints_a_v2_token_at_epoch_zero(harness: Harness) -> None:
    created = await create(harness)

    row = await stored(harness, created.id)
    token = token_of(dict(row.env))
    assert token.startswith(EGRESS_V2_PREFIX)
    claims = claims_of(dict(row.env), NOW)
    assert claims.sandbox_id == created.id
    assert claims.epoch == 0
    assert row.egress_allowlist == ALLOWED
    assert row.egress_policy_generation == 1
    assert row.egress_credential_epoch == 0
    assert token_of(await container_env(harness, row.driver_ref)) == token


async def test_the_v1_verifier_refuses_the_minted_token(harness: Harness) -> None:
    created = await create(harness)

    token = token_of(dict(created.env))

    assert not token.startswith(EGRESS_PREFIX)
    with pytest.raises(InvalidEgressToken):
        verify_egress_token(EGRESS_SECRET, token, NOW)


async def test_the_proxy_environment_layout_is_unchanged(harness: Harness) -> None:
    created = await create(harness)

    assert len(PROXY_VARIABLES) == 4
    token = token_of(dict(created.env))
    for name in PROXY_VARIABLES:
        proxy = urlsplit(created.env[name])
        assert proxy.scheme == "http"
        assert proxy.hostname == "proxy.internal"
        assert proxy.port == 3128
        assert proxy.username == created.id
        assert proxy.password is not None
        assert unquote(proxy.password) == token
    for name in NO_PROXY_VARIABLES:
        assert created.env[name] == NO_PROXY_HOSTS
    assert set(created.env) == {*PROXY_VARIABLES, *NO_PROXY_VARIABLES}


async def test_create_without_auto_delete_uses_the_settings_lifetime(harness: Harness) -> None:
    created = await create(harness)

    assert lifetime_of(dict(created.env), NOW) == timedelta(seconds=TTL_S)


async def test_create_follows_the_auto_delete_horizon(harness: Harness) -> None:
    created = await create(harness, auto_delete_minutes=HOUR_MINUTES)

    assert lifetime_of(dict(created.env), NOW) == timedelta(hours=1, days=1)


async def test_create_caps_a_long_horizon_at_the_settings_lifetime(harness: Harness) -> None:
    created = await create(harness, auto_delete_minutes=10 * DAY_S // 60)

    assert lifetime_of(dict(created.env), NOW) == timedelta(seconds=TTL_S)


async def test_create_without_an_allowlist_stores_generation_zero_and_mints_nothing(
    harness: Harness,
) -> None:
    created = await create(harness, allowlist=None)

    row = await stored(harness, created.id)
    assert row.egress_allowlist is None
    assert row.egress_policy_generation == 0
    assert row.egress_credential_epoch == 0
    assert not set(row.env) & {*PROXY_VARIABLES, *NO_PROXY_VARIABLES}
    assert not any(value.startswith(EGRESS_V2_PREFIX) for value in row.env.values())


async def test_create_with_an_empty_allowlist_stores_generation_one_and_mints_nothing(
    harness: Harness,
) -> None:
    created = await create(harness, allowlist=())

    row = await stored(harness, created.id)
    assert row.egress_allowlist == ()
    assert row.egress_policy_generation == 1
    assert row.egress_credential_epoch == 0
    assert not set(row.env) & {*PROXY_VARIABLES, *NO_PROXY_VARIABLES}


# ---- reset -------------------------------------------------------------------------


async def test_reset_raises_the_epoch_and_mints_with_it(harness: Harness) -> None:
    created = await create(harness, auto_delete_minutes=HOUR_MINUTES)
    before = dict((await stored(harness, created.id)).env)
    later = harness.clock.advance(timedelta(minutes=5))

    reset = await harness.service.reset(harness.org_id, ACTOR, created.id)

    row = await stored(harness, created.id)
    assert row.egress_credential_epoch == 1
    assert row.egress_policy_generation == 1
    after = dict(reset.env)
    assert dict(row.env) == after
    assert token_of(after).startswith(EGRESS_V2_PREFIX)
    assert token_of(after) != token_of(before)
    claims = claims_of(after, later)
    assert claims.sandbox_id == created.id
    assert claims.epoch == 1
    assert claims.issued_at == later
    assert lifetime_of(after, later) == timedelta(hours=1, days=1)
    assert token_of(await container_env(harness, reset.driver_ref)) == token_of(after)


async def test_a_second_reset_stores_epoch_two(harness: Harness) -> None:
    created = await create(harness)
    await harness.service.reset(harness.org_id, ACTOR, created.id)
    harness.clock.advance(timedelta(minutes=1))

    second = await harness.service.reset(harness.org_id, ACTOR, created.id)

    row = await stored(harness, created.id)
    assert row.egress_credential_epoch == 2
    assert claims_of(dict(second.env), harness.clock.now()).epoch == 2
    assert row.egress_policy_generation == 1


async def test_a_reset_of_a_legacy_row_upgrades_it_to_generation_one(harness: Harness) -> None:
    created = await create(harness)
    force_generation(harness, created.id, 0)
    assert (await stored(harness, created.id)).egress_policy_generation == 0

    reset = await harness.service.reset(harness.org_id, ACTOR, created.id)

    row = await stored(harness, created.id)
    assert row.egress_policy_generation == 1
    assert row.egress_credential_epoch == 1
    assert claims_of(dict(reset.env), harness.clock.now()).epoch == 1


async def test_a_reset_keeps_a_generation_above_one(harness: Harness) -> None:
    created = await create(harness)
    force_generation(harness, created.id, 5)

    await harness.service.reset(harness.org_id, ACTOR, created.id)

    row = await stored(harness, created.id)
    assert row.egress_policy_generation == 5  # max(1, current)
    assert row.egress_credential_epoch == 1


async def test_a_reset_after_a_patch_to_empty_still_raises_the_epoch(harness: Harness) -> None:
    created = await create(harness)
    old_token_epoch = claims_of(dict(created.env), harness.clock.now()).epoch
    await harness.service.update(harness.org_id, ACTOR, created.id, egress_allowlist=())
    assert (await stored(harness, created.id)).egress_allowlist == ()

    reset = await harness.service.reset(harness.org_id, ACTOR, created.id)
    await harness.service.update(harness.org_id, ACTOR, created.id, egress_allowlist=ALLOWED)

    row = await stored(harness, created.id)
    assert row.egress_allowlist == ALLOWED
    assert row.egress_credential_epoch == 1
    assert old_token_epoch != row.egress_credential_epoch  # the copied-out token stays revoked
    assert claims_of(dict(reset.env), harness.clock.now()).epoch == 1


async def test_a_destroy_failure_during_reset_is_recorded_as_a_failed_reset(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    created = await create(harness)

    async def failing_destroy(ref: str, *, remove_volumes: bool = True) -> None:
        raise DriverError("cannot remove the container", ref=ref)

    monkeypatch.setattr(harness.driver, "destroy", failing_destroy)

    with pytest.raises(DriverError):
        await harness.service.reset(harness.org_id, ACTOR, created.id)

    row = await stored(harness, created.id)
    assert row.state is SandboxState.ERROR
    assert row.error_code == ERROR_RESET_FAILED
    assert row.driver_ref == created.driver_ref  # the old container is still the one on record
    assert row.egress_credential_epoch == 1  # the fail-closed bump stays


# ---- Lifecycle.refresh_egress ----------------------------------------------------------------


class _Sandboxes:
    """In-memory sandbox repository that records every write."""

    def __init__(self, sandbox: Sandbox) -> None:
        self.rows = {sandbox.id: sandbox}
        self.writes: list[Sandbox] = []

    async def get(self, org_id: str, sandbox_id: str) -> Sandbox | None:
        row = self.rows.get(sandbox_id)
        return row if row is not None and row.org_id == org_id else None

    async def update(self, org_id: str, sandbox: Sandbox, expected_version: int) -> Sandbox:
        assert self.rows[sandbox.id].version == expected_version
        saved = sandbox.model_copy(update={"version": expected_version + 1})
        self.rows[sandbox.id] = saved
        self.writes.append(saved)
        return saved


class _Uow:
    def __init__(self, sandboxes: _Sandboxes) -> None:
        self.sandboxes = sandboxes

    async def __aenter__(self) -> "_Uow":
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def commit(self) -> None:
        return None


def _stored_row(*, generation: int, epoch: int) -> Sandbox:
    env = {"KEEP": "1", **compose_proxy_env(PROXY_ADDRESS, EGRESS_SECRET, SANDBOX, NOW, epoch=0)}
    return Sandbox(
        id=SANDBOX,
        org_id=ORG,
        name="refresh",
        state=SandboxState.STARTED,
        image_ref="alpine:3.20",
        driver="fake",
        driver_ref="ref-1",
        env=env,
        egress_allowlist=ALLOWED,
        egress_policy_generation=generation,
        egress_credential_epoch=epoch,
        auto_delete_minutes=60,
        created_at=NOW,
        updated_at=NOW,
    )


def _lifecycle(rows: _Sandboxes, now: datetime) -> Lifecycle:
    uow_factory: Any = lambda: _Uow(rows)  # noqa: E731
    driver: Any = None
    reminting = EgressReminting(PROXY_ADDRESS, EGRESS_SECRET, TTL_S)
    return Lifecycle(uow_factory, driver, FrozenClock(now), egress=reminting)


@pytest.mark.parametrize(
    ("generation", "epoch", "want_generation", "want_epoch"),
    [(1, 0, 1, 1), (3, 4, 3, 5), (0, 0, 1, 1)],
)
async def test_refresh_egress_persists_epoch_generation_and_env_in_one_update(
    generation: int, epoch: int, want_generation: int, want_epoch: int
) -> None:
    rows = _Sandboxes(_stored_row(generation=generation, epoch=epoch))
    old_env = dict(rows.rows[SANDBOX].env)
    later = NOW + timedelta(days=1)

    saved = await _lifecycle(rows, later).refresh_egress(ORG, SANDBOX)

    assert rows.writes == [saved]  # a single update carries all three fields
    assert saved.egress_credential_epoch == want_epoch
    assert saved.egress_policy_generation == want_generation
    assert saved.env["KEEP"] == "1"
    assert token_of(dict(saved.env)) != token_of(old_env)
    claims = claims_of(dict(saved.env), later)
    assert claims.sandbox_id == SANDBOX
    assert claims.epoch == want_epoch
    assert claims.issued_at == later


async def test_refresh_egress_leaves_a_sandbox_without_an_allowlist_alone() -> None:
    row = _stored_row(generation=0, epoch=0).model_copy(
        update={"egress_allowlist": None, "env": {"KEEP": "1"}}
    )
    rows = _Sandboxes(row)

    saved = await _lifecycle(rows, NOW).refresh_egress(ORG, SANDBOX)

    assert rows.writes == []
    assert saved.egress_credential_epoch == 0
    assert saved.egress_policy_generation == 0
    assert dict(saved.env) == {"KEEP": "1"}


async def test_refresh_egress_bumps_the_epoch_of_a_sandbox_patched_to_empty() -> None:
    row = _stored_row(generation=2, epoch=0).model_copy(update={"egress_allowlist": ()})
    rows = _Sandboxes(row)

    saved = await _lifecycle(rows, NOW).refresh_egress(ORG, SANDBOX)

    assert saved.egress_credential_epoch == 1
    assert claims_of(dict(saved.env), NOW).epoch == 1


async def test_refresh_egress_leaves_a_blocked_sandbox_without_a_proxy_environment() -> None:
    row = _stored_row(generation=1, epoch=0).model_copy(
        update={
            "egress_allowlist": (),
            "network": NetworkPolicy(block_all=True),
            "env": {"KEEP": "1"},
        }
    )
    rows = _Sandboxes(row)

    saved = await _lifecycle(rows, NOW).refresh_egress(ORG, SANDBOX)

    assert rows.writes == []
    assert dict(saved.env) == {"KEEP": "1"}
    assert saved.egress_credential_epoch == 0
