"""Egress token lifetime without breaking running sandboxes (audit r58 follow-up).

Tokens issued before the cut-over are accepted whatever their lifetime (logged once per
sandbox); later ones must respect the proxy maximum. New tokens follow the auto-delete
horizon, the settings value reaches the minter, a start keeps the stored token (it reuses the
container) and a reset re-mints it (it recreates the container).
"""

import asyncio
import base64
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import unquote, urlsplit

import pytest

from sandfort.clock import FrozenClock
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.egress.env import compose_proxy_env
from sandfort.egress.proxy import EgressProxy, ProxyConfig
from sandfort.egress.tokens import (
    LEGACY_TOKEN_CUTOVER,
    InvalidEgressToken,
    mint_egress_token,
    token_lifetime_s,
    verify_egress_token,
)
from sandfort.egress.tokens_v2 import verify_egress_token_v2
from sandfort.services.sandbox_jobs import EgressReminting, Lifecycle

SECRET = "test-egress-secret-r58-tokens"
SANDBOX = "sbx_legacy"
ORG = "org_test"
ALLOWED = "allowed.test"
ADDRESS = "10.0.0.1:3128"
DAY_S = 24 * 3600
WEEK_S = 7 * DAY_S
TTL_ENV = "SANDFORT_EGRESS_TOKEN_TTL_S"
BEFORE_CUTOVER = datetime(2026, 10, 1, tzinfo=UTC)
AFTER_CUTOVER = LEGACY_TOKEN_CUTOVER + timedelta(days=1)
IO_TIMEOUT_S = 5.0


def _mint(now: datetime, ttl_s: int, sandbox_id: str = SANDBOX) -> str:
    return mint_egress_token(
        SECRET, sandbox_id=sandbox_id, allowlist=[ALLOWED], now=now, ttl_s=ttl_s
    )


def _lifetime(token: str, now: datetime) -> timedelta:
    claims = verify_egress_token_v2(SECRET, token, now)
    return claims.expires_at - claims.issued_at


def _token_of(env: dict[str, str]) -> str:
    password = urlsplit(env["https_proxy"]).password
    assert password is not None
    return unquote(password)


def _proxy_env(now: datetime, ttl_s: int) -> dict[str, str]:
    return compose_proxy_env(ADDRESS, SECRET, SANDBOX, now, epoch=0, ttl_s=ttl_s)


# ---- 1. legacy tokens and the cut-over ------------------------------------------------------


def test_cutover_is_the_eleventh_of_november() -> None:
    assert LEGACY_TOKEN_CUTOVER == datetime(2026, 11, 11, tzinfo=UTC)


def test_legacy_token_is_accepted_regardless_of_lifetime() -> None:
    token = _mint(BEFORE_CUTOVER, 400 * DAY_S)
    later = BEFORE_CUTOVER + timedelta(days=60)

    claims = verify_egress_token(SECRET, token, later, WEEK_S, legacy_before=LEGACY_TOKEN_CUTOVER)

    assert claims.sandbox_id == SANDBOX
    with pytest.raises(InvalidEgressToken):
        verify_egress_token(SECRET, token, later, WEEK_S)  # no cut-over: the limit applies


def test_legacy_token_still_expires() -> None:
    token = _mint(BEFORE_CUTOVER, 30 * DAY_S)

    with pytest.raises(InvalidEgressToken):
        verify_egress_token(
            SECRET,
            token,
            BEFORE_CUTOVER + timedelta(days=31),
            WEEK_S,
            legacy_before=LEGACY_TOKEN_CUTOVER,
        )


def test_post_cutover_long_token_is_refused() -> None:
    token = _mint(AFTER_CUTOVER, 30 * DAY_S)

    with pytest.raises(InvalidEgressToken):
        verify_egress_token(
            SECRET, token, AFTER_CUTOVER, WEEK_S, legacy_before=LEGACY_TOKEN_CUTOVER
        )
    short = _mint(AFTER_CUTOVER, WEEK_S)
    verify_egress_token(SECRET, short, AFTER_CUTOVER, WEEK_S, legacy_before=LEGACY_TOKEN_CUTOVER)


@asynccontextmanager
async def _serving(proxy: EgressProxy) -> AsyncIterator[int]:
    server = await proxy.start("127.0.0.1", 0)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()


async def _status(port: int, token: str, sandbox_id: str = SANDBOX) -> int:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    credential = base64.b64encode(f"{sandbox_id}:{token}".encode()).decode("ascii")
    request = (
        "CONNECT elsewhere.test:443 HTTP/1.1\r\n"
        "Host: elsewhere.test:443\r\n"
        f"Proxy-Authorization: Basic {credential}\r\n\r\n"
    )
    writer.write(request.encode("ascii"))
    await writer.drain()
    line = await asyncio.wait_for(reader.readline(), IO_TIMEOUT_S)
    writer.close()
    return int(line.split()[1])


async def test_configured_proxy_accepts_a_legacy_token_and_logs_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = ProxyConfig.from_env({"SANDFORT_EGRESS_SECRET": SECRET})
    proxy = EgressProxy.from_config(config)
    legacy = _mint(BEFORE_CUTOVER, 400 * DAY_S)

    with caplog.at_level(logging.INFO, logger="sandfort.egress"):
        async with _serving(proxy) as port:
            # 403 (host not allowlisted) proves the credential passed; 407 would refuse it
            assert await _status(port, legacy) == 403
            assert await _status(port, legacy) == 403

    notes = [r for r in caplog.records if "legacy egress token" in r.getMessage()]
    assert len(notes) == 1
    assert SANDBOX in notes[0].getMessage()
    assert legacy not in caplog.text


# ---- 2. lifetime of new tokens ----------------------------------------------------------------


def test_lifetime_follows_the_auto_delete_horizon() -> None:
    assert token_lifetime_s(WEEK_S, 60) == 60 * 60 + DAY_S
    assert token_lifetime_s(WEEK_S, 0) == DAY_S


def test_lifetime_without_auto_delete_is_the_maximum() -> None:
    assert token_lifetime_s(WEEK_S, -1) == WEEK_S
    assert token_lifetime_s(WEEK_S, None) == WEEK_S


def test_lifetime_never_exceeds_the_maximum() -> None:
    assert token_lifetime_s(WEEK_S, 30 * 24 * 60) == WEEK_S


def test_composer_mints_for_the_auto_delete_horizon() -> None:
    now = datetime(2026, 11, 12, tzinfo=UTC)

    env = compose_proxy_env(
        ADDRESS, SECRET, SANDBOX, now, epoch=0, ttl_s=WEEK_S, auto_delete_minutes=120
    )

    assert _lifetime(_token_of(env), now) == timedelta(hours=2, days=1)


# ---- 3. the settings value reaches the minter -----------------------------------------------


def test_settings_value_is_honoured_over_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(TTL_ENV, str(30 * DAY_S))
    now = datetime(2026, 11, 12, tzinfo=UTC)

    env = _proxy_env(now, 3600)

    assert _lifetime(_token_of(env), now) == timedelta(hours=1)


def test_reminting_settings_carry_the_configured_lifetime() -> None:
    reminting = EgressReminting(proxy_address=ADDRESS, secret=SECRET, max_ttl_s=3600)

    assert reminting.max_ttl_s == 3600
    assert SECRET not in repr(reminting)


# ---- 4. a start keeps the token, a reset re-mints it ------------------------------------------


class _Sandboxes:
    def __init__(self, sandbox: Sandbox) -> None:
        self.rows = {sandbox.id: sandbox}

    async def get(self, org_id: str, sandbox_id: str) -> Sandbox | None:
        row = self.rows.get(sandbox_id)
        return row if row is not None and row.org_id == org_id else None

    async def update(self, org_id: str, sandbox: Sandbox, expected_version: int) -> Sandbox:
        assert self.rows[sandbox.id].version == expected_version
        saved = sandbox.model_copy(update={"version": expected_version + 1})
        self.rows[sandbox.id] = saved
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


class _Driver:
    def __init__(self) -> None:
        self.started: list[str] = []

    async def start(self, ref: str) -> None:
        self.started.append(ref)


def _stored(env: dict[str, str], **changes: Any) -> Sandbox:
    base = Sandbox(
        id=SANDBOX,
        org_id=ORG,
        name="legacy",
        state=SandboxState.STARTING,
        image_ref="alpine:3.20",
        driver="fake",
        driver_ref="ref-1",
        env=env,
        egress_allowlist=(ALLOWED,),
        auto_delete_minutes=60,
        created_at=BEFORE_CUTOVER,
        updated_at=BEFORE_CUTOVER,
    )
    return base.model_copy(update=changes)


def _lifecycle(
    sandbox: Sandbox, reminting: EgressReminting | None, now: datetime
) -> tuple[Lifecycle, _Sandboxes, _Driver]:
    rows, driver = _Sandboxes(sandbox), _Driver()
    uow_factory: Any = lambda: _Uow(rows)  # noqa: E731
    fake_driver: Any = driver
    core = Lifecycle(uow_factory, fake_driver, FrozenClock(now), egress=reminting)
    return core, rows, driver


async def test_start_keeps_the_token_because_the_container_is_reused() -> None:
    old_env = {"KEEP": "1", **_proxy_env(BEFORE_CUTOVER, 400 * DAY_S)}
    reminting = EgressReminting(proxy_address=ADDRESS, secret=SECRET, max_ttl_s=WEEK_S)
    core, rows, driver = _lifecycle(_stored(old_env), reminting, AFTER_CUTOVER)

    started = await core.drive_start(ORG, SANDBOX)

    assert started.state is SandboxState.STARTED
    assert driver.started == ["ref-1"]
    assert rows.rows[SANDBOX].env == old_env


async def test_reset_remints_the_token_and_rewrites_the_env() -> None:
    old_env = {"KEEP": "1", **_proxy_env(BEFORE_CUTOVER, 400 * DAY_S)}
    now = AFTER_CUTOVER
    reminting = EgressReminting(proxy_address=ADDRESS, secret=SECRET, max_ttl_s=WEEK_S)
    core, rows, driver = _lifecycle(_stored(old_env), reminting, now)

    await core.refresh_egress(ORG, SANDBOX)  # what SandboxReset calls before recreating

    assert driver.started == []
    env = rows.rows[SANDBOX].env
    assert env["KEEP"] == "1"
    assert _token_of(env) != _token_of(old_env)
    assert _lifetime(_token_of(env), now) == timedelta(hours=1, days=1)
    verify_egress_token_v2(SECRET, _token_of(env), now, WEEK_S)
    assert env["no_proxy"] == old_env["no_proxy"]


async def test_reset_leaves_an_unrestricted_sandbox_alone() -> None:
    reminting = EgressReminting(proxy_address=ADDRESS, secret=SECRET, max_ttl_s=WEEK_S)
    sandbox = _stored({"KEEP": "1"}, egress_allowlist=None)
    core, rows, _ = _lifecycle(sandbox, reminting, AFTER_CUTOVER)

    await core.refresh_egress(ORG, SANDBOX)

    assert rows.rows[SANDBOX].env == {"KEEP": "1"}


async def test_start_without_reminting_keeps_the_stored_token() -> None:
    old_env = _proxy_env(BEFORE_CUTOVER, WEEK_S)
    core, rows, _ = _lifecycle(_stored(old_env), None, AFTER_CUTOVER)

    await core.drive_start(ORG, SANDBOX)

    assert rows.rows[SANDBOX].env == old_env
