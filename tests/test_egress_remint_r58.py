"""The egress re-mint is wired from the settings (audit r58, HIGH).

``sandfort.wiring.wire_egress`` builds the re-minting settings and installs them for the job
handlers. A start does not recreate the container, so it leaves the stored token alone; a reset
(``Lifecycle.refresh_egress``) recreates it and mints a fresh one.
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import unquote, urlsplit

import pytest

from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.egress.env import EgressReminting, compose_proxy_env
from sandfort.egress.tokens import verify_egress_token
from sandfort.services.sandbox_jobs import (
    Lifecycle,
    handle_start,
    install_job_egress,
    job_lifecycle,
)
from sandfort.wiring import egress_reminting, wire_egress
from sandfort.workers.autostop import AutoStopScanner
from sandfort.workers.handlers import JobContext

SECRET = "test-egress-secret-r58-remint-0123456789"
ADDRESS = "10.0.0.1:3128"
SANDBOX = "sbx_remint"
ORG = "org_test"
ALLOWED = "allowed.test"
WEEK_S = 7 * 24 * 3600
ISSUED = datetime(2026, 11, 12, tzinfo=UTC)
LATER = ISSUED + timedelta(days=3)


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


def _token_of(env: dict[str, str]) -> str:
    password = urlsplit(env["https_proxy"]).password
    assert password is not None
    return unquote(password)


def _settings(**changes: Any) -> Settings:
    base: dict[str, Any] = {
        "egress_proxy_address": ADDRESS,
        "egress_secret": SECRET,
        "egress_token_ttl_s": WEEK_S,
    }
    return Settings(**{**base, **changes})


def _stored() -> Sandbox:
    env = {"KEEP": "1", **compose_proxy_env(ADDRESS, SECRET, SANDBOX, [ALLOWED], ISSUED)}
    return Sandbox(
        id=SANDBOX,
        org_id=ORG,
        name="remint",
        state=SandboxState.STARTING,
        image_ref="alpine:3.20",
        driver="fake",
        driver_ref="ref-1",
        env=env,
        egress_allowlist=(ALLOWED,),
        auto_delete_minutes=60,
        created_at=ISSUED,
        updated_at=ISSUED,
    )


def _context() -> tuple[JobContext, _Sandboxes, _Driver]:
    rows, driver = _Sandboxes(_stored()), _Driver()
    uow_factory: Any = lambda: _Uow(rows)  # noqa: E731
    fake_driver: Any = driver
    return JobContext(uow_factory, fake_driver, FrozenClock(LATER)), rows, driver


@pytest.fixture(autouse=True)
def _reset_installed() -> Iterator[None]:
    install_job_egress(None)
    yield
    install_job_egress(None)


def test_reminting_is_built_from_the_settings() -> None:
    reminting = egress_reminting(_settings())

    assert reminting == EgressReminting(ADDRESS, SECRET, WEEK_S)


@pytest.mark.parametrize("changes", [{"egress_proxy_address": ""}, {"egress_secret": ""}])
def test_reminting_is_off_without_the_proxy_or_the_secret(changes: dict[str, Any]) -> None:
    assert egress_reminting(_settings(**changes)) is None
    assert wire_egress(_settings(**changes)) is None


async def test_job_lifecycle_without_wiring_does_not_remint() -> None:
    context, rows, _ = _context()
    before = rows.rows[SANDBOX].env

    await job_lifecycle(context).refresh_egress(ORG, SANDBOX)

    assert rows.rows[SANDBOX].env == before


async def test_wired_job_lifecycle_remints_on_reset() -> None:
    reminting = wire_egress(_settings())
    assert reminting is not None
    context, rows, _ = _context()
    old_env = rows.rows[SANDBOX].env

    await job_lifecycle(context).refresh_egress(ORG, SANDBOX)

    env = rows.rows[SANDBOX].env
    assert env["KEEP"] == "1"
    assert _token_of(env) != _token_of(old_env)
    claims = verify_egress_token(SECRET, _token_of(env), LATER, WEEK_S)
    assert claims.issued_at == LATER
    assert claims.expires_at - claims.issued_at == timedelta(hours=1, days=1)


async def test_start_job_leaves_the_token_unchanged() -> None:
    wire_egress(_settings())
    context, rows, driver = _context()
    old_env = rows.rows[SANDBOX].env

    await handle_start({"org_id": ORG, "sandbox_id": SANDBOX, "actor_id": None}, context)

    assert driver.started == ["ref-1"]
    assert rows.rows[SANDBOX].state is SandboxState.STARTED
    assert rows.rows[SANDBOX].env == old_env


async def test_start_leaves_the_token_unchanged_even_with_reminting_on_the_lifecycle() -> None:
    reminting = EgressReminting(ADDRESS, SECRET, WEEK_S)
    context, rows, _ = _context()
    old_env = rows.rows[SANDBOX].env
    core = Lifecycle(context.uow_factory, context.driver, context.clock, egress=reminting)

    await core.drive_start(ORG, SANDBOX)

    assert rows.rows[SANDBOX].env == old_env


def test_autostop_scanner_accepts_the_reminting() -> None:
    context, _, _ = _context()
    reminting = EgressReminting(ADDRESS, SECRET, WEEK_S)

    scanner = AutoStopScanner(
        context.uow_factory,
        context.driver,
        context.clock,
        tracker=None,  # type: ignore[arg-type]
        interval_s=1.0,
        egress=reminting,
    )

    assert scanner.running is False
