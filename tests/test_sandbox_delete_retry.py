"""``SandboxService.delete`` decides again when its versioned transition races a writer.

The reconciler or the exec route can move a crashed sandbox (started -> stopped) between the
service's read and its versioned write. That stale-version refusal is retried (bounded); every
other conflict, such as a snapshot in progress, propagates untouched.
"""

from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import Org
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.drivers.fake import FakeDriver
from sandfort.errors import Conflict
from sandfort.ids import new_org_id
from sandfort.services.sandboxes import DELETE_MAX_ATTEMPTS, CreateSandboxCommand, SandboxService

ROOT = Path(__file__).resolve().parents[1]
START = datetime(2026, 1, 1, tzinfo=UTC)
PEPPER = "test-pepper"
ACTOR = "key_test"

SessionFactory = async_sessionmaker[AsyncSession]
Transition = Callable[..., Awaitable[Sandbox]]


@pytest.fixture
async def session_factory(tmp_path: Path) -> AsyncIterator[SessionFactory]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'delete-retry.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    engine = create_engine(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))
    try:
        yield create_session_factory(engine)
    finally:
        await engine.dispose()


@pytest.fixture
async def org_id(session_factory: SessionFactory) -> str:
    org = Org(id=new_org_id(), name="acme", slug="acme", created_at=START)
    async with UnitOfWork(session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


def make_service(session_factory: SessionFactory) -> SandboxService:
    def uow_factory() -> UnitOfWorkPort:
        return UnitOfWork(session_factory)

    settings = Settings(driver="fake", api_key_pepper=PEPPER)
    clock = FrozenClock(START)
    return SandboxService(uow_factory, FakeDriver(clock), settings, clock)


@pytest.fixture
def service(session_factory: SessionFactory) -> SandboxService:
    return make_service(session_factory)


def version_conflict(sandbox_id: str) -> Conflict:
    """The error ``SandboxRepository.update`` raises for a stale expected version."""
    return Conflict(
        f"sandbox {sandbox_id} was modified concurrently", details={"expected_version": 1}
    )


class TransitionSpy:
    """Replaces ``Lifecycle.transition``: counts calls and runs ``behaviour`` first."""

    def __init__(
        self,
        original: Transition,
        behaviour: Callable[[int], Awaitable[None]],
    ) -> None:
        self._original = original
        self._behaviour = behaviour
        self.calls = 0

    async def __call__(
        self, org_id: str, sandbox_id: str, target: SandboxState, **kw: Any
    ) -> Sandbox:
        if target is SandboxState.DESTROYING:  # the later DESTROYED move is not counted
            self.calls += 1
            await self._behaviour(self.calls)
        return await self._original(org_id, sandbox_id, target, **kw)


def install_spy(
    monkeypatch: pytest.MonkeyPatch,
    service: SandboxService,
    behaviour: Callable[[int], Awaitable[None]],
) -> TransitionSpy:
    core = service._core
    spy = TransitionSpy(core.transition, behaviour)
    monkeypatch.setattr(core, "transition", spy)
    return spy


async def started_sandbox(service: SandboxService, org_id: str) -> Sandbox:
    created = await service.create(org_id, ACTOR, CreateSandboxCommand())
    sandbox = await service.get(org_id, created.id)
    assert sandbox.state is SandboxState.STARTED
    return sandbox


async def test_delete_succeeds_on_retry_after_a_concurrent_version_change(
    monkeypatch: pytest.MonkeyPatch, service: SandboxService, org_id: str
) -> None:
    sandbox = await started_sandbox(service, org_id)

    async def conflict_once(call: int) -> None:
        if call == 1:
            raise version_conflict(sandbox.id)

    spy = install_spy(monkeypatch, service, conflict_once)

    deleted = await service.delete(org_id, ACTOR, sandbox.id)

    assert deleted.state is SandboxState.DESTROYED
    assert spy.calls == 2
    assert (await service.get(org_id, sandbox.id)).state is SandboxState.DESTROYED


async def test_delete_returns_the_row_when_it_became_destroyed_meanwhile(
    monkeypatch: pytest.MonkeyPatch,
    session_factory: SessionFactory,
    service: SandboxService,
    org_id: str,
) -> None:
    sandbox = await started_sandbox(service, org_id)
    rival = make_service(session_factory)

    async def destroyed_by_rival(call: int) -> None:
        await rival.delete(org_id, ACTOR, sandbox.id)
        raise version_conflict(sandbox.id)

    spy = install_spy(monkeypatch, service, destroyed_by_rival)

    deleted = await service.delete(org_id, ACTOR, sandbox.id)

    assert deleted.state is SandboxState.DESTROYED
    assert spy.calls == 1  # the re-read saw DESTROYED: no second transition


async def test_delete_propagates_after_the_last_version_conflict(
    monkeypatch: pytest.MonkeyPatch, service: SandboxService, org_id: str
) -> None:
    sandbox = await started_sandbox(service, org_id)

    async def always_conflict(call: int) -> None:
        raise version_conflict(sandbox.id)

    spy = install_spy(monkeypatch, service, always_conflict)

    with pytest.raises(Conflict, match="was modified concurrently"):
        await service.delete(org_id, ACTOR, sandbox.id)

    assert spy.calls == DELETE_MAX_ATTEMPTS == 3
    assert (await service.get(org_id, sandbox.id)).state is SandboxState.STARTED


async def test_delete_does_not_retry_other_conflicts(
    monkeypatch: pytest.MonkeyPatch, service: SandboxService, org_id: str
) -> None:
    sandbox = await started_sandbox(service, org_id)

    async def snapshot_in_progress(call: int) -> None:
        raise Conflict(f"sandbox {sandbox.id} has a snapshot in progress; wait, then retry")

    spy = install_spy(monkeypatch, service, snapshot_in_progress)

    with pytest.raises(Conflict, match="snapshot in progress"):
        await service.delete(org_id, ACTOR, sandbox.id)

    assert spy.calls == 1
