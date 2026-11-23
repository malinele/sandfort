"""WP 3.1: job repository, runner, sandbox lifecycle handlers and the jobs api.

Daemon-free: temp SQLite migrated to head, FakeDriver, a FrozenClock for lease and backoff
time. Sleeping (wakeup, polling) is real time, so every wait is bounded.
"""

import asyncio
from collections import Counter
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sandfort.api.app import create_app
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.repositories.ports import JobRecord, UnitOfWorkPort
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import SandboxState
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import JOB, new_api_key_id, new_id, new_org_id
from sandfort.services.sandboxes import CreateSandboxCommand, SandboxService
from sandfort.workers.handlers import DEFAULT_REGISTRY, HandlerRegistry, JobContext
from sandfort.workers.jobs import (
    SANDBOX_CREATE,
    SANDBOX_DELETE,
    SANDBOX_START,
    SANDBOX_STOP,
    JobWakeup,
    enqueue_job,
)
from sandfort.workers.runner import JobRunner, RunnerConfig

ROOT = Path(__file__).resolve().parents[1]
START = datetime(2026, 1, 1, tzinfo=UTC)
PEPPER = "test-pepper"
KIND = "test.job"
ACTOR = "key_test"
WAIT_S = 5.0
LEASE = timedelta(seconds=60)

SessionFactory = async_sessionmaker[AsyncSession]


@pytest.fixture
async def database(tmp_path: Path) -> AsyncIterator[tuple[str, SessionFactory]]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'jobs.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    engine = create_engine(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))
    try:
        yield url, create_session_factory(engine)
    finally:
        await engine.dispose()


@pytest.fixture
def session_factory(database: tuple[str, SessionFactory]) -> SessionFactory:
    return database[1]


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock(START)


async def add_org(session_factory: SessionFactory, slug: str = "acme") -> str:
    org = Org(id=new_org_id(), name=slug, slug=slug, created_at=START)
    async with UnitOfWork(session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


@pytest.fixture
async def org_id(session_factory: SessionFactory) -> str:
    return await add_org(session_factory)


def make_job(
    org_id: str, *, state: str = "queued", payload: Mapping[str, Any] | None = None
) -> JobRecord:
    return JobRecord(
        id=new_id(JOB),
        org_id=org_id,
        kind=KIND,
        payload=dict(payload or {}),
        state=state,
        attempts=0,
        run_after=START,
        lease_expires_at=None,
        last_error=None,
        created_at=START,
        updated_at=START,
    )


async def put(session_factory: SessionFactory, job: JobRecord) -> JobRecord:
    async with UnitOfWork(session_factory) as uow:
        await uow.jobs.enqueue(job)
        await uow.commit()
    return job


async def fetch(session_factory: SessionFactory, org_id: str, job_id: str) -> JobRecord:
    async with UnitOfWork(session_factory) as uow:
        found = await uow.jobs.get_for_org(org_id, job_id)  # type: ignore[attr-defined]
    assert found is not None
    return found  # type: ignore[no-any-return]


async def lease(
    session_factory: SessionFactory, now: datetime, kinds: tuple[str, ...] = (KIND,)
) -> JobRecord | None:
    async with UnitOfWork(session_factory) as uow:
        leased = await uow.jobs.lease_next(kinds, now=now, lease_expires_at=now + LEASE)
        await uow.commit()
    return leased


async def fail(
    session_factory: SessionFactory, job_id: str, now: datetime, max_attempts: int
) -> None:
    async with UnitOfWork(session_factory) as uow:
        await uow.jobs.fail(
            job_id, error="boom", now=now, backoff_s=30.0, max_attempts=max_attempts
        )
        await uow.commit()


async def wait_until(predicate: Callable[[], Awaitable[bool]]) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + WAIT_S
    while loop.time() < deadline:
        if await predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition not reached within the bounded wait")


# --- repository -----------------------------------------------------------------


async def test_concurrent_leases_hand_the_job_to_exactly_one_caller(
    session_factory: SessionFactory, org_id: str
) -> None:
    job = await put(session_factory, make_job(org_id))

    results = await asyncio.gather(*(lease(session_factory, START) for _ in range(2)))

    winners = [item for item in results if item is not None]
    assert [item.id for item in winners] == [job.id]
    assert winners[0].state == "leased"
    assert winners[0].attempts == 1
    assert winners[0].lease_expires_at == START + LEASE


async def test_lease_skips_future_jobs_and_other_kinds(
    session_factory: SessionFactory, org_id: str
) -> None:
    job = await put(session_factory, make_job(org_id))

    assert await lease(session_factory, START - timedelta(seconds=1)) is None
    assert await lease(session_factory, START, kinds=("other.kind",)) is None
    assert await lease(session_factory, START, kinds=()) is None
    leased = await lease(session_factory, START)
    assert leased is not None and leased.id == job.id


async def test_fail_requeues_with_backoff_then_goes_dead(
    session_factory: SessionFactory, org_id: str
) -> None:
    job = await put(session_factory, make_job(org_id))
    max_attempts = 2

    await lease(session_factory, START)
    await fail(session_factory, job.id, START, max_attempts)
    requeued = await fetch(session_factory, org_id, job.id)

    assert (requeued.state, requeued.attempts) == ("queued", 1)
    assert requeued.run_after == START + timedelta(seconds=30)
    assert requeued.last_error == "boom"
    assert await lease(session_factory, START) is None  # still backing off

    later = START + timedelta(seconds=31)
    assert await lease(session_factory, later) is not None
    await fail(session_factory, job.id, later, max_attempts)
    dead = await fetch(session_factory, org_id, job.id)

    assert (dead.state, dead.attempts) == ("dead", 2)
    assert await lease(session_factory, later + timedelta(days=1)) is None


async def test_reap_returns_only_expired_leases_to_queued(
    session_factory: SessionFactory, org_id: str
) -> None:
    job = await put(session_factory, make_job(org_id))
    await lease(session_factory, START)

    async def reap(now: datetime) -> int:
        async with UnitOfWork(session_factory) as uow:
            reaped = await uow.jobs.reap_expired(now)
            await uow.commit()
        return reaped

    assert await reap(START + LEASE - timedelta(seconds=1)) == 0
    assert await reap(START + LEASE + timedelta(seconds=1)) == 1
    reaped = await fetch(session_factory, org_id, job.id)
    assert (reaped.state, reaped.lease_expires_at) == ("queued", None)
    assert reaped.attempts == 1
    again = await lease(session_factory, START + LEASE + timedelta(seconds=1))
    assert again is not None and again.attempts == 2


# --- runner ---------------------------------------------------------------------


def make_runner(
    session_factory: SessionFactory,
    clock: FrozenClock,
    registry: HandlerRegistry,
    wakeup: JobWakeup,
    **config: float,
) -> JobRunner:
    def uow_factory() -> UnitOfWorkPort:
        return UnitOfWork(session_factory)

    return JobRunner(
        uow_factory,
        FakeDriver(clock),
        clock,
        registry=registry,
        wakeup=wakeup,
        config=RunnerConfig(**config),
    )


async def enqueue_committed(
    session_factory: SessionFactory,
    clock: FrozenClock,
    org_id: str,
    wakeup: JobWakeup,
    payload: Mapping[str, Any] | None = None,
) -> JobRecord:
    async with UnitOfWork(session_factory) as uow:
        job = await enqueue_job(uow, clock, org_id, KIND, payload or {})
        await uow.commit()
    wakeup.notify()
    return job


async def test_runner_runs_a_job_on_wakeup_without_waiting_for_the_poll(
    session_factory: SessionFactory, clock: FrozenClock, org_id: str
) -> None:
    registry, wakeup, ran = HandlerRegistry(), JobWakeup(), asyncio.Event()

    @registry.register(KIND)
    async def handler(payload: Mapping[str, Any], context: JobContext) -> None:
        ran.set()

    runner = make_runner(session_factory, clock, registry, wakeup, poll_interval_s=60.0)
    async with runner:
        await asyncio.sleep(0.1)  # let the loop find nothing and go to sleep
        job = await enqueue_committed(session_factory, clock, org_id, wakeup)
        await asyncio.wait_for(ran.wait(), WAIT_S)

        async def done() -> bool:
            return (await fetch(session_factory, org_id, job.id)).state == "done"

        await wait_until(done)
    assert not runner.running


async def test_handler_exception_requeues_with_backoff_then_succeeds(
    session_factory: SessionFactory, clock: FrozenClock, org_id: str
) -> None:
    registry, wakeup, calls = HandlerRegistry(), JobWakeup(), Counter[str]()

    @registry.register(KIND)
    async def handler(payload: Mapping[str, Any], context: JobContext) -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("flaky")

    runner = make_runner(session_factory, clock, registry, wakeup, backoff_base_s=10.0)
    job = await enqueue_committed(session_factory, clock, org_id, wakeup)

    assert await runner.run_once() is True
    failed = await fetch(session_factory, org_id, job.id)
    assert (failed.state, failed.attempts) == ("queued", 1)
    assert failed.last_error == "RuntimeError: flaky"
    assert failed.run_after == START + timedelta(seconds=10)
    assert await runner.run_once() is False  # backing off

    clock.advance(timedelta(seconds=11))
    assert await runner.run_once() is True
    done = await fetch(session_factory, org_id, job.id)
    assert (done.state, done.attempts, calls["n"]) == ("done", 2, 2)


async def test_handler_timeout_counts_as_a_failure(
    session_factory: SessionFactory, clock: FrozenClock, org_id: str
) -> None:
    registry, wakeup = HandlerRegistry(), JobWakeup()

    @registry.register(KIND)
    async def handler(payload: Mapping[str, Any], context: JobContext) -> None:
        await asyncio.sleep(30)

    runner = make_runner(session_factory, clock, registry, wakeup, job_timeout_s=0.05)
    job = await enqueue_committed(session_factory, clock, org_id, wakeup)

    await runner.run_once()

    timed_out = await fetch(session_factory, org_id, job.id)
    assert (timed_out.state, timed_out.attempts) == ("queued", 1)
    assert timed_out.last_error is not None and "TimeoutError" in timed_out.last_error


async def test_concurrent_runners_never_double_run_a_job(
    session_factory: SessionFactory, clock: FrozenClock, org_id: str
) -> None:
    registry, wakeup, runs = HandlerRegistry(), JobWakeup(), Counter[int]()
    total = 12

    @registry.register(KIND)
    async def handler(payload: Mapping[str, Any], context: JobContext) -> None:
        await asyncio.sleep(0)
        runs[payload["n"]] += 1

    runners = [
        make_runner(session_factory, clock, registry, wakeup, poll_interval_s=0.05)
        for _ in range(3)
    ]
    jobs = [
        await enqueue_committed(session_factory, clock, org_id, wakeup, {"n": n})
        for n in range(total)
    ]
    for runner in runners:
        runner.start()
    try:

        async def all_done() -> bool:
            states = [(await fetch(session_factory, org_id, job.id)).state for job in jobs]
            return states == ["done"] * total

        await wait_until(all_done)
    finally:
        for runner in runners:
            await runner.stop()

    assert runs == Counter(dict.fromkeys(range(total), 1))


async def test_runner_reaps_expired_leases(
    session_factory: SessionFactory, clock: FrozenClock, org_id: str
) -> None:
    runner = make_runner(session_factory, clock, HandlerRegistry(), JobWakeup())
    job = await put(session_factory, make_job(org_id))
    await lease(session_factory, START)
    clock.advance(LEASE + timedelta(seconds=1))

    assert await runner.reap() == 1
    assert (await fetch(session_factory, org_id, job.id)).state == "queued"


async def test_runner_stop_is_idempotent_and_cancellation_safe(
    session_factory: SessionFactory, clock: FrozenClock
) -> None:
    runner = make_runner(session_factory, clock, HandlerRegistry(), JobWakeup())
    await runner.stop()  # never started
    runner.start()
    runner.start()  # a second start is a no-op
    assert runner.running
    await runner.stop()
    await runner.stop()
    assert not runner.running


# --- sandbox lifecycle handlers ---------------------------------------------------


@pytest.fixture
def driver(clock: FrozenClock) -> FakeDriver:
    return FakeDriver(clock)


@pytest.fixture
def job_service(
    session_factory: SessionFactory, driver: FakeDriver, clock: FrozenClock
) -> SandboxService:
    def uow_factory() -> UnitOfWorkPort:
        return UnitOfWork(session_factory)

    settings = Settings(driver="fake", api_key_pepper=PEPPER)
    return SandboxService(uow_factory, driver, settings, clock, use_jobs=True)


class Handlers:
    """Runs a registered lifecycle handler the way the runner would."""

    def __init__(
        self, session_factory: SessionFactory, driver: FakeDriver, clock: FrozenClock, org_id: str
    ) -> None:
        def uow_factory() -> UnitOfWorkPort:
            return UnitOfWork(session_factory)

        self._context = JobContext(uow_factory, driver, clock)
        self._org_id = org_id

    async def run(self, kind: str, sandbox_id: str, times: int = 1) -> None:
        payload = {"org_id": self._org_id, "sandbox_id": sandbox_id, "actor_id": ACTOR}
        for _ in range(times):
            await DEFAULT_REGISTRY.lookup(kind)(payload, self._context)


@pytest.fixture
def handlers(
    session_factory: SessionFactory, driver: FakeDriver, clock: FrozenClock, org_id: str
) -> Handlers:
    return Handlers(session_factory, driver, clock, org_id)


async def test_create_job_is_idempotent_and_starts_the_sandbox(
    job_service: SandboxService, handlers: Handlers, driver: FakeDriver, org_id: str
) -> None:
    pending = await job_service.create(org_id, ACTOR, CreateSandboxCommand())
    assert pending.state is SandboxState.PENDING

    await handlers.run(SANDBOX_CREATE, pending.id, times=2)

    started = await job_service.get(org_id, pending.id)
    assert started.state is SandboxState.STARTED
    assert started.driver_ref is not None
    assert len(await driver.list_managed()) == 1


async def test_stop_and_start_jobs_are_idempotent(
    job_service: SandboxService, handlers: Handlers, org_id: str
) -> None:
    sandbox = await job_service.create(org_id, ACTOR, CreateSandboxCommand())
    await handlers.run(SANDBOX_CREATE, sandbox.id)

    assert (await job_service.stop(org_id, ACTOR, sandbox.id)).state is SandboxState.STOPPING
    await handlers.run(SANDBOX_STOP, sandbox.id, times=2)
    assert (await job_service.get(org_id, sandbox.id)).state is SandboxState.STOPPED

    await job_service.start(org_id, ACTOR, sandbox.id)
    await handlers.run(SANDBOX_START, sandbox.id, times=2)
    assert (await job_service.get(org_id, sandbox.id)).state is SandboxState.STARTED


async def test_stop_job_succeeds_when_the_container_is_already_gone(
    job_service: SandboxService, handlers: Handlers, driver: FakeDriver, org_id: str
) -> None:
    sandbox = await job_service.create(org_id, ACTOR, CreateSandboxCommand())
    await handlers.run(SANDBOX_CREATE, sandbox.id)
    ref = (await job_service.get(org_id, sandbox.id)).driver_ref
    assert ref is not None
    await job_service.stop(org_id, ACTOR, sandbox.id)
    await driver.destroy(ref)

    await handlers.run(SANDBOX_STOP, sandbox.id)

    assert (await job_service.get(org_id, sandbox.id)).state is SandboxState.STOPPED


async def test_delete_job_is_idempotent_even_if_the_container_is_missing(
    job_service: SandboxService, handlers: Handlers, driver: FakeDriver, org_id: str
) -> None:
    sandbox = await job_service.create(org_id, ACTOR, CreateSandboxCommand())
    await handlers.run(SANDBOX_CREATE, sandbox.id)
    ref = (await job_service.get(org_id, sandbox.id)).driver_ref
    assert ref is not None
    deleting = await job_service.delete(org_id, ACTOR, sandbox.id)
    assert deleting.state is SandboxState.DESTROYING
    await driver.destroy(ref)  # a previous attempt already removed the container

    await handlers.run(SANDBOX_DELETE, sandbox.id, times=2)

    assert (await job_service.get(org_id, sandbox.id)).state is SandboxState.DESTROYED


async def test_runner_finishes_lifecycle_jobs_enqueued_by_the_service(
    job_service: SandboxService,
    session_factory: SessionFactory,
    driver: FakeDriver,
    clock: FrozenClock,
    org_id: str,
) -> None:
    def uow_factory() -> UnitOfWorkPort:
        return UnitOfWork(session_factory)

    runner = JobRunner(uow_factory, driver, clock, config=RunnerConfig(poll_interval_s=0.05))
    async with runner:
        sandbox = await job_service.create(org_id, ACTOR, CreateSandboxCommand())
        started = await job_service.get(
            org_id, sandbox.id, wait_for=SandboxState.STARTED, timeout_s=WAIT_S
        )
    assert started.state is SandboxState.STARTED


# --- jobs api -------------------------------------------------------------------


@pytest.fixture
async def app(database: tuple[str, SessionFactory]) -> AsyncIterator[FastAPI]:
    settings = Settings(driver="fake", database_url=database[0], api_key_pepper=PEPPER)
    application = create_app(settings)
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


async def issue_key(session_factory: SessionFactory, org_id: str) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset({Scope.SANDBOXES_READ}),
        created_at=START,
    )
    async with UnitOfWork(session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


async def test_jobs_api_requires_authentication(client: httpx.AsyncClient) -> None:
    listing = await client.get("/v1/jobs")
    single = await client.get("/v1/jobs/job_whatever")

    assert listing.status_code == 401
    assert single.status_code == 401


async def test_jobs_api_hides_other_orgs_jobs(
    client: httpx.AsyncClient, session_factory: SessionFactory, org_id: str
) -> None:
    other_org = await add_org(session_factory, "other")
    foreign = await put(session_factory, make_job(other_org))
    key = await issue_key(session_factory, org_id)
    headers = {"Authorization": f"Bearer {key}"}

    single = await client.get(f"/v1/jobs/{foreign.id}", headers=headers)
    listing = await client.get("/v1/jobs", headers=headers)

    assert single.status_code == 404
    assert single.json()["error"]["code"] == "NOT_FOUND"
    assert listing.json()["data"] == []


async def test_jobs_api_lists_filters_and_paginates(
    client: httpx.AsyncClient, session_factory: SessionFactory, org_id: str
) -> None:
    queued = await put(session_factory, make_job(org_id, payload={"n": 1}))
    dead = await put(session_factory, make_job(org_id, state="dead"))
    key = await issue_key(session_factory, org_id)
    headers = {"Authorization": f"Bearer {key}"}

    everything = (await client.get("/v1/jobs", headers=headers)).json()
    only_dead = (await client.get("/v1/jobs", headers=headers, params={"state": "dead"})).json()
    first_page = (await client.get("/v1/jobs", headers=headers, params={"limit": 1})).json()
    fetched = (await client.get(f"/v1/jobs/{queued.id}", headers=headers)).json()
    bad_state = await client.get("/v1/jobs", headers=headers, params={"state": "nope"})

    assert {item["id"] for item in everything["data"]} == {queued.id, dead.id}
    assert [item["id"] for item in only_dead["data"]] == [dead.id]
    assert len(first_page["data"]) == 1 and first_page["meta"]["next_cursor"] is not None
    assert fetched["data"]["payload"] == {"n": 1} and fetched["data"]["state"] == "queued"
    assert bad_state.status_code in (400, 422)
