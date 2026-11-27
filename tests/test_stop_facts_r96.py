"""Round 96 (B8): ``sandbox.drift_detected`` carries ``oom_killed`` and ``exit_code`` of a stop.

FakeDriver, temp SQLite migrated to head. When a started sandbox's container exited, the audit
row says what the host knew: the exit code (``int``, ``null`` when unknown) and ``oom_killed``
(``true`` when the runtime flagged an out-of-memory kill, ``null`` otherwise: the driver
protocol cannot tell "not an OOM" from "cannot tell"). ``stop_cause`` keeps its values.

Driver calls are made before the unit of work that writes the row opens (intent-then-act).
"""

import sys
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any, Self

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402

from sandfort.clock import FrozenClock  # noqa: E402
from sandfort.db.unit_of_work import UnitOfWork  # noqa: E402
from sandfort.domain.org import Scope  # noqa: E402
from sandfort.domain.sandbox import (  # noqa: E402
    STOP_CAUSE_CONTAINER_EXITED,
    STOP_CAUSE_OOM_KILLED,
    Sandbox,
)
from sandfort.drivers.base import OomObservableDriver  # noqa: E402
from sandfort.drivers.exit_status import ExitStatusDriver  # noqa: E402
from sandfort.drivers.fake import FakeDriver  # noqa: E402
from sandfort.workers.reconciler import DRIFT_DETECTED, Reconciler  # noqa: E402
from sandfort.workers.stop_facts import StopFacts, gather_stop_facts  # noqa: E402
from test_api_sandboxes import BASE, add_org, migrated_app, seed_key, send  # noqa: E402

READ_WRITE = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})
OOM_EXIT = 137


class Tracker:
    """How many units of work were open at each driver call."""

    def __init__(self) -> None:
        self.open = 0
        self.calls: list[tuple[str, int]] = []


class TrackingUow(UnitOfWork):
    def __init__(self, session_factory: Any, tracker: Tracker) -> None:
        super().__init__(session_factory)
        self._tracker = tracker

    async def __aenter__(self) -> Self:
        self._tracker.open += 1
        return await super().__aenter__()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            await super().__aexit__(exc_type, exc, tb)
        finally:
            self._tracker.open -= 1


class RaisingDriver(FakeDriver):
    """A driver whose runtime cannot be read: both optional members fail."""

    async def container_oom_killed(self, ref: str) -> bool:
        raise RuntimeError("daemon unreachable")

    async def container_exit_code(self, ref: str) -> int | None:
        raise RuntimeError("daemon unreachable")


class BareDriver:
    """Implements neither optional member."""


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    async with migrated_app(tmp_path) as application:
        yield application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.fixture
def driver(app: FastAPI) -> FakeDriver:
    fake = app.state.driver
    assert isinstance(fake, FakeDriver)
    return fake


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    return await add_org(app, "stopfacts")


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id, READ_WRITE)


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock(datetime.now(UTC))


async def create(client: httpx.AsyncClient, key: str) -> str:
    body = await send(client, "POST", BASE, key, status=201, json={})
    sandbox_id: str = body["data"]["id"]
    return sandbox_id


async def load(app: FastAPI, org_id: str, sandbox_id: str) -> Sandbox:
    async with UnitOfWork(app.state.session_factory) as uow:
        found = await uow.sandboxes.get(org_id, sandbox_id)
    assert found is not None
    return found


async def drift_rows(app: FastAPI, org_id: str) -> list[dict[str, Any]]:
    async with UnitOfWork(app.state.session_factory) as uow:
        events = await uow.audit.list(org_id, action=DRIFT_DETECTED, limit=50)
    return [event.details for event in events]


def reconciler_for(app: FastAPI, driver: Any, clock: FrozenClock, **kwargs: Any) -> Reconciler:
    return Reconciler(app.state.uow_factory, driver, clock, interval_s=1, grace_s=300, **kwargs)


# -- the audit row ---------------------------------------------------------------------------


async def test_an_oom_kill_with_exit_137_is_written_into_the_drift_row(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    clock: FrozenClock,
) -> None:
    sandbox_id = await create(client, key)
    ref = (await load(app, org_id, sandbox_id)).driver_ref
    assert ref is not None
    driver.kill_instance(ref, vanish=False, oom=True, exit_code=OOM_EXIT)

    await reconciler_for(app, driver, clock).reconcile_once()

    (details,) = await drift_rows(app, org_id)
    assert details["oom_killed"] is True
    assert details["exit_code"] == OOM_EXIT
    assert details["stop_cause"] == STOP_CAUSE_OOM_KILLED
    assert details["stopped_unexpectedly"] is True


async def test_a_normal_exit_1_is_written_without_an_oom_claim(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    clock: FrozenClock,
) -> None:
    sandbox_id = await create(client, key)
    ref = (await load(app, org_id, sandbox_id)).driver_ref
    assert ref is not None
    driver.kill_instance(ref, vanish=False, exit_code=1)

    await reconciler_for(app, driver, clock).reconcile_once()

    (details,) = await drift_rows(app, org_id)
    assert details["exit_code"] == 1
    assert details["oom_killed"] is None
    assert details["stop_cause"] == STOP_CAUSE_CONTAINER_EXITED


async def test_an_unreadable_runtime_still_writes_the_row_with_nulls(
    monkeypatch: pytest.MonkeyPatch,
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    clock: FrozenClock,
) -> None:
    sandbox_id = await create(client, key)
    ref = (await load(app, org_id, sandbox_id)).driver_ref
    assert ref is not None
    driver.kill_instance(ref, vanish=False)
    attempts: list[str] = []

    async def unreadable_oom(ref: str) -> bool:
        attempts.append("oom")
        raise RuntimeError("daemon unreachable")

    async def unreadable_exit_code(ref: str) -> int | None:
        attempts.append("exit_code")
        raise RuntimeError("daemon unreachable")

    monkeypatch.setattr(driver, "container_oom_killed", unreadable_oom)
    monkeypatch.setattr(driver, "container_exit_code", unreadable_exit_code)

    report = await reconciler_for(app, driver, clock).reconcile_once()

    assert sorted(attempts) == ["exit_code", "oom"]  # both reads ran and raised RuntimeError
    assert report.drifted == (sandbox_id,)
    (details,) = await drift_rows(app, org_id)
    assert details["exit_code"] is None
    assert details["oom_killed"] is None
    assert details["stop_cause"] == STOP_CAUSE_CONTAINER_EXITED


async def test_a_driver_that_does_not_know_the_exit_code_writes_null(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    clock: FrozenClock,
) -> None:
    sandbox_id = await create(client, key)
    ref = (await load(app, org_id, sandbox_id)).driver_ref
    assert ref is not None
    driver.kill_instance(ref, vanish=False)  # no exit code recorded

    await reconciler_for(app, driver, clock).reconcile_once()

    (details,) = await drift_rows(app, org_id)
    assert details["exit_code"] is None
    assert details["oom_killed"] is None


async def test_a_vanished_container_has_no_stop_facts(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    clock: FrozenClock,
) -> None:
    sandbox_id = await create(client, key)
    ref = (await load(app, org_id, sandbox_id)).driver_ref
    assert ref is not None
    driver.kill_instance(ref, vanish=True)

    await reconciler_for(app, driver, clock).reconcile_once()

    (details,) = await drift_rows(app, org_id)
    assert "exit_code" not in details
    assert "oom_killed" not in details


async def test_mark_stopped_unexpectedly_writes_the_facts_too(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    clock: FrozenClock,
) -> None:
    sandbox_id = await create(client, key)
    row = await load(app, org_id, sandbox_id)
    assert row.driver_ref is not None
    driver.kill_instance(row.driver_ref, vanish=False, oom=True, exit_code=OOM_EXIT)

    assert await reconciler_for(app, driver, clock).mark_stopped_unexpectedly(row) is True

    (details,) = await drift_rows(app, org_id)
    assert (details["oom_killed"], details["exit_code"]) == (True, OOM_EXIT)


async def test_driver_calls_are_made_before_the_transaction_opens(
    monkeypatch: pytest.MonkeyPatch,
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    clock: FrozenClock,
) -> None:
    sandbox_id = await create(client, key)
    row = await load(app, org_id, sandbox_id)
    assert row.driver_ref is not None
    driver.kill_instance(row.driver_ref, vanish=False, oom=True, exit_code=OOM_EXIT)
    tracker = Tracker()
    real_oom, real_exit = driver.container_oom_killed, driver.container_exit_code

    async def oom_seen(ref: str) -> bool:
        tracker.calls.append(("oom", tracker.open))
        return await real_oom(ref)

    async def exit_seen(ref: str) -> int | None:
        tracker.calls.append(("exit_code", tracker.open))
        return await real_exit(ref)

    monkeypatch.setattr(driver, "container_oom_killed", oom_seen)
    monkeypatch.setattr(driver, "container_exit_code", exit_seen)
    reconciler = Reconciler(
        lambda: TrackingUow(app.state.session_factory, tracker),
        driver,
        clock,
        interval_s=1,
        grace_s=300,
    )

    assert await reconciler.mark_stopped_unexpectedly(row) is True

    assert {name for name, _ in tracker.calls} == {"oom", "exit_code"}
    assert [open_units for _, open_units in tracker.calls] == [0, 0]


# -- the gatherer ----------------------------------------------------------------------------


async def test_the_gatherer_reads_both_facts_from_a_fake_driver(driver: FakeDriver) -> None:
    ref = driver.plant_instance("x", "org")
    driver.kill_instance(ref, vanish=False, oom=True, exit_code=OOM_EXIT)

    facts = await gather_stop_facts(driver, ref, "x")

    assert facts == StopFacts(oom_killed=True, exit_code=OOM_EXIT)


async def test_the_gatherer_answers_unknown_for_a_driver_without_the_members() -> None:
    facts = await gather_stop_facts(BareDriver(), "ref", "sbx")  # type: ignore[arg-type]

    assert facts == StopFacts(oom_killed=None, exit_code=None)


async def test_the_gatherer_answers_unknown_without_a_driver_ref(driver: FakeDriver) -> None:
    assert await gather_stop_facts(driver, None, "sbx") == StopFacts(None, None)


async def test_the_gatherer_survives_a_failing_driver(clock: FrozenClock) -> None:
    facts = await gather_stop_facts(RaisingDriver(clock), "ref", "sbx")

    assert facts == StopFacts(oom_killed=None, exit_code=None)


def test_the_details_of_the_facts_are_plain_json_values() -> None:
    assert StopFacts(True, 137).as_details() == {"oom_killed": True, "exit_code": 137}
    assert StopFacts(None, None).as_details() == {"oom_killed": None, "exit_code": None}


def test_the_fake_driver_offers_both_optional_members(driver: FakeDriver) -> None:
    assert isinstance(driver, OomObservableDriver)
    assert isinstance(driver, ExitStatusDriver)


# -- the Docker reader -----------------------------------------------------------------------


class InspectApi:
    def __init__(self, state: dict[str, Any] | Exception) -> None:
        self._state = state

    def inspect_container(self, ref: str) -> dict[str, Any]:
        if isinstance(self._state, Exception):
            raise self._state
        return {"State": self._state}


class InspectClient:
    def __init__(self, state: dict[str, Any] | Exception) -> None:
        self.api = InspectApi(state)


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ({"Running": False, "ExitCode": 137}, 137),
        ({"Running": False, "ExitCode": 1}, 1),
        ({"Running": False, "ExitCode": 0}, 0),
        ({"Running": True, "ExitCode": 0}, None),  # still running: no exit code yet
        ({"Running": False}, None),
        ({"Running": False, "ExitCode": "137"}, None),
        ({"Running": False, "ExitCode": True}, None),
        (RuntimeError("daemon unreachable"), None),
    ],
)
async def test_the_docker_reader_answers_the_recorded_exit_code_or_none(
    state: dict[str, Any] | Exception, expected: int | None
) -> None:
    from sandfort.drivers.docker import exit_status

    assert await exit_status.container_exit_code(InspectClient(state), "ref") == expected


def test_the_docker_driver_offers_the_exit_code() -> None:
    from sandfort.drivers.docker.driver import DockerDriver

    assert hasattr(DockerDriver, "container_exit_code")
