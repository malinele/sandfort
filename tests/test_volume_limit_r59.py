"""Round 59: a soft size limit for volumes (``SANDFORT_VOLUME_MAX_BYTES``).

Docker local volumes cannot be capped by the daemon, so the platform enforces the limit from
the sampled size: a read-write mount of an over-limit volume is refused with 422
``VOLUME_OVER_LIMIT``; a read-only mount is allowed. The fake driver reports a volume's size
as the bytes of the files written under it.

The sizes are sampled by a pre-step before the create transaction opens (driver calls never run
inside an open transaction); ``resolve_mounts`` then decides from those sizes without the driver.
The limit and the sampling interval come from ``Settings`` through the service constructor.
The limit a response reports travels with the volume the service returns, so two wirings in one
process never share it. The pre-step runs after the cheap refusals (scope, quota, key cap) and
only for volumes the key may mount; start and the resize recreate path apply the same check.
"""

from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import Any, NamedTuple, Self

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.schemas.volumes import volume_response
from sandfort.api.wiring import VOLUME_SERVICE_ATTR
from sandfort.auth.api_keys import generate_api_key
from sandfort.auth.label_scope import set_label_scope
from sandfort.clock import Clock, FrozenClock
from sandfort.config import Settings
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.quota import OrgQuota
from sandfort.domain.resources import ResourceSpec
from sandfort.domain.sandbox import SandboxState
from sandfort.domain.volume import Volume
from sandfort.drivers.fake import FakeDriver
from sandfort.errors import Forbidden, QuotaExceeded
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.quota import QuotaService
from sandfort.services.resize import ResizeCommand, ResizeService
from sandfort.services.sandboxes import CreateSandboxCommand, SandboxService
from sandfort.services.volume_limit import MountGuard, VolumeOverLimit
from sandfort.services.volumes import MountRequest, VolumeService, resolve_mounts

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 11, 9, 0, tzinfo=UTC)
PEPPER = "test-pepper"
ENV_NAME = "SANDFORT_VOLUME_MAX_BYTES"
LIMIT = 1000
INTERVAL_S = 300
FULL_ACCESS = frozenset(
    {
        Scope.SANDBOXES_READ,
        Scope.SANDBOXES_WRITE,
        Scope.TOOLBOX,
        Scope.VOLUMES_READ,
        Scope.VOLUMES_WRITE,
    }
)

ServiceFactory = Callable[[int], VolumeService]
UowFactory = Callable[[], UnitOfWorkPort]


class Tracker:
    """Counts open units of work and records how many were open at each driver inspect."""

    def __init__(self) -> None:
        self.open = 0
        self.inspects: list[int] = []
        self.refs: list[str] = []


class TrackingUow(UnitOfWork):
    """The real unit of work, flagging the tracker while it is open."""

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


class FailingCommitUow(UnitOfWork):
    async def commit(self) -> None:
        raise RuntimeError("commit failed")


class RecordingDriver(FakeDriver):
    """Fake driver noting whether a unit of work was open at every ``inspect_volume``."""

    def __init__(self, clock: Clock, tracker: Tracker) -> None:
        super().__init__(clock)
        self._tracker = tracker

    async def inspect_volume(self, ref: str) -> Any:
        self._tracker.inspects.append(self._tracker.open)
        self._tracker.refs.append(ref)
        return await super().inspect_volume(ref)


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'vollimit.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(
        driver="fake",
        database_url=url,
        api_key_pepper=PEPPER,
        volume_max_bytes=LIMIT,
        metering_sample_interval_s=INTERVAL_S,
    )
    application = create_app(settings)
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
def driver(app: FastAPI) -> FakeDriver:
    fake = app.state.driver
    assert isinstance(fake, FakeDriver)
    return fake


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock(NOW)


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


@pytest.fixture
def uow_factory(app: FastAPI) -> UowFactory:
    return lambda: UnitOfWork(app.state.session_factory)


@pytest.fixture
def make_service(
    uow_factory: UowFactory, driver: FakeDriver, clock: FrozenClock
) -> ServiceFactory:
    """A volume service enforcing ``max_bytes``; each one owns its guard."""

    def build(max_bytes: int) -> VolumeService:
        return VolumeService(
            uow_factory, driver, clock, max_bytes=max_bytes, sample_interval_s=INTERVAL_S
        )

    return build


def write_bytes(driver: FakeDriver, volume: Volume, size: int) -> None:
    driver._volume_files[volume.provider_volume_name] = {"blob": b"x" * size}


async def mount(
    service: VolumeService,
    factory: UowFactory,
    org_id: str,
    volume: Volume,
    *,
    read_only: bool = False,
) -> tuple[Any, ...]:
    """The two steps of a create: sample before the transaction, then decide inside it."""
    requests = [MountRequest(volume.id, "/data", read_only)]
    limit = await service.guard.prepare(factory, org_id, requests)
    async with factory() as uow:
        return await resolve_mounts(uow, org_id, requests, limit=limit)


def stored(size: int | None) -> Volume:
    return Volume(
        id="vol_1",
        org_id="org_1",
        name="data",
        provider_volume_name="sf-vol-vol_1",
        sampled_size_bytes=size,
        created_at=NOW,
    )


# -- the setting ---------------------------------------------------------------------------


def test_setting_defaults_to_no_limit() -> None:
    assert Settings().volume_max_bytes == 0
    assert Settings.from_env({}).volume_max_bytes == 0


def test_setting_parses_an_integer() -> None:
    assert Settings.from_env({ENV_NAME: "1073741824"}).volume_max_bytes == 1073741824


def test_setting_accepts_zero_as_no_limit() -> None:
    assert Settings.from_env({ENV_NAME: "0"}).volume_max_bytes == 0


@pytest.mark.parametrize("raw", ["-1", "-1073741824"])
def test_negative_setting_is_a_settings_error(raw: str) -> None:
    with pytest.raises(ValueError, match=ENV_NAME):
        Settings.from_env({ENV_NAME: raw})


@pytest.mark.parametrize("raw", ["abc", "1.5", "1GiB", ""])
def test_non_integer_setting_is_a_settings_error(raw: str) -> None:
    with pytest.raises(ValueError, match=ENV_NAME):
        Settings.from_env({ENV_NAME: raw})


def test_wiring_takes_the_limit_and_interval_from_a_settings_object(app: FastAPI) -> None:
    guard = getattr(app.state, VOLUME_SERVICE_ATTR).guard
    assert (guard.max_bytes, guard.sample_interval_s) == (LIMIT, INTERVAL_S)


async def test_settings_without_a_limit_build_a_service_without_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("aiosqlite")
    monkeypatch.setenv(ENV_NAME, "5")  # the process environment is not consulted
    url = f"sqlite+aiosqlite:///{tmp_path / 'nolimit.db'}"
    application = create_app(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))
    try:
        assert getattr(application.state, VOLUME_SERVICE_ATTR).guard.max_bytes is None
    finally:
        await application.state.engine.dispose()


def test_two_services_hold_independent_limits(
    uow_factory: UowFactory, driver: FakeDriver, clock: FrozenClock
) -> None:
    strict = VolumeService(uow_factory, driver, clock, max_bytes=10, sample_interval_s=1)
    lenient = VolumeService(uow_factory, driver, clock, max_bytes=LIMIT, sample_interval_s=60)
    assert (strict.guard.max_bytes, strict.guard.sample_interval_s) == (10, 1)
    assert (lenient.guard.max_bytes, lenient.guard.sample_interval_s) == (LIMIT, 60)
    assert strict.guard is not lenient.guard


# -- the response --------------------------------------------------------------------------


def test_response_without_a_limit_has_null_max_and_is_not_over() -> None:
    response = volume_response(stored(5000), max_bytes=0)
    assert response.max_bytes is None
    assert response.over_limit is False


def test_response_under_the_limit_is_not_over() -> None:
    response = volume_response(stored(LIMIT), max_bytes=LIMIT)
    assert response.max_bytes == LIMIT
    assert response.over_limit is False


def test_response_over_the_limit_is_over() -> None:
    response = volume_response(stored(LIMIT + 1), max_bytes=LIMIT)
    assert response.max_bytes == LIMIT
    assert response.over_limit is True


def test_response_with_an_unsampled_volume_is_not_over() -> None:
    assert volume_response(stored(None), max_bytes=LIMIT).over_limit is False


async def test_service_read_reports_the_fresh_sample(
    make_service: ServiceFactory, driver: FakeDriver, org_id: str
) -> None:
    service = make_service(LIMIT)
    volume = await service.create(org_id, None, "data")
    write_bytes(driver, volume, LIMIT + 10)
    response = volume_response(await service.get(org_id, volume.id), max_bytes=LIMIT)
    assert (response.size_bytes, response.max_bytes, response.over_limit) == (
        LIMIT + 10,
        LIMIT,
        True,
    )


# -- the mount decision --------------------------------------------------------------------


async def test_read_write_mount_of_an_over_limit_volume_is_refused_with_details(
    make_service: ServiceFactory,
    uow_factory: UowFactory,
    driver: FakeDriver,
    org_id: str,
) -> None:
    service = make_service(LIMIT)
    volume = await service.create(org_id, None, "data")
    write_bytes(driver, volume, LIMIT + 1)
    with pytest.raises(VolumeOverLimit) as caught:
        await mount(service, uow_factory, org_id, volume)
    assert (caught.value.status, caught.value.code) == (422, "VOLUME_OVER_LIMIT")
    assert caught.value.details == {
        "volume_id": volume.id,
        "size_bytes": LIMIT + 1,
        "max_bytes": LIMIT,
    }


async def test_read_only_mount_of_an_over_limit_volume_is_allowed(
    make_service: ServiceFactory,
    uow_factory: UowFactory,
    driver: FakeDriver,
    org_id: str,
) -> None:
    service = make_service(LIMIT)
    volume = await service.create(org_id, None, "data")
    write_bytes(driver, volume, LIMIT * 5)
    mounts = await mount(service, uow_factory, org_id, volume, read_only=True)
    assert [item.volume_id for item in mounts] == [volume.id]


async def test_read_write_mount_at_exactly_the_limit_is_allowed(
    make_service: ServiceFactory,
    uow_factory: UowFactory,
    driver: FakeDriver,
    org_id: str,
) -> None:
    service = make_service(LIMIT)
    volume = await service.create(org_id, None, "data")
    write_bytes(driver, volume, LIMIT)
    assert len(await mount(service, uow_factory, org_id, volume)) == 1


async def test_without_a_limit_any_size_mounts_read_write(
    make_service: ServiceFactory,
    uow_factory: UowFactory,
    driver: FakeDriver,
    org_id: str,
) -> None:
    service = make_service(0)
    volume = await service.create(org_id, None, "data")
    write_bytes(driver, volume, 10 * LIMIT)
    assert len(await mount(service, uow_factory, org_id, volume)) == 1


async def test_stale_sample_is_refreshed_before_the_decision(
    make_service: ServiceFactory,
    uow_factory: UowFactory,
    driver: FakeDriver,
    clock: FrozenClock,
    org_id: str,
) -> None:
    service = make_service(LIMIT)
    volume = await service.create(org_id, None, "data")
    write_bytes(driver, volume, 10)
    await service.get(org_id, volume.id)  # samples 10 bytes now
    write_bytes(driver, volume, LIMIT + 1)  # filled after the sample
    assert len(await mount(service, uow_factory, org_id, volume)) == 1  # fresh: stored 10 used
    clock.advance(timedelta(seconds=INTERVAL_S + 1))
    with pytest.raises(VolumeOverLimit) as caught:
        await mount(service, uow_factory, org_id, volume)
    assert caught.value.details["size_bytes"] == LIMIT + 1


async def test_never_sampled_volume_is_sampled_before_the_decision(
    make_service: ServiceFactory,
    uow_factory: UowFactory,
    driver: FakeDriver,
    org_id: str,
) -> None:
    service = make_service(LIMIT)
    volume = await service.create(org_id, None, "data")
    write_bytes(driver, volume, LIMIT + 1)
    with pytest.raises(VolumeOverLimit):
        await mount(service, uow_factory, org_id, volume)


async def test_the_pre_step_stores_the_fresh_size(
    make_service: ServiceFactory,
    uow_factory: UowFactory,
    driver: FakeDriver,
    org_id: str,
) -> None:
    service = make_service(LIMIT)
    volume = await service.create(org_id, None, "data")
    write_bytes(driver, volume, 77)
    await mount(service, uow_factory, org_id, volume)
    async with uow_factory() as uow:
        row = await uow.volumes.get(org_id, volume.id)
    assert row is not None and row.sampled_size_bytes == 77


# -- no driver call inside a transaction ---------------------------------------------------


@pytest.mark.parametrize(
    ("size", "refused"), [(LIMIT + 1, True), (10, False)], ids=["over-limit", "under-limit"]
)
async def test_sandbox_create_never_calls_the_driver_inside_a_transaction(
    app: FastAPI, clock: FrozenClock, org_id: str, size: int, refused: bool
) -> None:
    tracker = Tracker()
    recording = RecordingDriver(clock, tracker)

    def factory() -> UnitOfWorkPort:
        return TrackingUow(app.state.session_factory, tracker)

    volumes = VolumeService(
        factory, recording, clock, max_bytes=LIMIT, sample_interval_s=INTERVAL_S
    )
    sandboxes = SandboxService(
        factory,
        recording,
        Settings(driver="fake", api_key_pepper=PEPPER),
        clock,
        volume_guard=volumes.guard,
    )
    volume = await volumes.create(org_id, None, "data")
    recording._volume_files[volume.provider_volume_name] = {"blob": b"x" * size}
    create = sandboxes.create(
        org_id, "actor", CreateSandboxCommand(volumes=(MountRequest(volume.id, "/data"),))
    )
    if refused:
        with pytest.raises(VolumeOverLimit):
            await create
    else:
        await create
    assert tracker.inspects, "the pre-step must sample the requested read-write volume"
    assert tracker.inspects == [0] * len(tracker.inspects)  # no unit of work was open
    assert tracker.open == 0


async def test_resolve_mounts_alone_does_not_touch_the_driver(
    make_service: ServiceFactory,
    uow_factory: UowFactory,
    driver: FakeDriver,
    org_id: str,
) -> None:
    volume = await make_service(LIMIT).create(org_id, None, "data")
    write_bytes(driver, volume, LIMIT * 3)  # over the limit, but nobody sampled it
    async with uow_factory() as uow:  # no sizes handed in: the stored sample decides (none)
        mounts = await resolve_mounts(uow, org_id, [MountRequest(volume.id, "/data")])
    assert len(mounts) == 1


# -- when a sample is remembered -----------------------------------------------------------


async def test_a_sample_is_remembered_only_after_its_commit(
    app: FastAPI,
    make_service: ServiceFactory,
    uow_factory: UowFactory,
    driver: FakeDriver,
    org_id: str,
) -> None:
    service = make_service(LIMIT)
    volume = await service.create(org_id, None, "data")
    write_bytes(driver, volume, 50)  # differs from the stored (none): a write is needed
    requests = [MountRequest(volume.id, "/data")]

    def failing() -> UnitOfWorkPort:
        return FailingCommitUow(app.state.session_factory)

    with pytest.raises(RuntimeError, match="commit failed"):
        await service.guard.prepare(failing, org_id, requests)
    assert service.guard.is_fresh(volume.id) is False  # the rolled-back sample is not trusted
    await service.guard.prepare(uow_factory, org_id, requests)
    assert service.guard.is_fresh(volume.id) is True


async def test_a_read_refresh_remembers_the_sample_after_it_commits(
    make_service: ServiceFactory, driver: FakeDriver, org_id: str
) -> None:
    service = make_service(LIMIT)
    volume = await service.create(org_id, None, "data")
    write_bytes(driver, volume, 5)
    assert service.guard.is_fresh(volume.id) is False
    await service.get(org_id, volume.id)
    assert service.guard.is_fresh(volume.id) is True


# -- the bookkeeping is bounded ------------------------------------------------------------


def test_sampled_at_bookkeeping_keeps_a_fixed_number_of_volumes(clock: FrozenClock) -> None:
    async def never(ref: str) -> dict[str, Any]:
        raise AssertionError(ref)

    guard = MountGuard(LIMIT, INTERVAL_S, clock, never, max_tracked=3)
    for number in range(10):
        guard.note_sample(f"vol_{number}")
    assert guard.tracked_ids() == ("vol_7", "vol_8", "vol_9")  # the least recent were dropped


def test_a_refreshed_volume_outlives_older_ones(clock: FrozenClock) -> None:
    async def never(ref: str) -> dict[str, Any]:
        raise AssertionError(ref)

    guard = MountGuard(LIMIT, INTERVAL_S, clock, never, max_tracked=2)
    guard.note_sample("vol_a")
    guard.note_sample("vol_b")
    guard.note_sample("vol_a")  # sampled again: now the most recent
    guard.note_sample("vol_c")
    assert guard.tracked_ids() == ("vol_a", "vol_c")


async def test_deleting_a_volume_drops_its_entry(
    make_service: ServiceFactory, driver: FakeDriver, org_id: str
) -> None:
    service = make_service(LIMIT)
    volume = await service.create(org_id, None, "data")
    await service.get(org_id, volume.id)
    assert volume.id in service.guard.tracked_ids()
    await service.delete(org_id, None, volume.id)
    assert volume.id not in service.guard.tracked_ids()


# -- the sandbox create path ---------------------------------------------------------------


async def test_sandbox_create_answers_422_for_an_over_limit_read_write_volume(
    app: FastAPI, driver: FakeDriver, org_id: str
) -> None:
    generated = generate_api_key(PEPPER)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(
            ApiKey(
                id=new_api_key_id(),
                org_id=org_id,
                name="ci",
                prefix=generated.prefix,
                secret_hash=generated.secret_hash,
                scopes=FULL_ACCESS,
                created_at=NOW,
            )
        )
        await uow.commit()
    volume = await getattr(app.state, VOLUME_SERVICE_ATTR).create(org_id, None, "data")
    write_bytes(driver, volume, LIMIT + 1)
    headers = {"Authorization": f"Bearer {generated.key}"}
    mount_body = {"volume_id": volume.id, "mount_path": "/data"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        refused = await client.post(
            "/v1/sandboxes", headers=headers, json={"volumes": [mount_body]}
        )
        allowed = await client.post(
            "/v1/sandboxes",
            headers=headers,
            json={"volumes": [{**mount_body, "read_only": True}]},
        )
        read = await client.get(f"/v1/volumes/{volume.id}", headers=headers)
    assert refused.status_code == 422, refused.text
    error = refused.json()["error"]
    assert error["code"] == "VOLUME_OVER_LIMIT"
    assert error["details"]["volume_id"] == volume.id
    assert allowed.status_code == 201, allowed.text
    assert read.json()["data"]["max_bytes"] == LIMIT


# -- helpers for the third-review fixes ----------------------------------------------------


class Stack(NamedTuple):
    volumes: VolumeService
    sandboxes: SandboxService
    driver: RecordingDriver
    tracker: Tracker
    quota: QuotaService
    settings: Settings
    factory: UowFactory


def build_stack(app: FastAPI, clock: FrozenClock) -> Stack:
    """Volume and sandbox services over one tracking driver and one tracking unit of work."""
    tracker = Tracker()
    recording = RecordingDriver(clock, tracker)

    def factory() -> UnitOfWorkPort:
        return TrackingUow(app.state.session_factory, tracker)

    settings = Settings(driver="fake", api_key_pepper=PEPPER)
    volumes = VolumeService(
        factory, recording, clock, max_bytes=LIMIT, sample_interval_s=INTERVAL_S
    )
    quota = QuotaService(factory, settings, clock)
    sandboxes = SandboxService(
        factory, recording, settings, clock, quota=quota, volume_guard=volumes.guard
    )
    return Stack(volumes, sandboxes, recording, tracker, quota, settings, factory)


@contextmanager
def label_scope(scope: dict[str, str]) -> Iterator[None]:
    token = set_label_scope(scope)
    try:
        yield
    finally:
        set_label_scope(None)
        del token


async def build_wired_app(tmp_path: Path, name: str, max_bytes: int) -> tuple[FastAPI, str]:
    """A fully wired app on its own database with one org; returns it and the org id."""
    url = f"sqlite+aiosqlite:///{tmp_path / (name + '.db')}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(
        Settings(
            driver="fake", database_url=url, api_key_pepper=PEPPER, volume_max_bytes=max_bytes
        )
    )
    org = Org(id=new_org_id(), name=name, slug=name, created_at=NOW)
    async with UnitOfWork(application.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return application, org.id


# -- the reported limit belongs to the service instance ------------------------------------


async def test_two_wirings_with_different_limits_report_independently(tmp_path: Path) -> None:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    strict, strict_org = await build_wired_app(tmp_path, "strict", 100)
    open_app, open_org = await build_wired_app(tmp_path, "open", 0)  # wired after the first
    try:
        reported = []
        for application, org in ((strict, strict_org), (open_app, open_org)):
            service = getattr(application.state, VOLUME_SERVICE_ATTR)
            volume = await service.create(org, None, "data")
            write_bytes(application.state.driver, volume, 500)
            read = volume_response(await service.get(org, volume.id))
            reported.append((read.max_bytes, read.over_limit))
        assert reported == [(100, True), (None, False)]
    finally:
        await strict.state.engine.dispose()
        await open_app.state.engine.dispose()


async def test_response_of_a_service_volume_without_a_limit_reports_none(
    make_service: ServiceFactory, org_id: str
) -> None:
    volume = await make_service(0).create(org_id, None, "data")
    response = volume_response(volume)
    assert (response.max_bytes, response.over_limit) == (None, False)


async def test_every_service_read_carries_the_services_limit(
    make_service: ServiceFactory, driver: FakeDriver, org_id: str
) -> None:
    service = make_service(LIMIT)
    created = await service.create(org_id, None, "data")
    write_bytes(driver, created, LIMIT + 1)
    listed = (await service.list(org_id))[0]
    deleted = await service.delete(org_id, None, created.id)
    for volume in (created, listed, deleted):
        assert volume_response(volume).max_bytes == LIMIT
    assert volume_response(listed).over_limit is True


# -- a sample for a volume deleted meanwhile -----------------------------------------------


async def test_a_sample_of_a_volume_deleted_meanwhile_is_not_noted(
    make_service: ServiceFactory, uow_factory: UowFactory, org_id: str
) -> None:
    service = make_service(LIMIT)
    volume = await service.create(org_id, None, "data")
    async with uow_factory() as uow:  # deleted by someone else after the volume was read
        await uow.volumes.delete(org_id, volume.id)
        await uow.commit()
    result = await service.guard.store_sample(uow_factory, volume, 50)
    assert result == volume
    assert service.guard.is_fresh(volume.id) is False
    assert volume.id not in service.guard.tracked_ids()


# -- the pre-step runs after the cheap refusals --------------------------------------------


async def test_scoped_key_causes_no_inspect_of_volumes_it_cannot_mount(
    app: FastAPI, clock: FrozenClock, org_id: str
) -> None:
    stack = build_stack(app, clock)
    outside = await stack.volumes.create(org_id, None, "outside")
    with label_scope({"team": "a"}):
        inside = await stack.volumes.create(org_id, None, "inside")  # scope merged into labels
    only_outside = CreateSandboxCommand(volumes=(MountRequest(outside.id, "/out"),))
    both = CreateSandboxCommand(
        volumes=(MountRequest(outside.id, "/out"), MountRequest(inside.id, "/in"))
    )
    with label_scope({"team": "a"}):
        with pytest.raises(Forbidden):
            await stack.sandboxes.create(org_id, "actor", only_outside)
        assert stack.tracker.refs == []  # nothing the key may mount, nothing inspected
        with pytest.raises(Forbidden):
            await stack.sandboxes.create(org_id, "actor", both)
    assert stack.tracker.refs == [inside.provider_volume_name]  # the out-of-scope one is skipped


async def test_quota_refusal_happens_before_any_inspect(
    app: FastAPI, clock: FrozenClock, org_id: str
) -> None:
    stack = build_stack(app, clock)
    volume = await stack.volumes.create(org_id, None, "data")
    await stack.quota.set_limits(org_id, None, OrgQuota(max_sandboxes=0))
    command = CreateSandboxCommand(volumes=(MountRequest(volume.id, "/data"),))
    with pytest.raises(QuotaExceeded):
        await stack.sandboxes.create(org_id, "actor", command)
    assert stack.tracker.refs == []
    assert stack.tracker.open == 0


async def test_read_only_mounts_cost_no_inspect(
    app: FastAPI, clock: FrozenClock, org_id: str
) -> None:
    stack = build_stack(app, clock)
    volume = await stack.volumes.create(org_id, None, "data")
    await stack.sandboxes.create(
        org_id, "actor", CreateSandboxCommand(volumes=(MountRequest(volume.id, "/d", True),))
    )
    assert stack.tracker.refs == []


# -- a volume that reports no size is not inspected on every create ------------------------


async def test_a_no_size_inspection_is_not_repeated_within_the_interval(
    make_service: ServiceFactory,
    uow_factory: UowFactory,
    clock: FrozenClock,
    org_id: str,
) -> None:
    volume = await make_service(LIMIT).create(org_id, None, "data")
    calls: list[str] = []

    async def without_size(ref: str) -> dict[str, Any]:
        calls.append(ref)
        return {}

    guard = MountGuard(LIMIT, INTERVAL_S, clock, without_size)
    requests = [MountRequest(volume.id, "/data")]
    first = await guard.prepare(uow_factory, org_id, requests)
    second = await guard.prepare(uow_factory, org_id, requests)
    assert len(calls) == 1
    assert first is not None and second is not None and not first.sizes and not second.sizes
    clock.advance(timedelta(seconds=INTERVAL_S + 1))
    await guard.prepare(uow_factory, org_id, requests)
    assert len(calls) == 2


# -- start and the resize recreate path ----------------------------------------------------


async def stopped_with_volume(
    stack: Stack, org_id: str, *, read_only: bool = False
) -> tuple[Volume, str]:
    """A stopped sandbox mounting a fresh volume; returns the volume and the sandbox id."""
    volume = await stack.volumes.create(org_id, None, "data")
    command = CreateSandboxCommand(volumes=(MountRequest(volume.id, "/data", read_only),))
    sandbox = await stack.sandboxes.create(org_id, "actor", command)
    await stack.sandboxes.stop(org_id, "actor", sandbox.id)
    return volume, sandbox.id


async def sandbox_state(stack: Stack, org_id: str, sandbox_id: str) -> SandboxState:
    async with stack.factory() as uow:
        row = await uow.sandboxes.get(org_id, sandbox_id)
    assert row is not None
    return row.state


async def test_start_refuses_a_read_write_mount_of_an_over_limit_volume(
    app: FastAPI, clock: FrozenClock, org_id: str
) -> None:
    stack = build_stack(app, clock)
    volume, sandbox_id = await stopped_with_volume(stack, org_id)
    write_bytes(stack.driver, volume, LIMIT + 1)  # filled while the sandbox was stopped
    clock.advance(timedelta(seconds=INTERVAL_S + 1))
    stack.tracker.inspects.clear()
    with pytest.raises(VolumeOverLimit) as caught:
        await stack.sandboxes.start(org_id, "actor", sandbox_id)
    assert (caught.value.status, caught.value.code) == (422, "VOLUME_OVER_LIMIT")
    assert caught.value.details["volume_id"] == volume.id
    assert stack.tracker.inspects == [0]  # sampled once, outside any unit of work
    assert await sandbox_state(stack, org_id, sandbox_id) is SandboxState.STOPPED


async def test_start_allows_a_read_only_mount_of_an_over_limit_volume(
    app: FastAPI, clock: FrozenClock, org_id: str
) -> None:
    stack = build_stack(app, clock)
    volume, sandbox_id = await stopped_with_volume(stack, org_id, read_only=True)
    write_bytes(stack.driver, volume, LIMIT * 5)
    clock.advance(timedelta(seconds=INTERVAL_S + 1))
    await stack.sandboxes.start(org_id, "actor", sandbox_id)
    assert await sandbox_state(stack, org_id, sandbox_id) is SandboxState.STARTED
    assert stack.tracker.refs == []


async def test_start_of_a_sandbox_under_the_limit_still_works(
    app: FastAPI, clock: FrozenClock, org_id: str
) -> None:
    stack = build_stack(app, clock)
    volume, sandbox_id = await stopped_with_volume(stack, org_id)
    write_bytes(stack.driver, volume, 10)
    clock.advance(timedelta(seconds=INTERVAL_S + 1))
    await stack.sandboxes.start(org_id, "actor", sandbox_id)
    assert await sandbox_state(stack, org_id, sandbox_id) is SandboxState.STARTED


async def test_resize_recreate_is_refused_before_the_container_is_replaced(
    app: FastAPI, clock: FrozenClock, org_id: str
) -> None:
    stack = build_stack(app, clock)
    volume, sandbox_id = await stopped_with_volume(stack, org_id)
    async with stack.factory() as uow:
        before = await uow.sandboxes.get(org_id, sandbox_id)
    assert before is not None and before.driver_ref is not None
    resizer = ResizeService(stack.factory, stack.quota, stack.settings, clock)
    bigger = ResizeCommand(memory_mib=ResourceSpec().memory_mib * 2)
    await resizer.resize(org_id, None, sandbox_id, bigger)  # the container keeps the old size
    write_bytes(stack.driver, volume, LIMIT + 1)
    clock.advance(timedelta(seconds=INTERVAL_S + 1))
    with pytest.raises(VolumeOverLimit):
        await stack.sandboxes.start(org_id, "actor", sandbox_id)
    survivor = await stack.driver.inspect(before.driver_ref)  # not destroyed, not recreated
    assert survivor.resources == before.resources
    assert await sandbox_state(stack, org_id, sandbox_id) is SandboxState.STOPPED
