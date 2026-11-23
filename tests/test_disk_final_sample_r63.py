"""Round 63: a final disk sample at stop and delete.

Stop and delete read the size from the driver before it stops or removes the container (no
transaction open) and credit it in their own short unit of work, so a sandbox deleted before
its first tick is credited over its whole run and a size change since the last tick is credited
over the tail the sampler missed (at most one sample interval). When the driver cannot answer,
the last known size stands. Fake clock, fake driver whose sizes the test sets.
"""

from datetime import timedelta

import pytest

import test_usage
from sandfort.domain.sandbox import SandboxState
from sandfort.domain.usage import UsageInterval
from sandfort.services.sandbox_jobs import Lifecycle
from sandfort.services.usage import BYTES_PER_GIB, with_usage_metering
from test_usage import (
    ACTOR,
    DISK,
    HOUR,
    SAMPLE_INTERVAL_S,
    T0,
    VCPU,
    World,
    add_org,
    metering,
    start_sandbox,
    totals,
)

world = test_usage.world  # the shared fixture: migrated app, fake clock, fake driver
TICK = timedelta(seconds=SAMPLE_INTERVAL_S)
MINUTE = timedelta(minutes=1)
TWO_GIB = 2 * BYTES_PER_GIB
FOUR_GIB = 4 * BYTES_PER_GIB
DAY = 24 * HOUR


class Sizes:
    """The driver's answer, how often it was asked, and whether the container still existed."""

    def __init__(self, world: World, size: int | None | Exception) -> None:
        self.world = world
        self.size = size
        self.container_present: list[bool] = []

    async def __call__(self, provider_id: str) -> int | None:
        self.container_present.append(provider_id in self.world.driver._instances)
        if isinstance(self.size, Exception):
            raise self.size
        return self.size


def drive_sizes(
    world: World, monkeypatch: pytest.MonkeyPatch, size: int | None | Exception
) -> Sizes:
    sizes = Sizes(world, size)
    monkeypatch.setattr(world.driver, "instance_size_bytes", sizes)
    return sizes


async def disk_intervals(world: World, org_id: str) -> list[UsageInterval]:
    async with world.uow_factory() as uow:
        found = await uow.usage.list_intervals(T0 - DAY, T0 + DAY, org_id=org_id)
    return [item for item in found if item.dimension is DISK]


async def test_a_delete_before_the_first_sample_credits_the_run_at_the_final_size(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    sizes = drive_sizes(world, monkeypatch, TWO_GIB)
    org_id = await add_org(world, "acme")
    sandbox_id = await start_sandbox(world, org_id)
    world.clock.advance(timedelta(seconds=100))

    await world.sandboxes.delete(org_id, ACTOR, sandbox_id)
    world.clock.advance(HOUR)  # nothing accrues after the delete and no tick adds any
    assert await metering(world).sample_once() == 0
    got = await totals(world, org_id, T0, T0 + 2 * HOUR)

    assert got[DISK] == 2.0 * 100
    assert got[DISK] == got[VCPU]
    (interval,) = await disk_intervals(world, org_id)
    assert (interval.started_at, interval.ended_at) == (T0, T0 + timedelta(seconds=100))
    assert sizes.container_present == [True]  # read while the container still existed


async def test_a_stop_before_the_first_sample_credits_the_run_at_the_final_size(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    sizes = drive_sizes(world, monkeypatch, TWO_GIB)
    org_id = await add_org(world, "acme")
    sandbox_id = await start_sandbox(world, org_id)
    world.clock.advance(timedelta(seconds=40))

    await world.sandboxes.stop(org_id, ACTOR, sandbox_id)
    got = await totals(world, org_id, T0, T0 + HOUR)

    assert got[DISK] == 2.0 * 40
    assert sizes.container_present == [True]


async def test_a_size_change_in_the_last_minute_before_stop_is_credited(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    drive_sizes(world, monkeypatch, TWO_GIB)
    org_id = await add_org(world, "acme")
    sandbox_id = await start_sandbox(world, org_id)
    world.clock.advance(TICK)
    await metering(world).sample_once()  # unchanged: one open interval from the start
    world.clock.advance(MINUTE)
    drive_sizes(world, monkeypatch, FOUR_GIB)  # grew since the tick

    await world.sandboxes.stop(org_id, ACTOR, sandbox_id)
    world.clock.advance(HOUR)
    got = await totals(world, org_id, T0, T0 + 2 * HOUR)

    # The final size covers the tail the sampler could not see: one sample interval, up to stop.
    stop_at = T0 + TICK + MINUTE
    first, second = await disk_intervals(world, org_id)
    assert (first.started_at, first.ended_at, first.amount) == (T0, stop_at - TICK, 2.0)
    assert (second.started_at, second.ended_at, second.amount) == (stop_at - TICK, stop_at, 4.0)
    assert got[DISK] == 2.0 * 60 + 4.0 * 300
    assert got[VCPU] == 2.0 * 360


async def test_a_size_change_never_reaches_back_before_the_open_interval(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    drive_sizes(world, monkeypatch, TWO_GIB)
    org_id = await add_org(world, "acme")
    sandbox_id = await start_sandbox(world, org_id)
    world.clock.advance(timedelta(seconds=20))
    await metering(world).sample_once()
    drive_sizes(world, monkeypatch, FOUR_GIB)
    world.clock.advance(timedelta(seconds=10))

    await world.sandboxes.stop(org_id, ACTOR, sandbox_id)
    got = await totals(world, org_id, T0, T0 + HOUR)

    old, new = await disk_intervals(world, org_id)  # the whole run is now at the final size
    assert (old.started_at, old.ended_at, old.amount) == (T0, T0, 2.0)  # zero length
    assert (new.started_at, new.amount) == (T0, 4.0)
    assert got[DISK] == 4.0 * 30


async def test_an_unchanged_size_at_stop_adds_no_interval(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    drive_sizes(world, monkeypatch, TWO_GIB)
    org_id = await add_org(world, "acme")
    sandbox_id = await start_sandbox(world, org_id)
    world.clock.advance(TICK)
    await metering(world).sample_once()
    world.clock.advance(MINUTE)

    await world.sandboxes.stop(org_id, ACTOR, sandbox_id)

    (interval,) = await disk_intervals(world, org_id)
    assert (interval.started_at, interval.ended_at) == (T0, T0 + TICK + MINUTE)
    assert (await totals(world, org_id, T0, T0 + HOUR))[DISK] == 2.0 * 360


async def test_a_driver_error_keeps_the_last_known_size_and_the_stop_goes_through(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    drive_sizes(world, monkeypatch, TWO_GIB)
    org_id = await add_org(world, "acme")
    sandbox_id = await start_sandbox(world, org_id)
    world.clock.advance(TICK)
    await metering(world).sample_once()
    world.clock.advance(MINUTE)
    drive_sizes(world, monkeypatch, RuntimeError("docker is not answering"))

    stopped = await world.sandboxes.stop(org_id, ACTOR, sandbox_id)
    got = await totals(world, org_id, T0, T0 + HOUR)

    assert stopped.state is SandboxState.STOPPED
    assert got[DISK] == 2.0 * 360  # the last known size to the stop time
    (interval,) = await disk_intervals(world, org_id)
    assert interval.amount == 2.0


async def test_a_driver_error_before_the_first_sample_keeps_today_s_behaviour_on_delete(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    drive_sizes(world, monkeypatch, RuntimeError("container is gone"))
    org_id = await add_org(world, "acme")
    sandbox_id = await start_sandbox(world, org_id)
    world.clock.advance(timedelta(seconds=100))

    deleted = await world.sandboxes.delete(org_id, ACTOR, sandbox_id)
    got = await totals(world, org_id, T0, T0 + HOUR)

    assert deleted.state is SandboxState.DESTROYED
    assert got[DISK] == 0.0  # no size was ever known
    assert got[VCPU] == 2.0 * 100
    assert await disk_intervals(world, org_id) == []


async def test_a_size_the_driver_does_not_have_keeps_the_last_known_size(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    drive_sizes(world, monkeypatch, TWO_GIB)
    org_id = await add_org(world, "acme")
    sandbox_id = await start_sandbox(world, org_id)
    world.clock.advance(TICK)
    await metering(world).sample_once()
    world.clock.advance(MINUTE)
    drive_sizes(world, monkeypatch, None)

    await world.sandboxes.delete(org_id, ACTOR, sandbox_id)

    assert (await totals(world, org_id, T0, T0 + HOUR))[DISK] == 2.0 * 360


async def test_the_job_lifecycle_on_a_metered_factory_takes_the_final_sample(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    drive_sizes(world, monkeypatch, TWO_GIB)
    org_id = await add_org(world, "acme")
    sandbox_id = await start_sandbox(world, org_id)
    world.clock.advance(timedelta(seconds=90))
    metered = with_usage_metering(world.uow_factory, world.clock, world.driver)
    lifecycle = Lifecycle(metered, world.driver, world.clock)

    await lifecycle.transition(org_id, sandbox_id, SandboxState.DESTROYING)
    await lifecycle.drive_delete(org_id, sandbox_id, ACTOR)
    got = await totals(world, org_id, T0, T0 + HOUR)

    assert got[DISK] == 2.0 * 90


async def test_a_metered_factory_without_a_driver_takes_no_final_sample(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    sizes = drive_sizes(world, monkeypatch, TWO_GIB)
    org_id = await add_org(world, "acme")
    sandbox_id = await start_sandbox(world, org_id)
    world.clock.advance(timedelta(seconds=90))
    metered = with_usage_metering(world.uow_factory, world.clock)
    lifecycle = Lifecycle(metered, world.driver, world.clock)

    await lifecycle.transition(org_id, sandbox_id, SandboxState.STOPPING)
    await lifecycle.drive_stop(org_id, sandbox_id)

    assert sizes.container_present == []
    assert (await totals(world, org_id, T0, T0 + HOUR))[DISK] == 0.0
