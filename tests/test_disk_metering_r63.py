"""Round 63: disk usage is credited for the full started time, like vCPU and memory.

A fake clock and a driver whose reported sizes the test sets. The sampler keeps the 300 s tick
for size sampling; the credit itself follows the run: the open disk interval is closed with the
last known size at stop and delete, a run seen only after the fact is credited from its start,
a size change at a tick splits the interval, and reports clip disk like vCPU.
"""

from datetime import timedelta

import pytest

import test_usage
from sandfort.domain.usage import UsageInterval
from sandfort.services.usage import BYTES_PER_GIB
from test_usage import (
    ACTOR,
    DISK,
    HALF_HOUR,
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
TWO_GIB = 2 * BYTES_PER_GIB
FOUR_GIB = 4 * BYTES_PER_GIB
DAY = 24 * HOUR


def set_size(world: World, monkeypatch: pytest.MonkeyPatch, size_bytes: int) -> None:
    async def size(provider_id: str) -> int | None:
        return size_bytes

    monkeypatch.setattr(world.driver, "instance_size_bytes", size)


async def disk_intervals(world: World, org_id: str) -> list[UsageInterval]:
    async with world.uow_factory() as uow:
        found = await uow.usage.list_intervals(T0 - DAY, T0 + DAY, org_id=org_id)
    return [item for item in found if item.dimension is DISK]


async def test_a_sandbox_that_lives_120_seconds_gets_120_times_its_size(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def unreadable(provider_id: str) -> int | None:
        return None  # the driver cannot answer at stop: the first tick sizes the stopped run

    monkeypatch.setattr(world.driver, "instance_size_bytes", unreadable)
    org_id = await add_org(world, "acme")
    sandbox_id = await start_sandbox(world, org_id)
    world.clock.advance(timedelta(seconds=120))
    await world.sandboxes.stop(org_id, ACTOR, sandbox_id)
    set_size(world, monkeypatch, TWO_GIB)
    world.clock.advance(TICK)  # the first tick sees the sandbox only after it stopped

    recorded = await metering(world).sample_once()
    got = await totals(world, org_id, T0, T0 + HOUR)

    assert recorded == 1
    assert got[DISK] == 2.0 * 120
    assert got[VCPU] == 2.0 * 120


async def test_a_stop_before_the_first_tick_credits_the_whole_run(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_size(world, monkeypatch, TWO_GIB)
    org_id = await add_org(world, "acme")
    sandbox_id = await start_sandbox(world, org_id)
    world.clock.advance(timedelta(seconds=5))
    assert await metering(world).sample_once() == 1  # sized soon after the start
    world.clock.advance(timedelta(seconds=115))

    await world.sandboxes.stop(org_id, ACTOR, sandbox_id)
    world.clock.advance(HOUR)  # nothing accrues after the stop, and no later pass adds any
    await metering(world).sample_once()
    got = await totals(world, org_id, T0, T0 + 2 * HOUR)

    assert got[DISK] == 2.0 * 120
    (interval,) = await disk_intervals(world, org_id)
    assert (interval.started_at, interval.ended_at) == (T0, T0 + timedelta(seconds=120))


async def test_the_tail_after_the_last_tick_is_credited_at_stop(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_size(world, monkeypatch, TWO_GIB)
    org_id = await add_org(world, "acme")
    sandbox_id = await start_sandbox(world, org_id)
    world.clock.advance(TICK)
    await metering(world).sample_once()
    world.clock.advance(timedelta(seconds=200))  # the tail after the tick

    await world.sandboxes.stop(org_id, ACTOR, sandbox_id)
    world.clock.advance(HOUR)
    got = await totals(world, org_id, T0, T0 + 2 * HOUR)

    assert got[DISK] == 2.0 * 500
    assert got[DISK] == got[VCPU]  # vCPU is 2 for the same 500 s


async def test_a_delete_closes_the_open_disk_interval(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_size(world, monkeypatch, TWO_GIB)
    org_id = await add_org(world, "acme")
    sandbox_id = await start_sandbox(world, org_id)
    world.clock.advance(TICK)
    await metering(world).sample_once()
    world.clock.advance(TICK)

    await world.sandboxes.delete(org_id, ACTOR, sandbox_id)
    world.clock.advance(HOUR)  # a destroyed sandbox accrues nothing more
    await metering(world).sample_once()
    got = await totals(world, org_id, T0, T0 + 2 * HOUR)

    assert got[DISK] == 2.0 * 600
    (interval,) = await disk_intervals(world, org_id)
    assert interval.ended_at == T0 + 2 * TICK


async def test_an_unchanged_size_keeps_one_interval_across_ticks(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_size(world, monkeypatch, TWO_GIB)
    org_id = await add_org(world, "acme")
    await start_sandbox(world, org_id)
    for _ in range(3):
        world.clock.advance(TICK)
        await metering(world).sample_once()

    (interval,) = await disk_intervals(world, org_id)
    got = await totals(world, org_id, T0, T0 + 3 * TICK)

    assert interval.ended_at is None
    assert got[DISK] == 2.0 * 900


async def test_a_size_change_at_a_tick_splits_the_interval(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_size(world, monkeypatch, TWO_GIB)
    org_id = await add_org(world, "acme")
    sandbox_id = await start_sandbox(world, org_id)
    world.clock.advance(TICK)
    await metering(world).sample_once()
    world.clock.advance(TICK)
    set_size(world, monkeypatch, FOUR_GIB)
    assert await metering(world).sample_once() == 1
    world.clock.advance(TICK)
    await world.sandboxes.stop(org_id, ACTOR, sandbox_id)

    first, second = await disk_intervals(world, org_id)
    got = await totals(world, org_id, T0, T0 + HOUR)

    assert (first.started_at, first.ended_at, first.amount) == (T0, T0 + 2 * TICK, 2.0)
    assert (second.started_at, second.ended_at, second.amount) == (
        T0 + 2 * TICK,
        T0 + 3 * TICK,
        4.0,
    )
    assert got[DISK] == 2.0 * 600 + 4.0 * 300


async def test_a_restart_credits_the_new_run_and_not_the_stopped_time(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_size(world, monkeypatch, TWO_GIB)
    org_id = await add_org(world, "acme")
    sandbox_id = await start_sandbox(world, org_id)
    world.clock.advance(TICK)
    await metering(world).sample_once()
    await world.sandboxes.stop(org_id, ACTOR, sandbox_id)
    world.clock.advance(HALF_HOUR)
    await world.sandboxes.start(org_id, ACTOR, sandbox_id)
    world.clock.advance(TICK)
    await metering(world).sample_once()
    world.clock.advance(TICK)
    await world.sandboxes.stop(org_id, ACTOR, sandbox_id)

    got = await totals(world, org_id, T0, T0 + 2 * HOUR)

    assert got[DISK] == 2.0 * 900
    assert got[DISK] == got[VCPU]


async def test_a_driver_without_a_size_credits_nothing_and_changes_nothing(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def not_cheap(provider_id: str) -> int | None:
        return None

    monkeypatch.setattr(world.driver, "instance_size_bytes", not_cheap)
    org_id = await add_org(world, "acme")
    await start_sandbox(world, org_id)
    world.clock.advance(TICK)

    recorded = await metering(world).sample_once()

    assert recorded == 0
    assert await disk_intervals(world, org_id) == []


async def test_disk_is_clipped_at_the_window_edges_like_vcpu(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_size(world, monkeypatch, TWO_GIB)
    org_id = await add_org(world, "acme")
    sandbox_id = await start_sandbox(world, org_id, cpu_millicores=1000)
    world.clock.advance(TICK)
    await metering(world).sample_once()
    world.clock.advance(2 * HOUR)
    await world.sandboxes.stop(org_id, ACTOR, sandbox_id)
    inside = (T0 + HALF_HOUR, T0 + HOUR + HALF_HOUR)
    straddling = (T0 - HOUR, T0 + 2 * HOUR)
    around = (T0 - HOUR, T0 + 5 * HOUR)

    for start, end in (inside, straddling, around):
        got = await totals(world, org_id, start, end)
        assert got[DISK] == 2.0 * got[VCPU]  # 1 vCPU and 2 GiB over the same clipped seconds
        assert got[VCPU] > 0

    assert (await totals(world, org_id, *inside))[DISK] == 2.0 * 3600
    assert (await totals(world, org_id, *around))[DISK] == 2.0 * (2 * 3600 + 300)


async def test_a_running_sandbox_is_clipped_at_now(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_size(world, monkeypatch, TWO_GIB)
    org_id = await add_org(world, "acme")
    await start_sandbox(world, org_id, cpu_millicores=1000)
    world.clock.advance(TICK)
    await metering(world).sample_once()
    world.clock.advance(timedelta(seconds=100))

    got = await totals(world, org_id, T0, T0 + DAY)

    assert got[DISK] == 2.0 * 400
    assert got[DISK] == 2.0 * got[VCPU]


async def test_the_sum_of_groups_equals_the_total(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_size(world, monkeypatch, TWO_GIB)
    org_id = await add_org(world, "acme")
    first = await start_sandbox(world, org_id)
    world.clock.advance(timedelta(seconds=50))
    second = await start_sandbox(world, org_id, cpu_millicores=1000)
    world.clock.advance(timedelta(seconds=250))
    await metering(world).sample_once()
    world.clock.advance(timedelta(seconds=100))
    await world.sandboxes.stop(org_id, ACTOR, first)
    world.clock.advance(timedelta(seconds=200))
    await world.sandboxes.delete(org_id, ACTOR, second)
    start, end = T0 + timedelta(seconds=30), T0 + timedelta(seconds=500)

    groups = await world.usage.report_grouped(org_id, start, end, "sandbox")
    total = await totals(world, org_id, start, end)

    per_sandbox = {
        group.value: {item.dimension: item.total for item in group.totals} for group in groups
    }
    assert set(per_sandbox) == {first, second}
    assert per_sandbox[first][DISK] == 2.0 * (400 - 30)  # stopped at 400 s, window opens at 30 s
    assert per_sandbox[second][DISK] == 2.0 * (500 - 50)  # runs to 600 s, window ends at 500 s
    assert sum(item[DISK] for item in per_sandbox.values()) == pytest.approx(total[DISK])
    assert sum(item[VCPU] for item in per_sandbox.values()) == pytest.approx(total[VCPU])
