# ruff: noqa: F401, F811
"""Round 73 (SF78-001): orphan ``sf-vxfer-`` helpers of an interrupted transfer must not block
volume recovery (no daemon).

Uses the fake docker-py client of ``test_docker_volume_transfer_unit_r67``. A helper is created
and never started, so neither its state nor its age tells a live transfer from a dead one; the
in-process (client, volume) counter is the liveness source.
"""

import logging
import time
from typing import Any

import pytest
from tests.test_docker_volume_transfer_unit_r67 import (
    HELPER_IMAGE,
    MANAGED,
    REF,
    FakeClient,
    client,
    drain,
    driver,
    error,
    source,
    tar_of,
)

from sandfort.drivers.docker.driver import DockerDriver
from sandfort.drivers.docker.labels import LABEL_MANAGED, LABEL_SANDBOX_ID
from sandfort.drivers.docker.volume_helper import (
    HELPER_LABEL,
    HELPER_NAME_PREFIX,
    HELPER_STARTED_LABEL,
    STALE_HELPER_S,
    helper_container,
    prune_stale_helpers,
    remove_orphan_helpers,
)
from sandfort.drivers.errors import DriverNotFound

OTHER_REF = "sf-vol-vol_other"


def helper_entry(
    helper_id: str,
    ref: str = REF,
    *,
    started: float | None = None,
    extra_labels: dict[str, str] | None = None,
    name: str | None = None,
) -> dict[str, Any]:
    """A listing entry of a helper; fresh by default (never stale by age)."""
    stamp = time.time() if started is None else started
    labels = {HELPER_LABEL: "helper", HELPER_STARTED_LABEL: str(int(stamp))}
    labels.update(extra_labels or {})
    return {
        "Id": helper_id,
        "Names": [name if name is not None else f"/{HELPER_NAME_PREFIX}{helper_id}"],
        "Labels": labels,
        "Mounts": [{"Type": "volume", "Name": ref}],
    }


def removed_ids(client: FakeClient) -> list[str]:
    return [container for container, _ in client.api.removed_containers]


# -- a, b: the recovery paths sweep first -------------------------------------------------------


async def test_clear_removes_a_fresh_orphan_helper_before_recreating_the_volume(
    driver: DockerDriver, client: FakeClient
) -> None:
    client.api.listing = [helper_entry("orphan1")]

    await driver.clear_volume(REF)

    assert removed_ids(client) == ["orphan1"]
    events = client.api.events
    assert (
        events.index("remove_container")
        < events.index("remove_volume")
        < events.index("create_volume")
    )


async def test_restore_sweeps_an_orphan_first_and_then_succeeds_end_to_end(
    driver: DockerDriver, client: FakeClient
) -> None:
    client.api.listing = [helper_entry("orphan1")]

    await driver.restore_volume(REF, source(tar_of(("a.txt", b"1"))))

    assert client.api.uploaded and client.api.uploaded[0]
    assert removed_ids(client) == ["orphan1", "c0ffee"]  # the orphan, then its own helper
    events = client.api.events
    assert events.index("remove_container") < events.index("remove_volume")
    assert events.index("create_volume") < events.index("create_container")


# -- c, d: what is and is not swept -------------------------------------------------------------


async def test_an_orphan_of_another_volume_is_left_alone(client: FakeClient) -> None:
    client.api.listing = [helper_entry("other", OTHER_REF)]

    await remove_orphan_helpers(client, REF)

    assert removed_ids(client) == []


async def test_only_a_plain_helper_is_removed_never_a_sandbox_or_managed_or_foreign_name(
    client: FakeClient,
) -> None:
    client.api.listing = [
        helper_entry("sandboxed", extra_labels={LABEL_SANDBOX_ID: "sbx_1"}),
        helper_entry("managed", extra_labels={LABEL_MANAGED: "true"}),
        helper_entry("foreign", name="/some-other-container"),
        helper_entry("real"),
    ]

    await remove_orphan_helpers(client, REF)

    assert removed_ids(client) == ["real"]


# -- e: logging ---------------------------------------------------------------------------------


async def test_the_removal_is_logged_at_warning_with_the_helper_id_and_the_volume(
    client: FakeClient, caplog: pytest.LogCaptureFixture
) -> None:
    client.api.listing = [helper_entry("deadbeef42")]

    with caplog.at_level(logging.WARNING, logger="sandfort.drivers.docker.volume_helper"):
        await remove_orphan_helpers(client, REF)

    messages = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any("deadbeef42" in m and REF in m for m in messages)


# -- f, g, h: the in-process counter ------------------------------------------------------------


async def test_a_live_transfer_of_the_volume_blocks_the_sweep_until_it_closes(
    client: FakeClient,
) -> None:
    async with helper_container(client, HELPER_IMAGE, REF, writable=True):
        client.api.listing = [helper_entry("looks-orphaned")]
        await remove_orphan_helpers(client, REF)
        assert "looks-orphaned" not in removed_ids(client)

    await remove_orphan_helpers(client, REF)

    assert "looks-orphaned" in removed_ids(client)


async def test_the_early_return_is_per_volume(client: FakeClient) -> None:
    async with helper_container(client, HELPER_IMAGE, REF, writable=True):
        client.api.listing = [helper_entry("other-orphan", OTHER_REF)]

        await remove_orphan_helpers(client, OTHER_REF)

        assert "other-orphan" in removed_ids(client)


async def test_the_counter_is_per_client(client: FakeClient) -> None:
    other = FakeClient()
    other.api.listing = [helper_entry("on-b")]

    async with helper_container(client, HELPER_IMAGE, REF, writable=True):
        await remove_orphan_helpers(other, REF)

    assert removed_ids(other) == ["on-b"]


async def test_the_counter_is_decremented_when_the_transfer_fails(client: FakeClient) -> None:
    with pytest.raises(RuntimeError):
        async with helper_container(client, HELPER_IMAGE, REF, writable=True):
            raise RuntimeError("the transfer failed")
    client.api.listing = [helper_entry("after-failure")]

    await remove_orphan_helpers(client, REF)

    assert "after-failure" in removed_ids(client)


async def test_the_counter_counts_concurrent_transfers_of_one_volume(client: FakeClient) -> None:
    async with helper_container(client, HELPER_IMAGE, REF, writable=False):
        async with helper_container(client, HELPER_IMAGE, REF, writable=False):
            pass
        client.api.listing = [helper_entry("still-live")]
        await remove_orphan_helpers(client, REF)
        assert "still-live" not in removed_ids(client)


async def test_a_missing_volume_leaves_no_count_behind(client: FakeClient) -> None:
    client.api.volume = None
    with pytest.raises(DriverNotFound):
        async with helper_container(client, HELPER_IMAGE, REF, writable=True):
            pass
    client.api.listing = [helper_entry("after-missing")]

    await remove_orphan_helpers(client, REF)

    assert removed_ids(client) == ["after-missing"]


# -- i, j: never raises -------------------------------------------------------------------------


async def test_a_failing_listing_never_raises(client: FakeClient) -> None:
    def broken(**kwargs: Any) -> list[dict[str, Any]]:
        raise RuntimeError("daemon down")

    client.api.containers = broken  # type: ignore[method-assign]

    await remove_orphan_helpers(client, REF)


async def test_a_failing_removal_never_raises_and_does_not_stop_the_loop(
    client: FakeClient,
) -> None:
    attempted: list[str] = []

    def failing(container: str, **kwargs: Any) -> None:
        attempted.append(container)
        raise RuntimeError("cannot remove")

    client.api.remove_container = failing  # type: ignore[method-assign]
    client.api.listing = [helper_entry("first"), helper_entry("second")]

    await remove_orphan_helpers(client, REF)

    assert attempted == ["first", "second"]


async def test_a_malformed_entry_does_not_stop_the_sweep_of_the_next_one(
    client: FakeClient,
) -> None:
    client.api.listing = [
        {"Id": "broken", "Names": None, "Labels": None, "Mounts": None},
        {"Id": "broken2", "Names": [None], "Labels": {HELPER_LABEL: "helper"}, "Mounts": [None]},
        None,  # type: ignore[list-item]
        helper_entry("good"),
    ]

    await remove_orphan_helpers(client, REF)

    assert removed_ids(client) == ["good"]


# -- k: volume delete ---------------------------------------------------------------------------


async def test_remove_volume_sweeps_an_orphan_export_helper_before_removing_the_volume(
    driver: DockerDriver, client: FakeClient
) -> None:
    client.api.listing = [helper_entry("export-orphan")]

    await driver.remove_volume(REF)

    assert removed_ids(client) == ["export-orphan"]
    events = client.api.events
    assert events.index("remove_container") < events.index("remove_volume")


# -- l: the 6 h prune honours live transfers ----------------------------------------------------


async def test_prune_skips_a_stale_looking_helper_of_a_volume_with_a_live_transfer(
    client: FakeClient,
) -> None:
    old = time.time() - STALE_HELPER_S - 60
    entry = helper_entry("long-export", started=old)

    async with helper_container(client, HELPER_IMAGE, REF, writable=False):
        client.api.listing = [entry]
        await prune_stale_helpers(client)
        assert "long-export" not in removed_ids(client)

    fresh = FakeClient()
    fresh.api.listing = [entry]
    await prune_stale_helpers(fresh)

    assert removed_ids(fresh) == ["long-export"]
