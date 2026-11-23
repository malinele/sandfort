# ruff: noqa: F401, F811
"""Round 72: two fault-injection flags for the agreed post-extraction fault window.

``restore_extract_hold`` stalls the docker restore upload after its first piece went to the
daemon, so an operator can kill the server knowing extraction had begun.
``volume_recovery_clear_fail`` makes the start-up restore recovery fail to empty every volume (the
driver is not called), so the marked volumes stay marked. Neither does anything when unset.
"""

import asyncio
import gzip
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from tests.test_docker_volume_transfer_unit_r67 import (
    REF,
    FakeClient,
    drain,
    source,
    tar_of,
)
from tests.test_volume_restore_marker_r71 import marker, set_marker, volume_files
from tests.test_volume_transfer_r67 import (
    FILES,
    RESTORE_ACTION,
    add_key,
    add_org,
    audit_rows,
    auth,
    error,
    export,
    make_app,
    make_archive,
    new_volume,
    restore,
    seeded_volume,
)

from sandfort.config import (
    FAULT_RESTORE_EXTRACT_HOLD,
    FAULT_VOLUME_RECOVERY_CLEAR_FAIL,
    VALID_FAULTS,
    Settings,
    parse_fault_injection,
)
from sandfort.drivers.docker.driver import DockerDriver
from sandfort.drivers.fake import FakeDriver

KEEP = {"keep.txt": b"safe"}
BOTH = (FAULT_RESTORE_EXTRACT_HOLD, FAULT_VOLUME_RECOVERY_CLEAR_FAIL)
STALL_S = 0.4  # long enough to call it a stall, short enough for the suite


def test_the_two_flags_have_the_agreed_names_and_are_known() -> None:
    assert FAULT_RESTORE_EXTRACT_HOLD == "restore_extract_hold"
    assert FAULT_VOLUME_RECOVERY_CLEAR_FAIL == "volume_recovery_clear_fail"
    assert {FAULT_RESTORE_EXTRACT_HOLD, FAULT_VOLUME_RECOVERY_CLEAR_FAIL} <= set(VALID_FAULTS)


def test_the_flags_parse_next_to_each_other_and_a_typo_is_still_refused() -> None:
    assert parse_fault_injection(" Restore_Extract_Hold, volume_recovery_clear_fail ,") == BOTH
    with pytest.raises(ValueError, match="unknown fault"):
        parse_fault_injection("restore_extract_hld")


# -- restore_extract_hold, at the docker upload ----------------------------------------------


def big_tar() -> bytes:
    return tar_of(("a.bin", bytes(600 * 1024)), ("b.txt", b"tail"))  # several upload pieces


def driver_with(client: FakeClient, *faults: str) -> DockerDriver:
    return DockerDriver(Settings(driver="docker", fault_injection=faults), client=client)


class SlowApi:
    """Wraps ``put_archive`` so a test sees which pieces the daemon was handed, and when."""

    def __init__(self, client: FakeClient) -> None:
        self.pieces: list[int] = []
        self.finished = False

        def put_archive(container: str, path: str, data: Any) -> bool:
            for piece in data:
                self.pieces.append(len(piece))
            self.finished = True
            return True

        client.api.put_archive = put_archive  # type: ignore[method-assign]


async def test_with_the_hold_the_upload_stalls_after_the_first_piece_reached_the_daemon() -> None:
    client = FakeClient()
    api = SlowApi(client)
    driver = driver_with(client, FAULT_RESTORE_EXTRACT_HOLD)

    task = asyncio.ensure_future(driver.restore_volume(REF, source(big_tar(), step=64 * 1024)))
    await asyncio.sleep(STALL_S)

    assert not task.done()
    assert len(api.pieces) == 1  # exactly the first piece went out; the rest never did
    assert not api.finished
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_cancelling_a_held_restore_ends_the_upload_and_removes_the_helper() -> None:
    client = FakeClient()
    SlowApi(client)
    driver = driver_with(client, FAULT_RESTORE_EXTRACT_HOLD)
    task = asyncio.ensure_future(driver.restore_volume(REF, source(big_tar(), step=64 * 1024)))
    await asyncio.sleep(STALL_S)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert "remove_container" in client.api.events


async def test_a_small_archive_is_held_after_its_only_piece_before_the_body_ends() -> None:
    client = FakeClient()
    api = SlowApi(client)
    driver = driver_with(client, FAULT_RESTORE_EXTRACT_HOLD)

    task = asyncio.ensure_future(driver.restore_volume(REF, source(tar_of(("a", b"1")))))
    await asyncio.sleep(STALL_S)

    assert not task.done()
    assert len(api.pieces) == 1
    assert not api.finished  # the request body was never terminated
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_without_the_flag_the_same_restore_runs_to_the_end() -> None:
    client = FakeClient()
    api = SlowApi(client)
    driver = driver_with(client)

    await asyncio.wait_for(driver.restore_volume(REF, source(big_tar(), step=64 * 1024)), 10)

    assert api.finished
    assert len(api.pieces) > 1


async def test_the_other_flag_does_not_hold_a_restore() -> None:
    client = FakeClient()
    api = SlowApi(client)
    driver = driver_with(client, FAULT_VOLUME_RECOVERY_CLEAR_FAIL)

    await asyncio.wait_for(driver.restore_volume(REF, source(tar_of(("a", b"1")))), 10)

    assert api.finished


# -- the held restore through the service: cancel still cleans up -----------------------------


async def test_a_restore_stalled_after_extraction_began_is_cleaned_up_when_it_is_cancelled(
    make_app: Any,
) -> None:
    app: FastAPI = make_app(faults=(FAULT_RESTORE_EXTRACT_HOLD,))
    org = await add_org(app)
    api_key = await add_key(app, org)
    fake = app.state.driver
    assert isinstance(fake, FakeDriver)
    started = asyncio.Event()
    original = fake.restore_volume

    async def held(ref: str, tar: Any) -> None:
        await original(ref, _first_then_stall(tar, started))

    fake.restore_volume = held  # type: ignore[method-assign]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as http:
        volume_id = await seeded_volume(http, api_key, files=KEEP)

        task = asyncio.ensure_future(restore(http, api_key, volume_id, make_archive(FILES)))
        await asyncio.wait_for(started.wait(), 10)
        assert await marker(app, org, volume_id) is not None  # extraction began, marker is set
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0.2)  # the shielded cleanup finishes

        assert await marker(app, org, volume_id) is None
        assert await volume_files(http, api_key, volume_id) == {}


async def _first_then_stall(tar: Any, started: asyncio.Event) -> Any:
    async for piece in tar:
        yield piece
        started.set()
        await asyncio.sleep(3600)  # stands for the docker driver's hold


# -- volume_recovery_clear_fail ---------------------------------------------------------------


@pytest.fixture
async def faulty(make_app: Any) -> Any:
    app: FastAPI = make_app(faults=(FAULT_VOLUME_RECOVERY_CLEAR_FAIL,))
    org = await add_org(app)
    api_key = await add_key(app, org)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as http:
        yield app, http, org, api_key


async def test_recovery_with_the_flag_clears_nothing_and_never_calls_the_driver(
    faulty: Any,
) -> None:
    app, http, org, api_key = faulty
    volume_id = await seeded_volume(http, api_key, files=KEEP)
    await set_marker(app, org, volume_id)
    calls: list[str] = []
    fake = app.state.driver

    async def spy(ref: str) -> None:
        calls.append(ref)

    fake.clear_volume = spy

    recovered = await app.state.volume_transfer.recover_interrupted()

    assert recovered == 0
    assert calls == []
    assert await marker(app, org, volume_id) is not None
    assert await audit_rows(app, org, RESTORE_ACTION) == []


async def test_a_volume_left_marked_by_the_flag_refuses_export_and_mount(faulty: Any) -> None:
    app, http, org, api_key = faulty
    volume_id = await seeded_volume(http, api_key, files=KEEP)
    await set_marker(app, org, volume_id)
    await app.state.volume_transfer.recover_interrupted()

    exported = await export(http, api_key, volume_id)
    body = {"volumes": [{"volume_id": volume_id, "mount_path": "/data"}]}
    mounted = await http.post("/v1/sandboxes", headers=auth(api_key), json=body)

    assert (exported.status_code, mounted.status_code) == (409, 409)
    assert error(exported)["details"]["reason"] == "restore_unrecovered"
    assert error(mounted)["details"]["reason"] == "restore_unrecovered"


async def test_a_new_restore_still_works_with_the_flag_set(faulty: Any) -> None:
    app, http, org, api_key = faulty
    volume_id = await seeded_volume(http, api_key, files=KEEP)
    await set_marker(app, org, volume_id)
    await app.state.volume_transfer.recover_interrupted()

    restored = await restore(http, api_key, volume_id, make_archive(FILES))

    assert restored.status_code == 200, restored.text
    assert await marker(app, org, volume_id) is None
    assert await volume_files(http, api_key, volume_id) == FILES


async def test_without_the_flag_recovery_empties_the_marked_volume(make_app: Any) -> None:
    app: FastAPI = make_app()
    org = await add_org(app)
    api_key = await add_key(app, org)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as http:
        volume_id = await seeded_volume(http, api_key, files=KEEP)
        await set_marker(app, org, volume_id)

        assert await app.state.volume_transfer.recover_interrupted() == 1
        assert await marker(app, org, volume_id) is None
        assert await volume_files(http, api_key, volume_id) == {}


# -- the status notice ------------------------------------------------------------------------


async def test_both_flags_appear_in_the_status_notice(make_app: Any) -> None:
    app: FastAPI = make_app(faults=BOTH)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as http:
        response = await http.get("/v1/status")

    assert response.json()["data"]["notice"]["message"] == (
        "fault injection active: restore_extract_hold, volume_recovery_clear_fail"
    )
