# ruff: noqa: F401, F811
"""Round 71: a persistent restore marker (``volumes.restoring_since``) and the crash recovery.

A SIGKILL during a restore never runs the in-request cleanup, so the volume could keep part of
the archive. The restore sets ``restoring_since`` after the first decompressed chunk is read and
before the driver starts, and clears it when the restore ended (success, or a failure that left
the volume empty). A marker found at server start is a restore that never finished: the volume
is emptied, the marker cleared and the recovery audited.
"""

import dataclasses
import gzip
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from tests.test_volume_transfer_r67 import (
    FILES,
    MIB,
    RESTORE_ACTION,
    STEP_LIMIT,
    add_key,
    add_org,
    app,
    audit_rows,
    auth,
    client,
    driver,
    error,
    export,
    key,
    make_app,
    make_archive,
    new_volume,
    org_id,
    read_archive,
    restore,
    seeded_volume,
)

from sandfort.api.app import _lifespan, _worker_lifespan
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import ActorType, AuditOutcome
from sandfort.drivers.errors import DriverError, DriverNotFound
from sandfort.drivers.fake import FakeDriver
from sandfort.services.volume_restore_recovery import RECOVERY_REASON

KEEP = {"keep.txt": b"safe"}
SINCE = datetime(2026, 11, 14, 9, 0, tzinfo=UTC)


async def marker(app: FastAPI, org_id: str, volume_id: str) -> datetime | None:
    async with UnitOfWork(app.state.session_factory) as uow:
        volume = await uow.volumes.get(org_id, volume_id)
    assert volume is not None
    return volume.restoring_since


async def set_marker(app: FastAPI, org_id: str, volume_id: str) -> None:
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.volumes.set_restoring_since(org_id, volume_id, SINCE)
        await uow.commit()


async def volume_files(client: httpx.AsyncClient, key: str, volume_id: str) -> dict[str, bytes]:
    return read_archive((await export(client, key, volume_id)).content)


# -- the marker during a restore -------------------------------------------------------------


async def test_a_body_that_is_not_gzip_leaves_no_marker_and_the_volume_untouched(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    volume_id = await seeded_volume(client, key, files=KEEP)

    refused = await restore(client, key, volume_id, b"this is not gzip at all")
    empty = await restore(client, key, volume_id, b"")

    assert (refused.status_code, empty.status_code) == (422, 422)
    assert await marker(app, org_id, volume_id) is None
    assert await volume_files(client, key, volume_id) == KEEP


async def test_the_marker_is_set_while_the_driver_extracts_and_cleared_after_success(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, org_id: str, key: str
) -> None:
    volume_id = await new_volume(client, key)
    seen: list[datetime | None] = []
    original = driver.restore_volume

    async def watching(ref: str, tar: Any) -> None:
        seen.append(await marker(app, org_id, volume_id))
        await original(ref, tar)

    driver.restore_volume = watching  # type: ignore[method-assign]

    response = await restore(client, key, volume_id, make_archive(FILES))

    assert response.status_code == 200, response.text
    (during,) = seen
    assert during is not None
    assert during.tzinfo is not None
    assert await marker(app, org_id, volume_id) is None
    assert await volume_files(client, key, volume_id) == FILES


@pytest.mark.parametrize("body", ["oversize", "bad_tar"])
async def test_a_handled_failure_clears_the_marker_and_empties_the_volume(
    make_app: Any, body: str
) -> None:
    app: FastAPI = make_app(max_bytes=STEP_LIMIT)
    org = await add_org(app)
    api_key = await add_key(app, org)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as http:
        volume_id = await seeded_volume(http, api_key, files=KEEP)
        payload = (
            make_archive({"big": bytes(3 * MIB)})
            if body == "oversize"
            else gzip.compress(b"x" * 4000 + b"not a tar" * 1000)
        )

        refused = await restore(http, api_key, volume_id, payload)

        assert refused.status_code in (413, 422), refused.text
        assert error(refused)["details"]["volume_emptied"] is True
        assert await marker(app, org, volume_id) is None
        assert await volume_files(http, api_key, volume_id) == {}


async def test_a_failure_that_could_not_empty_the_volume_keeps_the_marker(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, org_id: str, key: str
) -> None:
    volume_id = await seeded_volume(client, key, files=KEEP)

    async def broken_clear(ref: str) -> None:
        raise DriverError("daemon unreachable")

    driver.clear_volume = broken_clear  # type: ignore[method-assign]

    refused = await restore(client, key, volume_id, gzip.compress(b"x" * 4000 + b"no tar" * 900))

    assert refused.status_code == 422, refused.text
    assert error(refused)["details"]["volume_emptied"] is False
    assert await marker(app, org_id, volume_id) is not None


# -- recovery at start ------------------------------------------------------------------------


async def test_recovery_empties_a_volume_with_a_dangling_marker_and_audits_it(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    volume_id = await seeded_volume(client, key, name="crashed", files=KEEP)
    await set_marker(app, org_id, volume_id)

    recovered = await app.state.volume_transfer.recover_interrupted()

    assert recovered == 1
    assert await marker(app, org_id, volume_id) is None
    assert await volume_files(client, key, volume_id) == {}
    (row,) = await audit_rows(app, org_id, RESTORE_ACTION)
    assert (row.target_id, row.outcome, row.actor_type) == (
        volume_id,
        AuditOutcome.ERROR,
        ActorType.SYSTEM,
    )
    assert row.details["reason"] == RECOVERY_REASON == "recovered_after_crash"
    assert row.details["volume_emptied"] is True
    assert row.details["name"] == "crashed"


async def test_recovery_leaves_a_volume_without_a_marker_untouched(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    volume_id = await seeded_volume(client, key, files=KEEP)

    recovered = await app.state.volume_transfer.recover_interrupted()

    assert recovered == 0
    assert await volume_files(client, key, volume_id) == KEEP
    assert await audit_rows(app, org_id, RESTORE_ACTION) == []


async def test_a_driver_failure_leaves_the_marker_set_for_the_next_start(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, org_id: str, key: str
) -> None:
    volume_id = await seeded_volume(client, key, files=KEEP)
    await set_marker(app, org_id, volume_id)
    healthy = driver.clear_volume

    async def broken_clear(ref: str) -> None:
        raise DriverError("daemon unreachable")

    driver.clear_volume = broken_clear  # type: ignore[method-assign]
    assert await app.state.volume_transfer.recover_interrupted() == 0
    assert await marker(app, org_id, volume_id) is not None
    assert await audit_rows(app, org_id, RESTORE_ACTION) == []

    driver.clear_volume = healthy  # type: ignore[method-assign]
    assert await app.state.volume_transfer.recover_interrupted() == 1
    assert await marker(app, org_id, volume_id) is None


async def test_a_marker_on_a_volume_the_provider_no_longer_has_is_cleared(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, org_id: str, key: str
) -> None:
    volume_id = await new_volume(client, key)
    await set_marker(app, org_id, volume_id)
    driver._volumes.clear()  # the provider volume is gone

    await app.state.volume_transfer.recover_interrupted()

    assert await marker(app, org_id, volume_id) is None


async def test_recovery_reaches_volumes_of_every_org(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    other_org = await add_org(app, "other")
    other_key = await add_key(app, other_org)
    mine = await new_volume(client, key)
    theirs = await new_volume(client, other_key)
    await set_marker(app, org_id, mine)
    await set_marker(app, other_org, theirs)

    assert await app.state.volume_transfer.recover_interrupted() == 2
    assert await marker(app, org_id, mine) is None
    assert await marker(app, other_org, theirs) is None


async def test_recovery_never_erases_a_newer_marker(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, org_id: str, key: str
) -> None:
    volume_id = await seeded_volume(client, key, files=KEEP)
    await set_marker(app, org_id, volume_id)
    newer = datetime(2026, 11, 14, 9, 30, tzinfo=UTC)
    original = driver.clear_volume

    async def clear_while_a_new_restore_marks(ref: str) -> None:
        await original(ref)
        async with UnitOfWork(app.state.session_factory) as uow:
            await uow.volumes.set_restoring_since(org_id, volume_id, newer)
            await uow.commit()

    driver.clear_volume = clear_while_a_new_restore_marks  # type: ignore[method-assign]

    recovered = await app.state.volume_transfer.recover_interrupted()

    assert recovered == 0
    assert await marker(app, org_id, volume_id) == newer
    assert await audit_rows(app, org_id, RESTORE_ACTION) == []


# -- a marked volume is not handed out --------------------------------------------------------


async def test_export_of_a_marked_volume_is_refused(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    volume_id = await seeded_volume(client, key, files=KEEP)
    await set_marker(app, org_id, volume_id)

    refused = await export(client, key, volume_id)

    assert refused.status_code == 409, refused.text
    assert error(refused)["details"]["reason"] == "restore_unrecovered"


async def test_mounting_a_marked_volume_into_a_new_sandbox_is_refused(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    volume_id = await new_volume(client, key)
    await set_marker(app, org_id, volume_id)

    body = {"volumes": [{"volume_id": volume_id, "mount_path": "/data"}]}

    refused = await client.post("/v1/sandboxes", headers=auth(key), json=body)

    assert refused.status_code == 409, refused.text
    assert error(refused)["details"]["reason"] == "restore_unrecovered"


async def test_a_new_restore_of_a_marked_volume_is_allowed_and_clears_the_marker(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    volume_id = await seeded_volume(client, key, files=KEEP)
    await set_marker(app, org_id, volume_id)

    response = await restore(client, key, volume_id, make_archive(FILES))

    assert response.status_code == 200, response.text
    assert await marker(app, org_id, volume_id) is None
    assert await volume_files(client, key, volume_id) == FILES


# -- failure paths of the marker itself -------------------------------------------------------


async def test_a_clear_volume_that_finds_no_volume_keeps_the_marker_and_says_not_emptied(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, org_id: str, key: str
) -> None:
    volume_id = await seeded_volume(client, key, files=KEEP)

    async def gone(ref: str) -> None:
        raise DriverNotFound(f"no such volume: {ref}", ref=ref)

    driver.clear_volume = gone  # type: ignore[method-assign]

    refused = await restore(client, key, volume_id, gzip.compress(b"x" * 4000 + b"no tar" * 900))

    assert refused.status_code == 422, refused.text
    assert error(refused)["details"]["volume_emptied"] is False
    assert await marker(app, org_id, volume_id) is not None
    # the next start finds no provider volume either and clears the marker
    assert await app.state.volume_transfer.recover_interrupted() == 1
    assert await marker(app, org_id, volume_id) is None


async def test_a_failing_mark_leaves_no_marker_and_the_volume_untouched(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, org_id: str, key: str
) -> None:
    volume_id = await seeded_volume(client, key, files=KEEP)
    extracted: list[str] = []
    original = driver.restore_volume

    async def watching(ref: str, tar: Any) -> None:
        extracted.append(ref)
        await original(ref, tar)

    async def broken_mark(volume: Any) -> None:
        raise RuntimeError("database is gone")

    driver.restore_volume = watching  # type: ignore[method-assign]
    app.state.volume_service.mark_restoring = broken_mark

    with pytest.raises(RuntimeError, match="database is gone"):
        await restore(client, key, volume_id, make_archive(FILES))

    assert extracted == []
    assert await marker(app, org_id, volume_id) is None
    assert await volume_files(client, key, volume_id) == KEEP


# -- start-up wiring --------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["all", "api"])
async def test_the_api_start_recovers_before_it_serves(make_app: Any, role: str) -> None:
    application: FastAPI = make_app()
    application.state.settings = dataclasses.replace(application.state.settings, role=role)
    org = await add_org(application)
    api_key = await add_key(application, org)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as http:
        volume_id = await seeded_volume(http, api_key, files=KEEP)
        await set_marker(application, org, volume_id)

        async with _lifespan(application):
            assert await marker(application, org, volume_id) is None
            assert await volume_files(http, api_key, volume_id) == {}


async def test_the_worker_start_does_not_recover(make_app: Any) -> None:
    application: FastAPI = make_app()
    org = await add_org(application)
    api_key = await add_key(application, org)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as http:
        volume_id = await seeded_volume(http, api_key, files=KEEP)
        await set_marker(application, org, volume_id)
        cleared: list[str] = []
        fake = application.state.driver
        original = fake.clear_volume

        async def spy(ref: str) -> None:
            cleared.append(ref)
            await original(ref)

        fake.clear_volume = spy

        async with _worker_lifespan(application):
            assert await marker(application, org, volume_id) is not None
        assert cleared == []
        assert await marker(application, org, volume_id) is not None
