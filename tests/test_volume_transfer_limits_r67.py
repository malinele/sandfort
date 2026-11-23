# ruff: noqa: F401, F811
"""Round 67 limits (security review): an expansion ratio cap and concurrent-transfer caps.

A restore is capped at ``EXPANSION_RATIO`` times its compressed size (never below
``EXPANSION_FLOOR_BYTES``) whatever ``SANDFORT_VOLUME_MAX_BYTES`` says; export and restore
each hold one slot of a per-org and a global cap for as long as they run.
"""

import gzip
import io
import tarfile
from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from tests.test_volume_transfer_r67 import (
    FILES,
    MIB,
    app,
    audit_rows,
    client,
    driver,
    error,
    export,
    key,
    make_app,
    make_archive,
    org_id,
    read_archive,
    restore,
    seeded_volume,
)

from sandfort.config import Settings
from sandfort.errors import Conflict
from sandfort.services import volume_transfer
from sandfort.services.transfer_slots import (
    ORG_TRANSFER_LIMIT,
    TRANSFER_LIMIT,
    TransferSlots,
)

RATIO = volume_transfer.EXPANSION_RATIO


def test_the_ratio_is_the_documented_constant() -> None:
    assert RATIO == 64
    assert volume_transfer.EXPANSION_FLOOR_BYTES >= 10 * 1024  # a tar record


async def test_a_small_archive_that_compresses_past_the_ratio_is_fine_under_the_floor(
    client: httpx.AsyncClient, key: str
) -> None:
    volume_id = await seeded_volume(client, key, files={})
    body = make_archive({"zeros": bytes(1 * MIB)})  # about 1000:1, a few hundred KiB at most

    assert len(bytes(1 * MIB)) > RATIO * len(body)
    assert (await restore(client, key, volume_id, body)).status_code == 200


async def test_a_body_that_expands_past_the_ratio_is_413_and_leaves_the_volume_empty(
    client: httpx.AsyncClient, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(volume_transfer, "EXPANSION_FLOOR_BYTES", 1 * MIB)
    volume_id = await seeded_volume(client, key, files={"old": b"will be lost"})
    body = make_archive({"zeros.bin": bytes(8 * MIB)})
    assert len(body) * RATIO < 8 * MIB  # the bomb: far over the ratio

    refused = await restore(client, key, volume_id, body)

    assert refused.status_code == 413, refused.text
    failure = error(refused)
    assert failure["code"] == "PAYLOAD_TOO_LARGE"
    assert failure["details"]["max_expansion_ratio"] == RATIO
    assert failure["details"]["limit_bytes"] == 1 * MIB
    assert failure["details"]["volume_emptied"] is True
    assert "compressed size" in failure["message"]
    assert read_archive((await export(client, key, volume_id)).content) == {}


async def test_the_ratio_applies_to_a_body_sent_without_a_content_length(
    client: httpx.AsyncClient, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(volume_transfer, "EXPANSION_FLOOR_BYTES", 1 * MIB)
    volume_id = await seeded_volume(client, key, files={"old": b"x"})
    body = make_archive({"zeros.bin": bytes(8 * MIB)})

    async def chunked() -> AsyncIterator[bytes]:
        for start in range(0, len(body), 4096):
            yield body[start : start + 4096]

    refused = await client.post(
        f"/v1/volumes/{volume_id}/restore",
        headers={"Authorization": f"Bearer {key}"},
        content=chunked(),
    )

    assert refused.status_code == 413, refused.text
    assert error(refused)["details"]["max_expansion_ratio"] == RATIO
    assert error(refused)["details"]["volume_emptied"] is True


async def test_the_size_limit_still_applies_next_to_the_ratio(make_app: object) -> None:
    app = make_app(max_bytes=64 * 1024)  # type: ignore[operator]
    from tests.test_volume_transfer_r67 import add_key, add_org, http_client, new_volume

    api_key = await add_key(app, await add_org(app))
    async with http_client(app) as client:
        volume_id = await new_volume(client, api_key)
        refused = await restore(client, api_key, volume_id, make_archive({"b": bytes(200_000)}))

    assert refused.status_code == 413
    assert error(refused)["details"]["limit_bytes"] == 64 * 1024


# -- concurrent transfers ---------------------------------------------------------------------


def test_slots_cap_one_org_and_the_whole_process_with_distinct_reasons() -> None:
    slots = TransferSlots(per_org=2, total=3)
    slots.hold("org_a", "t1")
    slots.hold("org_a", "t2")

    with pytest.raises(Conflict) as org_full:
        slots.hold("org_a", "t3")
    slots.hold("org_b", "t4")  # another org still has room
    with pytest.raises(Conflict) as all_full:
        slots.hold("org_b", "t5")

    assert org_full.value.reason == ORG_TRANSFER_LIMIT
    assert org_full.value.details["limit"] == 2
    assert all_full.value.reason == TRANSFER_LIMIT
    assert all_full.value.details["limit"] == 3


def test_a_released_slot_is_free_again_and_holding_twice_takes_one_slot() -> None:
    slots = TransferSlots(per_org=1, total=0)
    slots.hold("org_a", "t1")
    slots.hold("org_a", "t1")  # idempotent

    slots.release("t1")
    slots.release("t1")  # releasing twice is harmless
    slots.hold("org_a", "t2")

    assert len(slots) == 1


def test_a_cap_of_zero_means_unlimited() -> None:
    slots = TransferSlots(per_org=0, total=0)

    for number in range(50):
        slots.hold("org_a", f"t{number}")

    assert len(slots) == 50


def test_the_caps_come_from_the_settings() -> None:
    defaults = Settings()
    configured = Settings.from_env(
        {
            "SANDFORT_MAX_VOLUME_TRANSFERS_PER_ORG": "5",
            "SANDFORT_MAX_VOLUME_TRANSFERS": "11",
        }
    )

    assert (defaults.max_volume_transfers_per_org, defaults.max_volume_transfers) == (2, 8)
    assert (configured.max_volume_transfers_per_org, configured.max_volume_transfers) == (5, 11)
    with pytest.raises(ValueError, match="MAX_VOLUME_TRANSFERS_PER_ORG"):
        Settings.from_env({"SANDFORT_MAX_VOLUME_TRANSFERS_PER_ORG": "-1"})


def fill_org(app: FastAPI, org_id: str, count: int) -> None:
    for number in range(count):
        app.state.volume_transfer.slots.hold(org_id, f"other-{number}")


async def test_export_and_restore_are_409_when_the_org_has_no_free_transfer_slot(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    volume_id = await seeded_volume(client, key, files={"keep": b"safe"})
    fill_org(app, org_id, app.state.settings.max_volume_transfers_per_org)

    refused_export = await export(client, key, volume_id)
    refused_restore = await restore(client, key, volume_id, make_archive({"x": b"1"}))

    for refused in (refused_export, refused_restore):
        assert refused.status_code == 409, refused.text
        assert error(refused)["details"]["reason"] == ORG_TRANSFER_LIMIT
    assert await audit_rows(app, org_id, "volume.restore") == []
    app.state.volume_transfer.slots.release("other-0")
    assert read_archive((await export(client, key, volume_id)).content) == {"keep": b"safe"}


async def test_the_global_cap_answers_with_its_own_reason(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    volume_id = await seeded_volume(client, key)
    for number in range(app.state.settings.max_volume_transfers):
        app.state.volume_transfer.slots.hold(f"org_other_{number}", f"other-{number}")

    refused = await restore(client, key, volume_id, make_archive({"x": b"1"}))

    assert refused.status_code == 409, refused.text
    assert error(refused)["details"]["reason"] == TRANSFER_LIMIT


async def test_every_finished_or_failed_transfer_gives_its_slot_back(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    volume_id = await seeded_volume(client, key)
    slots = app.state.volume_transfer.slots

    await export(client, key, volume_id)
    await restore(client, key, volume_id, make_archive({"x": b"1"}))
    await restore(client, key, volume_id, gzip.compress(b"not a tar" * 100))  # fails: 422
    await restore(client, key, volume_id, b"not gzip at all")  # refused before the driver

    assert len(slots) == 0


async def test_a_restore_claim_of_the_volume_is_still_enforced_next_to_the_slots(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    volume_id = await seeded_volume(client, key)
    assert app.state.volume_transfer.claims.try_claim(volume_id)

    refused = await restore(client, key, volume_id, make_archive({"x": b"1"}))

    assert error(refused)["details"]["reason"] == "restore_in_progress"
    assert len(app.state.volume_transfer.slots) == 0  # a refused claim holds no slot


# -- gzip members and cooperative reading -----------------------------------------------------


def split_members(tar_gz: bytes, parts: int) -> bytes:
    """The tar of ``tar_gz`` as ``parts`` gzip members in a row (one stream for the reader)."""
    tar = gzip.decompress(tar_gz)
    step = -(-len(tar) // parts)
    return b"".join(gzip.compress(tar[at : at + step]) for at in range(0, len(tar), step))


async def feed(data: bytes, step: int) -> AsyncIterator[bytes]:
    for at in range(0, len(data), step):
        yield data[at : at + step]


async def run_gunzip(data: bytes, step: int = 4096) -> bytes:
    tally = volume_transfer.Tally()
    stream = volume_transfer.gunzip_counted(
        feed(data, step), tally, max_input=10**9, max_output=None
    )
    return b"".join([piece async for piece in stream])


def test_the_member_cap_is_a_generous_named_constant() -> None:
    assert volume_transfer.MAX_GZIP_MEMBERS >= 100


async def test_a_body_of_many_gzip_members_under_the_cap_is_read_as_one_stream() -> None:
    body = split_members(make_archive({"a": b"1" * 50_000, "b": b"2" * 50_000}), 40)
    assert body.count(b"\x1f\x8b\x08") >= 40

    assert gzip.decompress(body) == await run_gunzip(body)


async def test_more_gzip_members_than_the_cap_are_refused_as_unprocessable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(volume_transfer, "MAX_GZIP_MEMBERS", 5)
    body = split_members(make_archive({"a": b"1" * 50_000}), 6)

    with pytest.raises(volume_transfer.Unprocessable, match="gzip members"):
        await run_gunzip(body)
    assert await run_gunzip(split_members(make_archive({"a": b"1" * 50_000}), 5))


async def test_a_flood_of_empty_gzip_members_is_refused_long_before_the_end() -> None:
    body = gzip.compress(b"") * 100_000 + gzip.compress(b"tail")

    with pytest.raises(volume_transfer.Unprocessable, match="gzip members"):
        await run_gunzip(body)


async def test_a_restore_with_too_many_gzip_members_is_422_and_the_volume_is_not_corrupted(
    client: httpx.AsyncClient, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(volume_transfer, "MAX_GZIP_MEMBERS", 3)
    volume_id = await seeded_volume(client, key, files={"keep": b"safe"})

    refused = await restore(
        client, key, volume_id, split_members(make_archive({"a": b"1" * 50_000}), 8)
    )

    assert refused.status_code == 422, refused.text
    assert "gzip members" in error(refused)["message"]
    emptied = error(refused)["details"].get("volume_emptied")
    listing = read_archive((await export(client, key, volume_id)).content)
    assert listing == ({} if emptied else {"keep": b"safe"})


async def test_the_decompressor_yields_to_the_event_loop_once_per_input_chunk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []

    async def checkpoint() -> None:
        calls.append(1)

    monkeypatch.setattr(volume_transfer.anyio.lowlevel, "checkpoint", checkpoint)
    body = make_archive({"a": b"x" * 10_000})

    await run_gunzip(body, step=50)

    assert len(calls) == -(-len(body) // 50)
