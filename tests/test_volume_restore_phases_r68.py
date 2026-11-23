# ruff: noqa: F401, F811
"""Round 68 (SF74-004): the two phases of a restore, pinned as the guide documents them.

A refusal before extraction starts leaves the volume untouched and carries no ``volume_emptied``
key. Once the restore has begun, any failure leaves the volume empty and says so. A gzip CRC is
only checked at the end of the stream: a small archive with a bad CRC is found while the first
block is decoded (phase one), a larger one after the volume was emptied (phase two). The early
rejection is intentional and stays.
"""

import io
import tarfile

import httpx
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

KEEP = {"keep.txt": b"safe"}
CRC_BYTES = 8  # the gzip trailer: CRC32 then ISIZE


def bad_crc(archive: bytes) -> bytes:
    """``archive`` with a valid header and deflate stream but a wrong CRC32 in the trailer."""
    head, trailer = archive[:-CRC_BYTES], bytearray(archive[-CRC_BYTES:])
    trailer[0] ^= 0xFF
    return head + bytes(trailer)


async def volume_files(client: httpx.AsyncClient, key: str, volume_id: str) -> dict[str, bytes]:
    return read_archive((await export(client, key, volume_id)).content)


async def test_a_small_archive_with_a_bad_crc_is_refused_before_anything_is_emptied(
    client: httpx.AsyncClient, key: str
) -> None:
    volume_id = await seeded_volume(client, key, files=KEEP)

    refused = await restore(client, key, volume_id, bad_crc(make_archive({"a": b"1" * 2000})))

    assert refused.status_code == 422, refused.text
    assert "volume_emptied" not in error(refused)["details"]
    assert await volume_files(client, key, volume_id) == KEEP


async def test_a_large_archive_with_a_bad_crc_is_refused_after_the_volume_was_emptied(
    client: httpx.AsyncClient, key: str
) -> None:
    volume_id = await seeded_volume(client, key, files=KEEP)
    large = bad_crc(make_archive({"a": bytes(3 * MIB)}))  # past the first 1 MiB decoded block

    refused = await restore(client, key, volume_id, large)

    assert refused.status_code == 422, refused.text
    assert error(refused)["details"]["volume_emptied"] is True
    assert await volume_files(client, key, volume_id) == {}


async def test_a_body_that_is_not_gzip_never_touches_the_volume(
    client: httpx.AsyncClient, key: str
) -> None:
    volume_id = await seeded_volume(client, key, files=KEEP)

    refused = await restore(client, key, volume_id, b"this is not gzip at all")

    assert refused.status_code == 422
    assert "volume_emptied" not in error(refused)["details"]
    assert await volume_files(client, key, volume_id) == KEEP


async def test_a_tar_the_policy_refuses_is_always_a_second_phase_failure(
    client: httpx.AsyncClient, key: str
) -> None:
    volume_id = await seeded_volume(client, key, files=KEEP)
    traversal = make_archive({"../escape": b"x"})

    refused = await restore(client, key, volume_id, traversal)

    assert refused.status_code == 422
    assert error(refused)["details"]["volume_emptied"] is True
    assert await volume_files(client, key, volume_id) == {}


async def test_a_duplicate_member_name_is_refused_and_leaves_the_volume_empty(
    client: httpx.AsyncClient, key: str
) -> None:
    volume_id = await seeded_volume(client, key, files=KEEP)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for content in (b"FIRST", b"SECOND"):
            info = tarfile.TarInfo("same.txt")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))

    refused = await restore(client, key, volume_id, buffer.getvalue())

    assert refused.status_code == 422
    details = error(refused)["details"]
    assert details["violation"] == "duplicate_entry"
    assert details["volume_emptied"] is True
    assert await volume_files(client, key, volume_id) == {}
