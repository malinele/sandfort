# ruff: noqa: F401, F811
"""Round 67: the archive policy as the restore route answers it (fake driver, docker policy).

A restore whose tar holds a forbidden member answers 422 with ``details.reason ==
"forbidden_entry"`` and the violation code; like every failure after the driver began, it
leaves the volume empty.
"""

import gzip
import io
import tarfile

import httpx
import pytest
from tests.test_volume_transfer_r67 import (
    FILES,
    RESTORE_ACTION,
    app,
    audit_rows,
    client,
    driver,
    error,
    export,
    key,
    make_app,
    org_id,
    read_archive,
    restore,
    seeded_volume,
)

Entry = tuple[tarfile.TarInfo, bytes | None]


def gz_tar(*entries: Entry) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for info, content in entries:
            archive.addfile(info, None if content is None else io.BytesIO(content))
    return buffer.getvalue()


def file_entry(name: str, content: bytes = b"data", mode: int = 0o644) -> Entry:
    info = tarfile.TarInfo(name)
    info.size, info.mode = len(content), mode
    return info, content


def node(name: str, kind: bytes, target: str = "") -> Entry:
    info = tarfile.TarInfo(name)
    info.type, info.linkname = kind, target
    return info, None


FORBIDDEN = [
    pytest.param(file_entry("../escape.txt"), "path_traversal", id="traversal"),
    pytest.param(file_entry("sub/../../escape.txt"), "path_traversal", id="nested-traversal"),
    pytest.param(file_entry("/etc/cron.d/job"), "absolute_path", id="absolute-path"),
    pytest.param(node("link", tarfile.SYMTYPE, "../../etc/passwd"), "symlink_escape", id="escape"),
    pytest.param(node("link", tarfile.SYMTYPE, "/etc/passwd"), "symlink_absolute", id="abs-link"),
    pytest.param(node("hard", tarfile.LNKTYPE, "a.txt"), "hardlink", id="hardlink"),
    pytest.param(node("dev", tarfile.CHRTYPE), "special_file", id="device-node"),
    pytest.param(node("pipe", tarfile.FIFOTYPE), "special_file", id="fifo"),
]


@pytest.mark.parametrize(("entry", "violation"), FORBIDDEN)
async def test_a_forbidden_member_is_422_forbidden_entry_and_leaves_the_volume_empty(
    client: httpx.AsyncClient, key: str, entry: Entry, violation: str
) -> None:
    volume_id = await seeded_volume(client, key, files={"gone": b"soon"})
    body = gz_tar(file_entry("a.txt", b"ok"), entry, file_entry("never.txt"))

    refused = await restore(client, key, volume_id, body)

    assert refused.status_code == 422, refused.text
    failure = error(refused)
    assert failure["code"] == "UNPROCESSABLE"
    assert failure["details"]["reason"] == "forbidden_entry"
    assert failure["details"]["violation"] == violation
    assert failure["details"]["entry"] == entry[0].name
    assert failure["details"]["volume_emptied"] is True
    assert "the volume was emptied" in failure["message"]
    assert read_archive((await export(client, key, volume_id)).content) == {}


async def test_a_refused_restore_is_audited_with_the_reason_and_the_empty_volume(
    app: object, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    volume_id = await seeded_volume(client, key)

    await restore(client, key, volume_id, gz_tar(file_entry("../x")))

    (row,) = await audit_rows(app, org_id, RESTORE_ACTION)  # type: ignore[arg-type]
    assert row.outcome.value == "error"
    assert row.details["volume_emptied"] is True
    assert "not allowed" in row.details["reason"]


async def test_a_plain_corrupt_tar_has_no_forbidden_entry_reason(
    client: httpx.AsyncClient, key: str
) -> None:
    volume_id = await seeded_volume(client, key)

    refused = await restore(client, key, volume_id, gzip.compress(b"not a tar" * 200))

    assert refused.status_code == 422
    assert "reason" not in error(refused)["details"]


async def test_symlinks_with_internal_relative_targets_are_accepted(
    client: httpx.AsyncClient, key: str
) -> None:
    volume_id = await seeded_volume(client, key)
    body = gz_tar(
        file_entry("a.txt", b"alpha"),
        node("sub", tarfile.DIRTYPE),
        node("sub/up", tarfile.SYMTYPE, "../a.txt"),
        node("alias", tarfile.SYMTYPE, "sub"),
    )

    restored = await restore(client, key, volume_id, body)

    assert restored.status_code == 200, restored.text
    assert read_archive((await export(client, key, volume_id)).content) == {"a.txt": b"alpha"}


async def test_a_setuid_file_is_accepted_because_sandboxes_run_with_no_new_privileges(
    client: httpx.AsyncClient, key: str
) -> None:
    volume_id = await seeded_volume(client, key)

    restored = await restore(
        client, key, volume_id, gz_tar(file_entry("tool", b"#!/bin/sh\n", mode=0o4755))
    )

    assert restored.status_code == 200, restored.text
    assert read_archive((await export(client, key, volume_id)).content) == {"tool": b"#!/bin/sh\n"}


async def test_a_refusal_never_touches_a_volume_of_another_restore(
    client: httpx.AsyncClient, key: str
) -> None:
    other = await seeded_volume(client, key, name="other", files=FILES)
    target = await seeded_volume(client, key, name="target", files={"x": b"1"})

    refused = await restore(client, key, target, gz_tar(file_entry("../x")))

    assert refused.status_code == 422
    assert read_archive((await export(client, key, other)).content) == FILES
