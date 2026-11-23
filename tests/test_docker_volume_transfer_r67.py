# ruff: noqa: F401, F811
"""Round 67: volume export and restore against a real local daemon (skipped without one).

The driver is exercised directly (the daemon's archive endpoints, the helper container, the
clear by remove-and-create) and through the API (the service around it): a restore round-trips
content, modes and owners; a forbidden member or a cut-short archive leaves the volume empty;
a volume written by a real sandbox exports; no helper container is left behind.
"""

import asyncio
import contextlib
import gzip
import io
import tarfile
import uuid
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx
import pytest
from tests.test_docker_volumes import (
    FILE_PATH,
    Cleanup,
    app,
    call,
    cleanup,
    client,
    http,
    image,
    key,
    start_mounting,
)
from tests.test_docker_volumes import auth as bearer
from tests.test_tar_policy_hardening_r67 import END, declared_header
from tests.test_tar_policy_hardening_r67 import member as raw_member

from sandfort.config import Settings
from sandfort.drivers.docker.driver import DockerDriver
from sandfort.drivers.docker.volume_helper import HELPER_FILTERS
from sandfort.drivers.errors import (
    DriverConflict,
    DriverForbiddenEntry,
    DriverInvalidArchive,
    DriverNotFound,
)

pytestmark = pytest.mark.docker

docker = pytest.importorskip("docker")

LABELS = {"team": "infra"}
EXPORT = "/v1/volumes/{}/export"
RESTORE = "/v1/volumes/{}/restore"


@pytest.fixture
def driver(client: Any, image: str) -> DockerDriver:
    return DockerDriver(Settings(driver="docker"), client=client)


@pytest.fixture
def volume_name(client: Any) -> Iterator[str]:
    name = f"sf-vol-r67-{uuid.uuid4().hex[:10]}"
    yield name
    with contextlib.suppress(docker.errors.NotFound):
        client.api.remove_volume(name, force=True)


async def chunks(data: bytes, step: int = 5000) -> AsyncIterator[bytes]:
    for start in range(0, len(data), step):
        yield data[start : start + step]


def tar_bytes(*members: tuple[tarfile.TarInfo, bytes | None]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for info, content in members:
            archive.addfile(info, None if content is None else io.BytesIO(content))
    return buffer.getvalue()


def file_member(
    name: str, content: bytes, mode: int = 0o644, uid: int = 0, gid: int = 0
) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.uid, info.gid = len(content), mode, uid, gid
    return info, content


def link_member(name: str, kind: bytes, target: str = "") -> tuple[tarfile.TarInfo, None]:
    info = tarfile.TarInfo(name)
    info.type, info.linkname = kind, target
    return info, None


def dir_member(name: str, mode: int = 0o755, uid: int = 0) -> tuple[tarfile.TarInfo, None]:
    info = tarfile.TarInfo(name)
    info.type, info.mode, info.uid = tarfile.DIRTYPE, mode, uid
    return info, None


async def exported(driver: DockerDriver, ref: str) -> dict[str, tarfile.TarInfo]:
    """The members of the volume's export by name, without the ``./`` prefix."""
    raw = b"".join([piece async for piece in driver.export_volume(ref)])
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(raw)), mode="r:") as archive:
        return {member.name.removeprefix("./"): member for member in archive.getmembers()}


async def exported_files(driver: DockerDriver, ref: str) -> dict[str, bytes]:
    raw = b"".join([piece async for piece in driver.export_volume(ref)])
    found: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(raw)), mode="r:") as archive:
        for member in archive.getmembers():
            handle = archive.extractfile(member) if member.isfile() else None
            if handle is not None:
                found[member.name.removeprefix("./")] = handle.read()
    return found


def helpers_left(client: Any) -> list[Any]:
    return list(client.api.containers(all=True, filters=HELPER_FILTERS))


def on_disk(client: Any, image: str, ref: str, command: str) -> str:
    """Run ``command`` in a throw-away container with the volume mounted read-only at /v."""
    output = client.containers.run(
        image,
        ["sh", "-c", command],
        volumes={ref: {"bind": "/v", "mode": "ro"}},
        network_mode="none",
        remove=True,
    )
    return str(output.decode())


async def test_restore_round_trips_content_modes_owners_and_internal_symlinks(
    client: Any, image: str, driver: DockerDriver, volume_name: str
) -> None:
    await driver.create_volume(volume_name, labels=LABELS)
    payload = bytes(range(256)) * 4000
    archive = tar_bytes(
        dir_member("sub", mode=0o700, uid=42),
        file_member("a.txt", b"alpha\n"),
        file_member("sub/big.bin", payload, mode=0o640, uid=1234, gid=4321),
        file_member("tool", b"#!/bin/sh\n", mode=0o4755, uid=1234, gid=4321),
        link_member("alias", tarfile.SYMTYPE, "sub/big.bin"),
        link_member("sub/up", tarfile.SYMTYPE, "../a.txt"),
    )

    await driver.restore_volume(volume_name, chunks(archive))
    files = await exported_files(driver, volume_name)
    members = await exported(driver, volume_name)

    assert files["a.txt"] == b"alpha\n" and files["sub/big.bin"] == payload
    assert members["tool"].mode == 0o4755
    assert (members["tool"].uid, members["tool"].gid) == (1234, 4321)
    assert members["sub"].mode == 0o700 and members["sub"].uid == 42
    assert members["alias"].issym() and members["alias"].linkname == "sub/big.bin"
    assert members["sub/up"].linkname == "../a.txt"
    stat = on_disk(client, image, volume_name, "stat -c '%u:%g %a' /v/tool /v/sub/big.bin /v/sub")
    assert stat.split() == ["1234:4321", "4755", "1234:4321", "640", "42:0", "700"]
    assert on_disk(client, image, volume_name, "cat /v/alias | wc -c").strip() == str(len(payload))
    assert helpers_left(client) == []


async def test_restore_replaces_what_the_volume_held_and_keeps_name_and_labels(
    client: Any, driver: DockerDriver, volume_name: str
) -> None:
    await driver.create_volume(volume_name, labels=LABELS)
    await driver.restore_volume(volume_name, chunks(tar_bytes(file_member("old", b"1"))))

    await driver.restore_volume(volume_name, chunks(tar_bytes(file_member("new", b"2"))))

    assert await exported_files(driver, volume_name) == {"new": b"2"}
    attrs = client.api.inspect_volume(volume_name)
    assert attrs["Labels"] == {**LABELS, "sandfort.managed": "true"}
    assert attrs["Driver"] == "local"


@pytest.mark.parametrize(
    ("entry", "violation"),
    [
        (file_member("../escape.txt", b"x"), "path_traversal"),
        (file_member("/tmp/escape.txt", b"x"), "absolute_path"),
        (link_member("l", tarfile.SYMTYPE, "../../etc/passwd"), "symlink_escape"),
        (link_member("l", tarfile.SYMTYPE, "/etc/passwd"), "symlink_absolute"),
        (link_member("h", tarfile.LNKTYPE, "first.txt"), "hardlink"),
        (link_member("dev", tarfile.CHRTYPE), "special_file"),
    ],
)
async def test_a_forbidden_member_is_refused_and_clear_leaves_the_volume_empty(
    client: Any, driver: DockerDriver, volume_name: str, entry: Any, violation: str
) -> None:
    await driver.create_volume(volume_name, labels=LABELS)
    await driver.restore_volume(volume_name, chunks(tar_bytes(file_member("kept", b"1"))))
    archive = tar_bytes(file_member("first.txt", b"x" * 20_000), entry, file_member("never", b"3"))

    with pytest.raises(DriverForbiddenEntry) as caught:
        await driver.restore_volume(volume_name, chunks(archive))
    await driver.clear_volume(volume_name)

    assert caught.value.violation == violation
    assert await exported_files(driver, volume_name) == {}
    assert client.api.inspect_volume(volume_name)["Labels"]["team"] == "infra"
    assert helpers_left(client) == []


async def test_nothing_is_written_outside_the_volume_by_a_traversal_archive(
    client: Any, image: str, driver: DockerDriver, volume_name: str
) -> None:
    await driver.create_volume(volume_name, labels=LABELS)
    marker = f"escape-{uuid.uuid4().hex}.txt"
    archive = tar_bytes(file_member(f"../{marker}", b"x"), file_member(f"x/../../{marker}", b"y"))

    with pytest.raises(DriverForbiddenEntry):
        await driver.restore_volume(volume_name, chunks(archive))

    assert on_disk(client, image, volume_name, f"ls / | grep -c {marker}; true").strip() == "0"


async def test_a_truncated_tar_is_an_invalid_archive_and_clear_empties_the_volume(
    client: Any, driver: DockerDriver, volume_name: str
) -> None:
    await driver.create_volume(volume_name, labels=LABELS)
    archive = tar_bytes(file_member("big", b"z" * 50_000))

    with pytest.raises(DriverInvalidArchive):
        await driver.restore_volume(volume_name, chunks(archive[:20_000]))
    await driver.clear_volume(volume_name)

    assert await exported_files(driver, volume_name) == {}
    assert helpers_left(client) == []


async def test_a_restore_cut_off_by_the_caller_leaves_no_helper_and_clear_empties_the_volume(
    client: Any, driver: DockerDriver, volume_name: str
) -> None:
    class Dropped(Exception):
        pass

    async def dropping() -> AsyncIterator[bytes]:
        archive = tar_bytes(file_member("one", b"1" * 30_000), file_member("two", b"2"))
        yield archive[:12_000]
        raise Dropped("the client went away")

    await driver.create_volume(volume_name, labels=LABELS)

    with pytest.raises(Dropped):
        await driver.restore_volume(volume_name, dropping())
    await driver.clear_volume(volume_name)

    assert helpers_left(client) == []
    assert await exported_files(driver, volume_name) == {}


async def test_a_cancelled_restore_removes_the_helper_and_the_volume_can_then_be_emptied(
    client: Any, driver: DockerDriver, volume_name: str
) -> None:
    release = asyncio.Event()

    async def stalling() -> AsyncIterator[bytes]:
        archive = tar_bytes(file_member("one", b"1" * 30_000), file_member("two", b"2"))
        yield archive[:12_000]
        await release.wait()
        yield archive[12_000:]

    await driver.create_volume(volume_name, labels=LABELS)

    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(driver.restore_volume(volume_name, stalling()), 1.5)
    release.set()
    await driver.clear_volume(volume_name)

    assert helpers_left(client) == []
    assert await exported_files(driver, volume_name) == {}


@pytest.mark.parametrize(
    ("label", "blob", "violation"),
    [
        (
            "nul-linkpath",
            raw_member("lnk", kind=tarfile.SYMTYPE, link="zz", pax={"linkpath": b"..\0"}),
            "invalid_link_target",
        ),
        (
            "nul-path-through-symlink",
            raw_member(
                "a", kind=tarfile.SYMTYPE, link="q", pax={"path": b"a\0zzz", "linkpath": b".."}
            )
            + raw_member("a/file", data=b"pwn"),
            "invalid_name",
        ),
        ("nul-path-dotdot", raw_member("safe", data=b"hi", pax={"path": b"..\0"}), "invalid_name"),
    ],
)
async def test_the_nul_reproductions_never_reach_the_daemon(
    client: Any, image: str, driver: DockerDriver, volume_name: str,
    label: str, blob: bytes, violation: str,
) -> None:
    await driver.create_volume(volume_name, labels=LABELS)

    with pytest.raises(DriverForbiddenEntry) as caught:
        await driver.restore_volume(volume_name, chunks(blob + END))

    assert caught.value.violation == violation
    assert on_disk(client, image, volume_name, "ls -A /v | wc -l").strip() == "0", label
    assert helpers_left(client) == []


class CountingSource:
    """A tar source that declares a huge extended header and counts what is read of it."""

    def __init__(self, kind: bytes) -> None:
        self.kind, self.pulled = kind, 0

    async def stream(self) -> AsyncIterator[bytes]:
        header = declared_header(self.kind, 400 * 1024 * 1024)
        yield self._count(header)
        block = bytes(64 * 1024)
        for _ in range(400 * 16):
            yield self._count(block)

    def _count(self, piece: bytes) -> bytes:
        self.pulled += len(piece)
        return piece


@pytest.mark.parametrize("kind", [b"x", b"L"], ids=["pax", "gnu-longname"])
async def test_a_huge_extended_header_is_refused_after_about_a_mib_by_the_real_driver(
    client: Any, driver: DockerDriver, volume_name: str, kind: bytes
) -> None:
    await driver.create_volume(volume_name, labels=LABELS)
    source = CountingSource(kind)

    with pytest.raises(DriverForbiddenEntry) as caught:
        await driver.restore_volume(volume_name, source.stream())

    assert caught.value.violation == "header_too_large"
    assert source.pulled <= 2 * 1024 * 1024
    assert helpers_left(client) == []


async def test_export_of_a_missing_volume_is_not_found_and_creates_nothing(
    client: Any, driver: DockerDriver, volume_name: str
) -> None:
    with pytest.raises(DriverNotFound):
        await anext(driver.export_volume(volume_name))

    with pytest.raises(docker.errors.NotFound):
        client.api.inspect_volume(volume_name)
    assert helpers_left(client) == []


async def test_a_volume_the_platform_did_not_create_is_never_mounted(
    client: Any, driver: DockerDriver, volume_name: str
) -> None:
    client.api.create_volume(name=volume_name)  # no sandfort.managed label

    with pytest.raises(DriverNotFound):
        await anext(driver.export_volume(volume_name))
    with pytest.raises(DriverNotFound):
        await driver.restore_volume(volume_name, chunks(tar_bytes(file_member("f", b"1"))))

    assert helpers_left(client) == []


async def test_the_helper_container_is_removed_when_the_export_is_closed_early(
    client: Any, driver: DockerDriver, volume_name: str
) -> None:
    await driver.create_volume(volume_name, labels=LABELS)
    big = tar_bytes(*[file_member(f"f{n}", bytes(300_000)) for n in range(8)])
    await driver.restore_volume(volume_name, chunks(big, 100_000))

    stream = driver.export_volume(volume_name)
    assert await anext(stream)
    assert len(helpers_left(client)) == 1
    await stream.aclose()  # type: ignore[attr-defined]

    assert helpers_left(client) == []


async def test_clear_is_refused_while_a_container_still_mounts_the_volume(
    client: Any, image: str, driver: DockerDriver, volume_name: str
) -> None:
    await driver.create_volume(volume_name, labels=LABELS)
    mount = {volume_name: {"bind": "/v", "mode": "rw"}}
    holder = client.containers.create(image, ["sleep", "1"], volumes=mount)
    try:
        with pytest.raises(DriverConflict):
            await driver.clear_volume(volume_name)
        assert client.api.inspect_volume(volume_name)["Name"] == volume_name
    finally:
        holder.remove(force=True)


# -- through the API ------------------------------------------------------------------------


async def test_a_volume_written_by_a_real_sandbox_is_exportable_and_restorable(
    client: Any, http: httpx.AsyncClient, key: str, cleanup: Cleanup
) -> None:
    created = await call(http, "POST", "/v1/volumes", key, status=201, json={"name": "work"})
    cleanup.volume_ids.append(created["id"])
    sandbox_id = await start_mounting(http, key, created["id"], cleanup)
    payload = f"sandbox-{uuid.uuid4().hex}".encode() + bytes(range(256))
    await call(
        http,
        "PUT",
        f"/v1/sandboxes/{sandbox_id}/toolbox/fs/upload",
        key,
        status=200,
        params={"path": FILE_PATH},
        content=payload,
    )

    live = await http.get(EXPORT.format(created["id"]), headers=bearer(key))  # still mounted
    assert live.status_code == 200, live.text
    assert live.headers["content-type"] == "application/gzip"
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(live.content)), mode="r:") as archive:
        handle = archive.extractfile("./payload.bin")
        assert handle is not None and handle.read() == payload

    await call(http, "DELETE", f"/v1/sandboxes/{sandbox_id}", key, status=200)
    restored = await http.post(
        RESTORE.format(created["id"]), headers=bearer(key), content=live.content
    )
    assert restored.status_code == 200, restored.text
    again = await http.get(EXPORT.format(created["id"]), headers=bearer(key))
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(again.content)), mode="r:") as archive:
        handle = archive.extractfile("./payload.bin")
        assert handle is not None and handle.read() == payload
    assert helpers_left(client) == []


async def test_api_forbidden_entry_and_truncated_gzip_leave_the_volume_empty(
    client: Any, http: httpx.AsyncClient, key: str, cleanup: Cleanup
) -> None:
    created = await call(http, "POST", "/v1/volumes", key, status=201, json={"name": "guard"})
    cleanup.volume_ids.append(created["id"])
    url = RESTORE.format(created["id"])
    good = gzip.compress(tar_bytes(file_member("kept.txt", b"kept")))
    assert (await http.post(url, headers=bearer(key), content=good)).status_code == 200

    evil = gzip.compress(tar_bytes(file_member("a", b"1"), file_member("../../x", b"2")))
    refused = await http.post(url, headers=bearer(key), content=evil)
    assert refused.status_code == 422, refused.text
    failure = refused.json()["error"]
    assert failure["details"]["reason"] == "forbidden_entry"
    assert failure["details"]["violation"] == "path_traversal"
    assert failure["details"]["volume_emptied"] is True

    assert (await http.post(url, headers=bearer(key), content=good)).status_code == 200
    cut = gzip.compress(tar_bytes(file_member("big", b"q" * 200_000)))[:-40]
    broken = await http.post(url, headers=bearer(key), content=cut)
    assert broken.status_code == 422, broken.text
    assert broken.json()["error"]["details"]["volume_emptied"] is True
    after = await http.get(EXPORT.format(created["id"]), headers=bearer(key))
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(after.content)), mode="r:") as archive:
        assert [m.name for m in archive.getmembers() if m.isfile()] == []
    assert helpers_left(client) == []
