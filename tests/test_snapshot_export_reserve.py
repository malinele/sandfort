"""The snapshot export drops the platform members and passes the rest unchanged.

Platform members are the root-level disk reserve file and Docker's ``/.dockerenv`` marker
(materialized by ``docker export`` even for a never-started container; partner finding E-001).
"""

import contextlib
import io
import tarfile
import uuid
from collections.abc import Iterator

import pytest

from sandfort.drivers.docker import image_export, images
from sandfort.drivers.docker.client import make_client
from sandfort.drivers.docker.disk_reserve import RESERVE_PATH
from sandfort.drivers.docker.tar_filter import (
    COPY_CHUNK_BYTES,
    drop_platform_members,
    is_platform_member,
    is_reserve_member,
)

MIB = 1024 * 1024
INPUT_CHUNK_BYTES = 8192

Member = tuple[tarfile.TarInfo, bytes]


def _file(name: str, data: bytes, mode: int = 0o644) -> Member:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.mtime = 1_700_000_000
    return info, data


def _special(name: str, kind: bytes, mode: int, linkname: str = "") -> Member:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.mode = mode
    info.linkname = linkname
    info.mtime = 1_700_000_000
    return info, b""


def _build(members: list[Member]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for info, data in members:
            tar.addfile(info, io.BytesIO(data) if info.isreg() else None)
    return buffer.getvalue()


def _chunks(data: bytes, size: int = INPUT_CHUNK_BYTES) -> Iterator[bytes]:
    for start in range(0, len(data), size):
        yield data[start : start + size]


def _summary(data: bytes) -> list[tuple[str, bytes, int, str, bytes]]:
    rows = []
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        for member in tar.getmembers():
            source = tar.extractfile(member) if member.isreg() else None
            content = source.read() if source is not None else b""
            rows.append((member.name, member.type, member.mode, member.linkname, content))
    return rows


def _sample_members() -> list[Member]:
    return [
        _file(".sandfort-reserve", bytes(4096), 0o600),
        _file("./.sandfort-reserve", b"", 0o600),
        _file("/.sandfort-reserve", b"", 0o600),
        _special("etc", tarfile.DIRTYPE, 0o755),
        _file("etc/hosts", b"127.0.0.1 localhost\n", 0o640),
        _special("etc/link", tarfile.SYMTYPE, 0o777, "hosts"),
        _special("etc/hard", tarfile.LNKTYPE, 0o640, "etc/hosts"),
        _file("opt/.sandfort-reserve", b"not at the root", 0o644),
    ]


def test_is_reserve_member_matches_only_the_root_file() -> None:
    assert RESERVE_PATH == "/.sandfort-reserve"
    for name in (".sandfort-reserve", "./.sandfort-reserve", "/.sandfort-reserve"):
        assert is_reserve_member(name)
    for name in ("opt/.sandfort-reserve", ".sandfort-reserve2", "sandfort-reserve", "./etc"):
        assert not is_reserve_member(name)


def test_filter_drops_the_reserve_file_and_keeps_every_other_member() -> None:
    source = _build(_sample_members())

    result = b"".join(drop_platform_members(_chunks(source)))

    names = [row[0] for row in _summary(result)]
    assert names == ["etc", "etc/hosts", "etc/link", "etc/hard", "opt/.sandfort-reserve"]
    expected = [row for row in _summary(source) if not is_reserve_member(row[0])]
    assert _summary(result) == expected
    kept = {row[0]: row for row in _summary(result)}
    assert kept["etc/hosts"][2:] == (0o640, "", b"127.0.0.1 localhost\n")
    assert kept["etc/link"][1:4] == (tarfile.SYMTYPE, 0o777, "hosts")
    assert kept["etc/hard"][1:4] == (tarfile.LNKTYPE, 0o640, "etc/hosts")
    assert kept["etc"][1] == tarfile.DIRTYPE
    assert len(result) % tarfile.RECORDSIZE == 0


def test_filter_leaves_an_archive_without_the_reserve_file_equivalent() -> None:
    members = [m for m in _sample_members() if not is_reserve_member(m[0].name)]
    source = _build(members)

    result = b"".join(drop_platform_members(_chunks(source, 1000)))

    assert _summary(result) == _summary(source)


def test_filter_streams_a_large_member_in_bounded_chunks() -> None:
    payload = bytes(range(256)) * (4 * MIB // 256)
    source = _build(
        [_file(".sandfort-reserve", bytes(MIB)), _file("big.bin", payload), _file("tail", b"t")]
    )
    consumed = 0

    def counting() -> Iterator[bytes]:
        nonlocal consumed
        for chunk in _chunks(source):
            consumed += len(chunk)
            yield chunk

    pieces: list[bytes] = []
    consumed_at_first_content = 0
    for piece in drop_platform_members(counting()):
        pieces.append(piece)
        if len(piece) == COPY_CHUNK_BYTES and not consumed_at_first_content:
            consumed_at_first_content = consumed

    assert max(len(piece) for piece in pieces) <= COPY_CHUNK_BYTES
    # The first content piece left long before the 4 MiB member (or the archive) was read.
    assert 0 < consumed_at_first_content < len(source) // 2
    rows = {row[0]: row for row in _summary(b"".join(pieces))}
    assert set(rows) == {"big.bin", "tail"}
    assert rows["big.bin"][4] == payload


def test_filter_reads_nothing_until_it_is_iterated() -> None:
    consumed: list[int] = []

    def source() -> Iterator[bytes]:
        consumed.append(1)
        yield b""

    drop_platform_members(source())

    assert consumed == []


def test_is_platform_member_matches_reserve_and_dockerenv_at_the_root_only() -> None:
    for name in (".dockerenv", "./.dockerenv", "/.dockerenv", ".sandfort-reserve",
                 "./.sandfort-reserve", "/.sandfort-reserve"):
        assert is_platform_member(name)
    for name in ("opt/.dockerenv", ".dockerenv2", "dockerenv", "etc/.dockerenv", "./etc"):
        assert not is_platform_member(name)


def test_filter_drops_the_dockerenv_marker_and_keeps_a_nested_one() -> None:
    source = _build(
        [
            _file(".dockerenv", b"", 0o755),
            _file("./.dockerenv", b"", 0o755),
            _file("/.dockerenv", b"", 0o755),
            _file("opt/.dockerenv", b"user content, not the root marker", 0o644),
            _file("etc/hosts", b"127.0.0.1 localhost\n", 0o640),
        ]
    )

    result = b"".join(drop_platform_members(_chunks(source)))

    names = [row[0] for row in _summary(result)]
    assert names == ["opt/.dockerenv", "etc/hosts"]
    kept = {row[0]: row for row in _summary(result)}
    assert kept["opt/.dockerenv"][4] == b"user content, not the root marker"


def test_filter_rejects_a_truncated_member() -> None:
    source = _build([_file("data", b"x" * 5000)])

    with pytest.raises(tarfile.TarError):
        b"".join(drop_platform_members(_chunks(source[:2000])))


def test_filter_closes_the_source_when_the_consumer_stops_early() -> None:
    closed: list[bool] = []

    def source() -> Iterator[bytes]:
        try:
            yield from _chunks(_build([_file("a", b"a" * 3000)]))
        finally:
            closed.append(True)

    output = drop_platform_members(source())
    next(output)
    output.close()

    assert closed == [True]


# --- real Docker -----------------------------------------------------------------------


@pytest.mark.docker
async def test_exported_image_does_not_contain_the_reserve_file() -> None:
    docker = pytest.importorskip("docker")
    try:
        client = make_client()
        client.ping()
        client.images.get("alpine:3.20")
    except Exception as exc:
        pytest.skip(f"no Docker daemon with alpine:3.20: {exc}")
    suffix = uuid.uuid4().hex[:8]
    reference = f"sandfort-snapshot-test:reserve-{suffix}"
    loaded_tag = f"sandfort-snapshot-test:reserve-loaded-{suffix}"
    container = client.api.create_container("alpine:3.20", command=["sleep", "60"])
    try:
        client.api.start(container["Id"])
        script = f"echo hi > /marker.txt && head -c 1048576 /dev/zero > {RESERVE_PATH}"
        code, _ = client.containers.get(container["Id"]).exec_run(["sh", "-c", script])
        assert code == 0
        await images.commit_container(client, container["Id"], reference)
        data = b"".join([c async for c in image_export.export_image(client, reference)])
        loaded = client.images.load(data)
        client.api.tag(loaded[0].id, *loaded_tag.split(":"))
        listing = client.containers.run(loaded_tag, ["ls", "-A", "/"], remove=True)
        marker = client.containers.run(loaded_tag, ["cat", "/marker.txt"], remove=True)
    finally:
        client.api.remove_container(container["Id"], v=True, force=True)
        for name in (reference, loaded_tag):
            with contextlib.suppress(docker.errors.NotFound):
                client.api.remove_image(name, force=True)
    assert ".sandfort-reserve" not in listing.decode().split()
    assert marker.strip() == b"hi"
    # Offline check of the tar itself: the running container above gets a fresh runtime
    # ``.dockerenv`` from Docker, so the archive members are the only honest place to look.
    with tarfile.open(fileobj=io.BytesIO(data)) as exported:
        layer_names = [m.name for m in exported.getmembers() if m.name.endswith(".tar")]
        for layer_name in layer_names:
            layer = exported.extractfile(layer_name)
            assert layer is not None
            with tarfile.open(fileobj=io.BytesIO(layer.read())) as layer_tar:
                assert not any(
                    is_platform_member(member.name) for member in layer_tar.getmembers()
                )
