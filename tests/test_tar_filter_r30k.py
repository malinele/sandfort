"""The tar filter copies each input byte a bounded number of times, keeps no member list, and
refuses a stream that was cut before its end-of-archive marker."""

import io
import tarfile
from collections.abc import Iterator

import pytest

from sandfort.drivers.docker.tar_filter import _ChunkReader, drop_platform_members

MIB = 1024 * 1024
TARFILE_READ_BYTES = 10 * 1024
BLOCK = tarfile.BLOCKSIZE

Member = tuple[str, bytes, int]


def _build(members: list[Member], *, end_marker: bool = True) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, data, mode in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            info.mtime = 1_700_000_000
            tar.addfile(info, io.BytesIO(data))
    raw = buffer.getvalue()
    if end_marker:
        return raw
    # tarfile pads with the end marker and record padding; strip back to the last member block
    end = len(raw)
    while end >= BLOCK and raw[end - BLOCK : end] == tarfile.NUL * BLOCK:
        end -= BLOCK
    return raw[:end]


def _chunks(data: bytes, size: int) -> Iterator[bytes]:
    for start in range(0, len(data), size):
        yield data[start : start + size]


def _summary(data: bytes) -> list[tuple[str, bytes, int]]:
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        rows = []
        for member in tar.getmembers():
            source = tar.extractfile(member)
            rows.append((member.name, source.read() if source else b"", member.mode))
        return rows


def _run(data: bytes, size: int = 8192) -> bytes:
    return b"".join(drop_platform_members(_chunks(data, size)))


def test_reader_copies_each_input_byte_a_bounded_number_of_times() -> None:
    payload = bytes(range(256)) * (4 * MIB // 256)
    reader = _ChunkReader(_chunks(payload, 2 * MIB))

    received = bytearray()
    while piece := reader.read(TARFILE_READ_BYTES):
        received += piece

    assert bytes(received) == payload
    assert reader.copied_bytes <= 2 * len(payload)


def test_reader_serves_reads_that_span_chunks_and_empty_chunks() -> None:
    reader = _ChunkReader(iter([b"ab", b"", b"cde", b"f"]))

    assert reader.read(3) == b"abc"
    assert reader.read(0) == b""
    assert reader.read(2) == b"de"
    assert reader.read(-1) == b"f"
    assert reader.read(5) == b""


def test_member_list_stays_small_over_many_files(monkeypatch: pytest.MonkeyPatch) -> None:
    count = 20_000
    members = [(f"d/f{index}", b"x", 0o644) for index in range(count)]
    source = _build(members)
    largest = 0
    original = tarfile.TarFile.next

    def watching(self: tarfile.TarFile) -> tarfile.TarInfo | None:
        nonlocal largest
        largest = max(largest, len(vars(self)["members"]))
        return original(self)

    monkeypatch.setattr(tarfile.TarFile, "next", watching)

    result = _run(source, 2 * MIB)

    monkeypatch.undo()
    assert largest <= 2
    assert _summary(result) == _summary(source)


def test_stream_cut_at_a_header_boundary_is_an_error() -> None:
    source = _build([("a", b"a" * 700, 0o644), ("b", b"b", 0o644)], end_marker=False)
    first_member_end = 3 * BLOCK  # header + two content blocks of "a"

    with pytest.raises(tarfile.ReadError, match="offset"):
        _run(source[:first_member_end])


def test_stream_cut_inside_a_header_is_an_error() -> None:
    source = _build([("a", b"a" * 700, 0o644), ("b", b"b", 0o644)], end_marker=False)
    cut = 3 * BLOCK + BLOCK // 2

    with pytest.raises(tarfile.ReadError, match="offset"):
        _run(source[:cut])


def test_archive_without_an_end_marker_is_an_error() -> None:
    source = _build([("a", b"abc", 0o644)], end_marker=False)

    with pytest.raises(tarfile.ReadError):
        _run(source)


def test_stream_cut_inside_member_content_is_an_error() -> None:
    source = _build([("a", b"a" * 5000, 0o644)])

    with pytest.raises(tarfile.ReadError):
        _run(source[:2000])


def test_normal_archive_round_trips_names_contents_and_modes() -> None:
    members = [("etc/hosts", b"127.0.0.1\n", 0o640), ("bin/run", b"#!/bin/sh\n", 0o755)]
    source = _build(members)

    assert _summary(_run(source, 1000)) == members


def test_end_marker_followed_by_record_padding_round_trips() -> None:
    members = [("a", b"abc", 0o600)]
    source = _build(members) + tarfile.NUL * (3 * tarfile.RECORDSIZE)

    assert _summary(_run(source)) == members


def test_archive_with_only_an_end_marker_is_empty_not_an_error() -> None:
    assert _summary(_run(tarfile.NUL * tarfile.RECORDSIZE)) == []


def test_archive_without_the_reserve_file_round_trips() -> None:
    members = [("opt/.sandfort-reserve", b"nested", 0o644), ("x", b"", 0o644)]

    assert _summary(_run(_build(members))) == members
