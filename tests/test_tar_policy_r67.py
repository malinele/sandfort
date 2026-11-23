"""Round 67: the archive policy every volume restore applies (``drivers.docker.tar_policy``).

``checked_tar`` reads a tar from chunks and re-emits it, member by member, from the parsed
headers: only regular files, directories and symlinks with an internal relative target survive,
and anything else raises ``DriverForbiddenEntry`` (an unreadable tar raises
``DriverInvalidArchive``).
"""

import io
import tarfile
from collections.abc import Iterable

import pytest

from sandfort.drivers.docker.tar_policy import (
    ABSOLUTE_PATH,
    DUPLICATE_ENTRY,
    HARDLINK,
    INVALID_NAME,
    PATH_TRAVERSAL,
    SPECIAL_FILE,
    SYMLINK_ABSOLUTE,
    SYMLINK_ESCAPE,
    SYMLINK_THROUGH,
    checked_tar,
)
from sandfort.drivers.errors import DriverForbiddenEntry, DriverInvalidArchive


def tar_of(*members: tuple[tarfile.TarInfo, bytes | None]) -> bytes:
    """A tar holding ``members`` as given (``TarInfo`` objects are not sanitised)."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for info, content in members:
            archive.addfile(info, None if content is None else io.BytesIO(content))
    return buffer.getvalue()


def regular(name: str, content: bytes = b"x", mode: int = 0o644) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.size = len(content)
    info.mode = mode
    return info, content


def directory(name: str, mode: int = 0o755) -> tuple[tarfile.TarInfo, None]:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = mode
    return info, None


def special(name: str, kind: bytes, target: str = "") -> tuple[tarfile.TarInfo, None]:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = target
    return info, None


def symlink(name: str, target: str) -> tuple[tarfile.TarInfo, None]:
    return special(name, tarfile.SYMTYPE, target)


def run(data: bytes, step: int = 4096) -> bytes:
    chunks: Iterable[bytes] = (data[at : at + step] for at in range(0, len(data), step))
    return b"".join(checked_tar(chunks))


def members_of(data: bytes) -> dict[str, tarfile.TarInfo]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        return {member.name: member for member in archive.getmembers()}


def refused(*members: tuple[tarfile.TarInfo, bytes | None]) -> DriverForbiddenEntry:
    with pytest.raises(DriverForbiddenEntry) as caught:
        run(tar_of(*members))
    return caught.value


# -- what is allowed ----------------------------------------------------------------------


def test_regular_files_directories_and_internal_symlinks_pass_unchanged_in_meaning() -> None:
    data = tar_of(
        directory("sub"),
        regular("a.txt", b"alpha"),
        regular("sub/b.txt", b"beta" * 5000),
        symlink("sub/up", "../a.txt"),
        symlink("here", "sub/b.txt"),
        symlink("dot", "./sub"),
    )

    found = members_of(run(data))

    assert set(found) == {"sub", "a.txt", "sub/b.txt", "sub/up", "here", "dot"}
    assert found["sub/up"].linkname == "../a.txt"
    assert found["sub/b.txt"].size == 20000


def test_modes_owners_and_the_setuid_bits_are_kept_as_recorded() -> None:
    info, content = regular("tool", b"#!", mode=0o4755)
    info.uid, info.gid = 1234, 4321
    info.uname = info.gname = ""
    sticky = directory("tmp", mode=0o1777)

    found = members_of(run(tar_of((info, content), sticky)))

    assert found["tool"].mode == 0o4755
    assert (found["tool"].uid, found["tool"].gid) == (1234, 4321)
    assert found["tmp"].mode == 0o1777


def test_leading_dot_slash_and_trailing_slashes_are_normalised() -> None:
    found = members_of(run(tar_of(directory("./"), directory("./d/"), regular("./d/f", b"1"))))

    assert set(found) == {".", "d", "d/f"}


def test_content_survives_chunking_at_any_boundary() -> None:
    payload = bytes(range(256)) * 300
    data = tar_of(regular("big.bin", payload), regular("after", b"tail"))

    for step in (1, 7, 511, 512, 513, 10_000):
        archive = tarfile.open(fileobj=io.BytesIO(run(data, step)), mode="r:")
        handle = archive.extractfile("big.bin")
        assert handle is not None and handle.read() == payload


def test_a_long_name_is_rebuilt_without_the_original_pax_path() -> None:
    long_name = "d/" + "n" * 200
    found = members_of(run(tar_of(regular(long_name, b"1"))))

    assert long_name in found


# -- what is refused ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "name", ["../evil", "a/../../evil", "a/..", "./../x", "sub/../../x", ".."]
)
def test_a_dot_dot_segment_in_a_path_is_refused(name: str) -> None:
    error = refused(regular(name))

    assert error.violation == PATH_TRAVERSAL
    assert error.entry == name


@pytest.mark.parametrize("name", ["/etc/passwd", "//x", "/"])
def test_an_absolute_path_is_refused(name: str) -> None:
    assert refused(regular(name)).violation == ABSOLUTE_PATH


def test_a_hardlink_is_refused_even_to_a_file_in_the_archive() -> None:
    error = refused(regular("a"), special("b", tarfile.LNKTYPE, "a"))

    assert error.violation == HARDLINK
    assert error.entry == "b"


@pytest.mark.parametrize(
    ("kind", "label"),
    [(tarfile.CHRTYPE, "char"), (tarfile.BLKTYPE, "block"), (tarfile.FIFOTYPE, "fifo")],
)
def test_device_nodes_and_fifos_are_refused(kind: bytes, label: str) -> None:
    assert refused(special(f"dev-{label}", kind)).violation == SPECIAL_FILE


@pytest.mark.parametrize("target", ["/etc/passwd", "/", "/volume-data/x"])
def test_an_absolute_symlink_target_is_refused(target: str) -> None:
    assert refused(symlink("l", target)).violation == SYMLINK_ABSOLUTE


@pytest.mark.parametrize(
    ("name", "target"),
    [
        ("l", ".."),
        ("l", "../x"),
        ("a/l", "../../x"),
        ("a/b/l", "../../../x"),
        ("l", "a/../../x"),  # a dot-dot after a name is refused outright, not resolved
        ("l", "a/.."),
    ],
)
def test_a_symlink_that_leaves_the_volume_is_refused(name: str, target: str) -> None:
    members = [directory("a"), directory("a/b"), symlink(name, target)]

    with pytest.raises(DriverForbiddenEntry) as caught:
        run(tar_of(*members))

    assert caught.value.violation == SYMLINK_ESCAPE


def test_a_symlink_to_a_directory_that_points_back_to_the_root_cannot_be_used_to_escape() -> None:
    # d -> . is internal; d/x -> ../y would then leave the volume. Nothing may be written
    # through a symlink of the archive, so the second member is the refusal.
    error = refused(symlink("d", "."), symlink("d/x", "../y"))

    assert error.violation == SYMLINK_THROUGH
    assert error.entry == "d/x"


def test_a_member_below_a_symlink_of_the_archive_is_refused() -> None:
    error = refused(directory("real"), symlink("link", "real"), regular("link/file"))

    assert error.violation == SYMLINK_THROUGH


def test_redefining_a_symlink_path_is_refused() -> None:
    error = refused(symlink("l", "x"), regular("l"))

    assert error.violation == DUPLICATE_ENTRY


def test_a_refusal_names_the_entry_and_carries_no_control_characters() -> None:
    error = refused(regular("../bad\nname"))

    assert "\n" not in str(error) and "\n" not in error.entry
    assert error.violation == INVALID_NAME


def test_the_first_bad_member_stops_the_stream_after_the_good_ones_before_it() -> None:
    data = tar_of(regular("ok", b"1"), regular("../bad", b"2"), regular("never", b"3"))
    seen: list[bytes] = []

    with pytest.raises(DriverForbiddenEntry):
        for piece in checked_tar([data]):
            seen.append(piece)

    assert b"never" not in b"".join(seen) and b"../bad" not in b"".join(seen)


# -- unreadable and truncated tars --------------------------------------------------------


def test_garbage_is_an_invalid_archive_not_a_forbidden_entry() -> None:
    with pytest.raises(DriverInvalidArchive) as caught:
        run(b"this is not a tar archive" * 100)

    assert not isinstance(caught.value, DriverForbiddenEntry)


def test_a_tar_cut_inside_a_member_is_an_invalid_archive() -> None:
    data = tar_of(regular("a", b"z" * 5000))

    with pytest.raises(DriverInvalidArchive):
        run(data[:1500])


def test_a_tar_without_the_end_of_archive_marker_is_an_invalid_archive() -> None:
    data = tar_of(regular("a", b"z" * 100))
    without_end = data[: 512 + 512]  # header and one data block, no zero blocks

    with pytest.raises(DriverInvalidArchive):
        run(without_end)


def test_data_after_the_end_of_archive_marker_is_refused() -> None:
    data = tar_of(regular("a", b"1")) + b"smuggled" * 100

    with pytest.raises(DriverInvalidArchive):
        run(data)


def test_zero_padding_after_the_end_of_archive_marker_is_fine() -> None:
    data = tar_of(regular("a", b"1")) + bytes(100_000)

    assert set(members_of(run(data))) == {"a"}


def test_every_input_chunk_is_read_even_after_the_end_marker() -> None:
    """The source's own checks (gzip trailer) only happen when it is read to its end."""
    consumed: list[int] = []

    def source() -> Iterable[bytes]:
        data = tar_of(regular("a", b"1")) + bytes(50_000)
        for at in range(0, len(data), 1000):
            consumed.append(at)
            yield data[at : at + 1000]

    b"".join(checked_tar(source()))

    assert consumed[-1] == (len(tar_of(regular("a", b"1"))) + 50_000 - 1) // 1000 * 1000
