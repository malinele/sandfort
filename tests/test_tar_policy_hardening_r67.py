"""Round 67 hardening of the archive policy (security review findings).

* Extended headers (pax ``x``/``g``, GNU long name ``L`` and long link ``K``) are buffered whole
  by ``tarfile``; a header claiming hundreds of MiB must be refused after reading about one MiB.
* A NUL (or any control character) in a name or link target made Python and the daemon read
  different strings; both are refused, and every rebuilt header is parsed back and compared.
* The number of members is capped.
"""

import io
import tarfile
from collections.abc import Iterator

import pytest

from sandfort.drivers.docker import tar_policy
from sandfort.drivers.docker.tar_filter import MAX_EXTENDED_HEADER_BYTES
from sandfort.drivers.docker.tar_policy import (
    HEADER_TOO_LARGE,
    INVALID_LINK_TARGET,
    INVALID_NAME,
    MAX_PATH_BYTES,
    SYMLINK_THROUGH,
    TOO_MANY_ENTRIES,
    checked_tar,
)
from sandfort.drivers.errors import DriverForbiddenEntry

END = bytes(1024)
MIB = 1024 * 1024
HUGE = 400 * MIB


def pax_records(headers: dict[str, bytes]) -> bytes:
    out = b""
    for key, value in headers.items():
        body = b" " + key.encode() + b"=" + value + b"\n"
        length = len(str(len(body))) + len(body)
        if len(str(length)) + len(body) != length:
            length = len(str(length)) + len(body)
        out += str(length).encode() + body
    return out


def member(
    name: str,
    kind: bytes = b"0",
    link: str = "",
    data: bytes = b"",
    pax: dict[str, bytes] | None = None,
) -> bytes:
    """A member whose own header is plain ustar; ``pax`` overrides fields as a pax header."""
    out = b""
    if pax:
        records = pax_records(pax)
        extended = tarfile.TarInfo("PaxHeader")
        extended.type, extended.size = tarfile.XHDTYPE, len(records)
        out += extended.tobuf(tarfile.USTAR_FORMAT) + records + bytes(-len(records) % 512)
    info = tarfile.TarInfo(name)
    info.type, info.linkname, info.size, info.mode = kind, link, len(data), 0o644
    return out + info.tobuf(tarfile.USTAR_FORMAT) + data + bytes(-len(data) % 512)


def run(data: bytes) -> bytes:
    return b"".join(checked_tar([data]))


def refusal(data: bytes) -> DriverForbiddenEntry:
    with pytest.raises(DriverForbiddenEntry) as caught:
        run(data)
    return caught.value


class Source:
    """A lazy tar source that counts the bytes it was asked for."""

    def __init__(self, head: bytes, filler: int) -> None:
        self.head, self.filler, self.pulled = head, filler, 0

    def __iter__(self) -> Iterator[bytes]:
        yield self._count(self.head)
        block = bytes(64 * 1024)
        for _ in range(self.filler // len(block)):
            yield self._count(block)
        yield self._count(END)

    def _count(self, piece: bytes) -> bytes:
        self.pulled += len(piece)
        return piece


def declared_header(kind: bytes, size: int) -> bytes:
    info = tarfile.TarInfo("PaxHeader" if kind in (b"x", b"g") else "././@LongLink")
    info.type, info.size = kind, size
    return info.tobuf(tarfile.GNU_FORMAT)


# -- HIGH-1: unbounded extended headers ------------------------------------------------------


@pytest.mark.parametrize(
    "kind", [b"x", b"g", b"L", b"K"], ids=["pax", "global", "longname", "link"]
)
def test_an_extended_header_claiming_hundreds_of_mib_is_refused_after_about_one_mib(
    kind: bytes,
) -> None:
    source = Source(declared_header(kind, HUGE), filler=HUGE)

    with pytest.raises(DriverForbiddenEntry) as caught:
        b"".join(checked_tar(source))

    assert caught.value.violation == HEADER_TOO_LARGE
    assert source.pulled <= 2 * MIB  # the declared 400 MiB was never read


def test_an_extended_header_just_over_the_limit_is_refused_and_one_at_the_limit_is_read() -> None:
    over = Source(declared_header(b"x", MAX_EXTENDED_HEADER_BYTES + 512), filler=2 * MIB)
    with pytest.raises(DriverForbiddenEntry):
        b"".join(checked_tar(over))

    # a big but legitimate pax header (a long comment record) just under the limit is read
    records = pax_records({"comment": b"c" * (MAX_EXTENDED_HEADER_BYTES - 1024)})
    extended = tarfile.TarInfo("PaxHeader")
    extended.type, extended.size = tarfile.XHDTYPE, len(records)
    padded = records + bytes(-len(records) % 512)
    blob = extended.tobuf(tarfile.USTAR_FORMAT) + padded + member("ok.txt", data=b"1") + END

    assert run(blob)


def test_a_pax_size_that_hides_a_header_from_a_scanner_cannot_hide_it_from_the_limit() -> None:
    # The member claims size 5000 in ustar but a pax ``size=0`` makes tarfile read the next
    # header at once: a limit that trusted the ustar size would skip over the huge header.
    hidden = declared_header(b"x", HUGE)
    outer = member("f.txt", data=bytes(5000), pax={"size": b"0"})
    source = Source(outer[: 3 * 512] + hidden, filler=HUGE)  # pax header, its records, member

    with pytest.raises(DriverForbiddenEntry) as caught:
        b"".join(checked_tar(source))

    assert caught.value.violation == HEADER_TOO_LARGE
    assert source.pulled <= 2 * MIB


def test_a_legitimate_path_of_about_4096_bytes_still_passes_in_every_extended_format() -> None:
    long_name = "/".join(["d" * 99] * 40)  # 3999 bytes
    assert len(long_name) < MAX_PATH_BYTES
    for fmt in (tarfile.PAX_FORMAT, tarfile.GNU_FORMAT):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=fmt) as archive:
            info = tarfile.TarInfo(long_name)
            info.size = 3
            archive.addfile(info, io.BytesIO(b"abc"))
        with tarfile.open(fileobj=io.BytesIO(run(buffer.getvalue())), mode="r:") as back:
            assert back.getnames() == [long_name]


def test_a_link_target_over_the_path_limit_is_refused() -> None:
    target = "a/" * (MAX_PATH_BYTES // 2 + 10)
    data = member("l", kind=tarfile.SYMTYPE, link="x", pax={"linkpath": target.encode()})

    assert refusal(data + END).violation == INVALID_LINK_TARGET


# -- HIGH-2: control characters and the NUL divergence ---------------------------------------


def test_a_nul_in_a_pax_linkpath_cannot_hide_an_escaping_symlink() -> None:
    data = member("lnk", kind=tarfile.SYMTYPE, link="zz", pax={"linkpath": b"..\0"})

    assert refusal(data + END).violation == INVALID_LINK_TARGET


def test_a_nul_in_a_pax_path_cannot_rename_a_member() -> None:
    data = member("safe", data=b"hi", pax={"path": b"..\0"})

    assert refusal(data + END).violation == INVALID_NAME


def test_nul_in_name_and_linkpath_cannot_get_a_write_through_an_escaping_symlink() -> None:
    first = member("a", kind=tarfile.SYMTYPE, link="q", pax={"path": b"a\0zzz", "linkpath": b".."})
    second = member("a/file", data=b"pwn")

    assert refusal(first + second + END).violation == INVALID_NAME


@pytest.mark.parametrize("char", ["\x00", "\x01", "\n", "\t", "\x1f"])
def test_any_control_character_in_a_name_or_a_link_target_is_refused(char: str) -> None:
    named = member("ok", data=b"1", pax={"path": f"dir/na{char}me".encode()})
    linked = member("l", kind=tarfile.SYMTYPE, link="x", pax={"linkpath": f"a{char}b".encode()})

    assert refusal(named + END).violation == INVALID_NAME
    assert refusal(linked + END).violation == INVALID_LINK_TARGET


def test_a_rebuilt_header_that_does_not_parse_back_to_the_checked_names_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = tar_policy._reparsed

    def skewed(header: bytes) -> tarfile.TarInfo:
        parsed = real(header)
        parsed.name = parsed.name + "x"
        return parsed

    monkeypatch.setattr(tar_policy, "_reparsed", skewed)

    assert refusal(member("fine.txt", data=b"1") + END).violation == INVALID_NAME


ALLOWED = [
    ("plain.txt", tarfile.REGTYPE, ""),
    ("dir/sub/file.bin", tarfile.REGTYPE, ""),
    ("unicode/ünï-ñame-日本語.txt", tarfile.REGTYPE, ""),
    ("with space/and:colon", tarfile.REGTYPE, ""),
    ("sub", tarfile.DIRTYPE, ""),
    ("deep/er/link", tarfile.SYMTYPE, "../../plain.txt"),
    ("here", tarfile.SYMTYPE, "dir/sub"),
    ("n" * 250 + "/" + "m" * 250, tarfile.REGTYPE, ""),
    ("/".join(["seg" * 30] * 30), tarfile.REGTYPE, ""),
]


@pytest.mark.parametrize(("name", "kind", "link"), ALLOWED)
def test_every_allowed_member_parses_back_with_the_names_that_were_checked(
    name: str, kind: bytes, link: str
) -> None:
    info = tarfile.TarInfo(name)
    info.type, info.linkname, info.mode, info.uid, info.gid = kind, link, 0o755, 70000, 4_000_000
    content = b"data" if kind == tarfile.REGTYPE else b""
    info.size = len(content)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        archive.addfile(info, io.BytesIO(content) if content else None)

    with tarfile.open(fileobj=io.BytesIO(run(buffer.getvalue())), mode="r:") as back:
        (rebuilt,) = back.getmembers()

    assert (rebuilt.name, rebuilt.linkname) == (name, link)
    assert (rebuilt.uid, rebuilt.gid, rebuilt.mode) == (70000, 4_000_000, 0o755)


def test_user_and_group_names_are_not_carried_over() -> None:
    info = tarfile.TarInfo("f")
    info.uname, info.gname, info.size = "mallory", "wheel", 1
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        archive.addfile(info, io.BytesIO(b"x"))

    with tarfile.open(fileobj=io.BytesIO(run(buffer.getvalue())), mode="r:") as back:
        (rebuilt,) = back.getmembers()

    assert (rebuilt.uname, rebuilt.gname) == ("", "")


# -- MEDIUM-2a: member count -----------------------------------------------------------------


def test_more_members_than_the_cap_are_refused_and_exactly_the_cap_is_fine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tar_policy, "MAX_MEMBERS", 5)
    five = b"".join(member(f"f{n}") for n in range(5)) + END
    six = b"".join(member(f"f{n}") for n in range(6)) + END

    assert run(five)
    error = refusal(six)
    assert error.violation == TOO_MANY_ENTRIES
    assert error.entry == "f5"


def test_symlink_bookkeeping_is_bounded_by_the_member_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tar_policy, "MAX_MEMBERS", 50)
    links = b"".join(member(f"l{n}", kind=tarfile.SYMTYPE, link="t") for n in range(51)) + END

    assert refusal(links).violation == TOO_MANY_ENTRIES


def test_a_through_symlink_is_still_refused_after_the_hardening() -> None:
    data = member("d", kind=tarfile.SYMTYPE, link=".") + member("d/x", data=b"1") + END

    assert refusal(data).violation == SYMLINK_THROUGH
