"""The archive policy of a volume restore: which tar members may reach a volume.

``checked_tar`` reads the restore's tar from chunks and writes a NEW tar, built member by member
from the headers it parsed and approved (the same machinery as ``tar_filter``). Nothing the
archive spelled differently from what was checked can reach the daemon: names are normalised,
every pax and GNU extension is dropped (extended attributes, sparse maps, a ``path`` override),
and only an explicit list of header fields is carried over. The daemon then extracts a tar that
contains regular files, directories and symlinks, nothing else.

Allowed members:

* regular files, with their recorded mode (setuid, setgid and sticky bits included), uid, gid
  and modification time;
* directories, with their recorded mode, uid, gid and modification time;
* symlinks whose target is relative and stays inside the volume.

Refused members (``DriverForbiddenEntry``; the ``violation`` codes are the ones named below):

* ``path_traversal``: a ``..`` segment anywhere in the member name;
* ``absolute_path``: a name that starts with ``/``;
* ``invalid_name``: an empty, over-long (``MAX_PATH_BYTES``) or control-character name (``\\0``
  included: Python and the daemon would read a different name);
* ``invalid_link_target``: a symlink target that is over-long or holds a control character;
* ``hardlink``: any hard link, even to a file of the same archive;
* ``symlink_absolute``: a symlink whose target starts with ``/``;
* ``symlink_escape``: a symlink whose target leaves the volume, resolved from the directory of
  the symlink; a ``..`` is accepted only as a leading run of segments (``../../x``), because a
  ``..`` after a name cannot be resolved without knowing every symlink of the archive, some of
  which may come later;
* ``symlink_through``: a member below a symlink of the archive (``link/file``), so a symlink can
  never redirect a later member and every symlink is resolved from a real directory;
* ``duplicate_entry``: a member whose normalised path equals that of any earlier member, whatever
  the types (two files of one name, a file then a directory, ``./a`` then ``a``): a restore never
  lets a later member replace an earlier one;
* ``special_file``: character and block devices, FIFOs;
* ``unsupported_entry``: anything else (sparse files, vendor types, an empty symlink target);
* ``header_too_large``: a pax or GNU long-name header over ``MAX_EXTENDED_HEADER_BYTES`` (one
  MiB; ``tarfile`` would buffer it whole), refused after reading about that much;
* ``too_many_entries``: more than ``MAX_MEMBERS`` members (this also bounds the set of seen paths).

Every rebuilt header is parsed back and its name and link target must equal what was checked.

An archive that is not a readable tar, ends without the end-of-archive marker, is cut inside a
member or carries data after the marker raises ``DriverInvalidArchive``. The input is always
read to its end, so a source that checks its own tail (a gzip trailer) gets to.

Setuid bits are kept on purpose: every sandbox container runs with ``no-new-privileges`` (see
``hardening._security_opt``, which has no switch to turn it off), so exec of a setuid file never
gains the file owner's rights.
"""

import io
import tarfile
from collections.abc import Iterable, Iterator

from sandfort.drivers.docker.client import echo_path
from sandfort.drivers.docker.tar_filter import (
    MAX_EXTENDED_HEADER_BYTES,
    HeaderTooLarge,
    rewrite_members,
)
from sandfort.drivers.errors import DriverForbiddenEntry, DriverInvalidArchive

PATH_TRAVERSAL = "path_traversal"
ABSOLUTE_PATH = "absolute_path"
INVALID_NAME = "invalid_name"
INVALID_LINK_TARGET = "invalid_link_target"
HARDLINK = "hardlink"
SYMLINK_ABSOLUTE = "symlink_absolute"
SYMLINK_ESCAPE = "symlink_escape"
SYMLINK_THROUGH = "symlink_through"
DUPLICATE_ENTRY = "duplicate_entry"
SPECIAL_FILE = "special_file"
UNSUPPORTED_ENTRY = "unsupported_entry"
HEADER_TOO_LARGE = "header_too_large"
TOO_MANY_ENTRIES = "too_many_entries"

MAX_PATH_BYTES = 4096  # PATH_MAX
MAX_MEMBERS = 100_000  # members of one archive; ArchivePolicy keeps at most this many paths
FIRST_PRINTABLE = " "  # every character below it, NUL included, is a control character
DELETE_CHAR = "\x7f"
PERMISSION_BITS = 0o7777
PARENT = ".."
ROOT_NAME = "."
_SPECIAL_TYPES = frozenset({tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE})
_SPARSE_PAX_PREFIX = "GNU.sparse."
_DESCRIPTIONS = {
    PATH_TRAVERSAL: "a path with a '..' segment",
    ABSOLUTE_PATH: "an absolute path",
    INVALID_NAME: "an empty, over-long or control-character name",
    INVALID_LINK_TARGET: "a symlink target that is over-long or has a control character",
    HARDLINK: "a hard link",
    SYMLINK_ABSOLUTE: "a symlink with an absolute target",
    SYMLINK_ESCAPE: "a symlink that leaves the volume",
    SYMLINK_THROUGH: "a path below a symlink of the archive",
    DUPLICATE_ENTRY: "a second entry at the path of an earlier entry",
    SPECIAL_FILE: "a device node or FIFO",
    UNSUPPORTED_ENTRY: "an entry type the volume cannot hold",
    HEADER_TOO_LARGE: "an extended header larger than the limit",
    TOO_MANY_ENTRIES: "more entries than the limit",
}
_UNREADABLE = (tarfile.TarError, EOFError, UnicodeError, OverflowError)


def forbidden(violation: str, name: str) -> DriverForbiddenEntry:
    """The refusal of ``violation`` for the member ``name``."""
    shown = echo_path(name)
    where = f": {shown}" if shown else ""
    return DriverForbiddenEntry(
        f"the archive holds an entry that is not allowed ({_DESCRIPTIONS[violation]}){where}",
        violation=violation,
        entry=shown,
    )


def _has_control(text: str) -> bool:
    return any(char < FIRST_PRINTABLE or char == DELETE_CHAR for char in text)


def _path_bytes(text: str) -> int:
    return len(text.encode("utf-8", "surrogateescape"))


def _segments(path: str) -> list[str]:
    """The segments of ``path`` without empty ones and ``.`` (a duplicate slash or ``./``)."""
    return [part for part in path.split("/") if part not in ("", ".")]


class ArchivePolicy:
    """Approves each member of one archive, in order; remembers every path and symlink approved."""

    def __init__(self) -> None:
        self._paths: set[str] = set()  # at most MAX_MEMBERS: every member is counted
        self._symlinks: set[str] = set()  # a subset of ``_paths``
        self._members = 0

    def __call__(self, member: tarfile.TarInfo) -> tarfile.TarInfo:
        """The header to write for ``member``; raises ``DriverForbiddenEntry`` to refuse it."""
        self._members += 1
        if self._members > MAX_MEMBERS:
            raise forbidden(TOO_MANY_ENTRIES, member.name)
        self._check_type(member)
        parts = self._check_name(member.name)
        path = "/".join(parts)
        self._check_ancestors(member.name, parts)
        self._paths.add(path)
        if member.issym():
            self._check_target(member, parts)
            self._symlinks.add(path)
        elif member.linkname:
            raise forbidden(UNSUPPORTED_ENTRY, member.name)  # only a symlink has a target
        return _checked_rebuild(member, path)

    @staticmethod
    def _check_type(member: tarfile.TarInfo) -> None:
        if member.islnk():
            raise forbidden(HARDLINK, member.name)
        if member.type in _SPECIAL_TYPES:
            raise forbidden(SPECIAL_FILE, member.name)
        sparse = member.issparse() or any(
            key.startswith(_SPARSE_PAX_PREFIX) for key in member.pax_headers
        )
        if sparse or not (member.isreg() or member.isdir() or member.issym()):
            raise forbidden(UNSUPPORTED_ENTRY, member.name)

    @staticmethod
    def _check_name(name: str) -> list[str]:
        if not name or _path_bytes(name) > MAX_PATH_BYTES or _has_control(name):
            raise forbidden(INVALID_NAME, name)
        if name.startswith("/"):
            raise forbidden(ABSOLUTE_PATH, name)
        parts = _segments(name)
        if PARENT in parts:
            raise forbidden(PATH_TRAVERSAL, name)
        return parts

    def _check_ancestors(self, name: str, parts: list[str]) -> None:
        if "/".join(parts) in self._paths:
            raise forbidden(DUPLICATE_ENTRY, name)
        for depth in range(1, len(parts)):
            if "/".join(parts[:depth]) in self._symlinks:
                raise forbidden(SYMLINK_THROUGH, name)

    @staticmethod
    def _check_target(member: tarfile.TarInfo, parts: list[str]) -> None:
        target = member.linkname
        if _path_bytes(target) > MAX_PATH_BYTES or _has_control(target):
            raise forbidden(INVALID_LINK_TARGET, member.name)
        if target.startswith("/"):
            raise forbidden(SYMLINK_ABSOLUTE, member.name)
        if not target:
            raise forbidden(UNSUPPORTED_ENTRY, member.name)  # a symlink must point somewhere
        segments = _segments(target)
        leading = len(segments) - len(_without_leading_parents(segments))
        if PARENT in segments[leading:] or leading > len(parts) - 1:
            raise forbidden(SYMLINK_ESCAPE, member.name)


def _without_leading_parents(segments: list[str]) -> list[str]:
    start = 0
    while start < len(segments) and segments[start] == PARENT:
        start += 1
    return segments[start:]


def _rebuilt(member: tarfile.TarInfo, path: str) -> tarfile.TarInfo:
    """A header made of the approved fields only: no pax or GNU extensions, no device numbers."""
    rebuilt = tarfile.TarInfo(path or ROOT_NAME)
    rebuilt.mode = member.mode & PERMISSION_BITS
    rebuilt.uid, rebuilt.gid = member.uid, member.gid
    rebuilt.mtime = member.mtime
    if member.isdir():
        rebuilt.type = tarfile.DIRTYPE
    elif member.issym():
        rebuilt.type = tarfile.SYMTYPE
        rebuilt.linkname = member.linkname
    else:
        rebuilt.type = tarfile.REGTYPE
        rebuilt.size = member.size
    return rebuilt


def _reparsed(header: bytes) -> tarfile.TarInfo:
    """The first member of ``header`` (the bytes of one rebuilt header, extensions included)."""
    with tarfile.open(fileobj=io.BytesIO(header), mode="r:") as archive:
        parsed = archive.next()
    if parsed is None:
        raise tarfile.ReadError("a rebuilt header does not parse")
    return parsed


def _checked_rebuild(member: tarfile.TarInfo, path: str) -> tarfile.TarInfo:
    """``_rebuilt``, after parsing its header back: the name and link target a reader gets must
    be byte for byte the ones that were checked (the daemon is such a reader, and reads C
    strings: a NUL must never make it see another name)."""
    rebuilt = _rebuilt(member, path)
    header = rebuilt.tobuf(tarfile.PAX_FORMAT, "utf-8", "surrogateescape")
    try:
        parsed = _reparsed(header)
        same = (parsed.name, parsed.linkname, parsed.type) == (
            rebuilt.name,
            rebuilt.linkname,
            rebuilt.type,
        )
    except (tarfile.TarError, UnicodeError):
        same = False
    if not same:
        raise forbidden(INVALID_NAME, member.name)
    return rebuilt


def checked_tar(chunks: Iterable[bytes]) -> Iterator[bytes]:
    """The tar in ``chunks`` as a policy-checked, rebuilt tar, lazily.

    Raises ``DriverForbiddenEntry`` at the first refused member (the members before it were
    already yielded) and ``DriverInvalidArchive`` for a tar that cannot be read. Errors of the
    ``chunks`` source itself pass through unchanged.
    """
    try:
        yield from rewrite_members(
            chunks,
            ArchivePolicy(),
            drain_trailer=True,
            max_read=MAX_EXTENDED_HEADER_BYTES,
        )
    except HeaderTooLarge as exc:
        raise forbidden(HEADER_TOO_LARGE, "") from exc
    except _UNREADABLE as exc:
        raise DriverInvalidArchive("the archive is not a readable tar") from exc
