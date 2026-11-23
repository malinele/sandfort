"""Shell-free ``stat``/``find`` invocations and the parsers for their output.

Both GNU coreutils (debian) and busybox (alpine) understand ``stat -c FORMAT`` and the
``%f %A %s %Y %n`` conversions, so one record layout serves both: ``MODE|SIZE|MTIME|NAME``.
``MODE`` is the raw hex ``st_mode`` (``%f``) or, for stripped-down builds lacking it, the
symbolic ``ls`` form (``%A``). Names come last so a ``|`` inside one cannot break a record;
a name containing a newline is stitched back from continuation lines.
"""

import posixpath
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

Kind = Literal["file", "dir", "symlink"]

S_IFMT = 0o170000
S_IFDIR = 0o040000
S_IFLNK = 0o120000
PERMISSION_MASK = 0o7777

_HEX_MODE = r"[0-9a-fA-F]+"
_SYMBOLIC_MODE = r"[-a-zA-Z?]{10}"
_FIELDS = r"\|(\d+)\|(-?\d+)\|(.*)$"


class FsParseError(ValueError):
    """The tool output did not match the expected record layout."""


@dataclass(frozen=True, slots=True)
class FsEntry:
    name: str
    path: str
    kind: Kind
    size_bytes: int
    mode: int  # permission bits only (setuid/setgid/sticky included)
    mtime: int  # unix seconds


@dataclass(frozen=True, slots=True)
class StatVariant:
    """One ``stat`` format string and the pattern that recognizes its mode column."""

    format: str
    mode_pattern: str
    symbolic: bool


VARIANTS: tuple[StatVariant, ...] = (
    StatVariant("%f|%s|%Y|%n", _HEX_MODE, symbolic=False),
    StatVariant("%A|%s|%Y|%n", _SYMBOLIC_MODE, symbolic=True),
)

_UNSUPPORTED_MARKERS = ("invalid option", "unrecognized option", "invalid conversion", "usage:")


def stat_argv(path: str, variant: StatVariant) -> list[str]:
    return ["stat", "-c", variant.format, path]


def list_argv(directory: str, variant: StatVariant) -> list[str]:
    # The trailing slash makes a symlinked directory resolve instead of being skipped.
    start = directory if directory.endswith("/") else directory + "/"
    return [
        "find",
        start,
        "-mindepth",
        "1",
        "-maxdepth",
        "1",
        "-exec",
        "stat",
        "-c",
        variant.format,
        "{}",
        "+",
    ]


def looks_unsupported(stderr: str) -> bool:
    """True when the tool rejected the invocation itself (so another variant may work)."""
    lowered = stderr.lower()
    return any(marker in lowered for marker in _UNSUPPORTED_MARKERS)


def _symbolic_mode(text: str) -> tuple[Kind, int]:
    kind: Kind = "dir" if text[0] == "d" else "symlink" if text[0] == "l" else "file"
    perm = 0
    for index, char in enumerate(text[1:10]):
        if char == "-":
            continue
        if index % 3 != 2:
            perm |= 1 << (8 - index)
            continue
        if char in "xst":
            perm |= 1 << (8 - index)
        if char in "sS":
            perm |= 0o4000 if index == 2 else 0o2000
        elif char in "tT":
            perm |= 0o1000
    return kind, perm


def _hex_mode(text: str) -> tuple[Kind, int]:
    raw = int(text, 16)
    file_type = raw & S_IFMT
    kind: Kind = "dir" if file_type == S_IFDIR else "symlink" if file_type == S_IFLNK else "file"
    return kind, raw & PERMISSION_MASK


def parse_stat_output(
    output: bytes | str, variant: StatVariant, *, directory: str | None = None
) -> list[FsEntry]:
    """Parse ``stat`` records.

    With ``directory`` set, each record's name is its basename inside that directory
    (listing); otherwise the record is the stat of a single path and keeps ``%n`` as is.
    """
    text = output.decode(errors="replace") if isinstance(output, bytes) else output
    start = re.compile(rf"^({variant.mode_pattern}){_FIELDS}", re.DOTALL)
    records: list[list[str]] = []
    for line in text.split("\n"):
        match = start.match(line)
        if match is not None:
            records.append(list(match.groups()))
        elif records and line:
            records[-1][3] += "\n" + line
        elif line:
            raise FsParseError(f"unrecognized stat output: {line[:80]!r}")
    entries: list[FsEntry] = []
    for mode_text, size, mtime, name in records:
        kind, perm = _symbolic_mode(mode_text) if variant.symbolic else _hex_mode(mode_text)
        base = posixpath.basename(name.rstrip("/")) or "/"
        path = name if directory is None else posixpath.join(directory, base)
        entries.append(
            FsEntry(
                name=base,
                path=path,
                kind=kind,
                size_bytes=int(size),
                mode=perm,
                mtime=int(mtime),
            )
        )
    return entries


def sorted_entries(entries: Sequence[FsEntry]) -> list[FsEntry]:
    return sorted(entries, key=lambda entry: entry.name)
