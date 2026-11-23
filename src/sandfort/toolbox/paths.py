"""Validation of sandbox-side paths (paths inside the container, never host paths).

A valid path is absolute, posix, free of NUL bytes and empty segments, and stays inside
``root`` after ``.``/``..`` segments are resolved. The normalized form is returned.
"""

import posixpath

from sandfort.errors import Unprocessable

MAX_PATH_BYTES = 4096
ROOT = "/"
# Kernel pseudo-filesystems: the archive upload (and mkdir/mv) cannot keep a file there. The
# whole of /dev is refused, /dev/shm included: it is a tmpfs, where ``docker cp`` drops the
# file silently exactly as under /dev (checked against a running container, round 63).
PSEUDO_FILESYSTEMS = ("/proc", "/sys", "/dev")


class PseudoFilesystemPath(Unprocessable):
    """422 VALIDATION_ERROR: a write target lies under a kernel pseudo-filesystem."""

    code = "VALIDATION_ERROR"


def _segments(path: str) -> list[str]:
    """Resolve ``.`` and ``..``; a ``..`` that climbs above ``/`` is a traversal."""
    resolved: list[str] = []
    for segment in path[1:].split("/"):
        if segment == ".":
            continue
        if segment == "..":
            if not resolved:
                raise Unprocessable("path escapes the filesystem root", details={"path": path})
            resolved.pop()
            continue
        resolved.append(segment)
    return resolved


def normalize_root(root: str) -> str:
    if not root.startswith("/") or "\x00" in root:
        raise Unprocessable("root must be an absolute path without NUL bytes")
    return posixpath.normpath(root) if root != ROOT else ROOT


def normalize_path(raw: str, *, root: str = ROOT) -> str:
    """Return the normalized absolute form of ``raw`` or raise ``Unprocessable``."""
    if not raw:
        raise Unprocessable("path must be a non-empty string")
    if "\x00" in raw:
        raise Unprocessable("path must not contain NUL bytes")
    if len(raw.encode(errors="surrogatepass")) > MAX_PATH_BYTES:
        raise Unprocessable(f"path is longer than {MAX_PATH_BYTES} bytes")
    if not raw.startswith("/"):
        raise Unprocessable("path must be absolute", details={"path": raw})
    if raw != ROOT and (raw.endswith("/") or "//" in raw):
        raise Unprocessable("path must not contain empty segments", details={"path": raw})
    normalized = "/" + "/".join(_segments(raw))
    base = normalize_root(root)
    if base != ROOT and normalized != base and not normalized.startswith(base + "/"):
        raise Unprocessable("path escapes the allowed root", details={"path": raw, "root": base})
    return normalized


def split_parent(path: str) -> tuple[str, str]:
    """``(parent directory, final name)`` of a normalized path other than ``/``."""
    if path == ROOT:
        raise Unprocessable("the filesystem root has no parent")
    parent, name = posixpath.split(path)
    return parent or ROOT, name


def under_pseudo_filesystem(path: str) -> bool:
    """True when a normalized path is /proc, /sys, /dev or lies under one of them."""
    return any(path == root or path.startswith(root + "/") for root in PSEUDO_FILESYSTEMS)


def refuse_pseudo_filesystem(path: str) -> None:
    """Raise ``PseudoFilesystemPath`` when a normalized write target is under /proc, /sys or /dev.

    Reads (stat, list, download) are not checked: they work there. Call this before any driver
    call so a write that would be dropped is never answered as a success.
    """
    for root in PSEUDO_FILESYSTEMS:
        if path == root or path.startswith(root + "/"):
            raise PseudoFilesystemPath(
                f"cannot write to {path}: {root} is a kernel pseudo-filesystem",
                details={"path": path, "pseudo_filesystem": root},
            )
