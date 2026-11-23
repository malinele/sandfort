"""Directory transfers for ``sandfort cp -r``: a gzip tar up, a tar stream down.

Upload packs the local directory into a temporary tar.gz, uploads it under ``/tmp`` in the
sandbox and unpacks it there with ``tar`` (argv only, no shell string built from user paths).
Download streams the SDK's directory tar into a local temporary file and extracts it with the
``data`` filter, after a check that rejects absolute and parent-directory member names.
"""

import os
import tarfile
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from sandfort_sdk import PayloadTooLarge, ReadOnlyPath, Sandbox, SandfortSDKError

from sandfort_cli.output import CliError

CHUNK_BYTES = 64 * 1024
REMOTE_TAR_TEMPLATE = "/tmp/.sandfort-cp-{token}.tar.gz"
EXTRACT_SCRIPT = 'mkdir -p "$1" && tar -xzf "$2" -C "$1"'
EXTRACT_TIMEOUT_S = 600
EXIT_COMMAND_NOT_FOUND = 127
NO_TAR_MESSAGE = "the sandbox image has no tar; install it or copy files one by one"
TOO_LARGE_HINT = "(directory archive too large; copy subdirectories separately)"
EMPTY_REMOTE_MESSAGE = "remote path must not be empty"
READ_ONLY_CODE = "READ_ONLY_PATH"
HTTP_CONFLICT = 409
# What a shell tool says when it writes into a read-only mount (the daemon's wording for a volume
# is the second one); matched case-insensitively at the end of an error line of the extract step.
READ_ONLY_MARKERS = ("read-only file system", "marked read-only")
# The commands of ``EXTRACT_SCRIPT`` that prefix their error lines (``tar: PATH: REASON``).
ERROR_LINE_PREFIXES = ("tar:", "mkdir:", "sh:")
PARTIAL_NOTE = (
    "the transfer stopped at the first read-only path; earlier entries may have been written"
)
NOTHING_WRITTEN_NOTE = "nothing was written"
CURRENT_DIR_PREFIX = "./"
SKIPPED_LINK_TEMPLATE = "skipped {kind} {name} -> {target} (points outside the copied tree)"
ROOT_OWNER = "root"
TAR_ERROR_PREFIX = "tar:"
MKDIR_ERROR_PREFIX = "mkdir:"


@dataclass(frozen=True)
class CopyStats:
    """What a transfer moved: the summed size of the regular files and how many there were,
    with the directories and symlinks counted apart and the warning lines of skipped entries."""

    bytes: int
    files: int
    directories: int = 0
    symlinks: int = 0
    skipped: tuple[str, ...] = ()  # one warning line per entry left out (see download_dir)


def root_owned(info: tarfile.TarInfo) -> tarfile.TarInfo:
    """``info`` owned by root (uid/gid 0, names ``root``): the client's own uid and user name
    must not reach the sandbox. Mode bits and times are kept."""
    info.uid = info.gid = 0
    info.uname = info.gname = ROOT_OWNER
    return info


def points_outside(source: Path, path: Path, linkname: str) -> bool:
    """True when the symlink at ``path`` (target text ``linkname``) is absolute or resolves,
    through any chain of links, to somewhere outside ``source``."""
    if os.path.isabs(linkname):
        return True
    return not Path(os.path.realpath(path)).is_relative_to(os.path.realpath(source))


def build_archive(source: Path, archive: tarfile.TarFile) -> tuple[int, int, list[str]]:
    """Add the contents of ``source`` to ``archive``; return ``(files, bytes, skipped)``.

    ``bytes`` is the sum of the sizes of the regular files added, not the archive size, and
    ``skipped`` has one warning line per symlink left out because it points outside ``source``
    (the download side skips such links the same way).

    Directories, regular files and symlinks that stay inside the tree (stored as links) go in;
    devices, fifos and sockets are skipped. Symlinked directories are never followed.
    """
    files = 0
    total = 0
    skipped: list[str] = []
    for root, dirnames, filenames in os.walk(source, followlinks=False):
        base = Path(root)
        for name in sorted(dirnames) + sorted(filenames):
            path = base / name
            arcname = path.relative_to(source).as_posix()
            info = root_owned(archive.gettarinfo(str(path), arcname=arcname))
            if not (info.isreg() or info.isdir() or info.issym()):
                continue
            if info.issym() and points_outside(source, path, info.linkname):
                skipped.append(
                    SKIPPED_LINK_TEMPLATE.format(kind="symlink", name=arcname, target=info.linkname)
                )
                continue
            if info.isreg():
                with path.open("rb") as handle:
                    archive.addfile(info, handle)
                files += 1
                total += info.size
            else:
                archive.addfile(info)
    return files, total, skipped


def _remote_dest(dest: str) -> str:
    # The cp entry point rejects an empty path (as a client error) before any request; this
    # guard runs after the sandbox lookup, so it carries no client marker.
    if not dest:
        raise CliError(EMPTY_REMOTE_MESSAGE)
    return f"./{dest}" if dest.startswith("-") else dest


def read_only_error(
    dest: str, *, partial: bool = True, request_id: str | None = None
) -> ReadOnlyPath:
    """The error a recursive copy raises for a write into a read-only mount (code
    READ_ONLY_PATH, as the single-file copy shows), carrying the request id of the refusing
    call when it is known. ``partial`` says that entries were sent before the refusal, so the
    extract may have written some of them; otherwise nothing was written, as for one file."""
    note = f": {PARTIAL_NOTE}" if partial else f"; {NOTHING_WRITTEN_NOTE}"
    return ReadOnlyPath(
        f"{dest} is on a read-only mount{note}",
        code=READ_ONLY_CODE,
        status_code=HTTP_CONFLICT,
        details={"path": dest},
        request_id=request_id,
    )


def _is_read_only_line(line: str) -> bool:
    lowered = line.strip().lower()
    return lowered.startswith(ERROR_LINE_PREFIXES) and lowered.endswith(READ_ONLY_MARKERS)


def _is_read_only_failure(stderr: str) -> bool:
    """True when an error line of the extract step (stderr, a command prefix, the reason last)
    names a read-only mount; the marker inside a file name or on stdout does not count."""
    return any(_is_read_only_line(line) for line in stderr.splitlines())


def _refused_entry(line: str) -> str:
    """The archive path a ``tar: PATH: REASON`` line names, without a leading ``./``."""
    body = line.strip()[len(TAR_ERROR_PREFIX) :].strip()
    path = body.split(": ", 1)[0]
    return path.removeprefix(CURRENT_DIR_PREFIX).rstrip("/")


def entries_sent_before_refusal(stderr: str, names: list[str]) -> bool:
    """True when the extract may already have written entries when it hit the read-only path.

    Nothing was written when ``mkdir`` could not create the target, or when ``tar`` refused the
    very first archive member with no other error before it. Anything this cannot tell (an
    unknown member, an earlier error line, another tool) counts as possibly written.
    """
    lines = [line for line in stderr.splitlines() if line.strip()]
    first = next((i for i, line in enumerate(lines) if _is_read_only_line(line)), None)
    if first is None or first > 0:
        return True
    lowered = lines[first].strip().lower()
    if lowered.startswith(MKDIR_ERROR_PREFIX):
        return False
    if not lowered.startswith(TAR_ERROR_PREFIX):
        return True
    entry = _refused_entry(lines[first])
    return entry not in names or names.index(entry) > 0


def _extract_remote(sandbox: Sandbox, dest: str, remote_tar: str, names: list[str]) -> None:
    argv = ["sh", "-c", EXTRACT_SCRIPT, "sh", dest, remote_tar]
    result = sandbox.process_exec(argv=argv, timeout_s=EXTRACT_TIMEOUT_S)
    if result.exit_code == EXIT_COMMAND_NOT_FOUND:
        raise CliError(NO_TAR_MESSAGE)
    if result.timed_out:
        raise CliError("extracting the archive in the sandbox timed out")
    if result.exit_code != 0:
        if _is_read_only_failure(result.stderr):
            partial = entries_sent_before_refusal(result.stderr, names)
            raise read_only_error(dest, partial=partial, request_id=result.request_id)
        detail = (result.stderr or result.stdout).strip()
        raise CliError(f"extracting the archive failed (exit {result.exit_code}): {detail}")


def _remove_remote(sandbox: Sandbox, remote_tar: str) -> None:
    try:
        sandbox.fs.delete(remote_tar)
    except SandfortSDKError:
        pass  # best effort: the copy outcome is already decided


def upload_dir(sandbox: Sandbox, source: Path, dest: str) -> CopyStats:
    """Pack ``source`` and extract its contents into ``dest`` (created when missing)."""
    target = _remote_dest(dest)
    remote_tar = REMOTE_TAR_TEMPLATE.format(token=uuid.uuid4().hex)
    with tempfile.TemporaryFile(suffix=".tar.gz") as scratch:
        with tarfile.open(fileobj=scratch, mode="w:gz") as archive:
            files, file_bytes, skipped = build_archive(source, archive)
            members = archive.getmembers()
            names = [member.name for member in members]
        size = scratch.tell()
        scratch.seek(0)
        try:
            sandbox.fs.upload_file(remote_tar, scratch, size_bytes=size, chunk_size=CHUNK_BYTES)
            _extract_remote(sandbox, target, remote_tar, names)
        except PayloadTooLarge as exc:
            raise CliError(f"{exc.message} {TOO_LARGE_HINT}") from exc
        finally:
            _remove_remote(sandbox, remote_tar)
    return CopyStats(
        bytes=file_bytes,
        files=files,
        directories=sum(1 for member in members if member.isdir()),
        symlinks=sum(1 for member in members if member.issym()),
        skipped=tuple(skipped),
    )


def check_member_names(members: list[tarfile.TarInfo]) -> None:
    """Reject absolute names and ``..`` components before anything is written."""
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise CliError(f"unsafe path in archive: {member.name!r}")


def strip_root(members: list[tarfile.TarInfo], root: str) -> list[tarfile.TarInfo]:
    """The members without their leading ``root`` component, or all of them unchanged.

    Stripping happens only when ``root`` is non-empty and every member starts with that single
    top-level name; the root directory entry itself is dropped. A hard link's target is an
    archive member name, so it loses the component too.
    """
    split = [PurePosixPath(member.name).parts for member in members]
    if not root or not members or any(parts[:1] != (root,) for parts in split):
        return members
    stripped: list[tarfile.TarInfo] = []
    for member, parts in zip(members, split, strict=True):
        if len(parts) == 1:
            continue
        link = PurePosixPath(member.linkname).parts
        rooted_link = member.islnk() and link[:1] == (root,)
        linkname = "/".join(link[1:]) if rooted_link else member.linkname
        stripped.append(member.replace(name="/".join(parts[1:]), linkname=linkname, deep=False))
    return stripped


def existing_ancestor(path: Path) -> Path | None:
    """The nearest of ``path`` and its parents that exists (``None`` when none does)."""
    for candidate in (path, *path.parents):
        if candidate.exists():
            return candidate
    return None


def dir_destination_problem(dest: Path) -> str | None:
    """Why ``dest`` cannot become the directory a recursive download extracts into (it, or the
    nearest of its parents that exists, is not a directory), or None."""
    found = existing_ancestor(dest)
    if found is not None and not found.is_dir():
        return f"destination {found} is not a directory"
    return None


def make_destination(dest: Path) -> None:
    """Create ``dest`` (and its parents); a file in the way is the clean "is not a directory"
    error, not the operating system's errno text (the path may change after the early check)."""
    try:
        dest.mkdir(parents=True, exist_ok=True)
    except (FileExistsError, NotADirectoryError):
        problem = dir_destination_problem(dest) or f"destination {dest} is not a directory"
        raise CliError(problem) from None


def extract_members(
    archive: tarfile.TarFile, members: list[tarfile.TarInfo], dest: Path, prefix: str
) -> tuple[list[tarfile.TarInfo], list[str]]:
    """Extract ``members`` into ``dest`` with the ``data`` filter; a link whose target is
    absolute or leaves ``dest`` is skipped (never written) instead of failing the copy.

    Returns the members written and one warning line per skipped link, named as the remote
    tree names it (``prefix`` puts back a stripped root).
    """
    written: dict[str, tarfile.TarInfo] = {}  # by name: tarfile filters a directory twice
    skipped: dict[str, str] = {}

    def keep_inside(member: tarfile.TarInfo, path: str) -> tarfile.TarInfo | None:
        try:
            checked = tarfile.data_filter(member, path)
        except (tarfile.AbsoluteLinkError, tarfile.LinkOutsideDestinationError):
            skipped[member.name] = SKIPPED_LINK_TEMPLATE.format(
                kind="symlink" if member.issym() else "link",
                name=f"{prefix}{member.name}",
                target=member.linkname,
            )
            return None
        if checked is not None:
            written[member.name] = checked
        return checked

    archive.extractall(dest, members=members, filter=keep_inside)
    return list(written.values()), list(skipped.values())


def download_dir(sandbox: Sandbox, remote: str, dest: Path) -> CopyStats:
    """Stream the remote directory as a tar and extract its contents into ``dest``.

    ``dest`` is created if missing. A trailing slash on ``remote`` is ignored. When the tar is
    rooted at the directory's own name, that name is stripped so ``dest`` receives the contents,
    as the upload direction does.
    """
    # The cp entry point rejects these (as client errors) before any request; this guard runs
    # after the sandbox lookup, so it carries no client marker.
    if not remote:
        raise CliError(EMPTY_REMOTE_MESSAGE)
    problem = dir_destination_problem(dest)
    if problem is not None:
        raise CliError(problem)
    remote = remote.rstrip("/") or "/"
    with tempfile.TemporaryFile(suffix=".tar") as scratch:
        with sandbox.fs.download_dir(remote, chunk_size=CHUNK_BYTES) as stream:
            for chunk in stream:
                scratch.write(chunk)
        scratch.seek(0)
        try:
            with tarfile.open(fileobj=scratch, mode="r:") as archive:
                listed = archive.getmembers()
                check_member_names(listed)
                members = strip_root(listed, PurePosixPath(remote).name)
                prefix = f"{PurePosixPath(remote).name}/" if members is not listed else ""
                make_destination(dest)
                extracted, skipped = extract_members(archive, members, dest, prefix)
        except (tarfile.TarError, OSError) as exc:
            raise CliError(f"cannot extract {remote} into {dest}: {exc}") from exc
    return CopyStats(
        bytes=sum(m.size for m in extracted if m.isfile()),
        files=sum(1 for m in extracted if m.isfile() or m.islnk()),
        directories=sum(1 for m in extracted if m.isdir()),
        symlinks=sum(1 for m in extracted if m.issym()),
        skipped=tuple(skipped),
    )
