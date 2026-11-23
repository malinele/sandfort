"""``sandfort cp``: scp-style copy between a local path and ``<sandbox-id>:<remote-path>``.

Both directions stream through the SDK fs facade in bounded chunks, so a file is never held
whole in memory. Downloads land in a ``.part`` sibling that replaces the target only on success.
"""

import os
import stat
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Annotated

import typer
from sandfort_sdk import InvalidResponseError, NotFound, Sandbox
from sandfort_sdk import fs as sdk_fs

try:  # typer 0.27+ vendors click; its UsageError is not the installed click's class
    from typer._click import exceptions as click_exceptions
except ImportError:  # pragma: no cover - older typer builds on the installed click
    from click import exceptions as click_exceptions  # type: ignore[no-redef]

from sandfort_cli import cp_dir
from sandfort_cli.config import open_client
from sandfort_cli.cp_dir import (
    EMPTY_REMOTE_MESSAGE,
    CopyStats,
    dir_destination_problem,
    existing_ancestor,
)
from sandfort_cli.output import (
    PLATFORM_ERROR_EXIT_CODE,
    CliError,
    app_state,
    cli_errors,
    reject_empty_name,
    render_message,
)
from sandfort_cli.refs import resolve_sandbox_id
from sandfort_cli.sandboxes import SANDBOX_METAVAR, ref_errors

# The exit status of every CLI usage error (bad local input found before any request is sent).
USAGE_ERROR_EXIT_CODE = 2
CHUNK_BYTES = 64 * 1024
PARTIAL_SUFFIX = ".part"
ENDPOINT_ERROR = "exactly one of source and destination must be <sandbox-id>:<path>"
SOURCE_METAVAR = "<source>"
DESTINATION_METAVAR = "<destination>"
DIRECTORY_HINT = "; use -r for directories"
# How the SDK's file download says the path is a directory (it names its own method).
SDK_DIRECTORY_PHRASE = "use download_dir"
HTTP_NOT_FOUND = 404
# The server's not-found text for a sandbox (as opposed to a path): "sandbox <id> not found".
SANDBOX_NOT_FOUND_PREFIX = "sandbox "
# A remote ``~`` is never expanded (no shell sees the path); the example home is root's.
HOME_PREFIX = "~"
EXAMPLE_HOME = "/root"


@dataclass(frozen=True)
class RemotePath:
    sandbox_id: str
    path: str


def parse_remote(arg: str) -> RemotePath | None:
    """``id:path`` is remote when a colon precedes any slash (scp rule); else it is local."""
    prefix, colon, path = arg.partition(":")
    if not colon or not prefix or "/" in prefix:
        return None
    return RemotePath(prefix, path)


def upload_problem(
    local: Path, remote: str, *, recursive: bool = False, typed: str | None = None
) -> str | None:
    """Why this upload cannot start (missing local source, empty remote path), or None.

    ``typed`` is the source as the person wrote it (``./file``), which a :class:`Path` does not
    keep; it is what a missing-file message names.
    """
    named = local if typed is None else typed
    try:
        info = local.stat()  # the one stat: the kind, the size and a file deleted since
    except OSError as error:
        if isinstance(error, FileNotFoundError | NotADirectoryError):
            if not local.is_symlink():
                return f"no such file: {named}"
            return f"{local} is not a regular file"  # a broken link
        return f"cannot read {named}: {error.strerror or error}"
    is_file = stat.S_ISREG(info.st_mode)
    if not (is_file or (recursive and stat.S_ISDIR(info.st_mode))):
        hint = DIRECTORY_HINT if stat.S_ISDIR(info.st_mode) else ""
        return f"{local} is not a regular file{hint}"
    if not remote:
        return EMPTY_REMOTE_MESSAGE
    if is_file and info.st_size > sdk_fs.UPLOAD_LIMIT_BYTES:
        return sdk_fs.upload_limit_message(sdk_fs.UPLOAD_LIMIT_BYTES, info.st_size)
    return None


def check_upload(
    local: Path, remote: str, *, recursive: bool = False, typed: str | None = None
) -> None:
    """Reject a missing local source or an empty remote path before any request is sent."""
    problem = upload_problem(local, remote, recursive=recursive, typed=typed)
    if problem is not None:
        raise CliError(problem, client=True)


def upload(sandbox: Sandbox, local: Path, remote: str) -> int:
    # ``_copy`` already ran ``check_upload`` before any request; this repeat runs after the
    # sandbox lookup, so it raises without the client marker.
    problem = upload_problem(local, remote)
    if problem is not None:
        raise CliError(problem)
    target = f"{remote}{local.name}" if remote.endswith("/") else remote
    with local.open("rb") as handle:
        return sandbox.fs.upload_file(target, handle, chunk_size=CHUNK_BYTES).size_bytes


def download_problem(local: Path) -> str | None:
    """Why a file download cannot land at ``local`` (its directory is missing, is a file or
    is not writable), or None."""
    directory = local if local.is_dir() else local.parent
    if not directory.is_dir():
        found = existing_ancestor(directory)
        if found is not None and not found.is_dir():
            return f"destination {found} is not a directory"
        return f"destination directory {directory} does not exist"
    if not os.access(directory, os.W_OK | os.X_OK):
        return f"destination directory {directory} is not writable"
    return None


def check_download(local: Path) -> None:
    """Reject an unusable local destination before any request is sent."""
    problem = download_problem(local)
    if problem is not None:
        raise CliError(problem, client=True)


def download(sandbox: Sandbox, remote: str, local: Path) -> int:
    target = local / PurePosixPath(remote).name if local.is_dir() else local
    staging = target.with_name(target.name + PARTIAL_SUFFIX)
    written = 0
    try:
        with sandbox.fs.download_file(remote, chunk_size=CHUNK_BYTES) as stream:
            with staging.open("wb") as handle:
                for chunk in stream:
                    handle.write(chunk)
                    written += len(chunk)
        staging.replace(target)
    except OSError as exc:  # a local write failed after the download started
        with suppress(OSError):
            staging.unlink(missing_ok=True)
        raise CliError(f"cannot write {target}: {exc.strerror or exc}") from None
    except InvalidResponseError as exc:
        staging.unlink(missing_ok=True)
        if SDK_DIRECTORY_PHRASE in str(exc):  # the server sent a tar: the source is a directory
            raise CliError(f"{remote} is a directory{DIRECTORY_HINT}") from None
        raise
    except BaseException:
        staging.unlink(missing_ok=True)
        raise
    return written


def check_download_source(remote: str, local: Path, *, recursive: bool = False) -> None:
    """Reject an empty remote path or an unusable local destination before any request."""
    if not remote:
        raise CliError(EMPTY_REMOTE_MESSAGE, client=True)
    problem = dir_destination_problem(local) if recursive else download_problem(local)
    if problem is not None:
        raise CliError(problem, client=True)


def check_arguments(source: str, destination: str) -> None:
    """The usage errors of ``cp`` (exit 2, nothing sent): not exactly one ``<sandbox>:<path>``
    endpoint, a blank sandbox reference, a blank remote path or a blank local path."""
    src, dst = parse_remote(source), parse_remote(destination)
    if (src is None) == (dst is None):
        raise click_exceptions.UsageError(ENDPOINT_ERROR)
    remote = src if src is not None else dst
    if remote is not None:
        reject_empty_name(remote.sandbox_id, SANDBOX_METAVAR)
    local, metavar = (destination, DESTINATION_METAVAR) if dst is None else (source, SOURCE_METAVAR)
    remote_metavar = SOURCE_METAVAR if dst is None else DESTINATION_METAVAR
    reject_empty_name(local, metavar)
    if remote is not None:
        reject_empty_name(remote.path, remote_metavar)


def home_example(path: str) -> str:
    """An absolute stand-in for a ``~`` path: ``~`` and ``~/x`` under ``/root``; ``~user/x``
    as ``/root/...``, since the user's real home is not known here."""
    if path == HOME_PREFIX or path.startswith(f"{HOME_PREFIX}/"):
        return f"{EXAMPLE_HOME}{path[len(HOME_PREFIX) :]}"
    return f"{EXAMPLE_HOME}/..."


def check_remote_absolute(arg: str, remote: RemotePath) -> None:
    """Reject a relative remote path before any request, naming the argument rewritten
    (``arg`` is ``<sandbox>:<path>`` exactly as typed): with a leading slash, or for a ``~``
    path, which is never expanded, with an absolute home path such as ``/root/...``."""
    if remote.path.startswith("/"):
        return
    prefix = arg[: len(arg) - len(remote.path)]
    if remote.path.startswith(HOME_PREFIX):
        raise CliError(
            "remote path must be absolute (start with a slash): ~ (the home directory of the "
            "sandbox user) is not expanded; write the absolute home path, for example "
            f"{prefix}{home_example(remote.path)}",
            client=True,
        )
    raise CliError(
        f"remote path must be absolute (start with a slash): write {prefix}/{remote.path}; "
        "the sandbox working directory for exec is the root directory (/), so a relative "
        "path has no anchor",
        client=True,
    )


def name_missing_remote(exc: NotFound, arg: str, remote: RemotePath) -> NotFound:
    """``exc`` for a missing remote file, with ``arg`` (the reference as typed) in front of the
    message and the remote path in the details. Any other not-found answer is returned as is
    (a sandbox that disappeared between the lookup and the download)."""
    if exc.status_code != HTTP_NOT_FOUND or exc.message.startswith(SANDBOX_NOT_FOUND_PREFIX):
        return exc
    return NotFound(
        f"{arg}: {exc.message}",
        code=exc.code,
        status_code=exc.status_code,
        details={**exc.details, "path": remote.path},
        request_id=exc.request_id,
    )


def _download(
    sandbox: Sandbox, source: str, src: RemotePath, destination: str, *, recursive: bool
) -> CopyStats:
    try:
        if recursive:
            return cp_dir.download_dir(sandbox, src.path, Path(destination))
        return CopyStats(download(sandbox, src.path, Path(destination)), 1)
    except NotFound as exc:
        raise name_missing_remote(exc, source, src) from None


def check_copy(source: str, destination: str, *, recursive: bool = False) -> None:
    """The client-side checks of a copy (a usage error, exit 2): nothing has been sent yet."""
    src, dst = parse_remote(source), parse_remote(destination)
    if (src is None) == (dst is None):
        raise CliError(ENDPOINT_ERROR, client=True)
    if dst is not None:
        check_upload(Path(source), dst.path, recursive=recursive, typed=source)
        check_remote_absolute(destination, dst)
    elif src is not None:
        check_download_source(src.path, Path(destination), recursive=recursive)
        check_remote_absolute(source, src)


def _copy(source: str, destination: str, *, recursive: bool = False) -> CopyStats:
    src, dst = parse_remote(source), parse_remote(destination)
    with open_client() as client:
        if dst is not None:
            sandbox = client.get(resolve_sandbox_id(client, dst.sandbox_id))
            local = Path(source)
            if recursive and local.is_dir():
                return cp_dir.upload_dir(sandbox, local, dst.path)
            return CopyStats(upload(sandbox, local, dst.path), 1)
        if src is not None:
            sandbox = client.get(resolve_sandbox_id(client, src.sandbox_id))
            return _download(sandbox, source, src, destination, recursive=recursive)
    raise CliError(ENDPOINT_ERROR)  # unreachable: exactly one side is remote


def plural(count: int, noun: str, many: str | None = None) -> str:
    return f"{count} {noun if count == 1 else many or noun + 's'}"


def summary_parts(stats: CopyStats) -> str:
    """``1 file``, then directories and symlinks when there are any, then what was skipped."""
    parts = [plural(stats.files, "file")]
    if stats.directories:
        parts.append(plural(stats.directories, "directory", "directories"))
    if stats.symlinks:
        parts.append(plural(stats.symlinks, "symlink"))
    text = ", ".join(parts)
    if stats.skipped:
        text += f"; skipped {plural(len(stats.skipped), 'symlink')}"
    return text


def cp_command(
    ctx: typer.Context,
    source: Annotated[
        str,
        typer.Argument(metavar=SOURCE_METAVAR, help="Local path or <sandbox-id-or-name>:<path>."),
    ],
    destination: Annotated[
        str,
        typer.Argument(
            metavar=DESTINATION_METAVAR, help="Local path or <sandbox-id-or-name>:<path>."
        ),
    ],
    recursive: Annotated[
        bool,
        typer.Option(
            "--recursive",
            "-r",
            help="Copy a directory. Its CONTENTS are extracted into the target path, which is "
            "created if missing (local mydir to sb:/x puts mydir/a at /x/a). Upload needs "
            "tar in the sandbox; the archive is capped at 256 MiB.",
        ),
    ] = False,
) -> None:
    """Copy a file (or with -r a directory) between this machine and a sandbox."""
    check_arguments(source, destination)
    remote = parse_remote(source) or parse_remote(destination)
    sandbox_ref = remote.sandbox_id if remote is not None else None
    with cli_errors(USAGE_ERROR_EXIT_CODE):
        check_copy(source, destination, recursive=recursive)
    with ref_errors(PLATFORM_ERROR_EXIT_CODE, sandbox_ref):
        stats = _copy(source, destination, recursive=recursive)
        payload = {
            "source": source,
            "destination": destination,
            "bytes": stats.bytes,
            "files": stats.files,
            "directories": stats.directories,
            "symlinks": stats.symlinks,
            "skipped": list(stats.skipped),
        }
        for warning in stats.skipped:
            typer.echo(warning, err=True)
        size = f"{stats.bytes} {'byte' if stats.bytes == 1 else 'bytes'}"
        message = f"copied {size} ({summary_parts(stats)}): {source} -> {destination}"
        render_message(app_state(ctx), message, payload)
