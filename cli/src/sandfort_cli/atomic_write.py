"""Write a stream of text lines to an ``--output`` file: whole or not at all, mode 600.

A regular file (or a path that does not exist yet) is written to a temporary file next to the
final target, which is renamed onto the target only when the stream completes. A symlink is
followed: the file it points to is replaced, the link itself is kept. A target that is not a
regular file (the null device, a fifo, a terminal) is opened and written directly.
"""

import os
import signal
import stat
import tempfile
import threading
from collections.abc import Iterator
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from types import FrameType, TracebackType
from typing import Any, TextIO

import typer

from sandfort_cli.output import CliError

EXPORT_FILE_MODE = 0o600
SIGNAL_EXIT_BASE = 128  # the shell's exit status for a process ended by a signal
HANDLED_SIGNALS = (signal.SIGTERM, signal.SIGINT)
DIRECT_OPEN_FLAGS = os.O_WRONLY | os.O_NOCTTY
ENCODING = "utf-8"


@dataclass(frozen=True)
class Target:
    """Where an export goes: ``path`` as given (for messages), ``final`` with symlinks
    followed, and ``direct`` for a target that is not a regular file."""

    path: Path
    final: Path
    direct: bool = False


def refuse_existing(path: Path) -> CliError:
    return CliError(f"{path} already exists; use --force to overwrite", client=True)


def refuse_appeared(path: Path) -> CliError:
    return CliError(
        f"{path} was created during the export and was not overwritten; "
        "use --force to overwrite"
    )


def cannot_write(path: Path, exc: OSError) -> CliError:
    return CliError(f"cannot write {path}: {exc.strerror or exc}")


def cannot_create_temporary(path: Path, directory: Path, exc: OSError) -> CliError:
    reason = exc.strerror or exc
    return CliError(
        f"cannot write {path}: cannot create a temporary file in {directory}: {reason}"
    )


def plan_target(path: Path, *, force: bool) -> Target:
    """The target of ``path``, checked before any request: an existing regular file needs
    ``force``; a directory is an error; any other existing file is written directly."""
    final = Path(os.path.realpath(path)) if path.is_symlink() else path
    try:
        info = final.stat()
    except FileNotFoundError:
        return Target(path, final)
    except OSError as exc:
        raise cannot_write(path, exc) from None
    if stat.S_ISDIR(info.st_mode):
        raise CliError(f"cannot write {path}: it is a directory", client=True)
    if not stat.S_ISREG(info.st_mode):
        return Target(path, final, direct=True)
    if not force:
        raise refuse_existing(path)
    return Target(path, final)


class SignalCleanup:
    """While active, SIGTERM and SIGINT remove :attr:`temporary` and end the command with
    ``128 + signal``. The previous handlers come back on exit. Off the main thread no handler
    is changed (Python allows signal handlers only there)."""

    def __init__(self) -> None:
        self.temporary: Path | None = None
        self._previous: dict[int, Any] = {}

    def __enter__(self) -> "SignalCleanup":
        if threading.current_thread() is threading.main_thread():
            for signum in HANDLED_SIGNALS:
                self._previous[signum] = signal.signal(signum, self._handle)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        for signum, previous in self._previous.items():
            signal.signal(signum, signal.SIG_DFL if previous is None else previous)
        self._previous = {}

    def remove_temporary(self) -> None:
        if self.temporary is not None:
            with suppress(OSError):
                self.temporary.unlink()

    def _handle(self, signum: int, frame: FrameType | None) -> None:
        self.remove_temporary()
        raise typer.Exit(SIGNAL_EXIT_BASE + signum)


def utf8_size(text: str) -> int:
    return len(text.encode(ENCODING))


def write_lines(handle: TextIO, first: str, rest: Iterator[str]) -> int:
    """Write ``first`` and then each line of ``rest`` as it arrives; the bytes written."""
    handle.write(first)
    written = utf8_size(first)
    for line in rest:
        handle.write(line)
        written += utf8_size(line)
    return written


def open_private(descriptor: int) -> TextIO:
    """A text handle on ``descriptor`` after narrowing its mode to 600 (whatever the umask or
    an old mode); the descriptor is closed when either step fails."""
    try:
        os.fchmod(descriptor, EXPORT_FILE_MODE)
        return os.fdopen(descriptor, "w", encoding=ENCODING, newline="")
    except BaseException:
        os.close(descriptor)
        raise


def publish(temporary: Path, target: Target, *, force: bool) -> None:
    """Rename the finished ``temporary`` onto the final target. Without ``force`` the target
    is checked again first, so a file created during the stream is kept."""
    if not force and os.path.lexists(target.final):
        raise refuse_appeared(target.path)
    os.replace(temporary, target.final)


def write_direct(target: Target, first: str, rest: Iterator[str]) -> int:
    """Write to a target that is not a regular file, in place: no temporary file, no rename."""
    try:
        descriptor = os.open(target.final, DIRECT_OPEN_FLAGS)
        with os.fdopen(descriptor, "w", encoding=ENCODING, newline="") as handle:
            return write_lines(handle, first, rest)
    except OSError as exc:
        raise cannot_write(target.path, exc) from None


def write_replacing(
    target: Target, first: str, rest: Iterator[str], cleanup: SignalCleanup, *, force: bool
) -> int:
    """Stream to a temporary file next to the final target, then publish it."""
    directory = target.final.parent
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{target.final.name}.", suffix=".tmp", dir=directory
        )
    except OSError as exc:
        raise cannot_create_temporary(target.path, directory, exc) from None
    temporary = Path(name)
    cleanup.temporary = temporary
    try:
        with open_private(descriptor) as handle:
            written = write_lines(handle, first, rest)
            handle.flush()
            os.fsync(handle.fileno())
        publish(temporary, target, force=force)
        return written
    except BaseException as exc:
        cleanup.remove_temporary()
        if isinstance(exc, OSError):
            raise cannot_write(target.path, exc) from None
        raise
    finally:
        cleanup.temporary = None  # after a rename the temporary name no longer exists


def write_export(target: Target, lines: Iterator[str], *, force: bool) -> int:
    """Write the export ``lines`` as they arrive to ``target``; the bytes written.

    The first line is awaited before any file is made, so a refused request leaves nothing.
    A failure or a SIGTERM/SIGINT part way removes the temporary file and keeps a file
    already at the target (replaced only with ``force``).
    """
    with SignalCleanup() as cleanup:
        first = next(lines, "")
        if target.direct:
            return write_direct(target, first, lines)
        return write_replacing(target, first, lines, cleanup, force=force)
