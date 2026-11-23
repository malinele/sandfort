"""``sandfort shell``: an interactive pty bridged to the local terminal.

Every terminal control call (termios, tty, signal, select, raw fd i/o) lives behind the small
:class:`TerminalSeam`, which the command receives by injection so tests can substitute it. The
seam's ``restore`` runs in a ``finally`` whatever the bridge does, exactly once per shell.
"""

import os
import select
import shutil
import signal
import sys
import termios
import threading
import tty
from collections.abc import Callable
from typing import Annotated, Any, Protocol

import typer
from sandfort_sdk import PtySession, Sandbox

from sandfort_cli.config import open_client
from sandfort_cli.exec_cmd import stdin_fileno
from sandfort_cli.output import PLATFORM_ERROR_EXIT_CODE, CliError, reject_empty_name
from sandfort_cli.refs import resolve_sandbox_id
from sandfort_cli.sandboxes import JSON_ERROR_EPILOG, SANDBOX_METAVAR, ref_errors

INPUT_POLL_S = 0.1
INPUT_READ_BYTES = 4096
OUTPUT_JOIN_TIMEOUT_S = 2.0
DEFAULT_TERMINAL_SIZE = (80, 24)
NO_TERMINAL = "shell needs an interactive terminal on stdin"


class TerminalSeam(Protocol):
    """Everything the shell needs from the local terminal."""

    def size(self) -> tuple[int, int]:
        """Current ``(rows, cols)``."""
        ...

    def require_interactive(self) -> None:
        """Raise a client :class:`CliError` when stdin is no terminal; runs before any request."""
        ...

    def enter_raw(self) -> None:
        """Remember the current attributes and switch the terminal to raw mode."""
        ...

    def restore(self) -> None:
        """Put back what ``enter_raw`` and ``watch_resize`` changed; safe if nothing changed."""
        ...

    def watch_resize(self, on_resize: Callable[[], None]) -> None:
        """Call ``on_resize`` (from a signal handler: keep it trivial) when the size changes."""
        ...

    def read_input(self, timeout_s: float) -> bytes | None:
        """Bytes typed locally; ``None`` if none within ``timeout_s``, ``b""`` at end of input."""
        ...

    def write_output(self, data: bytes) -> None:
        """Show bytes from the remote terminal."""
        ...


class PosixTerminal:
    """The real terminal: stdin in raw mode, stdout for output, SIGWINCH for resizes."""

    def __init__(self) -> None:
        self._saved: list[Any] | None = None
        self._previous_handler: Any = None
        self._watching = False

    def size(self) -> tuple[int, int]:
        size = shutil.get_terminal_size(fallback=DEFAULT_TERMINAL_SIZE)
        return size.lines, size.columns

    def require_interactive(self) -> None:
        fd = stdin_fileno()
        if fd is None or not os.isatty(fd):
            raise CliError(NO_TERMINAL, client=True)

    def enter_raw(self) -> None:
        fd = sys.stdin.fileno()
        if not os.isatty(fd):  # stdin replaced after the early check: requests already sent
            raise CliError(NO_TERMINAL)
        self._saved = termios.tcgetattr(fd)
        tty.setraw(fd)

    def restore(self) -> None:
        try:
            if self._saved is not None:
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self._saved)
                self._saved = None
        finally:
            if self._watching:
                signal.signal(signal.SIGWINCH, self._previous_handler)
                self._watching = False

    def watch_resize(self, on_resize: Callable[[], None]) -> None:
        self._previous_handler = signal.signal(signal.SIGWINCH, lambda _signum, _frame: on_resize())
        self._watching = True

    def read_input(self, timeout_s: float) -> bytes | None:
        fd = sys.stdin.fileno()
        ready, _, _ = select.select([fd], [], [], timeout_s)
        return os.read(fd, INPUT_READ_BYTES) if ready else None

    def write_output(self, data: bytes) -> None:
        fd = sys.stdout.fileno()
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]


def pump(session: PtySession, terminal: TerminalSeam) -> None:
    """Move bytes both ways until either side ends; re-raise a failure of the output relay."""
    finished = threading.Event()
    resized = threading.Event()
    failures: list[Exception] = []

    def relay_output() -> None:
        try:
            for chunk in session:
                terminal.write_output(chunk)
        except Exception as exc:
            failures.append(exc)
        finally:
            finished.set()

    terminal.watch_resize(resized.set)
    relay = threading.Thread(target=relay_output, name="sandfort-shell-output", daemon=True)
    relay.start()
    try:
        while not finished.is_set():
            if resized.is_set():
                resized.clear()
                session.resize(*terminal.size())
            data = terminal.read_input(INPUT_POLL_S)
            if data is None:
                continue
            if not data:
                break
            session.send_bytes(data)
    finally:
        session.close()  # unblocks the relay's pending receive
        relay.join(OUTPUT_JOIN_TIMEOUT_S)
    if failures:
        raise failures[0]


def run_shell(sandbox: Sandbox, terminal: TerminalSeam) -> int | None:
    """Run the shell until it ends; the remote shell's exit code, or ``None`` if unreported."""
    rows, cols = terminal.size()
    with sandbox.pty.create(rows=rows, cols=cols) as session:
        try:
            terminal.enter_raw()
            pump(session, terminal)
        finally:
            terminal.restore()
    return session.exit_code


def register(app: typer.Typer, terminal: TerminalSeam) -> None:
    """Add the ``shell`` command to ``app``, bound to the injected ``terminal``."""

    @app.command("shell", epilog=JSON_ERROR_EPILOG)
    def shell(
        sandbox_id: Annotated[
            str, typer.Argument(metavar=SANDBOX_METAVAR, help="Sandbox id or name.")
        ],
    ) -> None:
        """Open an interactive shell in a sandbox; exit with the shell's exit code."""
        reject_empty_name(sandbox_id, SANDBOX_METAVAR)
        with ref_errors(PLATFORM_ERROR_EXIT_CODE, sandbox_id):
            terminal.require_interactive()
            with open_client() as client:
                sandbox = client.get(resolve_sandbox_id(client, sandbox_id))
                exit_code = run_shell(sandbox, terminal)
        if exit_code:
            raise typer.Exit(exit_code)
