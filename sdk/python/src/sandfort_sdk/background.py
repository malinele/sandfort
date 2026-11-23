"""One-call background commands: ``sandbox.process.start(...)`` returns a handle.

The handle bundles the process facade with the session and command ids, so a caller does not
thread those ids through ``get_command`` / ``get_command_logs`` / ``follow_logs`` /
``kill_command`` by hand. Leaving a ``with`` / ``async with`` block kills the command if it is
still running (best effort: errors are ignored).
"""

import asyncio
import contextlib
import time
from types import TracebackType
from typing import TYPE_CHECKING, Self

from sandfort_sdk._requests import DEFAULT_EXEC_TIMEOUT_S
from sandfort_sdk.exceptions import InvalidResponseError, SandboxTimeoutError
from sandfort_sdk.models import COMMAND_RUNNING, CommandInfo, LogPage, SessionExecResult

if TYPE_CHECKING:
    from sandfort_sdk.process import AsyncLogStream, AsyncProcess, LogStream, Process

DEFAULT_POLL_INTERVAL_S = 0.5


def _check_start_args(
    cwd: str | None, env: dict[str, str] | None, session_id: str | None
) -> None:
    if session_id is not None and (cwd is not None or env is not None):
        raise ValueError("cwd and env apply to a new session; they cannot be set with session_id")


def _check_wait_args(timeout_s: float | None, poll_interval_s: float) -> None:
    if poll_interval_s <= 0:
        raise ValueError("poll_interval_s must be positive")
    if timeout_s is not None and timeout_s < 0:
        raise ValueError("timeout_s must not be negative")


def _started_command(result: SessionExecResult) -> CommandInfo:
    if result.command is None:
        raise InvalidResponseError("async session command reply carries no command")
    return result.command


def _wait_timeout(command_id: str, timeout_s: float | None, last: CommandInfo) -> Exception:
    message = f"command {command_id} still {last.state} after {timeout_s} s"
    return SandboxTimeoutError(message, state=last.state)


def _remaining(deadline: float | None, poll_interval_s: float) -> float | None:
    """Seconds to sleep before the next poll; ``None`` once the deadline has passed."""
    if deadline is None:
        return poll_interval_s
    left = deadline - time.monotonic()
    return None if left <= 0 else min(poll_interval_s, left)


class BackgroundCommand:
    """Handle of an async session command started with :meth:`Process.start`."""

    __slots__ = ("_command_id", "_process", "_session_id")

    def __init__(self, process: "Process", session_id: str, command_id: str) -> None:
        self._process = process
        self._session_id = session_id
        self._command_id = command_id

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def command_id(self) -> str:
        return self._command_id

    def info(self) -> CommandInfo:
        return self._process.get_command(self._session_id, self._command_id)

    def logs(self, offset: int = 0) -> LogPage:
        return self._process.get_command_logs(self._session_id, self._command_id, offset=offset)

    def follow(self, offset: int = 0) -> "LogStream":
        return self._process.follow_logs(self._session_id, self._command_id, offset=offset)

    def kill(self) -> CommandInfo:
        return self._process.kill_command(self._session_id, self._command_id)

    def wait(
        self, timeout_s: float | None = None, poll_interval_s: float = DEFAULT_POLL_INTERVAL_S
    ) -> CommandInfo:
        """Poll until the command is no longer ``running``; ``SandboxTimeoutError`` on timeout."""
        _check_wait_args(timeout_s, poll_interval_s)
        deadline = None if timeout_s is None else time.monotonic() + timeout_s
        while True:
            current = self.info()
            if current.state != COMMAND_RUNNING:
                return current
            pause = _remaining(deadline, poll_interval_s)
            if pause is None:
                raise _wait_timeout(self._command_id, timeout_s, current)
            time.sleep(pause)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        with contextlib.suppress(Exception):
            if self.info().state == COMMAND_RUNNING:
                self.kill()


class AsyncBackgroundCommand:
    """Async counterpart of :class:`BackgroundCommand`."""

    __slots__ = ("_command_id", "_process", "_session_id")

    def __init__(self, process: "AsyncProcess", session_id: str, command_id: str) -> None:
        self._process = process
        self._session_id = session_id
        self._command_id = command_id

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def command_id(self) -> str:
        return self._command_id

    async def info(self) -> CommandInfo:
        return await self._process.get_command(self._session_id, self._command_id)

    async def logs(self, offset: int = 0) -> LogPage:
        return await self._process.get_command_logs(
            self._session_id, self._command_id, offset=offset
        )

    async def follow(self, offset: int = 0) -> "AsyncLogStream":
        return await self._process.follow_logs(self._session_id, self._command_id, offset=offset)

    async def kill(self) -> CommandInfo:
        return await self._process.kill_command(self._session_id, self._command_id)

    async def wait(
        self, timeout_s: float | None = None, poll_interval_s: float = DEFAULT_POLL_INTERVAL_S
    ) -> CommandInfo:
        """Poll until the command is no longer ``running``; ``SandboxTimeoutError`` on timeout."""
        _check_wait_args(timeout_s, poll_interval_s)
        deadline = None if timeout_s is None else time.monotonic() + timeout_s
        while True:
            current = await self.info()
            if current.state != COMMAND_RUNNING:
                return current
            pause = _remaining(deadline, poll_interval_s)
            if pause is None:
                raise _wait_timeout(self._command_id, timeout_s, current)
            await asyncio.sleep(pause)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        with contextlib.suppress(Exception):
            if (await self.info()).state == COMMAND_RUNNING:
                await self.kill()


def start_background(
    process: "Process",
    command: str,
    *,
    cwd: str | None,
    env: dict[str, str] | None,
    timeout_s: int | None,
    session_id: str | None,
) -> BackgroundCommand:
    """Create a session when ``session_id`` is ``None``, run ``command`` async, return a handle."""
    _check_start_args(cwd, env, session_id)
    if session_id is None:
        session_id = process.create_session(cwd=cwd, env=env).id
    budget = DEFAULT_EXEC_TIMEOUT_S if timeout_s is None else timeout_s
    result = process.execute_session_command(session_id, command, run_async=True, timeout_s=budget)
    return BackgroundCommand(process, session_id, _started_command(result).id)


async def start_background_async(
    process: "AsyncProcess",
    command: str,
    *,
    cwd: str | None,
    env: dict[str, str] | None,
    timeout_s: int | None,
    session_id: str | None,
) -> AsyncBackgroundCommand:
    """Async twin of :func:`start_background`."""
    _check_start_args(cwd, env, session_id)
    if session_id is None:
        session_id = (await process.create_session(cwd=cwd, env=env)).id
    budget = DEFAULT_EXEC_TIMEOUT_S if timeout_s is None else timeout_s
    result = await process.execute_session_command(
        session_id, command, run_async=True, timeout_s=budget
    )
    return AsyncBackgroundCommand(process, session_id, _started_command(result).id)
