"""Process toolbox facade (``sandbox.process``): one-shot exec, code-run and exec sessions.

``follow_logs`` decodes the server-sent-event stream into ordered :class:`LogEvent` values
ending with the ``exit`` event; closing it early releases the HTTP response at once.
"""

import dataclasses
import json
from collections.abc import AsyncGenerator, Generator, Iterator, Sequence
from dataclasses import dataclass
from types import TracebackType
from typing import Self

import httpx

from sandfort_sdk._requests import (
    DEFAULT_EXEC_TIMEOUT_S,
    code_run_body,
    command_path,
    deletable_session_path,
    exec_body,
    exec_idempotency_headers,
    idempotency_headers,
    log_params,
    session_command_body,
    session_create_body,
    session_path,
    toolbox_path,
)
from sandfort_sdk._transport import AsyncTransport, Reply, SyncTransport, stream_read_error
from sandfort_sdk.background import (
    AsyncBackgroundCommand,
    BackgroundCommand,
    start_background,
    start_background_async,
)
from sandfort_sdk.exceptions import InvalidResponseError, TransportError
from sandfort_sdk.models import (
    STREAM_EXIT,
    CommandInfo,
    ExecResult,
    LogEvent,
    LogPage,
    SessionExecResult,
    SessionInfo,
    _as_dict,
    _as_list,
)

# The server emits a keepalive comment every 15 s; reads must outlast one idle gap.
FOLLOW_IDLE_S = 15.0
OUTPUT_STREAMS = frozenset({"stdout", "stderr"})
_SSE_HEADERS = {"Accept": "text/event-stream"}
_STREAM_ENDED = "log stream ended before the exit event"


@dataclass(frozen=True, slots=True)
class SseFrame:
    event: str
    data: str
    id: str | None = None


class SseDecoder:
    """Incremental server-sent-events decoder over raw body bytes.

    Lines are split on ``\\n`` only (a trailing ``\\r`` is dropped): JSON payloads may hold
    U+2028 or U+0085, which a generic ``splitlines`` would wrongly treat as line breaks.
    Comment lines (keepalives) are skipped; a blank line dispatches the pending frame.
    """

    def __init__(self) -> None:
        self._buffer = b""
        self._event: str | None = None
        self._id: str | None = None
        self._data: list[str] = []

    def feed(self, chunk: bytes) -> list[SseFrame]:
        lines = (self._buffer + chunk).split(b"\n")
        self._buffer = lines.pop()  # the unterminated tail waits for the next chunk
        frames: list[SseFrame] = []
        for raw in lines:
            frame = self._line(raw.removesuffix(b"\r").decode("utf-8", errors="replace"))
            if frame is not None:
                frames.append(frame)
        return frames

    def _line(self, line: str) -> SseFrame | None:
        if not line:
            return self._dispatch()
        if line.startswith(":"):
            return None
        name, _, value = line.partition(":")
        value = value.removeprefix(" ")
        if name == "event":
            self._event = value
        elif name == "data":
            self._data.append(value)
        elif name == "id":
            self._id = value
        return None

    def _dispatch(self) -> SseFrame | None:
        frame: SseFrame | None = None
        if self._data:
            frame = SseFrame(self._event or "message", "\n".join(self._data), self._id)
        self._event, self._id, self._data = None, None, []
        return frame


def _event_offset(event_id: str | None) -> int | None:
    if event_id is None or not event_id.strip():
        return None
    try:
        return int(event_id)
    except ValueError as exc:
        raise InvalidResponseError(f"log event id is not a byte offset: {event_id!r}") from exc


def log_event_from_frame(frame: SseFrame) -> LogEvent | None:
    """Map one SSE frame to a :class:`LogEvent`; ``None`` for event types this SDK ignores."""
    if frame.event not in OUTPUT_STREAMS and frame.event != STREAM_EXIT:
        return None
    try:
        raw = _as_dict(json.loads(frame.data), f"{frame.event} event")
    except ValueError as exc:
        raise InvalidResponseError(f"{frame.event} event data is not JSON") from exc
    next_offset = _event_offset(frame.id)
    if frame.event == STREAM_EXIT:
        return LogEvent(
            stream=STREAM_EXIT,
            offset=0 if next_offset is None else next_offset,
            next_offset=next_offset,
            exit_code=raw.get("exit_code"),
            state=raw.get("state"),
            truncated=bool(raw.get("truncated", False)),
            stop_cause=raw.get("stop_cause"),
        )
    return dataclasses.replace(LogEvent.from_payload(raw), next_offset=next_offset)


class LogStream:
    """Iterator of :class:`LogEvent` for a followed command; stops after the ``exit`` event."""

    def __init__(self, response: httpx.Response) -> None:
        self._response = response
        self._events = self._decode()

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> LogEvent:
        try:
            return next(self._events)
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        self._events.close()
        self._response.close()

    @property
    def closed(self) -> bool:
        return self._response.is_closed

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def _frames(self) -> Iterator[SseFrame]:
        decoder = SseDecoder()
        try:
            for chunk in self._response.iter_bytes():
                yield from decoder.feed(chunk)
        except httpx.HTTPError as exc:
            raise stream_read_error(exc) from exc

    def _decode(self) -> Generator[LogEvent, None, None]:
        for frame in self._frames():
            event = log_event_from_frame(frame)
            if event is None:
                continue
            yield event
            if event.is_exit:
                return
        raise TransportError(_STREAM_ENDED)


class AsyncLogStream:
    """Async counterpart of :class:`LogStream`."""

    def __init__(self, response: httpx.Response) -> None:
        self._response = response
        # Async generators nested in ``async for`` are not closed with their consumer.
        self._source = self._frames()
        self._events = self._decode()

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> LogEvent:
        try:
            return await anext(self._events)
        except BaseException:
            await self.aclose()
            raise

    async def aclose(self) -> None:
        await self._events.aclose()
        await self._source.aclose()
        await self._response.aclose()

    @property
    def closed(self) -> bool:
        return self._response.is_closed

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def _frames(self) -> AsyncGenerator[SseFrame, None]:
        decoder = SseDecoder()
        try:
            async for chunk in self._response.aiter_bytes():
                for frame in decoder.feed(chunk):
                    yield frame
        except httpx.HTTPError as exc:
            raise stream_read_error(exc) from exc

    async def _decode(self) -> AsyncGenerator[LogEvent, None]:
        async for frame in self._source:
            event = log_event_from_frame(frame)
            if event is None:
                continue
            yield event
            if event.is_exit:
                return
        raise TransportError(_STREAM_ENDED)


def _exec_result(reply: Reply) -> ExecResult:
    result = ExecResult.from_payload(reply.data, reply.request_id)
    return dataclasses.replace(result, replayed=True) if reply.replayed else result


def _sessions(data: object) -> tuple[SessionInfo, ...]:
    return tuple(SessionInfo.from_payload(item) for item in _as_list(data, "sessions"))


class Process:
    """Synchronous process toolbox of one sandbox."""

    def __init__(self, sandbox_id: str, transport: SyncTransport) -> None:
        self._sandbox_id = sandbox_id
        self._transport = transport

    def exec(
        self,
        command: str | Sequence[str] | None = None,
        *,
        argv: list[str] | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout_s: int = DEFAULT_EXEC_TIMEOUT_S,
        stdin: str | None = None,
        idempotency_key: str | None = None,
    ) -> ExecResult:
        """Run a command and wait for its result.

        ``command`` is a shell string; a list is sent as ``argv``. ``idempotency_key`` (1 to 255
        printable ASCII characters) is sent as ``Idempotency-Key``: the same key and arguments
        return the first result with ``replayed`` set and the command does not run again, and a
        resend after a transport error or a 503 becomes safe, so the SDK retries it.
        """
        body = exec_body(
            command=command, argv=argv, cwd=cwd, env=env, timeout_s=timeout_s, stdin=stdin
        )
        headers = exec_idempotency_headers(idempotency_key)
        path = toolbox_path(self._sandbox_id, "execute")
        reply = self._transport.request(
            "POST", path, json=body, headers=headers, server_wait_s=timeout_s
        )
        return _exec_result(reply)

    def code_run(
        self,
        language: str,
        code: str,
        *,
        argv: list[str] | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout_s: int = DEFAULT_EXEC_TIMEOUT_S,
        idempotency_key: str | None = None,
    ) -> ExecResult:
        """Run code in ``language`` and wait for its result.

        ``idempotency_key``: as :meth:`exec` (1 to 255 printable ASCII characters, sent as
        ``Idempotency-Key``): the same key and arguments return the first result with
        ``replayed`` set and the code does not run again, and a resend after a transport error
        or a 503 becomes safe, so the SDK retries it. Without a key nothing is resent.
        """
        body = code_run_body(
            language=language, code=code, argv=argv, env=env, timeout_s=timeout_s, cwd=cwd
        )
        headers = exec_idempotency_headers(idempotency_key)
        path = toolbox_path(self._sandbox_id, "code-run")
        reply = self._transport.request(
            "POST", path, json=body, headers=headers, server_wait_s=timeout_s
        )
        return _exec_result(reply)

    def create_session(
        self,
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        idempotency_key: str | None = None,
    ) -> SessionInfo:
        """Create a session. With ``idempotency_key`` a retry returns the first session."""
        body = session_create_body(cwd, env)
        headers = idempotency_headers(idempotency_key)
        reply = self._transport.request(
            "POST", session_path(self._sandbox_id), json=body, headers=headers
        )
        return SessionInfo.from_payload(reply.data)

    def delete_session(self, session_id: str) -> SessionInfo:
        """Delete a session and kill its running commands; returns it with state ``closed``.

        An unknown or already deleted session raises :class:`NotFound`.
        """
        path = deletable_session_path(self._sandbox_id, session_id)
        reply = self._transport.request("DELETE", path)
        return SessionInfo.from_payload(reply.data)

    def list_sessions(self) -> tuple[SessionInfo, ...]:
        return _sessions(self._transport.request("GET", session_path(self._sandbox_id)).data)

    def get_session(self, session_id: str) -> SessionInfo:
        reply = self._transport.request("GET", session_path(self._sandbox_id, session_id))
        return SessionInfo.from_payload(reply.data)

    def execute_session_command(
        self,
        session_id: str,
        command: str,
        *,
        run_async: bool = False,
        timeout_s: int = DEFAULT_EXEC_TIMEOUT_S,
    ) -> SessionExecResult:
        """Run ``command`` in the session (shell state such as ``cd`` persists between calls)."""
        body = session_command_body(command, run_async=run_async, timeout_s=timeout_s)
        path = f"{session_path(self._sandbox_id, session_id)}/commands"
        reply = self._transport.request(
            "POST", path, json=body, server_wait_s=None if run_async else timeout_s
        )
        return SessionExecResult.from_payload(reply.data)

    def get_command(self, session_id: str, command_id: str) -> CommandInfo:
        reply = self._transport.request("GET", self._command(session_id, command_id))
        return CommandInfo.from_payload(reply.data)

    def get_command_logs(
        self, session_id: str, command_id: str, *, offset: int = 0, limit: int | None = None
    ) -> LogPage:
        path = self._command(session_id, command_id, "/logs")
        reply = self._transport.request("GET", path, params=log_params(offset, limit))
        return LogPage.from_payload(reply.data)

    def follow_logs(self, session_id: str, command_id: str, *, offset: int = 0) -> LogStream:
        response = self._transport.open_stream(
            "GET",
            self._command(session_id, command_id, "/logs/follow"),
            params=log_params(offset, None),
            headers=_SSE_HEADERS,
            server_wait_s=FOLLOW_IDLE_S,
        )
        return LogStream(response)

    def kill_command(self, session_id: str, command_id: str) -> CommandInfo:
        reply = self._transport.request("POST", self._command(session_id, command_id, "/kill"))
        return CommandInfo.from_payload(reply.data)

    def start(
        self,
        command: str,
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout_s: int | None = None,
        session_id: str | None = None,
    ) -> BackgroundCommand:
        """Run ``command`` in the background (new session unless given); return a handle."""
        return start_background(
            self, command, cwd=cwd, env=env, timeout_s=timeout_s, session_id=session_id
        )

    def _command(self, session_id: str, command_id: str, tail: str = "") -> str:
        return command_path(self._sandbox_id, session_id, command_id, tail)


class AsyncProcess:
    """Asynchronous process toolbox of one sandbox."""

    def __init__(self, sandbox_id: str, transport: AsyncTransport) -> None:
        self._sandbox_id = sandbox_id
        self._transport = transport

    async def exec(
        self,
        command: str | Sequence[str] | None = None,
        *,
        argv: list[str] | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout_s: int = DEFAULT_EXEC_TIMEOUT_S,
        stdin: str | None = None,
        idempotency_key: str | None = None,
    ) -> ExecResult:
        """Async twin of :meth:`Process.exec`, including ``idempotency_key``."""
        body = exec_body(
            command=command, argv=argv, cwd=cwd, env=env, timeout_s=timeout_s, stdin=stdin
        )
        headers = exec_idempotency_headers(idempotency_key)
        path = toolbox_path(self._sandbox_id, "execute")
        reply = await self._transport.request(
            "POST", path, json=body, headers=headers, server_wait_s=timeout_s
        )
        return _exec_result(reply)

    async def code_run(
        self,
        language: str,
        code: str,
        *,
        argv: list[str] | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout_s: int = DEFAULT_EXEC_TIMEOUT_S,
        idempotency_key: str | None = None,
    ) -> ExecResult:
        """Async twin of :meth:`Process.code_run`, including ``idempotency_key``."""
        body = code_run_body(
            language=language, code=code, argv=argv, env=env, timeout_s=timeout_s, cwd=cwd
        )
        headers = exec_idempotency_headers(idempotency_key)
        path = toolbox_path(self._sandbox_id, "code-run")
        reply = await self._transport.request(
            "POST", path, json=body, headers=headers, server_wait_s=timeout_s
        )
        return _exec_result(reply)

    async def create_session(
        self,
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        idempotency_key: str | None = None,
    ) -> SessionInfo:
        """Create a session. With ``idempotency_key`` a retry returns the first session."""
        body = session_create_body(cwd, env)
        headers = idempotency_headers(idempotency_key)
        reply = await self._transport.request(
            "POST", session_path(self._sandbox_id), json=body, headers=headers
        )
        return SessionInfo.from_payload(reply.data)

    async def delete_session(self, session_id: str) -> SessionInfo:
        """Delete a session and kill its running commands; returns it with state ``closed``.

        An unknown or already deleted session raises :class:`NotFound`.
        """
        path = deletable_session_path(self._sandbox_id, session_id)
        reply = await self._transport.request("DELETE", path)
        return SessionInfo.from_payload(reply.data)

    async def list_sessions(self) -> tuple[SessionInfo, ...]:
        reply = await self._transport.request("GET", session_path(self._sandbox_id))
        return _sessions(reply.data)

    async def get_session(self, session_id: str) -> SessionInfo:
        reply = await self._transport.request("GET", session_path(self._sandbox_id, session_id))
        return SessionInfo.from_payload(reply.data)

    async def execute_session_command(
        self,
        session_id: str,
        command: str,
        *,
        run_async: bool = False,
        timeout_s: int = DEFAULT_EXEC_TIMEOUT_S,
    ) -> SessionExecResult:
        body = session_command_body(command, run_async=run_async, timeout_s=timeout_s)
        path = f"{session_path(self._sandbox_id, session_id)}/commands"
        reply = await self._transport.request(
            "POST", path, json=body, server_wait_s=None if run_async else timeout_s
        )
        return SessionExecResult.from_payload(reply.data)

    async def get_command(self, session_id: str, command_id: str) -> CommandInfo:
        reply = await self._transport.request("GET", self._command(session_id, command_id))
        return CommandInfo.from_payload(reply.data)

    async def get_command_logs(
        self, session_id: str, command_id: str, *, offset: int = 0, limit: int | None = None
    ) -> LogPage:
        path = self._command(session_id, command_id, "/logs")
        reply = await self._transport.request("GET", path, params=log_params(offset, limit))
        return LogPage.from_payload(reply.data)

    async def follow_logs(
        self, session_id: str, command_id: str, *, offset: int = 0
    ) -> AsyncLogStream:
        response = await self._transport.open_stream(
            "GET",
            self._command(session_id, command_id, "/logs/follow"),
            params=log_params(offset, None),
            headers=_SSE_HEADERS,
            server_wait_s=FOLLOW_IDLE_S,
        )
        return AsyncLogStream(response)

    async def kill_command(self, session_id: str, command_id: str) -> CommandInfo:
        path = self._command(session_id, command_id, "/kill")
        reply = await self._transport.request("POST", path)
        return CommandInfo.from_payload(reply.data)

    async def start(
        self,
        command: str,
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout_s: int | None = None,
        session_id: str | None = None,
    ) -> AsyncBackgroundCommand:
        """Async twin of :meth:`Process.start`."""
        return await start_background_async(
            self, command, cwd=cwd, env=env, timeout_s=timeout_s, session_id=session_id
        )

    def _command(self, session_id: str, command_id: str, tail: str = "") -> str:
        return command_path(self._sandbox_id, session_id, command_id, tail)
