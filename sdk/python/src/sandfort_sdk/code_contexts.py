"""Persistent Python code contexts (``sandbox.code_contexts``): a kernel that keeps state.

``create`` starts a Python kernel inside a started sandbox; ``CodeContext.run`` executes a cell
in it and variables, imports and open data survive from one run to the next. The state lives in
the kernel process, so it is lost when the sandbox is stopped, reset or deleted. ``ensure(name)``
returns the live context of that name or starts one, so the same call brings a context back
after a stop (with empty state). Only Python is supported. A cell that exceeds ``timeout_s``
reports ``timed_out`` and the state stays.

``run`` returns a :class:`CellResult`: every ``ExecResult`` field plus ``result`` (the repr of
the trailing expression) and ``error`` (the exception the cell raised). Runs of one context are
serialized by the server; a run that is cancelled or whose client goes away interrupts its cell.
``run_stream`` yields the same run as server-sent events: an :class:`OutputChunk` for each piece
of stdout or stderr as it is written, then the final :class:`CellResult`.
Both context classes are context managers that delete the kernel on exit.
"""

import json
import logging
from collections.abc import AsyncGenerator, Generator, Iterator
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Literal, Self

import httpx

from sandfort_sdk._requests import DEFAULT_EXEC_TIMEOUT_S, area_path, segment
from sandfort_sdk._transport import (
    AsyncTransport,
    Reply,
    SyncTransport,
    stream_read_error,
)
from sandfort_sdk.exceptions import (
    ApiError,
    InvalidResponseError,
    NotFound,
    TransportError,
    error_for,
)
from sandfort_sdk.models import ExecResult, _as_dict, _as_list, _optional_str, _required
from sandfort_sdk.process import SseDecoder, SseFrame

logger = logging.getLogger(__name__)

AREA = "code-contexts"
LANGUAGE = "python"


def _contexts_path(sandbox_id: str) -> str:
    return area_path(sandbox_id, AREA)


def _context_path(sandbox_id: str, context_id: str, tail: str = "") -> str:
    return area_path(sandbox_id, AREA, f"/{segment(context_id)}{tail}")


def _create_body(
    cwd: str | None, name: str | None = None, language: str = LANGUAGE
) -> dict[str, Any]:
    body: dict[str, Any] = {"language": language}
    if cwd is not None:
        body["cwd"] = cwd
    if name is not None:
        body["name"] = name
    return body


def _run_body(code: str, timeout_s: int) -> dict[str, Any]:
    return {"language": LANGUAGE, "code": code, "timeout_s": timeout_s}


@dataclass(frozen=True, slots=True)
class CellError:
    """The exception a cell raised: its class name and ``str()`` (the traceback is on stderr)."""

    type: str
    message: str

    @classmethod
    def from_payload(cls, data: Any) -> "CellError":
        raw = _as_dict(data, "cell error")
        error_type, message = _required(raw, "cell error", "type", "message")
        if not isinstance(error_type, str) or not isinstance(message, str):
            raise InvalidResponseError("cell error type and message must be strings")
        return cls(type=error_type, message=message)


@dataclass(frozen=True, slots=True)
class CellResult(ExecResult):
    """An :class:`ExecResult` of a code-context run, plus the cell's structured outcome.

    ``result`` is the repr of the trailing expression (``None`` when the cell has none, when it
    is ``None``, when it raised, or when the run reported no outcome). ``error`` is set when the
    cell raised, including ``TimeoutError`` and ``KeyboardInterrupt``.
    """

    result: str | None = None
    error: CellError | None = None

    @classmethod
    def from_payload(cls, data: Any, request_id: str | None = None) -> "CellResult":
        base = ExecResult.from_payload(data, request_id)
        raw = _as_dict(data, "cell result")
        error = raw.get("error")
        return cls(
            exit_code=base.exit_code,
            stdout=base.stdout,
            stderr=base.stderr,
            timed_out=base.timed_out,
            truncated=base.truncated,
            duration_ms=base.duration_ms,
            sandbox_stopped=base.sandbox_stopped,
            stop_reason=base.stop_reason,
            request_id=base.request_id,
            result=_optional_str(raw.get("result"), "cell result"),
            error=None if error is None else CellError.from_payload(error),
        )


_SSE_HEADERS = {"Accept": "text/event-stream"}
_EVENT_RESULT = "result"
_EVENT_ERROR = "error"
_STREAM_ENDED = "run stream ended before the result event"
# A run may queue for up to timeout_s and then run for up to timeout_s; reads must outlast both.
_QUEUE_AND_RUN = 2


@dataclass(frozen=True, slots=True)
class OutputChunk:
    """A piece of output a streamed run wrote to ``stdout`` or ``stderr``."""

    stream: Literal["stdout", "stderr"]
    data: str


def _chunk(stream: Literal["stdout", "stderr"], data: str) -> OutputChunk:
    what = f"{stream} event"
    try:
        raw = _as_dict(json.loads(data), what)
    except ValueError as exc:
        raise InvalidResponseError(f"{what} data is not JSON") from exc
    (text,) = _required(raw, what, "data")
    if not isinstance(text, str):
        raise InvalidResponseError(f"{what} 'data' must be a string")
    return OutputChunk(stream, text)


def _stream_error_event(data: str, response: httpx.Response | None = None) -> ApiError:
    """The typed exception for an ``error`` event, mapped like a normal error reply.

    With the stream ``response`` the exception carries its ``x-request-id`` header and HTTP status
    (200: the failure arrived inside the stream), so logs and support lookups work. ``details``
    is the event's ``details`` object (``{}`` and ``has_details`` False when the event has none).
    """
    try:
        raw = _as_dict(json.loads(data), "error event")
    except ValueError as exc:
        raise InvalidResponseError("error event data is not JSON") from exc
    code, message = _required(raw, "error event", "code", "message")
    if not isinstance(code, str) or not isinstance(message, str):
        raise InvalidResponseError("error event 'code' and 'message' must be strings")
    details = raw.get("details")
    event_details = details if isinstance(details, dict) and details else None
    if response is None:
        return error_for(code, message, details=event_details)
    return error_for(
        code,
        message,
        status_code=response.status_code,
        details=event_details,
        request_id=_request_id(response),
    )


def _request_id(response: httpx.Response) -> str | None:
    request_id: str | None = response.headers.get("x-request-id")
    return request_id


def event_from_frame(
    frame: SseFrame, response: httpx.Response | None = None
) -> OutputChunk | CellResult | None:
    """Map one SSE frame to an event; ``None`` for event types this SDK ignores.

    An ``error`` event raises the :class:`ApiError` subclass for its code. A malformed event
    raises :class:`InvalidResponseError`, carrying the ``x-request-id`` of ``response``.
    """
    try:
        return _event(frame, response)
    except InvalidResponseError as exc:
        if response is None:
            raise
        raise InvalidResponseError(*exc.args, request_id=_request_id(response)) from exc


def _event(frame: SseFrame, response: httpx.Response | None) -> OutputChunk | CellResult | None:
    if frame.event == "stdout":
        return _chunk("stdout", frame.data)
    if frame.event == "stderr":
        return _chunk("stderr", frame.data)
    if frame.event == _EVENT_ERROR:
        raise _stream_error_event(frame.data, response)
    if frame.event != _EVENT_RESULT:
        return None
    try:
        payload = json.loads(frame.data)
    except ValueError as exc:
        raise InvalidResponseError("result event data is not JSON") from exc
    return CellResult.from_payload(payload, None if response is None else _request_id(response))


def _read_error(exc: httpx.HTTPError, response: httpx.Response) -> TransportError:
    """The :class:`TransportError` of a broken read, with the ``x-request-id`` of ``response``."""
    return TransportError(*stream_read_error(exc).args, request_id=_request_id(response))


class CellStream:
    """Iterator of :class:`OutputChunk` values ending with the run's :class:`CellResult`.

    Closing it early (or leaving a ``with`` block) releases the HTTP response at once.
    """

    def __init__(self, response: httpx.Response) -> None:
        self._response = response
        self._events = self._decode()

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> OutputChunk | CellResult:
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
            raise _read_error(exc, self._response) from exc

    def _decode(self) -> Generator[OutputChunk | CellResult, None, None]:
        for frame in self._frames():
            event = event_from_frame(frame, self._response)
            if event is None:
                continue
            yield event
            if isinstance(event, CellResult):
                return
        raise TransportError(_STREAM_ENDED, request_id=_request_id(self._response))


class AsyncCellStream:
    """Async counterpart of :class:`CellStream`."""

    def __init__(self, response: httpx.Response) -> None:
        self._response = response
        # Async generators nested in ``async for`` are not closed with their consumer.
        self._source = self._frames()
        self._events = self._decode()

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> OutputChunk | CellResult:
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
            raise _read_error(exc, self._response) from exc

    async def _decode(self) -> AsyncGenerator[OutputChunk | CellResult, None]:
        async for frame in self._source:
            event = event_from_frame(frame, self._response)
            if event is None:
                continue
            yield event
            if isinstance(event, CellResult):
                return
        raise TransportError(_STREAM_ENDED, request_id=_request_id(self._response))


def _interrupted(data: Any) -> bool:
    (interrupted,) = _required(_as_dict(data, "interrupt"), "interrupt", "interrupted")
    if not isinstance(interrupted, bool):
        raise InvalidResponseError("interrupt 'interrupted' must be a boolean")
    return interrupted


def _delete_error_is_ignored(error: Exception, propagating: bool, context_id: str) -> bool:
    """A missing context is ignored; other errors are raised unless one is propagating."""
    if isinstance(error, NotFound):
        return True
    if propagating:
        logger.warning("cannot delete code context %s on exit", context_id, exc_info=error)
    return propagating


def _fields(data: Any) -> tuple[str, str, str | None]:
    """``id``, ``cwd`` and ``name`` (``None`` for an unnamed context) of a context payload."""
    raw = _as_dict(data, "code context")
    context_id, cwd = _required(raw, "code context", "id", "cwd")
    return context_id, cwd, _optional_str(raw.get("name"), "code context name")


def _started_kernel(reply: Reply) -> bool:
    """Whether a create's final answer started a kernel.

    The server answers 200 for a live context it found and 201 for a new one; any other success
    status counts as new, so a caller that re-runs its setup on ``created`` never skips it.
    """
    return reply.status_code != httpx.codes.OK


class CodeContext:
    """One live kernel of a sandbox (synchronous); ``name`` is ``None`` for an unnamed one.

    ``created`` is True when the call that returned the handle started the kernel (``create``,
    or ``ensure`` that found no live context of the name) and False when it found a live one
    (``ensure``, a named ``create``) or listed it.
    """

    def __init__(
        self,
        sandbox_id: str,
        context_id: str,
        cwd: str,
        transport: SyncTransport,
        name: str | None = None,
        *,
        created: bool = False,
    ) -> None:
        self._sandbox_id = sandbox_id
        self._transport = transport
        self._created = created
        self.id = context_id
        self.cwd = cwd  # the kernel's working directory
        self.name = name
        self.language = LANGUAGE

    @property
    def created(self) -> bool:
        """True when this handle's call started the kernel; False when it found a live one."""
        return self._created

    def __repr__(self) -> str:
        return f"CodeContext(id={self.id!r}, cwd={self.cwd!r}, name={self.name!r})"

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Delete the context. A context that is gone already is ignored; another delete error
        is raised unless an exception is propagating (then it is logged, not masked)."""
        try:
            self.delete()
        except Exception as error:
            if not _delete_error_is_ignored(error, exc_type is not None, self.id):
                raise

    def run(self, code: str, *, timeout_s: int = DEFAULT_EXEC_TIMEOUT_S) -> CellResult:
        """Run ``code`` in the kernel; the state of earlier runs is visible to it."""
        path = _context_path(self._sandbox_id, self.id, "/run")
        reply = self._transport.request(
            "POST", path, json=_run_body(code, timeout_s), server_wait_s=timeout_s
        )
        return CellResult.from_payload(reply.data, reply.request_id)

    def run_stream(self, code: str, *, timeout_s: int = DEFAULT_EXEC_TIMEOUT_S) -> CellStream:
        """Run ``code`` like :meth:`run`, yielding its output as it is written.

        Iterate the result: an :class:`OutputChunk` per output event, then the final
        :class:`CellResult` (the same value ``run`` returns). Errors before the stream starts
        raise the same exceptions as ``run``; an ``error`` event raises the exception for its code;
        a stream that ends with neither it nor a result raises :class:`TransportError`.
        Close it (or use ``with``) when stopping early.
        """
        response = self._transport.open_stream(
            "POST",
            _context_path(self._sandbox_id, self.id, "/run/stream"),
            json=_run_body(code, timeout_s),
            headers=_SSE_HEADERS,
            server_wait_s=timeout_s * _QUEUE_AND_RUN,
        )
        return CellStream(response)

    def interrupt(self) -> bool:
        """Interrupt the running cell (``KeyboardInterrupt``); the state stays.

        True when a cell was running and the kernel was sent the interrupt.
        False when no cell is running (between cells nothing is signalled), or when the context
        has no live kernel.
        """
        path = _context_path(self._sandbox_id, self.id, "/interrupt")
        return _interrupted(self._transport.request("POST", path).data)

    def delete(self) -> None:
        """Kill the kernel; its state is gone."""
        self._transport.request("DELETE", _context_path(self._sandbox_id, self.id))


class AsyncCodeContext:
    """Async counterpart of :class:`CodeContext`."""

    def __init__(
        self,
        sandbox_id: str,
        context_id: str,
        cwd: str,
        transport: AsyncTransport,
        name: str | None = None,
        *,
        created: bool = False,
    ) -> None:
        self._sandbox_id = sandbox_id
        self._transport = transport
        self._created = created
        self.id = context_id
        self.cwd = cwd
        self.name = name
        self.language = LANGUAGE

    @property
    def created(self) -> bool:
        """As :attr:`CodeContext.created`."""
        return self._created

    def __repr__(self) -> str:
        return f"AsyncCodeContext(id={self.id!r}, cwd={self.cwd!r}, name={self.name!r})"

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            await self.delete()
        except Exception as error:
            if not _delete_error_is_ignored(error, exc_type is not None, self.id):
                raise

    async def run(self, code: str, *, timeout_s: int = DEFAULT_EXEC_TIMEOUT_S) -> CellResult:
        """Run ``code``. Cancelling the awaiting task interrupts the cell on the server."""
        path = _context_path(self._sandbox_id, self.id, "/run")
        reply = await self._transport.request(
            "POST", path, json=_run_body(code, timeout_s), server_wait_s=timeout_s
        )
        return CellResult.from_payload(reply.data, reply.request_id)

    async def run_stream(
        self, code: str, *, timeout_s: int = DEFAULT_EXEC_TIMEOUT_S
    ) -> AsyncCellStream:
        """Async counterpart of :meth:`CodeContext.run_stream`: ``async for`` the events.

        ``async with await ctx.run_stream(code) as events:`` closes the stream on exit.
        """
        response = await self._transport.open_stream(
            "POST",
            _context_path(self._sandbox_id, self.id, "/run/stream"),
            json=_run_body(code, timeout_s),
            headers=_SSE_HEADERS,
            server_wait_s=timeout_s * _QUEUE_AND_RUN,
        )
        return AsyncCellStream(response)

    async def interrupt(self) -> bool:
        """See ``CodeContext.interrupt``: False when no cell is running."""
        path = _context_path(self._sandbox_id, self.id, "/interrupt")
        return _interrupted((await self._transport.request("POST", path)).data)

    async def delete(self) -> None:
        await self._transport.request("DELETE", _context_path(self._sandbox_id, self.id))


class CodeContexts:
    """``sandbox.code_contexts``: create and list the kernels of one started sandbox."""

    def __init__(self, sandbox_id: str, transport: SyncTransport) -> None:
        self._sandbox_id = sandbox_id
        self._transport = transport

    def create(
        self, cwd: str | None = None, *, name: str | None = None, language: str = LANGUAGE
    ) -> CodeContext:
        """Start a kernel in ``cwd`` (the sandbox default when None).

        With ``name``, a live context of that name is returned instead of a new one; its own
        ``cwd`` is kept and the ``cwd`` passed here is ignored. Name uniqueness is enforced per
        API process: two creates of one name racing across processes may both succeed.
        ``created`` on the result is True for a new kernel, False for a found one (the server
        answers 201 or 200). Like any call it is resent after a 429 ``RATE_LIMITED``.
        """
        path = _contexts_path(self._sandbox_id)
        body = _create_body(cwd, name, language)
        reply = self._transport.request("POST", path, json=body)
        created = name is None or _started_kernel(reply)
        context_id, kernel_cwd, got = _fields(reply.data)
        return CodeContext(
            self._sandbox_id, context_id, kernel_cwd, self._transport, got, created=created
        )

    def ensure(
        self, name: str, *, language: str = LANGUAGE, cwd: str | None = None
    ) -> CodeContext:
        """The live context named ``name``, or a new one with that name when there is none.

        One idempotent call: after the sandbox was stopped and started (auto-stop included) it
        starts a new context with the same name. The state is not restored: variables, imports
        and loaded data of the earlier context are gone, so re-run the setup cells. ``cwd`` is
        used only when a context is created: when a live context has the name, its cwd is kept
        and ``cwd`` is ignored. Uniqueness is enforced per API process, so two ``ensure`` calls
        racing across processes may both create a context. ``created`` on the result says which
        happened: True for a new (empty) context, so run the setup cells; False when found.
        """
        return self.create(cwd, name=name, language=language)

    def list(self) -> tuple[CodeContext, ...]:
        reply = self._transport.request("GET", _contexts_path(self._sandbox_id))
        rows = [_fields(item) for item in _as_list(reply.data, "code contexts")]
        return tuple(CodeContext(self._sandbox_id, i, c, self._transport, n) for i, c, n in rows)


class AsyncCodeContexts:
    """Async counterpart of :class:`CodeContexts`."""

    def __init__(self, sandbox_id: str, transport: AsyncTransport) -> None:
        self._sandbox_id = sandbox_id
        self._transport = transport

    async def create(
        self, cwd: str | None = None, *, name: str | None = None, language: str = LANGUAGE
    ) -> AsyncCodeContext:
        """Async counterpart of :meth:`CodeContexts.create`."""
        path = _contexts_path(self._sandbox_id)
        body = _create_body(cwd, name, language)
        reply = await self._transport.request("POST", path, json=body)
        created = name is None or _started_kernel(reply)
        context_id, kernel_cwd, got = _fields(reply.data)
        return AsyncCodeContext(
            self._sandbox_id, context_id, kernel_cwd, self._transport, got, created=created
        )

    async def ensure(
        self, name: str, *, language: str = LANGUAGE, cwd: str | None = None
    ) -> AsyncCodeContext:
        """The live context named ``name``, or a new one with that name when there is none.

        As :meth:`CodeContexts.ensure`: after a sandbox stop and start the call brings a context
        of that name back, but its state (variables, imports, loaded data) is lost. An existing
        context keeps its cwd (``cwd`` is ignored); uniqueness is per API process only.
        ``created`` is True for a new context and False for a found one.
        """
        return await self.create(cwd, name=name, language=language)

    async def list(self) -> tuple[AsyncCodeContext, ...]:
        reply = await self._transport.request("GET", _contexts_path(self._sandbox_id))
        rows = [_fields(item) for item in _as_list(reply.data, "code contexts")]
        return tuple(
            AsyncCodeContext(self._sandbox_id, i, c, self._transport, n) for i, c, n in rows
        )
