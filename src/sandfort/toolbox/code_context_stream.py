"""Streaming runs of a code context: the cell's output is forwarded while the cell writes it.

A streamed run is the ordinary run (``code_contexts.run_in_context``) with one difference: the
client exec goes through the driver's ``exec_stream`` instead of ``exec``, and every output
chunk is also handed to a ``RunEvents`` queue as a ``stdout`` or ``stderr`` event
(``{"data": <text>}``, decoded as UTF-8 with replacement, a character split across two chunks
is joined). The exec result is the same one ``exec`` would give, so the outcome trailer, the
timeout handling and the final response are those of the plain run.

The client ends its stdout with an outcome trailer line keyed by the run's token. It is never
forwarded: stdout is held back to the last line break (a newline, or a carriage return so that
progress bars redraw live), so the (partial) last line is released only
when its break arrives, or at the end of the run with the trailer taken off by
``split_outcome``. Stderr has no trailer and is forwarded as it arrives, up to the first of two
driver lines the run may reword. The sandbox-death line names a resource limit, while the run
may find that the sandbox was stopped or its container is gone. The exec-deadline sentence
names the exec timeout (the cell's limit plus the margin) and asks for more time, while the
run may find that the kernel ignored its interrupt and replace it with the cell's own limit and
a stopped-context sentence. From the first of them on, stderr is sent as the final response
words it, just before the ``result`` event. Any other text the run appends to stderr (a
delete or reset sentence without a death line, an interrupted-context sentence) is sent the
same way, so the streamed stderr equals the result's ``stderr`` whenever the result extends
what was sent.

``stream_run`` drives one run: it starts the run as a task, yields the queued events, and ends
with exactly one ``result`` event (the final response) or, when the run failed after the stream
began, one ``error`` event. Closing the generator (the client went away) cancels the task.
"""

import asyncio
import codecs
import logging
import time
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import replace
from typing import Any

import anyio

from sandfort.domain.sandbox import Sandbox
from sandfort.drivers.base import ExecRequest, ExecResult, ExitEvent, OutputChunk, SandboxDriver
from sandfort.drivers.errors import DriverError
from sandfort.errors import Conflict, NotFound, SandfortError
from sandfort.toolbox.code_context_kernel import _PROBE_SCRIPT
from sandfort.toolbox.code_contexts import (
    CONTAINER_GONE_MESSAGE,
    DRIVER_DEATH_LINE,
    STOP_REASON_SANDBOX_STOPPED,
    STOPPED_WHILE_RUNNING_MESSAGE,
    GoneCause,
    RunExec,
    _checked_dir,
    _ref,
    _sh,
    split_outcome,
    stop_cause,
)
from sandfort.toolbox.process import MAX_OUTPUT_BYTES, MAX_TIMEOUT_S
from sandfort.toolbox.stop_wording import CELL_DIED_MESSAGE

logger = logging.getLogger(__name__)

STDOUT = "stdout"
STDERR = "stderr"
RESULT_EVENT = "result"
ERROR_EVENT = "error"
FAILED_MESSAGE = "the streamed run failed; see the server log"
INTERNAL_CODE = "INTERNAL"

type Event = tuple[str, dict[str, Any]]  # (event name, JSON object of its data)
type Finish = Callable[["RunEvents"], Awaitable[dict[str, Any]]]
# The stop reason the sandbox row gives (``sandbox_deleted``, ``sandbox_reset``,
# ``sandbox_stopped`` for a stop by the caller or auto-stop) or None; the route reads the row.
type StopCheck = Callable[[], Awaitable[str | None]]
# The line for each stop reason; a route passes its own (a cell run names the cell).
DEFAULT_GONE_LINES: Mapping[str, bytes] = {
    STOP_REASON_SANDBOX_STOPPED: STOPPED_WHILE_RUNNING_MESSAGE.encode(),
}
# The driver's exec-deadline sentence up to its number of seconds (the Docker driver's
# ``TIMEOUT_MESSAGE_TEMPLATE``, repeated: this module stays off the driver package).
DRIVER_DEADLINE_PREFIX = b"the command was stopped after "
# The driver's output-limit sentence up to its number of bytes (``OUTPUT_CAP_MESSAGE_TEMPLATE``,
# repeated for the same reason); a cell run words it for the cell.
DRIVER_OUTPUT_LIMIT_PREFIX = b"the command was stopped because its output exceeded the limit"
# The driver lines the run may reword; stderr from the first of them on is held back.
HELD_LINE_ANCHORS = (DRIVER_DEATH_LINE, DRIVER_DEADLINE_PREFIX, DRIVER_OUTPUT_LIMIT_PREFIX)


class RunEvents:
    """The events of one streamed run, from the exec to the response generator.

    It also keeps the stderr text sent so far and whether the driver's sandbox-death line or
    exec-deadline sentence was held back (``hold``); ``_produce`` sends the rest of the final
    stderr before the result.
    """

    def __init__(self) -> None:
        self._queue: asyncio.Queue[Event | None] = asyncio.Queue()
        self._stderr_sent: list[str] = []
        self.held = False

    def emit(self, name: str, payload: dict[str, Any]) -> None:
        if name == STDERR:
            self._stderr_sent.append(str(payload.get("data", "")))
        self._queue.put_nowait((name, payload))

    def hold(self) -> None:
        """Mark that stderr from the first held driver line (``HELD_LINE_ANCHORS``) was not sent."""
        self.held = True

    def stderr_sent(self) -> str:
        return "".join(self._stderr_sent)

    def close(self) -> None:
        self._queue.put_nowait(None)

    async def items(self) -> AsyncIterator[Event]:
        """The events in order, until ``close``."""
        while (item := await self._queue.get()) is not None:
            yield item


class TrailerFilter:
    """Passes stdout on up to the last line break and never lets the run's outcome trailer through.

    A line break is a newline or a carriage return (a progress bar redraws its line with
    ``\\r``), so such updates are forwarded as they arrive; the text is passed on unchanged.
    The rest, still without a break, is held back; ``finish`` releases it. The trailer
    can follow cell output that has no final newline, so text before the marker is kept.
    """

    def __init__(self, token: str) -> None:
        self._token = token
        self._held = b""

    def feed(self, data: bytes) -> bytes:
        """The complete lines of the held text plus ``data``, without the trailer."""
        held = self._held + data
        cut = max(held.rfind(b"\n"), held.rfind(b"\r")) + 1
        self._held = held[cut:]
        return split_outcome(held[:cut], self._token)[0] if cut else b""

    def finish(self) -> bytes:
        """The held last line, without a trailer (also one cut short) it may carry."""
        held, self._held = self._held, b""
        return split_outcome(held, self._token)[0]


class _Channel:
    """One output stream: everything the exec wrote, and the text forwarded as events.

    The stderr channel holds back the first of the driver's sandbox-death line (it names a
    resource limit) and exec-deadline sentence (it names the exec timeout, not the cell's
    limit), and everything after it: the run's final stderr decides the wording, see
    ``_send_stderr_tail``. The driver yields each of these lines as one chunk of its own (a
    leading newline at most before the deadline sentence), so an anchor is never split across
    two chunks and a find on the chunk's bytes is enough.
    """

    def __init__(self, name: str, events: RunEvents, hold: TrailerFilter | None = None) -> None:
        self.raw = bytearray()
        self._name = name
        self._events = events
        self._hold = hold
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

    def feed(self, data: bytes) -> None:
        self.raw.extend(data)
        if self._name == STDERR:
            data = self._before_held_line(data)
        self._send(data if self._hold is None else self._hold.feed(data), final=False)

    def _before_held_line(self, data: bytes) -> bytes:
        """The part of ``data`` that may be sent now; none once a held driver line was seen."""
        if self._events.held:
            return b""
        found = [at for anchor in HELD_LINE_ANCHORS if (at := data.find(anchor)) >= 0]
        if not found:
            return data
        self._events.hold()
        return data[: min(found)]

    def finish(self) -> None:
        self._send(b"" if self._hold is None else self._hold.finish(), final=True)

    def _send(self, data: bytes, *, final: bool) -> None:
        text = self._decoder.decode(data, final)
        if text:
            self._events.emit(self._name, {"data": text})


async def stream_exec(
    driver: SandboxDriver,
    sandbox: Sandbox,
    request: ExecRequest,
    token: str,
    events: RunEvents,
) -> ExecResult:
    """``execute`` through ``exec_stream``: the same result, the output also sent to ``events``.

    Any timeout line is part of the driver's own stream, so the result equals the one
    ``driver.exec`` gives.
    """
    ref = _ref(sandbox)
    bounded = replace(
        request,
        timeout_s=min(request.timeout_s, MAX_TIMEOUT_S),
        max_output_bytes=min(request.max_output_bytes, MAX_OUTPUT_BYTES),
    )
    started = time.monotonic()
    out = _Channel(STDOUT, events, TrailerFilter(token))
    err = _Channel(STDERR, events)
    exit_event: ExitEvent | None = None
    async for event in driver.exec_stream(ref, bounded):
        if isinstance(event, OutputChunk):
            (out if event.stream == STDOUT else err).feed(event.data)
        else:
            exit_event = event
    if exit_event is None:
        raise DriverError("exec stream ended without an exit event", ref=ref)
    out.finish()
    err.finish()
    return ExecResult(
        exit_code=exit_event.exit_code,
        stdout=bytes(out.raw),
        stderr=bytes(err.raw),
        timed_out=exit_event.timed_out,
        truncated=exit_event.truncated,
        duration_ms=int((time.monotonic() - started) * 1000),
        sandbox_stopped=exit_event.sandbox_stopped,
        oom_killed=exit_event.oom_killed,
    )


def streaming_runner(driver: SandboxDriver, sandbox: Sandbox, events: RunEvents) -> RunExec:
    """The ``runner`` for ``run_in_context`` that forwards the cell's output to ``events``."""

    async def run(request: ExecRequest, token: str) -> ExecResult:
        return await stream_exec(driver, sandbox, request, token, events)

    return run


async def ensure_context(driver: SandboxDriver, sandbox: Sandbox, context_id: str) -> None:
    """Raise ``NotFound`` for an unknown context, so the route can answer 404 before it streams."""
    result = await _sh(driver, _ref(sandbox), _PROBE_SCRIPT, _checked_dir(context_id))
    if result.exit_code != 0:
        raise NotFound(f"code context {context_id} not found")


async def _gone_line(
    cause: GoneCause, stop_check: StopCheck | None, gone_lines: Mapping[str, bytes]
) -> str:
    """The sentence for a sandbox that is no longer running, chosen as the result path does.

    A vanished container is named as such. For a container that is not running, ``stop_check``
    (the route reads the row) gives the stop reason: a delete or a reset gets its line from
    ``gone_lines``, and so does a stop by the caller or auto-stop (its default entry is the stop
    sentence); any other death keeps the driver's line (a resource limit was hit or the main
    process ended). Without a check there is no row to read, so the driver's line stays.
    """
    if cause == "gone":
        return CONTAINER_GONE_MESSAGE
    reason = await stop_check() if stop_check is not None else None
    line = gone_lines.get(reason) if reason is not None else None
    return (line if line is not None else CELL_DIED_MESSAGE).decode()


async def _driver_failure(
    exc: DriverError, stop_check: StopCheck | None, gone_lines: Mapping[str, bytes]
) -> dict[str, Any]:
    """The ``error`` event of a driver failure.

    One that means the sandbox is no longer running carries the line ``_gone_line`` picks and
    the ``stop_reason`` of the plain run; any other failure is the generic internal error.
    """
    cause = stop_cause(exc)
    if cause is None:
        logger.error("streamed code-context run failed", exc_info=exc)
        return {"code": INTERNAL_CODE, "message": FAILED_MESSAGE}
    return {
        "code": Conflict.code,
        "message": await _gone_line(cause, stop_check, gone_lines),
        "stop_reason": STOP_REASON_SANDBOX_STOPPED,
    }


def _send_stderr_tail(events: RunEvents, response: dict[str, Any]) -> None:
    """Send the part of the final ``response``'s stderr that was not streamed yet.

    The streamed stderr then equals the response's ``stderr`` in every ending. The tail is the
    held-back death line as the plain run words it (a stop, a vanished container, a delete or a
    reset rewords it, a limit keeps it), the held-back deadline sentence as the plain run words
    it (a kernel that ignored its interrupt gets the cell's limit and the stopped-context
    sentence in its place; a kept context keeps it and gets the interrupted-context sentence
    after it), or a line the run appended without any held text: a delete or a reset whose
    container vanished without the driver's death line. When the response's stderr does not
    start with the text already
    sent, nothing is sent (the result event still carries the whole stderr).
    """
    final, sent = response.get(STDERR), events.stderr_sent()
    if not isinstance(final, str) or not final.startswith(sent):
        logger.warning("the streamed stderr is not a prefix of the result; its tail is not sent")
        return
    if rest := final[len(sent) :]:
        events.emit(STDERR, {"data": rest})


async def _produce(
    events: RunEvents,
    finish: Finish,
    stop_check: StopCheck | None = None,
    gone_lines: Mapping[str, bytes] = DEFAULT_GONE_LINES,
) -> None:
    """Run ``finish``; its response is the ``result`` event, a failure the one ``error`` event.

    The rest of the response's stderr (held back or appended by the run) is sent just before
    the ``result`` event (``_send_stderr_tail``). ``stop_check`` and ``gone_lines`` word a
    driver failure that means the sandbox is no longer running (``_gone_line``).
    """
    try:
        response = await finish(events)
        _send_stderr_tail(events, response)
        events.emit(RESULT_EVENT, response)
    except SandfortError as exc:
        events.emit(ERROR_EVENT, {"code": exc.code, "message": exc.message})
    except DriverError as exc:
        events.emit(ERROR_EVENT, await _driver_failure(exc, stop_check, gone_lines))
    except Exception:
        logger.exception("streamed code-context run failed")
        events.emit(ERROR_EVENT, {"code": INTERNAL_CODE, "message": FAILED_MESSAGE})
    finally:
        events.close()


async def stream_run(
    finish: Finish,
    stop_check: StopCheck | None = None,
    gone_lines: Mapping[str, bytes] = DEFAULT_GONE_LINES,
) -> AsyncGenerator[Event]:
    """Yield the output events of the run ``finish`` performs, then its ``result`` (or ``error``).

    ``finish`` gets the ``RunEvents`` to feed (through ``streaming_runner``) and returns the
    JSON object of the final response. ``stop_check`` is asked only when the run fails with a
    driver error meaning the sandbox is no longer running; ``gone_lines`` maps the reason it
    gives to the line of the ``error`` event (see ``_gone_line``). However
    the generator ends, the run task is cancelled and awaited, so a run whose client went away
    gets its cell interrupted before this returns.
    """
    events = RunEvents()
    task = asyncio.ensure_future(_produce(events, finish, stop_check, gone_lines))
    try:
        async for item in events.items():
            yield item
    finally:
        task.cancel()
        with anyio.CancelScope(shield=True):
            await asyncio.wait({task})
