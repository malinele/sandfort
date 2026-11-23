"""``POST .../code-contexts/{id}/run/stream``: FakeDriver with a scripted ``exec_stream``.

Daemon-free. ``Shell`` answers the platform's ``sh -c`` execs; each test scripts the chunks the
driver delivers for the client exec (the trailer is built from the run's token, ``argv[5]``).
"""

import asyncio
import json
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.openapi import build_document
from sandfort.api.routes.toolbox import code_contexts as routes
from sandfort.api.routes.toolbox import process as process_routes
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import Sandbox
from sandfort.drivers.base import ExecEvent, ExecRequest, ExecResult, ExitEvent, OutputChunk
from sandfort.drivers.docker.exec import output_cap_message, timeout_message, timeout_note
from sandfort.drivers.errors import DriverError
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.toolbox import code_context_stream, code_contexts

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
WAIT_DEADLINE_S = 5.0
OUTCOME = {"x": 0, "r": "42", "err": None, "lost": False}
Script = Callable[[str], list[ExecEvent]]  # the token of the run -> what the driver delivers
Events = list[tuple[str, dict[str, Any]]]


def trailer(token: str) -> bytes:
    return code_contexts.OUTCOME_MARK + f"{token} {json.dumps(OUTCOME)}\n".encode()


def out(data: bytes) -> OutputChunk:
    return OutputChunk("stdout", data)


def err(data: bytes) -> OutputChunk:
    return OutputChunk("stderr", data)


def done(token: str, *chunks: OutputChunk) -> list[ExecEvent]:
    """The chunks, then the client's trailer and a clean exit."""
    return [*chunks, out(trailer(token)), ExitEvent(0)]


class Shell:
    """A scripted sandbox: answers the platform's ``sh -c`` execs and the plain client exec."""

    def __init__(self) -> None:
        self.ready: dict[str, str] = {}
        self.interrupts: list[str] = []
        self.kills: list[str] = []
        self.idle = True  # False: an interrupted kernel never reports its cell done
        self.cell_result = ExecResult(exit_code=0)  # what a plain (non-streamed) run execs

    def __call__(self, env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        argv = list(request.argv)
        if argv[:2] == ["sh", "-c"]:
            return self._script(argv[2], argv[4:], request)
        if argv[0] == "python3":
            stdout = self.cell_result.stdout + trailer(argv[5])
            return ExecResult(exit_code=0, stdout=stdout, stderr=self.cell_result.stderr)
        return ExecResult(exit_code=0)

    def _script(self, script: str, args: list[str], request: ExecRequest) -> ExecResult:
        if script == code_contexts._START_SCRIPT:
            self.ready[args[0]] = request.cwd or "/workspace"
        elif script == code_contexts._READY_SCRIPT:
            cwd = self.ready.get(args[0])
            return ExecResult(exit_code=1 if cwd is None else 0, stdout=(cwd or "").encode())
        elif script == code_contexts._PROBE_SCRIPT:
            return ExecResult(exit_code=0 if args[0] in self.ready else 1)
        elif script == code_contexts._INTERRUPT_SCRIPT:
            self.interrupts.append(args[0])
        elif script == code_contexts._KILL_SCRIPT:
            self.kills.append(args[0])
        elif script == code_contexts._IDLE_SCRIPT:
            return ExecResult(exit_code=0 if self.idle else 1)
        return ExecResult(exit_code=0)  # also: python3 check, rm


def parse_sse(text: str) -> Events:
    """The (event, data) pairs of an event stream; comment frames are skipped."""
    events: Events = []
    for block in text.split("\n\n"):
        if block.strip() and not block.startswith(":"):
            fields = dict(line.split(": ", 1) for line in block.splitlines())
            events.append((fields["event"], json.loads(fields["data"])))
    return events


def joined(events: Events, name: str) -> str:
    return "".join(data["data"] for event, data in events if event == name)


@dataclass
class Session:
    """An org with a key, a started sandbox and a context, plus the helpers the tests share."""

    app: FastAPI
    client: httpx.AsyncClient
    key: str
    org_id: str
    driver: FakeDriver
    shell: Shell
    monkeypatch: pytest.MonkeyPatch
    sandbox_id: str = ""
    context_id: str = ""

    def deliver(self, script: Script) -> None:
        """Deliver ``script(token)`` for the client exec; other execs keep the fake's behaviour."""
        original = self.driver.exec_stream

        async def exec_stream(ref: str, request: ExecRequest) -> AsyncIterator[ExecEvent]:
            if request.argv[0] != "python3":
                async for event in original(ref, request):
                    yield event
                return
            for event in script(request.argv[5]):
                yield event

        self.monkeypatch.setattr(self.driver, "exec_stream", exec_stream)

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.key}"}

    def path(self, *parts: str, context_id: str | None = None) -> str:
        base = f"{BASE}/{self.sandbox_id}/toolbox/code-contexts"
        return "/".join([base, *([context_id or self.context_id] if parts else []), *parts])

    async def stream(
        self, script: Script | None = None, *, context_id: str | None = None, **body: Any
    ) -> tuple[httpx.Response, Events]:
        if script is not None:
            self.deliver(script)
        response = await self.client.post(
            self.path("run", "stream", context_id=context_id),
            headers=self.headers,
            json={"code": "1", **body},
        )
        is_stream = response.headers["content-type"].startswith("text/event-stream")
        return response, parse_sse(response.text) if is_stream else []

    async def stored_sandbox(self) -> Sandbox:
        async with UnitOfWork(self.app.state.session_factory) as uow:
            sandbox = await uow.sandboxes.get(self.org_id, self.sandbox_id)
        assert sandbox is not None
        return sandbox

    def hang_after_one_chunk(self) -> None:
        async def exec_stream(ref: str, request: ExecRequest) -> AsyncIterator[ExecEvent]:
            yield out(b"tick\n")
            await asyncio.Event().wait()  # the cell never ends until it is cancelled

        self.monkeypatch.setattr(self.driver, "exec_stream", exec_stream)


@pytest.fixture(autouse=True)
def quick_waits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(code_contexts, "INTERRUPT_WAIT_S", 0.2)
    monkeypatch.setattr(code_contexts, "INTERRUPT_POLL_S", 0.01)
    monkeypatch.setattr(process_routes, "DISCONNECT_POLL_INTERVAL_S", 0.01)


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'stream.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def session(app: FastAPI, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Session]:
    driver, shell = app.state.driver, Shell()
    assert isinstance(driver, FakeDriver)
    driver.exec_handler = shell
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    generated = generate_api_key(PEPPER)
    scopes = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=scopes,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored)
        await uow.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        current = Session(app, client, generated.key, org.id, driver, shell, monkeypatch)
        created = await client.post(BASE, headers=current.headers, json={})
        current.sandbox_id = created.json()["data"]["id"]
        made = await client.post(current.path(), headers=current.headers, json={})
        assert made.status_code == 201, made.text
        current.context_id = made.json()["data"]["id"]
        yield current


async def test_output_chunks_arrive_before_the_one_result_event(session: Session) -> None:
    response, events = await session.stream(
        lambda t: done(t, out(b"first\n"), err(b"warning\n"), out(b"second\n"))
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert [name for name, _ in events] == ["stdout", "stderr", "stdout", "result"]
    assert events[0][1] == {"data": "first\n"}
    assert joined(events, "stdout") == "first\nsecond\n"
    result = events[-1][1]
    assert (result["stdout"], result["stderr"]) == ("first\nsecond\n", "warning\n")
    assert (result["exit_code"], result["result"], result["stop_reason"]) == (0, "42", None)


async def test_the_result_event_equals_what_run_answers_for_the_same_output(
    session: Session,
) -> None:
    session.shell.cell_result = ExecResult(exit_code=0, stdout=b"hello\n", stderr=b"warn\n")
    run = await session.client.post(
        session.path("run"), headers=session.headers, json={"code": "1"}
    )

    response, events = await session.stream()

    assert response.status_code == 200
    assert events[-1][0] == "result"
    assert {**events[-1][1], "duration_ms": 0} == {**run.json()["data"], "duration_ms": 0}
    assert (joined(events, "stdout"), joined(events, "stderr")) == ("hello\n", "warn\n")


async def test_stdout_goes_by_whole_lines_and_stderr_decodes_split_characters(
    session: Session,
) -> None:
    chunks = [out(b"a\nb"), err(b"caf\xc3"), out(b"c\nd"), err(b"\xa9\xff\n"), out(b"e")]

    _, events = await session.stream(lambda t: done(t, *chunks))

    stdout = [data["data"] for name, data in events if name == "stdout"]
    assert stdout == ["a\n", "bc\n", "de"]  # the partial last line waits for its newline or the end
    assert events[-1][1]["stdout"] == "a\nbc\nde"
    replacement = chr(0xFFFD)  # what the invalid byte 0xff decodes to
    assert joined(events, "stderr") == f"café{replacement}\n"  # the split é is decoded once


@pytest.mark.parametrize("cut", [1, 10, len(code_contexts.OUTCOME_MARK) + 3, -1])
async def test_the_trailer_never_appears_in_a_stdout_event(session: Session, cut: int) -> None:
    def script(token: str) -> list[ExecEvent]:
        line = trailer(token)
        return [out(b"out\n"), out(line[:cut]), out(line[cut:]), ExitEvent(0)]

    response, events = await session.stream(script)

    assert joined(events, "stdout") == "out\n"
    assert "sandfort-outcome" not in response.text
    assert events[-1][1]["result"] == "42"


async def test_a_timeout_ends_with_the_timeout_stop_reason(session: Session) -> None:
    _, events = await session.stream(
        lambda token: [out(b"tick\n"), err(timeout_message(3)), ExitEvent(124, timed_out=True)],
        timeout_s=3,
    )

    # the deadline sentence is held back: it arrives with the interrupted sentence as one tail
    # chunk, just before the result
    assert [name for name, _ in events] == ["stdout", "stderr", "result"]
    assert events[-1][0] == "result"
    result = events[-1][1]
    assert events[1][1]["data"] == result["stderr"]
    assert result["stop_reason"] == "timeout"
    assert (result["timed_out"], result["exit_code"]) == (True, 124)
    assert joined(events, "stderr") == result["stderr"]  # the chunks add up to the result's stderr
    assert "(timeout)" in joined(events, "stderr")
    assert code_contexts.INTERRUPTED_MESSAGE.strip() in result["stderr"]  # in the result only
    assert session.shell.kills == []  # the kernel answered the interrupt: the context is kept


CELL_LIMIT_S = 3
EXEC_TIMEOUT_S = CELL_LIMIT_S + code_contexts.EXEC_MARGIN_S  # what the driver's deadline names


def deadline_cell(cell_stderr: bytes) -> Script:
    """A cell that ignores its interrupt: ``cell_stderr``, then the driver's deadline note.

    The note is what the Docker driver yields as its own chunk, a newline first when the cell's
    stderr does not end with one.
    """

    def script(token: str) -> list[ExecEvent]:
        note = timeout_note(cell_stderr, EXEC_TIMEOUT_S)
        return [out(b"tick\n"), err(cell_stderr), err(note), ExitEvent(124, timed_out=True)]

    return script


def stderr_chunks(events: Events) -> list[str]:
    return [data["data"] for name, data in events if name == "stderr"]


@pytest.mark.parametrize("cell_stderr", [b"warn: busy\n", b"warn: busy"])
async def test_a_cell_that_ignores_its_interrupt_never_streams_the_deadline_sentence(
    session: Session, cell_stderr: bytes
) -> None:
    session.shell.idle = False  # the kernel blocks the interrupt: the context is removed

    _, events = await session.stream(deadline_cell(cell_stderr), timeout_s=CELL_LIMIT_S)

    assert events[-1][0] == "result"
    assert [name for name, _ in events].count("result") == 1
    result = events[-1][1]
    assert (result["stop_reason"], result["exit_code"]) == ("context_lost", 124)
    assert result["timed_out"] is True
    hard_kill = code_contexts.HARD_KILL_TEMPLATE.format(limit_s=CELL_LIMIT_S)
    assert result["stderr"] == f"warn: busy\n{hard_kill}\n{code_contexts.STOPPED_MESSAGE}"
    assert result["stderr"].endswith("\n")
    chunks = stderr_chunks(events)
    assert not [chunk for chunk in chunks if "allow more time" in chunk]
    assert not [chunk for chunk in chunks if f"{EXEC_TIMEOUT_S:g} s" in chunk]
    assert "".join(chunks) == result["stderr"]
    assert chunks[-1].endswith(code_contexts.STOPPED_MESSAGE)  # the tail comes last
    assert session.shell.kills == [code_contexts.context_dir(session.context_id)]


@pytest.mark.parametrize("cell_stderr", [b"warn: busy\n", b"warn: busy"])
async def test_a_kept_context_streams_the_deadline_sentence_last_with_the_interrupted_line(
    session: Session, cell_stderr: bytes
) -> None:
    _, events = await session.stream(deadline_cell(cell_stderr), timeout_s=CELL_LIMIT_S)

    assert events[-1][0] == "result"
    result = events[-1][1]
    assert (result["stop_reason"], result["exit_code"]) == ("timeout", 124)
    deadline = timeout_message(EXEC_TIMEOUT_S).decode()
    assert result["stderr"] == f"warn: busy\n{deadline}\n{code_contexts.INTERRUPTED_MESSAGE}"
    chunks = stderr_chunks(events)
    assert "".join(chunks) == result["stderr"]
    # the deadline sentence was held back and arrives verbatim in the tail, before the result
    assert chunks[-1] == f"{deadline}\n{code_contexts.INTERRUPTED_MESSAGE}"
    assert session.shell.kills == []


def test_the_held_deadline_prefix_is_the_drivers_sentence_up_to_its_number() -> None:
    sentence = timeout_message(EXEC_TIMEOUT_S)

    assert sentence.startswith(code_context_stream.DRIVER_DEADLINE_PREFIX)
    assert sentence[len(code_context_stream.DRIVER_DEADLINE_PREFIX) :].startswith(b"8 s")


@pytest.mark.parametrize("deadline_first", [True, False])
def test_the_stderr_channel_holds_from_the_earliest_driver_line(deadline_first: bool) -> None:
    events = code_context_stream.RunEvents()
    channel = code_context_stream._Channel("stderr", events)
    lines = [timeout_message(EXEC_TIMEOUT_S), code_contexts.DRIVER_DEATH_LINE]

    channel.feed(b"before\n" + b"\n".join(lines if deadline_first else lines[::-1]))
    channel.feed(b"after\n")
    channel.finish()

    assert events.held
    assert events.stderr_sent() == "before\n"


async def test_a_cell_that_prints_the_deadline_prefix_itself_holds_its_stderr_to_the_tail(
    session: Session,
) -> None:
    prefix = code_context_stream.DRIVER_DEADLINE_PREFIX.decode()
    user_line = f"{prefix}the user's own code printed this\n"
    # the cell ends normally: the final stderr is exactly what the executor wrote, no rewording
    written = [err(b"ordinary\n"), err(user_line.encode()), err(b"more ordinary\n")]

    _, events = await session.stream(lambda token: done(token, out(b"tick\n"), *written))

    names = [name for name, _ in events]
    assert names.count("result") == 1
    assert names[-1] == "result"
    result = events[-1][1]
    assert (result["stop_reason"], result["exit_code"]) == (None, 0)
    assert result["stderr"] == f"ordinary\n{user_line}more ordinary\n"
    assert names[-2] == "stderr"  # the tail arrives just before the result
    live = [data["data"] for name, data in events[:-2] if name == "stderr"]
    assert live == ["ordinary\n"]  # the chunks streamed live stop at the anchor
    chunks = stderr_chunks(events)
    assert chunks[-1] == f"{user_line}more ordinary\n"
    assert "".join(chunks) == result["stderr"]


async def test_the_output_limit_ends_with_its_stop_reason_and_interrupts_the_cell(
    session: Session,
) -> None:
    notice = output_cap_message(code_contexts.CLIENT_OUTPUT_LIMIT)

    _, events = await session.stream(
        lambda token: [out(b"x" * 100), err(notice), ExitEvent(137, truncated=True)]
    )

    result = events[-1][1]
    assert (result["stop_reason"], result["truncated"]) == ("output_limit", True)
    assert result["exit_code"] == process_routes.KILLED_EXIT_CODE
    assert joined(events, "stderr") == result["stderr"]
    assert result["stderr"].startswith("the cell was stopped because its output exceeded")
    assert session.shell.interrupts == [code_contexts.context_dir(session.context_id)]


async def test_a_failure_after_the_stream_started_sends_one_error_event(
    session: Session,
) -> None:
    def script(token: str) -> list[ExecEvent]:
        raise DriverError("the daemon went away")

    response, events = await session.stream(script)

    assert response.status_code == 200
    expected = {"code": "INTERNAL", "message": code_context_stream.FAILED_MESSAGE}
    assert events == [("error", expected)]


async def test_an_unknown_context_is_a_404_before_the_stream_starts(session: Session) -> None:
    response, _ = await session.stream(context_id="ctx_0123456789abcdef")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"


async def test_the_stream_is_audited_with_the_details_of_a_run(session: Session) -> None:
    await session.stream(code="x = 1")

    async with UnitOfWork(session.app.state.session_factory) as uow:
        rows = await uow.audit.list(session.org_id, limit=50)
    [row] = [e for e in rows if e.action == "toolbox.code_contexts.run_stream"]
    assert (row.target_id, row.details["context_id"]) == (session.sandbox_id, session.context_id)
    assert row.details["code"]["length"] == len("x = 1")  # the code itself is redacted


async def test_the_operation_is_in_the_openapi_schema_as_an_event_stream() -> None:
    path = "/v1/sandboxes/{sandbox_id}/toolbox/code-contexts/{context_id}/run/stream"

    operation = build_document()["paths"][path]["post"]

    assert operation["summary"].strip()
    assert "`error`" in operation["description"]
    assert list(operation["responses"]["200"]["content"]) == ["text/event-stream"]
    assert operation["requestBody"]["content"]["application/json"]


async def frames_of(session: Session, disconnect_after: int) -> Any:
    """The stream of a cell that never ends; the request is connected for that many polls."""
    session.hang_after_one_chunk()
    body = routes.CodeContextRunRequest(code="while True: pass")
    polls = 0

    async def is_disconnected() -> bool:
        nonlocal polls
        polls += 1
        return polls > disconnect_after

    request: Any = SimpleNamespace(is_disconnected=is_disconnected)
    sandbox = await session.stored_sandbox()
    return routes._stream_frames(request, session.driver, sandbox, session.context_id, body)


async def test_a_client_that_disconnects_interrupts_its_cell(session: Session) -> None:
    frames = await frames_of(session, disconnect_after=5)

    async with asyncio.timeout(WAIT_DEADLINE_S):
        collected = [frame async for frame in frames]

    assert collected[0].startswith("event: stdout\n")
    assert session.shell.interrupts == [code_contexts.context_dir(session.context_id)]
    assert session.shell.kills == []
    assert routes._RUN_LOCKS == {}


async def test_closing_the_stream_interrupts_the_cell_and_frees_the_context(
    session: Session,
) -> None:
    frames = await frames_of(session, disconnect_after=10**9)

    first = await asyncio.wait_for(anext(frames), WAIT_DEADLINE_S)
    await frames.aclose()  # what the server does when the connection is gone

    assert first.startswith("event: stdout\n")
    async with asyncio.timeout(WAIT_DEADLINE_S):
        while not (session.shell.interrupts and routes._RUN_LOCKS == {}):
            await asyncio.sleep(0.01)
    assert session.shell.interrupts == [code_contexts.context_dir(session.context_id)]
    assert session.shell.kills == []
