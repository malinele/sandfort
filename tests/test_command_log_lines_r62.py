# ruff: noqa: F401, F811
"""Command log events carry exactly one line each (round 62).

A chunk with several lines becomes one event per line, an unterminated tail is held until the
next chunk of the same stream or the end of the command, and the event ``id`` stays the byte
offset where the next line starts, so ``Last-Event-ID`` / ``?offset=`` resume exactly after the
last delivered line. Unit tests on ``CommandLog.read_lines`` and API tests over the fake driver.
"""

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest

from sandfort.api.routes.toolbox import sessions as session_routes
from sandfort.drivers.base import ExecEvent, ExecRequest, ExitEvent, OutputChunk
from sandfort.drivers.fake import FakeDriver
from sandfort.toolbox import command_logs
from sandfort.toolbox.command_logs import CommandLog
from test_toolbox_sessions import (
    Script,
    app,
    client,
    create_sandbox,
    create_session,
    driver,
    key,
    org_id,
    parse_sse,
    script,
    send,
    sessions_path,
    start_async,
    wait_for_state,
)

LONG_LINE_BYTES = 3 * command_logs.MAX_LINE_BYTES + 100


def lines_of(log: CommandLog, offset: int = 0) -> list[tuple[str, int, bytes]]:
    return [(line.stream, line.offset, line.data) for line in log.read_lines(offset).lines]


# --- the log store ----------------------------------------------------------------


def test_multi_line_chunk_becomes_one_event_per_line() -> None:
    log = CommandLog()
    log.append("stdout", b"l1\nl2\nl3\n")

    page = log.read_lines(0)

    assert [(line.offset, line.end, line.data) for line in page.lines] == [
        (0, 3, b"l1\n"),
        (3, 6, b"l2\n"),
        (6, 9, b"l3\n"),
    ]
    assert page.next_offset == 9


def test_partial_line_is_held_until_a_later_chunk_completes_it() -> None:
    log = CommandLog()
    log.append("stdout", b"one\ntw")

    first = log.read_lines(0)
    assert [line.data for line in first.lines] == [b"one\n"]
    assert (first.next_offset, first.seen_offset, first.complete) == (4, 6, False)
    log.append("stdout", b"o\nthr")
    second = log.read_lines(first.next_offset)
    assert [(line.offset, line.data) for line in second.lines] == [(4, b"two\n")]
    log.append("stdout", b"ee\n")
    third = log.read_lines(second.next_offset)

    assert [(line.offset, line.data) for line in third.lines] == [(8, b"three\n")]


def test_line_spanning_the_chunk_buffer_cap_stays_one_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(command_logs, "COALESCE_MAX_BYTES", 4)
    log = CommandLog()
    for part in (b"abc", b"def", b"gh\n"):
        log.append("stdout", part)

    assert lines_of(log) == [("stdout", 0, b"abcdefgh\n")]


def test_final_fragment_is_flushed_when_the_command_ends() -> None:
    log = CommandLog()
    log.append("stdout", b"done\ntail")
    held = log.read_lines(0)
    assert [line.data for line in held.lines] == [b"done\n"]
    assert held.complete is False

    log.finish("exited", 0)
    flushed = log.read_lines(held.next_offset)

    assert [(line.offset, line.data) for line in flushed.lines] == [(5, b"tail")]
    assert (flushed.next_offset, flushed.complete) == (9, True)


def test_fragment_is_flushed_when_the_other_stream_writes() -> None:
    log = CommandLog()
    log.append("stdout", b"prompt> ")
    log.append("stderr", b"warn\n")
    log.append("stdout", b"after\n")

    assert lines_of(log) == [
        ("stdout", 0, b"prompt> "),
        ("stderr", 8, b"warn\n"),
        ("stdout", 13, b"after\n"),
    ]


def test_resume_after_n_lines_yields_line_n_plus_one_exactly() -> None:
    log = CommandLog()
    log.append("stdout", b"a\nbb\n")
    log.append("stderr", b"ccc\n")
    log.append("stdout", b"dd\ne")
    log.append("stdout", b"e\nf")
    log.finish("exited", 0)
    everything = log.read_lines(0).lines
    assert [line.data for line in everything] == [b"a\n", b"bb\n", b"ccc\n", b"dd\n", b"ee\n", b"f"]

    for done in range(len(everything)):
        resumed = log.read_lines(everything[done - 1].end if done else 0).lines
        assert resumed == everything[done:]


def test_very_long_single_line_is_cut_into_capped_events() -> None:
    log = CommandLog()
    payload = b"x" * LONG_LINE_BYTES + b"\nnext\n"
    log.append("stdout", payload)
    log.finish("exited", 0)

    page = log.read_lines(0)

    sizes = [len(line.data) for line in page.lines]
    assert max(sizes) <= command_logs.MAX_LINE_BYTES
    assert b"".join(line.data for line in page.lines) == payload
    assert page.lines[-1].data == b"next\n"
    assert page.complete is True


def test_unterminated_long_line_is_emitted_in_capped_pieces_before_the_command_ends() -> None:
    log = CommandLog()
    log.append("stdout", b"y" * (command_logs.MAX_LINE_BYTES + 10))

    page = log.read_lines(0)

    assert [len(line.data) for line in page.lines] == [command_logs.MAX_LINE_BYTES]
    assert page.next_offset == command_logs.MAX_LINE_BYTES
    assert page.seen_offset == command_logs.MAX_LINE_BYTES + 10


def test_read_budget_still_caps_a_page_and_holds_the_cut_line() -> None:
    log = CommandLog()
    log.append("stdout", b"ab\ncdefghij\nk\n")

    first = log.read_lines(0, 5)
    assert [line.data for line in first.lines] == [b"ab\n"]
    second = log.read_lines(first.next_offset, 5)
    assert [line.data for line in second.lines] == [b"cdefg"]  # longer than the page: capped
    rest = log.read_lines(second.next_offset, 64)

    assert [line.data for line in rest.lines] == [b"hij\n", b"k\n"]


def test_crlf_stays_with_its_line_and_a_lone_cr_is_no_line_break() -> None:
    log = CommandLog()
    log.append("stdout", b"win\r\nprogress 1\rprogress 2\r\nend\r")
    log.append("stdout", b"\n")

    assert lines_of(log) == [
        ("stdout", 0, b"win\r\n"),
        ("stdout", 5, b"progress 1\rprogress 2\r\n"),
        ("stdout", 28, b"end\r\n"),
    ]


def test_log_cap_truncates_the_last_line_and_it_is_flushed_at_exit() -> None:
    log = CommandLog(cap=7)
    log.append("stdout", b"abc\ndefgh")
    log.finish("exited", 0)

    page = log.read_lines(0)

    assert [line.data for line in page.lines] == [b"abc\n", b"def"]
    assert (page.truncated, page.complete) == (True, True)


# --- the routes -------------------------------------------------------------------


class Feed:
    """What the fake exec stream yields: chunks, an optional gate, then the exit."""

    def __init__(self) -> None:
        self.before_gate: list[tuple[str, bytes]] = []
        self.after_gate: list[tuple[str, bytes]] = []
        self.gate: asyncio.Event | None = None


@pytest.fixture
def feed(driver: FakeDriver, monkeypatch: pytest.MonkeyPatch) -> Feed:
    state = Feed()

    async def stream(ref: str, request: ExecRequest) -> AsyncIterator[ExecEvent]:
        for name, data in state.before_gate:
            yield OutputChunk(name, data)
        if state.gate is not None:
            await state.gate.wait()
        for name, data in state.after_gate:
            yield OutputChunk(name, data)
        yield ExitEvent(0)

    monkeypatch.setattr(driver, "exec_stream", stream)
    return state


async def started(client: httpx.AsyncClient, key: str, script: Script) -> str:
    sandbox_id = await create_sandbox(client, key)
    session_id = await create_session(client, key, sandbox_id)
    command_id = await start_async(client, key, sandbox_id, session_id, "make")
    return sessions_path(sandbox_id, session_id, "commands", command_id)


async def logs(client: httpx.AsyncClient, key: str, path: str, query: str = "") -> Any:
    return (await send(client, "GET", path + "/logs" + query, key, status=200))["data"]


async def follow(
    client: httpx.AsyncClient, key: str, path: str, last_event_id: str | None = None
) -> list[dict[str, str]]:
    headers = {"Authorization": f"Bearer {key}"}
    if last_event_id is not None:
        headers["Last-Event-ID"] = last_event_id
    return parse_sse((await client.get(path + "/logs/follow", headers=headers)).text)


async def test_get_logs_returns_one_event_per_line(
    client: httpx.AsyncClient, key: str, script: Script, feed: Feed
) -> None:
    feed.before_gate = [("stdout", b"l1\nl2\nl3\n"), ("stderr", b"e1\ne2\n")]
    path = await started(client, key, script)
    await wait_for_state(client, key, path, "exited")

    page = await logs(client, key, path)

    assert [(e["stream"], e["offset"], e["line"]) for e in page["events"]] == [
        ("stdout", 0, "l1\n"),
        ("stdout", 3, "l2\n"),
        ("stdout", 6, "l3\n"),
        ("stderr", 9, "e1\n"),
        ("stderr", 12, "e2\n"),
    ]
    assert (page["next_offset"], page["complete"]) == (15, True)


async def test_follow_sends_one_line_per_event_with_the_next_offset_as_id(
    client: httpx.AsyncClient, key: str, script: Script, feed: Feed
) -> None:
    feed.before_gate = [("stdout", b"l1\nl2\nl3\n")]
    path = await started(client, key, script)
    await wait_for_state(client, key, path, "exited")

    frames = await follow(client, key, path)

    assert [f["event"] for f in frames] == ["stdout", "stdout", "stdout", "exit"]
    assert [json.loads(f["data"])["line"] for f in frames[:3]] == ["l1\n", "l2\n", "l3\n"]
    assert [f["id"] for f in frames] == ["3", "6", "9", "9"]


async def test_partial_line_waits_for_its_end_over_the_api(
    client: httpx.AsyncClient, key: str, script: Script, feed: Feed
) -> None:
    feed.before_gate = [("stdout", b"l1\npar")]
    feed.after_gate = [("stdout", b"tial\nl3")]
    feed.gate = asyncio.Event()
    path = await started(client, key, script)
    for _ in range(300):
        page = await logs(client, key, path)
        if page["events"]:
            break
        await asyncio.sleep(0.01)

    assert [e["line"] for e in page["events"]] == ["l1\n"]
    assert (page["next_offset"], page["complete"], page["state"]) == (3, False, "running")
    feed.gate.set()
    await wait_for_state(client, key, path, "exited")
    final = await logs(client, key, path)

    assert [e["line"] for e in final["events"]] == ["l1\n", "partial\n", "l3"]
    assert (final["next_offset"], final["complete"]) == (13, True)


async def test_follow_flushes_the_final_fragment_at_exit(
    client: httpx.AsyncClient, key: str, script: Script, feed: Feed
) -> None:
    feed.before_gate = [("stdout", b"a\nb")]
    path = await started(client, key, script)
    await wait_for_state(client, key, path, "exited")

    frames = await follow(client, key, path)

    assert [(f["event"], f["id"]) for f in frames] == [
        ("stdout", "2"),
        ("stdout", "3"),
        ("exit", "3"),
    ]
    assert json.loads(frames[1]["data"]) == {"stream": "stdout", "offset": 2, "line": "b"}


async def test_follow_holds_a_fragment_while_running_then_delivers_it_whole() -> None:
    log = CommandLog()
    frames = session_routes._follow_frames(log, 0, lambda state: None)
    log.append("stdout", b"one\ntw")

    first = await asyncio.wait_for(anext(frames), 5)
    pending = asyncio.ensure_future(anext(frames))
    await asyncio.sleep(0.05)
    assert pending.done() is False  # "tw" is held, nothing is sent for it
    log.append("stdout", b"o\n")
    second = await asyncio.wait_for(pending, 5)
    pending = asyncio.ensure_future(anext(frames))
    await asyncio.sleep(0.05)
    log.finish("exited", 0)
    final = await asyncio.wait_for(pending, 5)

    parsed = parse_sse(first + second + final)
    assert [(f["event"], f["id"]) for f in parsed] == [
        ("stdout", "4"),
        ("stdout", "8"),
        ("exit", "8"),
    ]
    assert [json.loads(f["data"])["line"] for f in parsed[:2]] == ["one\n", "two\n"]


async def test_last_event_id_resumes_exactly_after_the_last_delivered_line(
    client: httpx.AsyncClient, key: str, script: Script, feed: Feed
) -> None:
    feed.before_gate = [("stdout", b"a\nbb\nccc\n"), ("stderr", b"dd\ne")]
    path = await started(client, key, script)
    await wait_for_state(client, key, path, "exited")
    full = await follow(client, key, path)
    lines = [json.loads(f["data"])["line"] for f in full[:-1]]
    assert lines == ["a\n", "bb\n", "ccc\n", "dd\n", "e"]

    for done in range(len(lines) + 1):
        last_id = full[done - 1]["id"] if done else None
        resumed = await follow(client, key, path, last_id)
        assert [json.loads(f["data"])["line"] for f in resumed[:-1]] == lines[done:]
        assert resumed[-1]["event"] == "exit"
    paged = await logs(client, key, path, "?offset=" + full[1]["id"])
    assert [e["line"] for e in paged["events"]] == lines[2:]


async def test_crlf_lines_keep_their_terminator_over_the_api(
    client: httpx.AsyncClient, key: str, script: Script, feed: Feed
) -> None:
    feed.before_gate = [("stdout", b"x\r\ny\r\n")]
    path = await started(client, key, script)
    await wait_for_state(client, key, path, "exited")

    page = await logs(client, key, path)

    assert [e["line"] for e in page["events"]] == ["x\r\n", "y\r\n"]
    assert [f["id"] for f in await follow(client, key, path)] == ["3", "6", "6"]


async def test_long_line_is_capped_per_event_and_by_the_log_cap(
    client: httpx.AsyncClient,
    key: str,
    script: Script,
    feed: Feed,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(command_logs, "MAX_LOG_BYTES", 2 * command_logs.MAX_LINE_BYTES + 5)
    feed.before_gate = [("stdout", b"z" * LONG_LINE_BYTES)]
    path = await started(client, key, script)
    await wait_for_state(client, key, path, "exited")

    page = await logs(client, key, path, "?limit=1048576")

    sizes = [len(e["line"]) for e in page["events"]]
    assert sizes == [command_logs.MAX_LINE_BYTES, command_logs.MAX_LINE_BYTES, 5]
    assert (page["truncated"], page["complete"]) == (True, True)
