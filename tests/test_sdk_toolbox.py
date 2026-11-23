"""SDK toolbox facades (fs, git, process sessions, pty) against respx-mocked endpoints."""

import contextlib
import inspect
import io
import json
import sys
from pathlib import Path
from urllib.parse import parse_qs, quote_plus, urlsplit

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
import websockets.asyncio.client  # noqa: E402
import websockets.sync.client  # noqa: E402
from sandfort_sdk import (  # noqa: E402
    AsyncClient,
    Client,
    GitCredential,
    InvalidResponseError,
    LogEvent,
    NotFound,
    SandboxTimeoutError,
    TransportError,
    Unauthorized,
)
from sandfort_sdk._transport import DEFAULT_TIMEOUT_S, HTTP_MARGIN_S  # noqa: E402
from sandfort_sdk.git import LOCAL_WAIT_S, REMOTE_WAIT_S  # noqa: E402
from sandfort_sdk.pty import connect_url  # noqa: E402
from websockets.exceptions import ConnectionClosedError, ConnectionClosedOK  # noqa: E402
from websockets.frames import Close  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOX_URL = f"/v1/sandboxes/{SID}"
TOOLBOX = f"{SANDBOX_URL}/toolbox"
SESSION_ID = "ses_1"
COMMAND_ID = "cmd_1"
SESSION_URL = f"{TOOLBOX}/process/sessions/{SESSION_ID}"
COMMAND_URL = f"{SESSION_URL}/commands/{COMMAND_ID}"
PTY_ID = "pty_1"
PTY_TOKEN = "ct_s3cr3t/+="
PTY_CONNECT_PATH = f"{TOOLBOX}/pty/{PTY_ID}/connect"
GIT_TOKEN = "ghp_SUPERSECRETTOKEN"
CREATED = "2026-10-30T19:26:00Z"
OCTET = "application/octet-stream"
TAR = "application/x-tar"
SSE = "text/event-stream"

ENTRY = {
    "name": "a.txt",
    "path": "/w/a.txt",
    "kind": "file",
    "size_bytes": 5,
    "mode": "644",
    "modified_at": CREATED,
}
SESSION = {
    "id": SESSION_ID,
    "sandbox_id": SID,
    "cwd": "/w",
    "env": {"A": "1"},
    "state": "active",
    "created_at": CREATED,
}
COMMAND = {
    "id": COMMAND_ID,
    "session_id": SESSION_ID,
    "state": "running",
    "exit_code": None,
    "stdout_bytes": 0,
    "stderr_bytes": 0,
    "created_at": CREATED,
    "finished_at": None,
}
PTY = {
    "id": PTY_ID,
    "sandbox_id": SID,
    "state": "open",
    "rows": 40,
    "cols": 120,
    "created_at": CREATED,
}
PTY_CONNECT = {
    "pty_id": PTY_ID,
    "token": PTY_TOKEN,
    "websocket_url": f"ws://sandfort.test{PTY_CONNECT_PATH}",
}
EXEC = {
    "exit_code": 0,
    "stdout": "ok\n",
    "stderr": "",
    "timed_out": False,
    "truncated": False,
    "duration_ms": 3,
}
SANDBOX = {
    "id": SID,
    "name": "demo",
    "state": "started",
    "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
    "network": {"block_all": False},
}

# Server-shaped SSE body: a keepalive, three chunks (one with U+2028, one framed with CRLF),
# the exit event, then a late frame that must never be surfaced.
SSE_BODY = (
    ": keepalive\n\n"
    'event: stdout\nid: 6\ndata: {"stream":"stdout","offset":0,"line":"hello\\n"}\n\n'
    'event: stderr\nid: 10\ndata: {"stream":"stderr","offset":6,"line":"oops"}\n\n'
    "event: stdout\r\nid: 17\r\n"
    'data: {"stream":"stdout","offset":10,"line":"bye x"}\r\n\r\n'
    'event: exit\nid: 17\ndata: {"exit_code":3,"state":"exited","truncated":false}\n\n'
    'event: stdout\nid: 21\ndata: {"stream":"stdout","offset":17,"line":"late"}\n\n'
).encode()
EXPECTED_EVENTS = [
    LogEvent("stdout", 0, "hello\n", next_offset=6),
    LogEvent("stderr", 6, "oops", next_offset=10),
    LogEvent("stdout", 10, "bye x", next_offset=17),
    LogEvent("exit", 17, next_offset=17, exit_code=3, state="exited"),
]


def envelope(data: object) -> dict[str, object]:
    return {"success": True, "data": data, "error": None, "meta": None}


def error_envelope(code: str, message: str) -> dict[str, object]:
    error = {"code": code, "message": message, "details": {}, "request_id": "req_1"}
    return {"success": False, "data": None, "error": error, "meta": None}


async def call(fn, *args, **kwargs):  # type: ignore[no-untyped-def]
    """Invoke a sync or async SDK callable and return its result."""
    result = fn(*args, **kwargs)
    return await result if inspect.isawaitable(result) else result


def dig(obj, path: str):  # type: ignore[no-untyped-def]
    """Follow ``a.b.0.c`` through attributes and sequence indexes."""
    for part in path.split("."):
        obj = obj[int(part)] if part.isdigit() else getattr(obj, part)
    return obj


async def drain(iterable):  # type: ignore[no-untyped-def]
    if hasattr(iterable, "__aiter__"):
        return [item async for item in iterable]
    return list(iterable)


async def first_and_close(stream):  # type: ignore[no-untyped-def]
    if hasattr(stream, "__anext__"):
        item = await anext(stream)
        await stream.aclose()
        return item
    item = next(stream)
    stream.close()
    return item


def chunked(data: bytes, size: int) -> list[bytes]:
    return [data[start : start + size] for start in range(0, len(data), size)]


class TrackedStream(httpx.SyncByteStream, httpx.AsyncByteStream):
    """Response body recording how many chunks were pulled and whether it was released."""

    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.sent = 0
        self.closed = False

    def __iter__(self):  # type: ignore[no-untyped-def]
        for chunk in self.chunks:
            self.sent += 1
            yield chunk

    async def __aiter__(self):  # type: ignore[no-untyped-def]
        for chunk in self.chunks:
            self.sent += 1
            yield chunk

    def close(self) -> None:
        self.closed = True

    async def aclose(self) -> None:
        self.closed = True


def streamed(chunks: list[bytes], content_type: str) -> tuple[TrackedStream, httpx.Response]:
    tracked = TrackedStream(chunks)
    return tracked, httpx.Response(200, headers={"content-type": content_type}, stream=tracked)


class RecordingReader(io.BytesIO):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.read_sizes: list[int | None] = []

    def read(self, size: int | None = -1, /) -> bytes:
        self.read_sizes.append(size)
        return super().read(size)


class NonSeekable(io.BytesIO):
    def seekable(self) -> bool:
        return False


class FakeSocket:
    """Websocket stand-in: echoes what is sent, then closes normally (or with ``fail_with``)."""

    def __init__(self, url: str, kwargs: dict[str, object]) -> None:
        self.url, self.kwargs = url, kwargs
        self.incoming: list[bytes | str] = [b"$ "]
        self.sent: list[bytes] = []
        self.closed = False
        self.fail_with: Exception | None = None

    def _send(self, data: bytes) -> None:
        self.sent.append(data)
        self.incoming.append(data)

    def _recv(self) -> bytes | str:
        if self.incoming:
            return self.incoming.pop(0)
        raise self.fail_with or ConnectionClosedOK(None, None)


class SyncFakeSocket(FakeSocket):
    def send(self, data: bytes) -> None:
        self._send(data)

    def recv(self) -> bytes | str:
        return self._recv()

    def close(self) -> None:
        self.closed = True


class AsyncFakeSocket(FakeSocket):
    async def send(self, data: bytes) -> None:
        self._send(data)

    async def recv(self) -> bytes | str:
        return self._recv()

    async def close(self) -> None:
        self.closed = True


@pytest.fixture
def api():  # type: ignore[no-untyped-def]
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        yield router
        for recorded in router.calls:
            assert recorded.request.headers["authorization"] == f"Bearer {KEY}"


@pytest.fixture(params=["sync", "async"])
def kind(request) -> str:  # type: ignore[no-untyped-def]
    return request.param


@pytest.fixture
async def client(kind):  # type: ignore[no-untyped-def]
    instance = Client(BASE, KEY) if kind == "sync" else AsyncClient(BASE, KEY)
    yield instance
    await call(instance.close if kind == "sync" else instance.aclose)


@pytest.fixture
async def sandbox(api, client):  # type: ignore[no-untyped-def]
    api.get(SANDBOX_URL).respond(200, json=envelope(SANDBOX))
    return await call(client.get, SID)


@pytest.fixture
def sockets(monkeypatch):  # type: ignore[no-untyped-def]
    """Replace both websockets ``connect`` functions with stubs recording each socket."""
    opened: list[FakeSocket] = []

    def sync_connect(url: str, **kwargs: object) -> FakeSocket:
        opened.append(SyncFakeSocket(url, kwargs))
        return opened[-1]

    async def async_connect(url: str, **kwargs: object) -> FakeSocket:
        opened.append(AsyncFakeSocket(url, kwargs))
        return opened[-1]

    monkeypatch.setattr(websockets.sync.client, "connect", sync_connect)
    monkeypatch.setattr(websockets.asyncio.client, "connect", async_connect)
    return opened


# --- every REST call: method, path, payload shape and typed result -------------------------

REST_CASES = [
    # target, args, kwargs, verb, path, json body, query params, status, reply data, probe
    ("fs.list_dir", ("/w",), {}, "GET", "/fs/list", None, {"path": "/w"}, 200,
     {"path": "/w", "entries": [ENTRY]}, ("entries.0.modified_at.year", 2026)),
    ("fs.stat", ("/w/a.txt",), {}, "GET", "/fs/stat", None, {"path": "/w/a.txt"}, 200,
     {"entry": ENTRY}, ("size_bytes", 5)),
    ("fs.mkdir", ("/w/d",), {"mode": "700"}, "POST", "/fs/mkdir",
     {"path": "/w/d", "mode": "700", "parents": True}, None, 200,
     {"path": "/w/d", "created": True}, ("created", True)),
    ("fs.move", ("/a", "/b"), {"overwrite": True}, "POST", "/fs/move",
     {"source": "/a", "destination": "/b", "overwrite": True}, None, 200,
     {"source": "/a", "destination": "/b"}, ("destination", "/b")),
    ("fs.delete", ("/a",), {"recursive": True}, "POST", "/fs/delete",
     {"path": "/a", "recursive": True}, None, 200, {"path": "/a", "deleted": True},
     ("deleted", True)),
    ("git.clone", ("https://h/r.git", "/w/r"), {"branch": "main", "depth": 1}, "POST",
     "/git/clone", {"url": "https://h/r.git", "path": "/w/r", "branch": "main", "depth": 1},
     None, 200, {"path": "/w/r", "output": "Cloning"}, ("output", "Cloning")),
    ("git.status", ("/w/r",), {}, "GET", "/git/status", None, {"path": "/w/r"}, 200,
     {"branch": "main", "ahead": 1, "files": [{"path": "a", "index": "M", "worktree": " "}]},
     ("files.0.index", "M")),
    ("git.add", ("/w/r", ["a", "b"]), {}, "POST", "/git/add",
     {"path": "/w/r", "files": ["a", "b"]}, None, 200, {"path": "/w/r"}, ("output", "")),
    ("git.commit", ("/w/r", "msg"), {"author_name": "Ada", "author_email": "ada@example.com"},
     "POST", "/git/commit",
     {"path": "/w/r", "message": "msg", "author_name": "Ada", "author_email": "ada@example.com"},
     None, 200, {"sha": "abc123"}, ("sha", "abc123")),
    ("git.push", ("/w/r",), {"branch": "main"}, "POST", "/git/push",
     {"path": "/w/r", "remote": "origin", "branch": "main"}, None, 200,
     {"path": "/w/r", "output": "pushed"}, ("output", "pushed")),
    ("git.pull", ("/w/r",), {"remote": "upstream"}, "POST", "/git/pull",
     {"path": "/w/r", "remote": "upstream"}, None, 200, {"path": "/w/r", "output": "pulled"},
     ("output", "pulled")),
    ("process.exec", ("ls",), {}, "POST", "/process/execute",
     {"command": "ls", "timeout_s": 60}, None, 200, EXEC, ("stdout", "ok\n")),
    ("process.create_session", (), {"cwd": "/w", "env": {"A": "1"}}, "POST",
     "/process/sessions", {"cwd": "/w", "env": {"A": "1"}}, None, 201, SESSION,
     ("created_at.year", 2026)),
    ("process.list_sessions", (), {}, "GET", "/process/sessions", None, None, 200,
     [SESSION, {**SESSION, "id": "ses_2"}], ("1.id", "ses_2")),
    ("process.get_session", (SESSION_ID,), {}, "GET", f"/process/sessions/{SESSION_ID}", None,
     None, 200, SESSION, ("env", {"A": "1"})),
    ("process.execute_session_command", (SESSION_ID, "cd /tmp"), {}, "POST",
     f"/process/sessions/{SESSION_ID}/commands",
     {"command": "cd /tmp", "mode": "sync", "timeout_s": 60}, None, 200,
     {"mode": "sync", "cwd": "/tmp", "result": EXEC}, ("result.stdout", "ok\n")),
    ("process.execute_session_command", (SESSION_ID, "make"),
     {"run_async": True, "timeout_s": 9}, "POST", f"/process/sessions/{SESSION_ID}/commands",
     {"command": "make", "mode": "async", "timeout_s": 9}, None, 202,
     {"mode": "async", "cwd": "/w", "command": COMMAND}, ("command.finished", False)),
    ("process.get_command", (SESSION_ID, COMMAND_ID), {}, "GET",
     f"/process/sessions/{SESSION_ID}/commands/{COMMAND_ID}", None, None, 200,
     {**COMMAND, "state": "exited", "exit_code": 0, "finished_at": CREATED},
     ("finished", True)),
    ("process.get_command_logs", (SESSION_ID, COMMAND_ID), {"offset": 6, "limit": 100}, "GET",
     f"/process/sessions/{SESSION_ID}/commands/{COMMAND_ID}/logs", None,
     {"offset": "6", "limit": "100"}, 200,
     {"events": [{"stream": "stderr", "offset": 6, "line": "x"}], "next_offset": 7,
      "truncated": False, "complete": True, "state": "exited", "exit_code": 1},
     ("events.0", LogEvent("stderr", 6, "x"))),
    ("process.kill_command", (SESSION_ID, COMMAND_ID), {}, "POST",
     f"/process/sessions/{SESSION_ID}/commands/{COMMAND_ID}/kill", None, None, 200,
     {**COMMAND, "state": "killed"}, ("state", "killed")),
    ("pty.list_ptys", (), {}, "GET", "/pty", None, None, 200, [PTY], ("0.rows", 40)),
    ("pty.get", (PTY_ID,), {}, "GET", f"/pty/{PTY_ID}", None, None, 200, PTY, ("cols", 120)),
    ("pty.resize", (PTY_ID, 40, 120), {}, "POST", f"/pty/{PTY_ID}/resize",
     {"rows": 40, "cols": 120}, None, 200, PTY, ("rows", 40)),
    ("pty.delete", (PTY_ID,), {}, "DELETE", f"/pty/{PTY_ID}", None, None, 200,
     {**PTY, "state": "closed"}, ("state", "closed")),
]  # fmt: skip


@pytest.mark.parametrize(
    ("target", "args", "kwargs", "verb", "path", "body", "params", "status", "data", "probe"),
    REST_CASES,
    ids=[f"{case[0]}-{index}" for index, case in enumerate(REST_CASES)],
)
async def test_rest_call_shape_and_typed_result(
    api, sandbox, target, args, kwargs, verb, path, body, params, status, data, probe
):
    route = api.route(method=verb, path=f"{TOOLBOX}{path}").respond(status, json=envelope(data))

    result = await call(dig(sandbox, target), *args, **kwargs)

    request = route.calls.last.request
    assert route.call_count == 1
    assert dict(request.url.params) == (params or {})
    if body is None:
        assert request.content == b""
    else:
        assert json.loads(request.content) == body
    attribute, expected = probe
    assert dig(result, attribute) == expected


@pytest.mark.parametrize(
    ("target", "args", "kwargs", "path", "data", "read_timeout"),
    [
        ("process.execute_session_command", (SESSION_ID, "sleep 90"), {"timeout_s": 90},
         f"{SESSION_URL}/commands", {"mode": "sync", "result": EXEC}, 90 + HTTP_MARGIN_S),
        ("process.execute_session_command", (SESSION_ID, "sleep 90"),
         {"timeout_s": 90, "run_async": True}, f"{SESSION_URL}/commands",
         {"mode": "async", "command": COMMAND}, DEFAULT_TIMEOUT_S),
        ("git.clone", ("https://h/r.git", "/w/r"), {}, f"{TOOLBOX}/git/clone",
         {"path": "/w/r"}, REMOTE_WAIT_S + HTTP_MARGIN_S),
        ("git.commit", ("/w/r", "m"), {}, f"{TOOLBOX}/git/commit", {"sha": "x"},
         LOCAL_WAIT_S + HTTP_MARGIN_S),
    ],
)  # fmt: skip
async def test_read_timeout_covers_server_side_budget(
    api, sandbox, target, args, kwargs, path, data, read_timeout
):
    route = api.post(path).respond(200, json=envelope(data))

    await call(dig(sandbox, target), *args, **kwargs)

    assert route.calls.last.request.extensions["timeout"]["read"] == read_timeout


@pytest.mark.parametrize(
    ("target", "args", "kwargs", "match"),
    [
        ("process.execute_session_command", (SESSION_ID, "  "), {}, "must not be empty"),
        ("process.get_command_logs", (SESSION_ID, COMMAND_ID), {"offset": -1}, "offset"),
        ("git.commit", ("/w", " "), {}, "commit message"),
        ("git.add", ("/w", []), {}, "files"),
        ("fs.upload_file", ("/w/f", NonSeekable(b"x")), {}, "size_bytes is required"),
        ("fs.download_file", ("/w/f",), {"chunk_size": 0}, "chunk_size"),
    ],
)
async def test_invalid_arguments_fail_before_any_request(
    api, sandbox, target, args, kwargs, match
):
    with pytest.raises(ValueError, match=match):
        await call(dig(sandbox, target), *args, **kwargs)

    assert api.calls.call_count == 1  # only the sandbox get


# --- fs transfers --------------------------------------------------------------------------


async def test_upload_bytes_sends_exact_body_and_size(api, sandbox):
    route = api.put(f"{TOOLBOX}/fs/upload").respond(
        200, json=envelope({"path": "/w/f", "size_bytes": 5})
    )

    result = await call(sandbox.fs.upload_file, "/w/f", b"hello", overwrite=False, mode="600")

    request = route.calls.last.request
    assert (result.path, result.size_bytes) == ("/w/f", 5)
    assert request.content == b"hello"
    assert request.headers["content-length"] == "5"
    assert dict(request.url.params) == {
        "path": "/w/f",
        "overwrite": "false",
        "mode": "600",
        "size_bytes": "5",
    }


async def test_upload_file_object_streams_bounded_chunks_from_current_position(api, sandbox):
    data = bytes(range(256)) * 40
    source = RecordingReader(data)
    source.seek(240)
    size = len(data) - 240
    route = api.put(f"{TOOLBOX}/fs/upload").respond(
        200, json=envelope({"path": "/w/f", "size_bytes": size})
    )

    result = await call(sandbox.fs.upload_file, "/w/f", source, chunk_size=1000)

    request = route.calls.last.request
    assert result.size_bytes == size
    assert request.content == data[240:]
    assert request.headers["content-length"] == str(size)
    assert "transfer-encoding" not in request.headers
    assert request.url.params["size_bytes"] == str(size)
    assert source.read_sizes == [1000] * 10  # bounded reads, never one read of the whole file


@pytest.mark.parametrize(
    ("method", "content_type"), [("download_file", OCTET), ("download_dir", TAR)]
)
async def test_download_streams_chunks_and_releases_response(api, sandbox, method, content_type):
    tracked, response = streamed([b"abc", b"def", b"gh"], content_type)
    route = api.get(f"{TOOLBOX}/fs/download").mock(return_value=response)

    chunks = await drain(await call(getattr(sandbox.fs, method), "/w/x", chunk_size=3))

    assert chunks == [b"abc", b"def", b"gh"]
    assert tracked.closed
    assert dict(route.calls.last.request.url.params) == {"path": "/w/x"}


async def test_read_bytes_returns_whole_file(api, sandbox):
    tracked, response = streamed([b"hello ", b"world"], OCTET)
    api.get(f"{TOOLBOX}/fs/download").mock(return_value=response)

    assert await call(sandbox.fs.read_bytes, "/w/f") == b"hello world"
    assert tracked.closed


async def test_download_stopped_early_releases_response(api, sandbox):
    tracked, response = streamed([b"aaaa", b"bbbb", b"cccc"], OCTET)
    api.get(f"{TOOLBOX}/fs/download").mock(return_value=response)
    stream = await call(sandbox.fs.download_file, "/w/f", chunk_size=4)

    assert await first_and_close(stream) == b"aaaa"
    assert tracked.closed
    assert tracked.sent < len(tracked.chunks)


@pytest.mark.parametrize(
    ("method", "content_type"), [("download_file", TAR), ("download_dir", OCTET)]
)
async def test_download_kind_mismatch_raises_and_releases(api, sandbox, method, content_type):
    tracked, response = streamed([b"x"], content_type)
    api.get(f"{TOOLBOX}/fs/download").mock(return_value=response)

    with pytest.raises(InvalidResponseError, match="is not a"):
        await call(getattr(sandbox.fs, method), "/w/x")

    assert tracked.closed


@pytest.mark.parametrize(
    ("target", "args", "path"),
    [
        ("fs.download_file", ("/nope",), f"{TOOLBOX}/fs/download"),
        ("process.follow_logs", (SESSION_ID, COMMAND_ID), f"{COMMAND_URL}/logs/follow"),
    ],
)
async def test_streaming_error_status_raises_typed_error(api, sandbox, target, args, path):
    api.get(path).respond(404, json=error_envelope("NOT_FOUND", "gone"))

    with pytest.raises(NotFound, match="gone"):
        await call(dig(sandbox, target), *args)


# --- git credentials -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "args", "extra"),
    [
        ("clone", ("https://h/r.git", "/w/r"), {}),
        ("push", ("/w/r",), {"remote_url": "https://h/r.git"}),
        ("pull", ("/w/r",), {"remote_url": "https://h/r.git"}),
    ],
)
async def test_git_credential_travels_only_in_the_request_body(
    api, sandbox, method, args, extra
):
    route = api.post(f"{TOOLBOX}/git/{method}").respond(
        200, json=envelope({"path": "/w/r", "output": "done"})
    )
    credential = GitCredential("bot", GIT_TOKEN)

    result = await call(getattr(sandbox.git, method), *args, credential=credential, **extra)

    request = route.calls.last.request
    body = json.loads(request.content)
    assert body["credential"] == {"username": "bot", "token": GIT_TOKEN}
    assert all(body[name] == value for name, value in extra.items())
    assert GIT_TOKEN not in str(request.url)
    assert all(GIT_TOKEN not in value for value in request.headers.values())
    shown = [repr(credential), str(credential), repr(result), repr(vars(sandbox.git))]
    assert all(GIT_TOKEN not in text for text in shown)
    assert "bot" in repr(credential)


@pytest.mark.parametrize(("username", "token"), [("", "t"), ("u", "")])
def test_git_credential_rejects_empty_fields(username, token):
    with pytest.raises(ValueError, match="must not be empty"):
        GitCredential(username, token)


# --- follow_logs (server-sent events) ------------------------------------------------------


@pytest.mark.parametrize("chunk_size", [1, 7, len(SSE_BODY)])
async def test_follow_logs_parses_ordered_events_until_exit(api, sandbox, chunk_size):
    tracked, response = streamed(chunked(SSE_BODY, chunk_size), SSE)
    route = api.get(f"{COMMAND_URL}/logs/follow").mock(return_value=response)

    stream = await call(sandbox.process.follow_logs, SESSION_ID, COMMAND_ID, offset=4)
    events = await drain(stream)

    assert events == EXPECTED_EVENTS
    assert events[-1].is_exit and events[-1].exit_code == 3
    assert tracked.closed
    request = route.calls.last.request
    assert dict(request.url.params) == {"offset": "4"}
    assert request.headers["accept"] == SSE


async def test_follow_logs_stopped_early_releases_response(api, sandbox):
    tracked, response = streamed(chunked(SSE_BODY, 16), SSE)
    api.get(f"{COMMAND_URL}/logs/follow").mock(return_value=response)
    stream = await call(sandbox.process.follow_logs, SESSION_ID, COMMAND_ID)

    assert await first_and_close(stream) == EXPECTED_EVENTS[0]
    assert tracked.closed and stream.closed
    assert tracked.sent < len(tracked.chunks)


async def test_follow_logs_context_exit_releases_response(api, sandbox, kind):
    tracked, response = streamed(chunked(SSE_BODY, 16), SSE)
    api.get(f"{COMMAND_URL}/logs/follow").mock(return_value=response)
    stream = await call(sandbox.process.follow_logs, SESSION_ID, COMMAND_ID)

    if kind == "sync":
        with stream:
            first = next(stream)
    else:
        async with stream:
            first = await anext(stream)

    assert first == EXPECTED_EVENTS[0]
    assert tracked.closed


async def test_follow_logs_without_exit_event_raises_transport_error(api, sandbox):
    tracked, response = streamed([SSE_BODY.split(b"event: exit")[0]], SSE)
    api.get(f"{COMMAND_URL}/logs/follow").mock(return_value=response)
    stream = await call(sandbox.process.follow_logs, SESSION_ID, COMMAND_ID)

    with pytest.raises(TransportError, match="before the exit event"):
        await drain(stream)

    assert tracked.closed


# --- pty websocket -------------------------------------------------------------------------


async def test_pty_create_connects_with_token_and_echoes_bytes(api, sandbox, sockets):
    create = api.post(f"{TOOLBOX}/pty").respond(201, json=envelope(PTY_CONNECT))
    resize = api.post(f"{TOOLBOX}/pty/{PTY_ID}/resize").respond(200, json=envelope(PTY))

    session = await call(sandbox.pty.create, rows=30, cols=100, argv=["bash"], env={"T": "x"})
    await call(session.send_bytes, b"echo hi\n")
    socket = sockets[0]
    socket.incoming.append("ready")  # a text frame still surfaces as bytes
    received = await drain(session)
    info = await call(session.resize, 40, 120)
    await call(getattr(session, "aclose", None) or session.close)

    assert received == [b"$ ", b"echo hi\n", b"ready"]
    assert socket.sent == [b"echo hi\n"]
    assert socket.closed
    url = urlsplit(socket.url)
    assert (url.scheme, url.netloc, url.path) == ("ws", "sandfort.test", PTY_CONNECT_PATH)
    assert parse_qs(url.query) == {"token": [PTY_TOKEN]}
    assert "additional_headers" not in socket.kwargs  # the API key never goes to the socket
    assert json.loads(create.calls.last.request.content) == {
        "rows": 30,
        "cols": 100,
        "argv": ["bash"],
        "env": {"T": "x"},
    }
    assert json.loads(resize.calls.last.request.content) == {"rows": 40, "cols": 120}
    assert (info.rows, info.cols) == (40, 120)
    assert session.id == PTY_ID
    assert PTY_TOKEN not in repr(session)


async def test_pty_context_manager_closes_websocket_on_error(api, sandbox, kind, sockets):
    create = api.post(f"{TOOLBOX}/pty").respond(201, json=envelope(PTY_CONNECT))
    session = await call(sandbox.pty.create)

    with pytest.raises(RuntimeError, match="boom"):
        if kind == "sync":
            with session:
                raise RuntimeError("boom")
        else:
            async with session:
                raise RuntimeError("boom")

    assert sockets[0].closed
    assert json.loads(create.calls.last.request.content) == {"rows": 24, "cols": 80}


async def test_pty_rejected_token_close_raises_unauthorized(api, sandbox, sockets):
    api.post(f"{TOOLBOX}/pty").respond(201, json=envelope(PTY_CONNECT))
    session = await call(sandbox.pty.create)
    sockets[0].incoming.clear()
    sockets[0].fail_with = ConnectionClosedError(Close(4401, "invalid token"), None)

    with pytest.raises(Unauthorized, match="token was rejected"):
        await drain(session)


@pytest.mark.parametrize(("code", "expected"), [(4003, 3), (4000, 0), (4255, 255), (4042, 42)])
async def test_pty_exit_code_is_the_close_code_minus_4000(api, sandbox, sockets, code, expected):
    api.post(f"{TOOLBOX}/pty").respond(201, json=envelope(PTY_CONNECT))
    session = await call(sandbox.pty.create)
    sockets[0].fail_with = ConnectionClosedError(Close(code, ""), None)
    assert session.exit_code is None  # the terminal is still running

    received = await drain(session)  # an exit-code close ends the output like a normal close

    assert received == [b"$ "]
    assert session.exit_code == expected


@pytest.mark.parametrize("code", [1000, 1006, 3999, 4256, 4401, 4999])
async def test_pty_exit_code_is_none_for_any_other_close_code(api, sandbox, sockets, code):
    api.post(f"{TOOLBOX}/pty").respond(201, json=envelope(PTY_CONNECT))
    session = await call(sandbox.pty.create)
    sockets[0].fail_with = ConnectionClosedError(Close(code, ""), None)

    with contextlib.suppress(Exception):  # 1006, 4256 and 4401 still raise as before
        await drain(session)

    assert session.exit_code is None


async def test_pty_exit_code_falls_back_to_the_close_code_of_the_socket(api, sandbox, sockets):
    api.post(f"{TOOLBOX}/pty").respond(201, json=envelope(PTY_CONNECT))
    session = await call(sandbox.pty.create)

    await drain(session)  # a normal close without a close frame to read
    sockets[0].close_code = 4007

    assert session.exit_code == 7


async def test_pty_exit_code_stays_none_for_an_abnormal_close_with_an_error(api, sandbox, sockets):
    api.post(f"{TOOLBOX}/pty").respond(201, json=envelope(PTY_CONNECT))
    session = await call(sandbox.pty.create)
    sockets[0].fail_with = ConnectionClosedError(None, None)

    with pytest.raises(TransportError, match="closed abnormally"):
        await drain(session)

    assert session.exit_code is None


async def test_pty_connect_failure_never_leaks_the_token(api, sandbox, monkeypatch):
    def refuse(url: str, **kwargs: object) -> None:
        raise OSError(f"connection refused: {url}")

    async def async_refuse(url: str, **kwargs: object) -> None:
        refuse(url)

    monkeypatch.setattr(websockets.sync.client, "connect", refuse)
    monkeypatch.setattr(websockets.asyncio.client, "connect", async_refuse)
    api.post(f"{TOOLBOX}/pty").respond(201, json=envelope(PTY_CONNECT))

    with pytest.raises(TransportError, match="connection refused") as info:
        await call(sandbox.pty.create)

    message = str(info.value)
    assert PTY_TOKEN not in message
    assert quote_plus(PTY_TOKEN) not in message
    assert info.value.__cause__ is None


def test_connect_url_replaces_a_stale_token_and_keeps_other_params():
    url = urlsplit(connect_url("wss://h/p/connect?a=1&token=stale", "t/+="))

    assert url.scheme == "wss"
    assert parse_qs(url.query) == {"a": ["1"], "token": ["t/+="]}


@pytest.mark.parametrize(
    ("server_url", "expected_scheme"),
    [
        ("https://h/p/connect", "wss"),
        ("http://h/p/connect", "ws"),
        ("wss://h/p/connect", "wss"),
        ("ws://h/p/connect", "ws"),
    ],
)
def test_connect_url_normalizes_http_schemes_to_websocket_schemes(server_url, expected_scheme):
    url = urlsplit(connect_url(server_url, "tok-1"))

    assert url.scheme == expected_scheme
    assert parse_qs(url.query) == {"token": ["tok-1"]}
    assert (url.netloc, url.path) == ("h", "/p/connect")


@pytest.mark.parametrize(
    ("server_url", "base_url", "expected_scheme"),
    [
        ("ws://h/p/connect", "https://h", "wss"),  # older server behind a TLS edge: upgraded
        ("http://h/p/connect", "https://h", "wss"),
        ("ws://H/p/connect", "https://h/", "wss"),  # host case and a trailing slash do not matter
        ("ws://h:8443/p/connect", "https://h:8443", "wss"),
        ("ws://h/p/connect", "http://h", "ws"),  # plain base: left alone
        ("wss://h/p/connect", "https://h", "wss"),
        ("wss://h/p/connect", "http://h", "wss"),
        ("ws://other/p/connect", "https://h", "ws"),  # another host: left alone
        ("ws://h:8000/p/connect", "https://h", "ws"),  # same name, another port: another origin
    ],
)
def test_connect_url_upgrades_ws_to_wss_only_for_an_https_base_on_the_same_host(
    server_url, base_url, expected_scheme
):
    url = urlsplit(connect_url(server_url, "tok-1", base_url))

    assert url.scheme == expected_scheme
    assert parse_qs(url.query) == {"token": ["tok-1"]}


async def test_pty_create_dials_wss_when_the_client_base_url_is_https(kind, sockets):
    secure = "https://sandfort.test"  # the create reply still carries ws://sandfort.test/...
    with respx.mock(base_url=secure, assert_all_called=False) as router:
        router.get(SANDBOX_URL).respond(200, json=envelope(SANDBOX))
        router.post(f"{TOOLBOX}/pty").respond(201, json=envelope(PTY_CONNECT))
        instance = Client(secure, KEY) if kind == "sync" else AsyncClient(secure, KEY)
        try:
            box = await call(instance.get, SID)
            await call(box.pty.create)
        finally:
            await call(instance.close if kind == "sync" else instance.aclose)

    url = urlsplit(sockets[0].url)
    assert (url.scheme, url.netloc, url.path) == ("wss", "sandfort.test", PTY_CONNECT_PATH)
    assert parse_qs(url.query) == {"token": [PTY_TOKEN]}


# --- process.start: a one-call background command ------------------------------------------

SESSIONS_URL = f"{TOOLBOX}/process/sessions"
ASYNC_REPLY = {"mode": "async", "cwd": "/w", "command": COMMAND}
EXITED = {**COMMAND, "state": "exited", "exit_code": 0, "finished_at": CREATED}
POLL_S = 0.01


def mock_start(api):  # type: ignore[no-untyped-def]
    create = api.post(SESSIONS_URL).respond(201, json=envelope(SESSION))
    run = api.post(f"{SESSION_URL}/commands").respond(202, json=envelope(ASYNC_REPLY))
    return create, run


def command_reply(data: dict[str, object]) -> httpx.Response:
    return httpx.Response(200, json=envelope(data))


async def leave_block(handle, kind: str) -> None:  # type: ignore[no-untyped-def]
    if kind == "sync":
        with handle:
            pass
    else:
        async with handle:
            pass


@pytest.fixture
async def handle(api, sandbox):  # type: ignore[no-untyped-def]
    mock_start(api)
    return await call(sandbox.process.start, "make")


async def test_start_creates_a_session_and_runs_the_command_async(api, sandbox):
    create, run = mock_start(api)

    started = await call(
        sandbox.process.start, "npm run dev", cwd="/w", env={"A": "1"}, timeout_s=9
    )

    assert (started.session_id, started.command_id) == (SESSION_ID, COMMAND_ID)
    assert json.loads(create.calls.last.request.content) == {"cwd": "/w", "env": {"A": "1"}}
    sent = json.loads(run.calls.last.request.content)
    assert sent == {"command": "npm run dev", "mode": "async", "timeout_s": 9}


async def test_start_without_timeout_uses_the_default_exec_budget(api, sandbox):
    _, run = mock_start(api)

    await call(sandbox.process.start, "make")

    assert json.loads(run.calls.last.request.content)["timeout_s"] == 60


async def test_start_with_session_id_skips_the_session_create(api, sandbox):
    create, run = mock_start(api)

    started = await call(sandbox.process.start, "make", session_id=SESSION_ID)

    assert not create.called
    assert run.call_count == 1
    assert (started.session_id, started.command_id) == (SESSION_ID, COMMAND_ID)


async def test_start_rejects_cwd_or_env_for_an_existing_session(api, sandbox):
    create, run = mock_start(api)

    with pytest.raises(ValueError, match="session_id"):
        await call(sandbox.process.start, "make", cwd="/w", session_id=SESSION_ID)

    assert not create.called and not run.called


async def test_start_without_a_command_in_the_reply_raises(api, sandbox):
    api.post(SESSIONS_URL).respond(201, json=envelope(SESSION))
    reply = {"mode": "async", "cwd": "/w"}
    api.post(f"{SESSION_URL}/commands").respond(202, json=envelope(reply))

    with pytest.raises(InvalidResponseError):
        await call(sandbox.process.start, "make")


async def test_handle_info_reads_the_command(api, handle):
    route = api.get(COMMAND_URL).respond(200, json=envelope(COMMAND))

    info = await call(handle.info)

    assert (info.id, info.state) == (COMMAND_ID, "running")
    assert route.call_count == 1


async def test_handle_logs_reads_a_page_from_the_offset(api, handle):
    page = {"events": [], "next_offset": 6, "truncated": False, "complete": False}
    route = api.get(f"{COMMAND_URL}/logs").respond(200, json=envelope({**page, "state": "running"}))

    result = await call(handle.logs, 6)

    assert result.next_offset == 6
    assert dict(route.calls.last.request.url.params) == {"offset": "6"}


async def test_handle_follow_streams_events_from_the_offset(api, handle):
    _, response = streamed(chunked(SSE_BODY, 16), SSE)
    route = api.get(f"{COMMAND_URL}/logs/follow").mock(return_value=response)

    events = await drain(await call(handle.follow, 4))

    assert events == EXPECTED_EVENTS
    assert dict(route.calls.last.request.url.params) == {"offset": "4"}


async def test_handle_kill_posts_to_the_kill_path(api, handle):
    route = api.post(f"{COMMAND_URL}/kill").respond(
        200, json=envelope({**COMMAND, "state": "killed"})
    )

    info = await call(handle.kill)

    assert info.state == "killed"
    assert route.call_count == 1


async def test_wait_returns_once_the_command_is_no_longer_running(api, handle):
    replies = [command_reply(COMMAND), command_reply(COMMAND), command_reply(EXITED)]
    route = api.get(COMMAND_URL).mock(side_effect=replies)

    info = await call(handle.wait, timeout_s=5, poll_interval_s=POLL_S)

    assert (info.state, info.exit_code) == ("exited", 0)
    assert route.call_count == 3


async def test_wait_raises_the_timeout_error_while_the_command_keeps_running(api, handle):
    api.get(COMMAND_URL).respond(200, json=envelope(COMMAND))

    with pytest.raises(SandboxTimeoutError, match=COMMAND_ID) as caught:
        await call(handle.wait, timeout_s=0.05, poll_interval_s=POLL_S)

    assert caught.value.state == "running"


@pytest.mark.parametrize("kwargs", [{"poll_interval_s": 0}, {"timeout_s": -1}])
async def test_wait_rejects_invalid_arguments_before_any_request(api, handle, kwargs):
    route = api.get(COMMAND_URL).respond(200, json=envelope(COMMAND))

    with pytest.raises(ValueError, match="must"):
        await call(handle.wait, **kwargs)

    assert not route.called


async def test_leaving_the_block_kills_a_running_command(api, handle, kind):
    api.get(COMMAND_URL).respond(200, json=envelope(COMMAND))
    kill = api.post(f"{COMMAND_URL}/kill").respond(
        200, json=envelope({**COMMAND, "state": "killed"})
    )

    await leave_block(handle, kind)

    assert kill.call_count == 1


async def test_leaving_the_block_keeps_a_finished_command_alone(api, handle, kind):
    api.get(COMMAND_URL).respond(200, json=envelope(EXITED))
    kill = api.post(f"{COMMAND_URL}/kill").respond(200, json=envelope(EXITED))

    await leave_block(handle, kind)

    assert not kill.called


async def test_leaving_the_block_ignores_errors_from_the_kill(api, handle, kind):
    api.get(COMMAND_URL).respond(200, json=envelope(COMMAND))
    kill = api.post(f"{COMMAND_URL}/kill").respond(
        404, json=error_envelope("NOT_FOUND", "command is gone")
    )

    await leave_block(handle, kind)

    assert kill.call_count == 1
