"""CLI v1: typer CliRunner against respx-mocked endpoints, a fake terminal and a socket stub."""

import json
import os
import pty
import queue
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
import websockets.sync.client  # noqa: E402
from sandfort_cli import config, cp_cmd, exec_cmd, shell_cmd  # noqa: E402
from sandfort_cli.cp_cmd import RemotePath, parse_remote  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from typer.testing import CliRunner  # noqa: E402
from websockets.exceptions import ConnectionClosedError, ConnectionClosedOK  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
OTHER_SID = "sbx_01HYYYYYYYYYYYYYYYYYYYYYYY"
SANDBOXES_URL = "/v1/sandboxes"
SANDBOX_URL = f"{SANDBOXES_URL}/{SID}"
TOOLBOX = f"{SANDBOX_URL}/toolbox"
EXEC_URL = f"{TOOLBOX}/process/execute"
UPLOAD_URL = f"{TOOLBOX}/fs/upload"
DOWNLOAD_URL = f"{TOOLBOX}/fs/download"
PTY_ID = "pty_1"
PTY_TOKEN = "ct_s3cr3t"
CREATED = "2026-10-30T19:26:00Z"
OCTET = "application/octet-stream"
RESIZE = "resize"

RUNNER = CliRunner()

PTY_CONNECT = {
    "pty_id": PTY_ID,
    "token": PTY_TOKEN,
    "websocket_url": f"ws://sandfort.test{TOOLBOX}/pty/{PTY_ID}/connect",
}
PTY_INFO = {
    "id": PTY_ID,
    "sandbox_id": SID,
    "state": "open",
    "rows": 50,
    "cols": 200,
    "created_at": CREATED,
}


def envelope(data, next_cursor=None):
    meta = None if next_cursor is None else {"next_cursor": next_cursor}
    return {"success": True, "data": data, "error": None, "meta": meta}


def error_envelope(code, message):
    error = {"code": code, "message": message, "details": {}, "request_id": "req_1"}
    return {"success": False, "data": None, "error": error, "meta": None}


def sandbox_json(state="started", *, sandbox_id=SID, name="demo", isolation=None):
    data = {
        "id": sandbox_id,
        "name": name,
        "state": state,
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
    }
    return data if isolation is None else {**data, "isolation": isolation}


def exec_json(exit_code=0, *, timed_out=False, sandbox_stopped=None):
    data = {
        "exit_code": exit_code,
        "stdout": "out\n",
        "stderr": "err\n",
        "timed_out": timed_out,
        "truncated": False,
        "duration_ms": 3,
    }
    return data if sandbox_stopped is None else {**data, "sandbox_stopped": sandbox_stopped}


def invoke(args, *, as_json=False, terminal=None):
    app = create_app(terminal)
    return RUNNER.invoke(app, (["--json"] if as_json else []) + args)


# --- fixtures ------------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def profile_env(monkeypatch, tmp_path):
    """Keep every test away from the real home directory and any ambient credentials."""
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    return tmp_path / "cfg"


@pytest.fixture
def logged_in():
    return config.save_profile(BASE, KEY)


@pytest.fixture
def api(logged_in):
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        yield router
        for recorded in router.calls:
            assert recorded.request.headers["authorization"] == f"Bearer {KEY}"


@pytest.fixture
def sandbox_route(api):
    return api.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json()))


# --- login and profile ---------------------------------------------------------------------


def test_login_writes_profile_mode_600_and_never_echoes_key(profile_env):
    result = invoke(["login", "--base-url", f"{BASE}/", "--api-key", KEY, "--no-verify"])

    profile = profile_env / config.PROFILE_FILENAME
    assert result.exit_code == 0, result.output
    assert KEY not in result.output
    assert stat.S_IMODE(profile.stat().st_mode) == 0o600
    assert json.loads(profile.read_text()) == {"base_url": BASE, "api_key": KEY}


def test_login_json_mode_reports_profile_without_the_key(profile_env):
    result = invoke(["login", "--base-url", BASE, "--api-key", KEY, "--no-verify"], as_json=True)

    assert result.exit_code == 0, result.output
    assert KEY not in result.output
    assert json.loads(result.stdout) == {
        "profile": str(profile_env / config.PROFILE_FILENAME),
        "key_verified": False,
        "key_status": "not-checked",
    }


def test_login_tightens_an_existing_world_readable_profile(profile_env):
    profile_env.mkdir()
    profile = profile_env / config.PROFILE_FILENAME
    profile.write_text("{}")
    profile.chmod(0o644)

    result = invoke(["login", "--base-url", BASE, "--api-key", KEY, "--no-verify"])

    assert result.exit_code == 0, result.output
    assert stat.S_IMODE(profile.stat().st_mode) == 0o600


def test_login_rejects_a_base_url_without_scheme(profile_env):
    result = invoke(["login", "--base-url", "sandfort.test", "--api-key", KEY])

    assert result.exit_code == 2
    assert "http://" in result.stderr
    assert KEY not in result.output
    assert not (profile_env / config.PROFILE_FILENAME).exists()


def test_commands_require_a_login():
    result = invoke(["sandbox", "list"])

    assert result.exit_code == 1
    assert "not logged in" in result.stderr


def test_environment_overrides_the_stored_profile(monkeypatch, logged_in):
    monkeypatch.setenv(config.BASE_URL_ENV, "http://override.test")
    monkeypatch.setenv(config.API_KEY_ENV, "override-key")

    with respx.mock(base_url="http://override.test") as router:
        route = router.get(SANDBOXES_URL).respond(200, json=envelope([]))
        result = invoke(["sandbox", "list"])

    assert result.exit_code == 0, result.output
    assert route.calls.last.request.headers["authorization"] == "Bearer override-key"
    assert "override-key" not in result.output


def test_settings_repr_hides_the_key():
    assert KEY not in repr(config.Settings(BASE, KEY))


# --- sandbox commands ----------------------------------------------------------------------


@pytest.mark.parametrize("as_json", [False, True])
def test_sandbox_create_posts_name_and_snapshot(api, as_json):
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json("creating")))

    result = invoke(["sandbox", "create", "demo", "--snapshot", "python:3.12"], as_json=as_json)

    body = json.loads(route.calls.last.request.content)
    assert result.exit_code == 0, result.output
    assert (body["name"], body["snapshot"]) == ("demo", "python:3.12")
    assert api.calls.call_count == 1  # no wait requested: no polling
    assert KEY not in result.output
    if as_json:
        assert json.loads(result.stdout)["id"] == SID
    else:
        assert SID in result.stdout and "creating" in result.stdout


def test_sandbox_create_wait_polls_until_started(api):
    api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json("creating")))
    poll = api.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json("started")))

    result = invoke(["sandbox", "create", "demo", "--wait"], as_json=True)

    assert result.exit_code == 0, result.output
    assert poll.called
    assert json.loads(result.stdout)["state"] == "started"


@pytest.mark.parametrize("as_json", [False, True])
def test_sandbox_create_isolation_is_passed_through_and_shown(api, as_json):
    created = sandbox_json("creating", isolation="gvisor")
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(created))

    result = invoke(["sandbox", "create", "demo", "--isolation", "gvisor"], as_json=as_json)

    assert result.exit_code == 0, result.output
    assert json.loads(route.calls.last.request.content)["isolation"] == "gvisor"
    if as_json:
        assert json.loads(result.stdout)["isolation"] == "gvisor"
    else:
        assert "isolation" in result.stdout and "gvisor" in result.stdout


def test_sandbox_create_without_isolation_leaves_the_field_to_the_server(api):
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json("creating")))

    result = invoke(["sandbox", "create", "demo"])

    assert result.exit_code == 0, result.output
    assert "isolation" not in json.loads(route.calls.last.request.content)


def test_sandbox_create_rejects_an_unknown_isolation_choice(api):
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json("creating")))

    result = invoke(["sandbox", "create", "demo", "--isolation", "vm"])

    assert result.exit_code == 2
    assert not route.called
    for tier in ("container", "gvisor", "microvm"):
        assert tier in result.output


@pytest.mark.parametrize("as_json", [False, True])
def test_sandbox_create_surfaces_an_unavailable_tier_message(api, as_json):
    message = "isolation 'microvm' is not available here; available: container, gvisor"
    api.post(SANDBOXES_URL).respond(422, json=error_envelope("UNPROCESSABLE", message))

    result = invoke(["sandbox", "create", "demo", "--isolation", "microvm"], as_json=as_json)

    assert result.exit_code == 1
    if as_json:
        error = json.loads(result.stdout)["error"]
        assert (error["code"], error["message"]) == ("UNPROCESSABLE", message)
    else:
        assert f"error: UNPROCESSABLE: {message}" in result.stderr
        assert result.stdout == ""


def test_sandbox_list_table_has_an_isolation_column_after_state(api):
    first = sandbox_json(name="first", isolation="gvisor")
    second = sandbox_json("stopped", sandbox_id=OTHER_SID, name="second")  # older server
    api.get(SANDBOXES_URL).respond(200, json=envelope([first, second]))

    table = invoke(["sandbox", "list"])
    data = invoke(["sandbox", "list"], as_json=True)

    header = next(line for line in table.stdout.splitlines() if "ISOLATION" in line)
    assert header.index("STATE") < header.index("ISOLATION") < header.index("CPU")
    assert "gvisor" in table.stdout and "container" in table.stdout
    assert [item["isolation"] for item in json.loads(data.stdout)] == ["gvisor", "container"]


def test_sandbox_get_shows_the_isolation_after_the_state(api):
    api.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json(isolation="microvm")))

    table = invoke(["sandbox", "get", SID])
    data = invoke(["sandbox", "get", SID], as_json=True)

    rows = [line for line in table.stdout.splitlines() if "isolation" in line]
    assert len(rows) == 1 and "microvm" in rows[0]
    assert table.stdout.index("state") < table.stdout.index("isolation")
    assert json.loads(data.stdout)["isolation"] == "microvm"


ISOLATION_URL = "/v1/isolation"
ISOLATION_DATA = {"default": "container", "available": ["container", "gvisor"]}


def test_sandbox_isolation_prints_the_default_and_available_tiers(api):
    route = api.get(ISOLATION_URL).respond(200, json=envelope(ISOLATION_DATA))

    result = invoke(["sandbox", "isolation"])

    assert result.exit_code == 0, result.output
    assert route.call_count == 1
    rows = {line.split("│")[1].strip(): line for line in result.stdout.splitlines() if "│" in line}
    assert "yes" in rows["container"] and "yes" not in rows["gvisor"]
    assert "microvm" not in result.stdout


def test_sandbox_isolation_json_prints_the_object(api):
    api.get(ISOLATION_URL).respond(200, json=envelope(ISOLATION_DATA))

    result = invoke(["sandbox", "isolation"], as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == ISOLATION_DATA


@pytest.mark.parametrize("as_json", [False, True])
def test_sandbox_list_follows_pages_and_renders(api, as_json):
    first = sandbox_json(name="first")
    second = sandbox_json("stopped", sandbox_id=OTHER_SID, name="second")
    route = api.get(SANDBOXES_URL)
    route.side_effect = [
        httpx.Response(200, json=envelope([first], next_cursor="c1")),
        httpx.Response(200, json=envelope([second])),
    ]

    result = invoke(["sandbox", "list"], as_json=as_json)

    assert result.exit_code == 0, result.output
    assert route.call_count == 2
    assert route.calls.last.request.url.params["cursor"] == "c1"
    if as_json:
        assert [item["id"] for item in json.loads(result.stdout)] == [SID, OTHER_SID]
    else:
        for expected in (SID, OTHER_SID, "first", "second", "stopped"):
            assert expected in result.stdout


SANDBOX_ACTIONS = [
    ("get", "GET", "", "started"),
    ("stop", "POST", "/stop", "stopped"),
    ("start", "POST", "/start", "started"),
    ("rm", "DELETE", "", "destroying"),
]


@pytest.mark.parametrize("as_json", [False, True])
@pytest.mark.parametrize(("command", "method", "suffix", "state"), SANDBOX_ACTIONS)
def test_sandbox_action_sends_request_and_renders(api, command, method, suffix, state, as_json):
    route = api.request(method, f"{SANDBOX_URL}{suffix}").respond(
        200, json=envelope(sandbox_json(state))
    )

    result = invoke(["sandbox", command, SID], as_json=as_json)

    assert result.exit_code == 0, result.output
    assert route.call_count == 1
    assert KEY not in result.output
    if as_json:
        payload = json.loads(result.stdout)
        assert (payload["id"], payload["state"]) == (SID, state)
    elif command == "rm":
        assert result.stdout == f"{SID}\n"
    else:
        assert "FIELD" in result.stdout and SID in result.stdout and state in result.stdout


def test_api_errors_print_one_line_and_exit_1(api):
    api.get(SANDBOX_URL).respond(404, json=error_envelope("NOT_FOUND", "no such sandbox"))

    result = invoke(["sandbox", "get", SID])

    assert result.exit_code == 1
    assert "error: " in result.stderr and "no such sandbox" in result.stderr
    assert result.stdout == ""


# --- exec ----------------------------------------------------------------------------------


def test_exec_prints_streams_and_exits_with_the_remote_code(api, sandbox_route):
    route = api.post(EXEC_URL).respond(200, json=envelope(exec_json(3)))

    result = invoke(["exec", SID, "sh", "-c", "exit 3"])

    assert result.exit_code == 3
    assert result.stdout == "out\n"
    assert result.stderr == "err\n"
    body = json.loads(route.calls.last.request.content)
    assert body["argv"] == ["sh", "-c", "exit 3"]
    assert "cwd" not in body


def test_exec_options_precede_the_sandbox_id(api, sandbox_route):
    route = api.post(EXEC_URL).respond(200, json=envelope(exec_json(0)))

    result = invoke(["exec", "--cwd", "/w", "-t", "5", SID, "ls", "-la"])

    body = json.loads(route.calls.last.request.content)
    assert result.exit_code == 0, result.output
    assert (body["argv"], body["cwd"], body["timeout_s"]) == (["ls", "-la"], "/w", 5)


def test_exec_json_mode_emits_the_result_and_keeps_the_exit_code(api, sandbox_route):
    api.post(EXEC_URL).respond(200, json=envelope(exec_json(7)))

    result = invoke(["exec", SID, "false"], as_json=True)

    payload = json.loads(result.stdout)
    assert result.exit_code == 7
    assert (payload["exit_code"], payload["stdout"], payload["stderr"]) == (7, "out\n", "err\n")


def test_exec_timeout_exits_124(api, sandbox_route):
    api.post(EXEC_URL).respond(200, json=envelope(exec_json(0, timed_out=True)))

    result = invoke(["exec", SID, "sleep", "99"])

    assert result.exit_code == 124
    assert "timed out" in result.stderr


STOPPED_HINT = "sandfort: the sandbox has stopped; start it again with: sandfort sandbox start"


def test_exec_hints_how_to_restart_a_stopped_sandbox_and_keeps_the_exit_code(api, sandbox_route):
    api.post(EXEC_URL).respond(200, json=envelope(exec_json(137, sandbox_stopped=True)))

    result = invoke(["exec", SID, "stress"])

    assert result.exit_code == 137
    assert result.stdout == "out\n"
    assert result.stderr == f"err\n{STOPPED_HINT} {SID}\n"


def test_exec_starts_the_stopped_hint_on_its_own_line_after_unterminated_stderr(api, sandbox_route):
    sentence = "the sandbox was stopped while the command was running; start it again"
    payload = exec_json(137, sandbox_stopped=True)
    payload["stderr"] = sentence
    api.post(EXEC_URL).respond(200, json=envelope(payload))

    result = invoke(["exec", SID, "sleep", "60"])

    assert result.exit_code == 137
    assert result.stderr == f"{sentence}\n{STOPPED_HINT} {SID}\n"


def test_exec_inserts_no_blank_line_before_the_stopped_hint_after_terminated_stderr(
    api, sandbox_route
):
    sentence = "the sandbox was stopped while the command was running; start it again"
    payload = exec_json(137, sandbox_stopped=True)
    payload["stderr"] = f"{sentence}\n"
    api.post(EXEC_URL).respond(200, json=envelope(payload))

    result = invoke(["exec", SID, "sleep", "60"])

    assert result.exit_code == 137
    assert result.stderr == f"{sentence}\n{STOPPED_HINT} {SID}\n"


def test_exec_closes_the_stderr_line_once_when_timed_out_and_stopped(api, sandbox_route):
    payload = exec_json(0, timed_out=True, sandbox_stopped=True)
    payload["stderr"] = "partial"
    api.post(EXEC_URL).respond(200, json=envelope(payload))

    result = invoke(["exec", SID, "sleep", "60"])

    assert result.exit_code == 124
    assert result.stderr.startswith("partial\n")
    assert "\n\n" not in result.stderr
    assert result.stderr.endswith(f"{STOPPED_HINT} {SID}\n")


def test_exec_hint_uses_the_reference_the_user_passed(api, sandbox_route):
    listing(api, sandbox_json(name="marek-1"))
    api.post(EXEC_URL).respond(200, json=envelope(exec_json(137, sandbox_stopped=True)))

    result = invoke(["exec", "marek-1", "stress"])

    assert result.exit_code == 137
    assert f"{STOPPED_HINT} marek-1\n" in result.stderr


@pytest.mark.parametrize("sandbox_stopped", [None, False])
def test_exec_prints_no_hint_when_the_sandbox_is_running(api, sandbox_route, sandbox_stopped):
    payload = exec_json(137, sandbox_stopped=sandbox_stopped)
    api.post(EXEC_URL).respond(200, json=envelope(payload))

    result = invoke(["exec", SID, "kill", "-9", "$$"])

    assert result.exit_code == 137
    assert result.stderr == "err\n"


# --- cp ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("arg", "expected"),
    [
        (f"{SID}:/w/a.txt", RemotePath(SID, "/w/a.txt")),
        (f"{SID}:rel/a.txt", RemotePath(SID, "rel/a.txt")),
        (f"{SID}:", RemotePath(SID, "")),
        ("/tmp/a.txt", None),
        ("./odd:name", None),
        ("dir/odd:name", None),
        (":/x", None),
        ("plain", None),
    ],
)
def test_parse_remote_follows_the_scp_rule(arg, expected):
    assert parse_remote(arg) == expected


def test_cp_uploads_then_downloads_byte_identical(api, sandbox_route, tmp_path):
    data = os.urandom(3 * cp_cmd.CHUNK_BYTES + 17)  # several chunks plus a ragged tail
    source = tmp_path / "in.bin"
    source.write_bytes(data)
    stored = {}

    def on_upload(request):
        stored["body"] = request.read()
        stored["path"] = request.url.params["path"]
        payload = {"path": stored["path"], "size_bytes": len(stored["body"])}
        return httpx.Response(200, json=envelope(payload))

    def on_download(request):
        assert request.url.params["path"] == "/w/in.bin"
        return httpx.Response(200, content=stored["body"], headers={"content-type": OCTET})

    api.put(UPLOAD_URL).mock(side_effect=on_upload)
    api.get(DOWNLOAD_URL).mock(side_effect=on_download)
    target = tmp_path / "out.bin"

    up = invoke(["cp", str(source), f"{SID}:/w/in.bin"], as_json=True)
    down = invoke(["cp", f"{SID}:/w/in.bin", str(target)], as_json=True)

    assert up.exit_code == 0, up.output
    assert down.exit_code == 0, down.output
    assert stored["body"] == data
    assert stored["path"] == "/w/in.bin"
    assert json.loads(up.stdout)["bytes"] == len(data)
    assert json.loads(down.stdout)["bytes"] == len(data)
    assert target.read_bytes() == data
    assert not (tmp_path / "out.bin.part").exists()


def test_cp_download_into_a_directory_uses_the_remote_name(api, sandbox_route, tmp_path):
    api.get(DOWNLOAD_URL).respond(200, content=b"hello", headers={"content-type": OCTET})

    result = invoke(["cp", f"{SID}:/w/hello.txt", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert (tmp_path / "hello.txt").read_bytes() == b"hello"


def test_cp_failed_download_leaves_no_files_behind(api, sandbox_route, tmp_path):
    api.get(DOWNLOAD_URL).respond(404, json=error_envelope("NOT_FOUND", "no such file"))
    target = tmp_path / "out.bin"

    result = invoke(["cp", f"{SID}:/nope", str(target)])

    assert result.exit_code == 125
    assert "no such file" in result.stderr
    assert not target.exists()
    assert not (tmp_path / "out.bin.part").exists()


def test_cp_rejects_a_missing_local_file(api, sandbox_route, tmp_path):
    result = invoke(["cp", str(tmp_path / "absent"), f"{SID}:/w/x"])

    assert result.exit_code == 2
    assert "no such file:" in result.stderr


@pytest.mark.parametrize(
    ("source", "destination"),
    [("local-a", "local-b"), (f"{SID}:/a", f"{OTHER_SID}:/b")],
)
def test_cp_needs_exactly_one_remote_side(source, destination):
    result = invoke(["cp", source, destination])

    assert result.exit_code == 2
    assert "exactly one" in result.stderr


# --- shell ---------------------------------------------------------------------------------


class FakeTerminal:
    """Scripted terminal seam: records calls and never touches a real tty."""

    def __init__(self, script, size=(40, 120)):
        self.script = list(script)
        self.rows, self.cols = size
        self.raw_calls = 0
        self.restore_calls = 0
        self.output = []
        self.fail_write = False
        self.on_resize = None

    def size(self):
        return self.rows, self.cols

    def require_interactive(self):
        pass

    def enter_raw(self):
        self.raw_calls += 1

    def restore(self):
        self.restore_calls += 1

    def watch_resize(self, on_resize):
        self.on_resize = on_resize

    def read_input(self, timeout_s):
        if not self.script:
            return b""
        item = self.script.pop(0)
        if item == RESIZE:
            self.rows, self.cols = 50, 200
            self.on_resize()
            return None
        return item

    def write_output(self, data):
        if self.fail_write:
            raise RuntimeError("terminal write failed")
        self.output.append(data)


class QueueSocket:
    """Websocket stand-in: echoes what is sent; ``recv`` blocks until fed, closed or failed."""

    def __init__(self, url, incoming):
        self.url = url
        self.sent = []
        self.closed = False
        self.inbox = queue.Queue()
        for item in incoming:
            self.inbox.put(item)

    def send(self, data):
        self.sent.append(data)
        self.inbox.put(data)

    def recv(self):
        item = self.inbox.get(timeout=5)
        if item is None:
            raise ConnectionClosedOK(None, None)
        if isinstance(item, Exception):
            raise item
        return item

    def close(self):
        self.closed = True
        self.inbox.put(None)


class SocketHub:
    def __init__(self):
        self.incoming = [b"$ "]
        self.opened = []

    def connect(self, url, **kwargs):
        self.opened.append(QueueSocket(url, list(self.incoming)))
        return self.opened[-1]


@pytest.fixture
def hub(monkeypatch):
    stub = SocketHub()
    monkeypatch.setattr(websockets.sync.client, "connect", stub.connect)
    return stub


@pytest.fixture
def pty_create(api, sandbox_route):
    return api.post(f"{TOOLBOX}/pty").respond(200, json=envelope(PTY_CONNECT))


def test_shell_pumps_bytes_both_ways_and_restores_once(pty_create, hub):
    terminal = FakeTerminal([b"ls\n", b"exit\n"])

    result = invoke(["shell", SID], terminal=terminal)

    socket = hub.opened[0]
    assert result.exit_code == 0, result.output
    assert socket.sent == [b"ls\n", b"exit\n"]
    assert terminal.output == [b"$ ", b"ls\n", b"exit\n"]
    assert (terminal.raw_calls, terminal.restore_calls) == (1, 1)
    assert socket.closed
    assert json.loads(pty_create.calls.last.request.content) == {"rows": 40, "cols": 120}
    assert f"token={PTY_TOKEN}" in socket.url
    assert PTY_TOKEN not in result.output


def test_shell_restores_once_when_the_websocket_fails(pty_create, hub):
    hub.incoming = [b"$ ", ConnectionClosedError(None, None)]
    terminal = FakeTerminal([])

    result = invoke(["shell", SID], terminal=terminal)

    assert result.exit_code == 125
    assert "closed abnormally" in result.stderr
    assert terminal.output == [b"$ "]
    assert (terminal.raw_calls, terminal.restore_calls) == (1, 1)


def test_shell_hints_how_to_start_a_sandbox_that_is_not_running(api, sandbox_route):
    message = NOT_RUNNING_MESSAGES[0]
    api.post(f"{TOOLBOX}/pty").respond(409, json=error_envelope("CONFLICT", message))
    terminal = FakeTerminal([])

    result = invoke(["shell", SID], terminal=terminal)

    assert result.exit_code == 125
    assert result.stderr.startswith(f"error: CONFLICT: {message}")
    assert result.stderr.endswith(f"\nstart it with: sandfort sandbox start {SID}\n")
    assert terminal.raw_calls == 0


def test_shell_not_running_adds_a_hint_field_in_json_mode(api, sandbox_route):
    message = NOT_RUNNING_MESSAGES[0]
    api.post(f"{TOOLBOX}/pty").respond(409, json=error_envelope("CONFLICT", message))

    result = invoke(["shell", SID], as_json=True, terminal=FakeTerminal([]))

    assert result.exit_code == 125
    error = json.loads(result.stdout)["error"]
    assert error["hint"] == f"start it with: sandfort sandbox start {SID}"


def test_shell_restores_once_when_the_terminal_write_raises(pty_create, hub):
    terminal = FakeTerminal([])
    terminal.fail_write = True

    result = invoke(["shell", SID], terminal=terminal)

    assert isinstance(result.exception, RuntimeError)
    assert result.exit_code == 1
    assert (terminal.raw_calls, terminal.restore_calls) == (1, 1)


def test_shell_propagates_terminal_resizes(api, pty_create, hub):
    resize = api.post(f"{TOOLBOX}/pty/{PTY_ID}/resize").respond(200, json=envelope(PTY_INFO))
    terminal = FakeTerminal([b"a", RESIZE, b"b"])

    result = invoke(["shell", SID], terminal=terminal)

    assert result.exit_code == 0, result.output
    assert resize.call_count == 1
    assert json.loads(resize.calls.last.request.content) == {"rows": 50, "cols": 200}
    assert hub.opened[0].sent == [b"a", b"b"]
    assert terminal.restore_calls == 1


def test_posix_terminal_restore_without_raw_mode_is_a_no_op():
    shell_cmd.PosixTerminal().restore()


# --- sandbox names -------------------------------------------------------------------------

THIRD_SID = "sbx_01HXXXXXXXXXXXXXXXXXXXXXXX"


def listing(api, *items):
    return api.get(SANDBOXES_URL).respond(200, json=envelope(list(items)))


def test_an_id_reference_is_used_as_is_without_listing(api, sandbox_route):
    index = listing(api)

    result = invoke(["sandbox", "get", SID], as_json=True)

    assert result.exit_code == 0, result.output
    assert index.call_count == 0
    assert sandbox_route.call_count == 1


def test_a_unique_name_resolves_to_its_id(api, sandbox_route):
    listing(
        api,
        sandbox_json(sandbox_id=OTHER_SID, name="other"),
        sandbox_json(name="marek-1"),
    )

    result = invoke(["sandbox", "get", "marek-1"], as_json=True)

    assert result.exit_code == 0, result.output
    assert sandbox_route.call_count == 1
    assert json.loads(result.stdout)["id"] == SID


def test_a_destroyed_sandbox_with_the_name_is_ignored(api, sandbox_route):
    listing(
        api,
        sandbox_json("destroyed", sandbox_id=OTHER_SID, name="marek-1"),
        sandbox_json(name="marek-1"),
    )

    result = invoke(["sandbox", "get", "marek-1"], as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["id"] == SID


def test_a_live_sandbox_wins_over_one_in_error_with_the_same_name(api, sandbox_route):
    listing(
        api,
        sandbox_json("error", sandbox_id=OTHER_SID, name="marek-1"),
        sandbox_json("stopped", name="marek-1"),
    )

    result = invoke(["sandbox", "get", "marek-1"], as_json=True)

    assert result.exit_code == 0, result.output
    assert sandbox_route.call_count == 1


def test_an_ambiguous_name_lists_the_candidate_ids(api, sandbox_route):
    listing(
        api,
        sandbox_json(name="marek-1"),
        sandbox_json("stopped", sandbox_id=OTHER_SID, name="marek-1"),
        sandbox_json("error", sandbox_id=THIRD_SID, name="marek-1"),
    )

    result = invoke(["sandbox", "get", "marek-1"])

    assert result.exit_code == 1
    assert SID in result.stderr and OTHER_SID in result.stderr
    assert THIRD_SID not in result.stderr
    assert sandbox_route.call_count == 0


def test_an_unknown_name_says_what_to_pass_instead(api, sandbox_route):
    listing(api, sandbox_json(name="other"))

    result = invoke(["sandbox", "get", "marek-1"])

    expected = (
        "error: NOT_FOUND: no sandbox named 'marek-1'; "
        "pass an id (sbx_...) or the name of an existing sandbox\n"
    )
    assert result.exit_code == 1
    assert result.stderr == expected
    assert sandbox_route.call_count == 0


def test_names_resolve_for_stop_and_cp(api, sandbox_route, tmp_path):
    listing(api, sandbox_json(name="marek-1"))
    stop = api.post(f"{SANDBOX_URL}/stop").respond(200, json=envelope(sandbox_json("stopped")))
    upload = api.put(UPLOAD_URL).respond(200, json=envelope({"path": "/w/a.txt", "size_bytes": 2}))
    source = tmp_path / "a.txt"
    source.write_text("hi")

    stopped = invoke(["sandbox", "stop", "marek-1"], as_json=True)
    copied = invoke(["cp", str(source), "marek-1:/w/a.txt"], as_json=True)

    assert stopped.exit_code == 0, stopped.output
    assert copied.exit_code == 0, copied.output
    assert stop.call_count == 1 and upload.call_count == 1


# --- machine-readable errors with --json ---------------------------------------------------


def test_json_mode_reports_an_api_error_as_an_object_on_stdout(api):
    api.get(SANDBOX_URL).respond(404, json=error_envelope("NOT_FOUND", "no such sandbox"))

    result = invoke(["sandbox", "get", SID], as_json=True)

    assert result.exit_code == 1
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "error": {
            "code": "NOT_FOUND",
            "message": "no such sandbox",
            "details": {},
            "request_id": "req_1",
        }
    }


def test_json_mode_reports_a_failed_sandbox_with_its_id_and_state(api):
    failed = sandbox_json("error")
    failed["error_reason"] = "image pull failed"
    api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json("creating")))
    api.get(SANDBOX_URL).respond(200, json=envelope(failed))
    delete = api.delete(SANDBOX_URL).respond(200, json=envelope(sandbox_json("destroying")))

    result = invoke(["sandbox", "create", "demo", "--wait"], as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == 1
    assert delete.call_count == 1  # the SDK removes the failed sandbox before raising
    assert result.stderr == ""
    assert (error["code"], error["sandbox_id"], error["state"]) == ("SANDBOX_FAILED", SID, "error")
    assert "image pull failed" in error["message"]
    assert (error["details"], error["request_id"]) == ({}, None)


def test_json_mode_reports_a_name_miss_with_the_not_found_code_and_no_source(api):
    listing(api)

    result = invoke(["sandbox", "get", "marek-1"], as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == 1
    assert error["code"] == "NOT_FOUND"
    assert "source" not in error  # the list call reached the server
    assert error["message"].startswith("no sandbox named 'marek-1'")
    assert (error["details"], error["request_id"]) == ({}, None)


def test_plain_errors_stay_text_on_stderr_after_a_json_run(api):
    api.get(SANDBOX_URL).respond(404, json=error_envelope("NOT_FOUND", "no such sandbox"))

    invoke(["sandbox", "get", SID], as_json=True)
    result = invoke(["sandbox", "get", SID])

    assert result.exit_code == 1
    assert result.stdout == ""
    assert result.stderr == "error: NOT_FOUND: no such sandbox (request id req_1)\n"


# --- exec exit codes -----------------------------------------------------------------------


def test_exec_exits_125_when_the_platform_fails(api):
    api.get(SANDBOX_URL).respond(404, json=error_envelope("NOT_FOUND", "no such sandbox"))

    result = invoke(["exec", SID, "true"])

    assert result.exit_code == 125
    assert result.stderr == "error: NOT_FOUND: no such sandbox (request id req_1)\n"


def test_exec_exits_125_for_an_unknown_name_and_reports_json(api):
    listing(api)

    result = invoke(["exec", "marek-1", "true"], as_json=True)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == 125
    assert error["code"] == "NOT_FOUND"
    assert "source" not in error


def test_exec_runs_in_the_sandbox_found_by_name(api, sandbox_route):
    listing(api, sandbox_json(name="marek-1"))
    run = api.post(EXEC_URL).respond(200, json=envelope(exec_json(0)))

    result = invoke(["exec", "marek-1", "echo", "hi"])

    assert result.exit_code == 0, result.output
    assert json.loads(run.calls.last.request.content)["argv"] == ["echo", "hi"]


@pytest.mark.parametrize("remote_code", [1, 3, 125])
def test_exec_passes_the_remote_exit_code_through(api, sandbox_route, remote_code):
    api.post(EXEC_URL).respond(200, json=envelope(exec_json(remote_code)))

    result = invoke(["exec", SID, "sh", "-c", f"exit {remote_code}"])

    assert result.exit_code == remote_code


# --- exec: stdin, leading "--", sandbox not running ---------------------------------------


STDIN_WARNING = "sandfort: stdin is not forwarded to the command; pass -i to send it\n"


def invoke_with_input(args, data):
    return RUNNER.invoke(create_app(None), args, input=data)


@pytest.fixture
def fake_stdin(monkeypatch, tmp_path):
    """Point the CLI's stdin file descriptor at a pipe, a regular file, /dev/null or a tty."""
    opened = []

    def attach(kind):
        if kind == "pipe":
            fds = list(os.pipe())
            stdin_fd = fds[0]
        elif kind == "file":
            path = tmp_path / "in.txt"
            path.write_text("x")
            fds = [os.open(path, os.O_RDONLY)]
            stdin_fd = fds[0]
        elif kind == "devnull":
            fds = [os.open(os.devnull, os.O_RDONLY)]
            stdin_fd = fds[0]
        else:
            try:
                fds = list(pty.openpty())
            except OSError:
                pytest.skip("no pseudo-terminal available")
            stdin_fd = fds[1]
        opened.extend(fds)
        monkeypatch.setattr(exec_cmd, "stdin_fileno", lambda: stdin_fd)

    yield attach
    for fd in opened:
        os.close(fd)


def forbid_stdin_read(monkeypatch):
    def fail():
        raise AssertionError("stdin must not be read without -i")

    monkeypatch.setattr(exec_cmd, "read_stdin_text", fail)


@pytest.mark.parametrize("flag", ["-i", "--stdin"])
def test_exec_stdin_flag_forwards_piped_stdin(api, sandbox_route, flag):
    route = api.post(EXEC_URL).respond(200, json=envelope(exec_json(0)))

    result = invoke_with_input(["exec", flag, SID, "python", "-"], "print(1)\n")

    body = json.loads(route.calls.last.request.content)
    assert result.exit_code == 0, result.output
    assert (body["argv"], body["stdin"]) == (["python", "-"], "print(1)\n")


def test_exec_stdin_flag_prints_no_warning_for_a_pipe(api, sandbox_route, fake_stdin):
    api.post(EXEC_URL).respond(200, json=envelope(exec_json(0)))
    fake_stdin("pipe")

    result = invoke_with_input(["exec", "-i", SID, "cat"], "data")

    assert result.exit_code == 0, result.output
    assert result.stderr == "err\n"


def test_exec_stdin_flag_rejects_input_that_is_not_utf8(api, sandbox_route):
    route = api.post(EXEC_URL).respond(200, json=envelope(exec_json(0)))

    result = invoke_with_input(["exec", "-i", SID, "cat"], b"\xff\xfe\x00")

    assert result.exit_code == 125
    assert result.stderr == "error: stdin is not valid UTF-8 text\n"
    assert not route.called


@pytest.mark.parametrize("kind", ["pipe", "file"])
def test_exec_without_the_flag_warns_and_does_not_read_a_pipe_or_file(
    api, sandbox_route, fake_stdin, monkeypatch, kind
):
    route = api.post(EXEC_URL).respond(200, json=envelope(exec_json(0)))
    fake_stdin(kind)
    forbid_stdin_read(monkeypatch)

    result = invoke_with_input(["exec", SID, "cat"], "print(1)\n")

    assert result.exit_code == 0, result.output
    assert result.stderr == f"{STDIN_WARNING}err\n"
    assert json.loads(route.calls.last.request.content).get("stdin") is None


@pytest.mark.parametrize("kind", ["tty", "devnull"])
def test_exec_without_the_flag_is_silent_for_a_tty_or_dev_null(
    api, sandbox_route, fake_stdin, monkeypatch, kind
):
    api.post(EXEC_URL).respond(200, json=envelope(exec_json(0)))
    fake_stdin(kind)
    forbid_stdin_read(monkeypatch)

    result = invoke(["exec", SID, "true"])

    assert result.exit_code == 0, result.output
    assert result.stderr == "err\n"


def test_exec_drops_a_leading_double_dash(api, sandbox_route):
    route = api.post(EXEC_URL).respond(200, json=envelope(exec_json(0)))

    result = invoke(["exec", SID, "--", "ls", "-la"])

    assert result.exit_code == 0, result.output
    assert json.loads(route.calls.last.request.content)["argv"] == ["ls", "-la"]


def test_exec_with_only_a_double_dash_is_a_usage_error(api, sandbox_route):
    route = api.post(EXEC_URL).respond(200, json=envelope(exec_json(0)))

    result = invoke(["exec", SID, "--"])

    assert result.exit_code == 2
    assert "no command given" in result.output
    assert not route.called


NOT_RUNNING_MESSAGES = [
    "sandbox is stopped; toolbox calls require a started sandbox",
    "instance sf-sbx_1 is not running",
]


@pytest.mark.parametrize("message", NOT_RUNNING_MESSAGES)
def test_exec_hints_how_to_start_a_sandbox_that_is_not_running(api, sandbox_route, message):
    listing(api, sandbox_json(name="marek-1"))
    api.post(EXEC_URL).respond(409, json=error_envelope("CONFLICT", message))

    result = invoke(["exec", "marek-1", "true"])

    assert result.exit_code == 125
    assert result.stderr.startswith(f"error: CONFLICT: {message}")
    assert result.stderr.endswith("\nstart it with: sandfort sandbox start marek-1\n")


def test_exec_not_running_hint_goes_into_the_json_error_object(api, sandbox_route):
    message = NOT_RUNNING_MESSAGES[0]
    api.post(EXEC_URL).respond(409, json=error_envelope("CONFLICT", message))

    result = invoke(["exec", SID, "true"], as_json=True)

    assert result.exit_code == 125
    error = json.loads(result.stdout)["error"]
    assert error["message"] == message
    assert error["hint"] == f"start it with: sandfort sandbox start {SID}"
    assert "start it with" not in result.stderr


def test_exec_adds_no_start_hint_to_an_unrelated_conflict(api, sandbox_route):
    api.post(EXEC_URL).respond(409, json=error_envelope("CONFLICT", "modified concurrently"))

    result = invoke(["exec", SID, "true"])

    assert result.exit_code == 125
    assert "start it with" not in result.stderr


# --- sandbox list: destroyed tombstones -----------------------------------------------------


def listed_ids(result, as_json):
    assert result.exit_code == 0, result.output
    if as_json:
        return [item["id"] for item in json.loads(result.stdout)]
    return [sid for sid in (SID, OTHER_SID) if sid in result.stdout]


@pytest.fixture
def live_and_destroyed(api):
    live = sandbox_json(name="live")
    gone = sandbox_json("destroyed", sandbox_id=OTHER_SID, name="gone")
    return api.get(SANDBOXES_URL).respond(200, json=envelope([live, gone]))


@pytest.mark.parametrize("as_json", [False, True])
def test_sandbox_list_leaves_hiding_destroyed_sandboxes_to_the_server(api, as_json):
    route = api.get(SANDBOXES_URL).respond(200, json=envelope([sandbox_json(name="live")]))

    result = invoke(["sandbox", "list"], as_json=as_json)

    assert listed_ids(result, as_json) == [SID]
    assert "include_destroyed" not in route.calls.last.request.url.params


@pytest.mark.parametrize("as_json", [False, True])
def test_sandbox_list_all_asks_the_server_for_destroyed_sandboxes(api, live_and_destroyed, as_json):
    result = invoke(["sandbox", "list", "--all"], as_json=as_json)

    assert listed_ids(result, as_json) == [SID, OTHER_SID]
    assert live_and_destroyed.calls.last.request.url.params["include_destroyed"] == "true"


@pytest.mark.parametrize("as_json", [False, True])
def test_sandbox_list_state_destroyed_shows_destroyed_sandboxes(api, as_json):
    gone = sandbox_json("destroyed", sandbox_id=OTHER_SID, name="gone")
    route = api.get(SANDBOXES_URL).respond(200, json=envelope([gone]))

    result = invoke(["sandbox", "list", "--state", "destroyed"], as_json=as_json)

    assert listed_ids(result, as_json) == [OTHER_SID]
    assert route.calls.last.request.url.params["state"] == "destroyed"
