"""CLI phase 3: snapshot and volume command groups and sandbox mounts (respx, no network)."""

import contextlib
import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
import typer  # noqa: E402
from sandfort_cli import config, shell_cmd  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.sandboxes import parse_mount  # noqa: E402
from sandfort_sdk import VolumeMount  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SNAP_ID = "snap_01HZZZZZZZZZZZZZZZZZZZZZZ"
OTHER_SNAP_ID = "snap_01HYYYYYYYYYYYYYYYYYYYYYYY"
VOL_ID = "vol_01HZZZZZZZZZZZZZZZZZZZZZZZ"
OTHER_VOL_ID = "vol_01HYYYYYYYYYYYYYYYYYYYYYYY"
CREATED = "2026-10-30T19:26:00Z"
SSE = "text/event-stream"
SSE_HEADERS = {"content-type": SSE}
SNAPSHOTS_URL = "/v1/snapshots"
SNAPSHOT_URL = f"{SNAPSHOTS_URL}/{SNAP_ID}"
BUILDS_URL = "/v1/images/builds"
BUILD_LOGS_URL = f"{BUILDS_URL}/{SNAP_ID}/logs"
VOLUMES_URL = "/v1/volumes"
VOLUME_URL = f"{VOLUMES_URL}/{VOL_ID}"
SANDBOXES_URL = "/v1/sandboxes"
LOG_LINES = ["Step 1/2 : FROM python:3.12-slim", "Successfully built"]
SPEC = {"schema_version": "1", "base_image": "python:3.12-slim", "pip_packages": ["requests"]}
GET_AND_RM = [("get", "GET", "ready"), ("rm", "DELETE", "deleting")]

RUNNER = CliRunner()


def envelope(data, next_cursor=None):
    meta = None if next_cursor is None else {"next_cursor": next_cursor}
    return {"success": True, "data": data, "error": None, "meta": meta}


def error_envelope(code, message, details=None):
    error = {"code": code, "message": message, "details": details or {}, "request_id": "req_1"}
    return {"success": False, "data": None, "error": error, "meta": None}


def snapshot_json(state="ready", *, snapshot_id=SNAP_ID, name="py", **extra):
    data = {
        "id": snapshot_id,
        "name": name,
        "state": state,
        "image_ref": "python:3.12-slim",
        "digest": "sha256:abc" if state == "ready" else None,
        "layer_count": 3,
        "source_sandbox_id": None,
        "created_at": CREATED,
    }
    return {**data, **extra}


def volume_json(state="ready", *, volume_id=VOL_ID, name="data", size_bytes=4096):
    return {
        "id": volume_id,
        "name": name,
        "state": state,
        "size_bytes": size_bytes,
        "created_at": CREATED,
    }


def sandbox_json():
    return {
        "id": SID,
        "name": "demo",
        "state": "creating",
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
    }


def build_sse(state="ready", *, reason=None, final=True):
    """Server-shaped build log: log lines, a keepalive, then (optionally) the state event."""
    frames = [
        f"event: log\nid: {index}\ndata: {json.dumps({'line': line})}\n\n"
        for index, line in enumerate(LOG_LINES)
    ]
    frames.insert(1, ": keepalive\n\n")
    if final:
        digest = "sha256:abc" if state == "ready" else None
        payload = {"state": state, "snapshot_id": SNAP_ID, "digest": digest, "reason": reason}
        frames.append(f"event: state\ndata: {json.dumps(payload)}\n\n")
    return "".join(frames).encode()


def invoke(args, *, as_json=False):
    return RUNNER.invoke(create_app(), (["--json"] if as_json else []) + args)


@pytest.fixture(autouse=True)
def profile_env(monkeypatch, tmp_path):
    """Keep every test away from the real home directory and any ambient credentials."""
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    return tmp_path / "cfg"


@pytest.fixture
def api():
    config.save_profile(BASE, KEY)
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        yield router
        for recorded in router.calls:
            assert recorded.request.headers["authorization"] == f"Bearer {KEY}"


@pytest.fixture
def spec_file(tmp_path):
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(SPEC))
    return path


# --- snapshot commands ---------------------------------------------------------------------


@pytest.mark.parametrize("as_json", [False, True])
def test_snapshot_register_posts_image_and_name(api, as_json):
    route = api.post(SNAPSHOTS_URL).respond(201, json=envelope(snapshot_json()))

    result = invoke(["snapshot", "register", "python:3.12-slim", "--name", "py"], as_json=as_json)

    assert result.exit_code == 0, result.output
    assert json.loads(route.calls.last.request.content) == {
        "image": "python:3.12-slim",
        "name": "py",
    }
    assert KEY not in result.output
    if as_json:
        payload = json.loads(result.stdout)
        assert (payload["id"], payload["created_at"]) == (SNAP_ID, "2026-10-30T19:26:00+00:00")
    else:
        assert "FIELD" in result.stdout and SNAP_ID in result.stdout


def test_snapshot_create_from_sandbox(api):
    pending = snapshot_json("pending", source_sandbox_id=SID)
    route = api.post(f"{SNAPSHOTS_URL}/from-sandbox").respond(202, json=envelope(pending))

    result = invoke(["snapshot", "create", SID, "mine"], as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(route.calls.last.request.content) == {"sandbox_id": SID, "name": "mine"}
    payload = json.loads(result.stdout)
    assert (payload["state"], payload["source_sandbox_id"]) == ("pending", SID)


def test_snapshot_create_accepts_a_sandbox_name(api):
    api.get(SANDBOXES_URL).respond(200, json=envelope([sandbox_json()]))
    pending = snapshot_json("pending", source_sandbox_id=SID)
    route = api.post(f"{SNAPSHOTS_URL}/from-sandbox").respond(202, json=envelope(pending))

    result = invoke(["snapshot", "create", "demo", "mine"], as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(route.calls.last.request.content) == {"sandbox_id": SID, "name": "mine"}


@pytest.mark.parametrize("as_json", [False, True])
def test_snapshot_list_follows_pages(api, as_json):
    route = api.get(SNAPSHOTS_URL)
    route.side_effect = [
        httpx.Response(200, json=envelope([snapshot_json()], next_cursor="c1")),
        httpx.Response(200, json=envelope([snapshot_json(snapshot_id=OTHER_SNAP_ID, name="b")])),
    ]

    result = invoke(["snapshot", "list"], as_json=as_json)

    assert result.exit_code == 0, result.output
    assert route.calls.last.request.url.params["cursor"] == "c1"
    if as_json:
        assert [item["id"] for item in json.loads(result.stdout)] == [SNAP_ID, OTHER_SNAP_ID]
    else:
        assert SNAP_ID in result.stdout and OTHER_SNAP_ID in result.stdout


@pytest.mark.parametrize("as_json", [False, True])
@pytest.mark.parametrize(("command", "method", "state"), GET_AND_RM)
def test_snapshot_get_and_rm(api, command, method, state, as_json):
    route = api.request(method, SNAPSHOT_URL).respond(200, json=envelope(snapshot_json(state)))

    result = invoke(["snapshot", command, SNAP_ID], as_json=as_json)

    assert result.exit_code == 0, result.output
    assert route.call_count == 1
    if as_json:
        assert json.loads(result.stdout)["state"] == state
    else:
        assert SNAP_ID in result.stdout and state in result.stdout


def test_snapshot_rm_in_use_reports_the_conflict(api):
    api.delete(SNAPSHOT_URL).respond(409, json=error_envelope("CONFLICT", "snapshot in use"))

    result = invoke(["snapshot", "rm", SNAP_ID])

    assert result.exit_code == 1
    assert "snapshot in use" in result.stderr
    assert result.stdout == ""


# --- snapshot build ------------------------------------------------------------------------


def mock_build(api, sse_body):
    pending = snapshot_json("pending", spec_hash="h1", reused=False)
    build = api.post(BUILDS_URL).respond(202, json=envelope(pending))
    logs = api.get(BUILD_LOGS_URL).respond(200, content=sse_body, headers=SSE_HEADERS)
    return build, logs


def test_snapshot_build_follows_the_log_to_ready(api, spec_file):
    build, logs = mock_build(api, build_sse())

    result = invoke(["snapshot", "build", str(spec_file), "--name", "py-app"])

    assert result.exit_code == 0, result.output
    assert json.loads(build.calls.last.request.content) == {"spec": SPEC, "name": "py-app"}
    assert logs.calls.last.request.headers["accept"] == SSE
    assert result.stdout.splitlines()[:2] == LOG_LINES
    assert f"build {SNAP_ID} ready" in result.stdout and "sha256:abc" in result.stdout


def test_snapshot_build_json_mode_prints_only_the_final_result(api, spec_file):
    mock_build(api, build_sse())

    result = invoke(["snapshot", "build", str(spec_file)], as_json=True)

    payload = json.loads(result.stdout)
    assert result.exit_code == 0, result.output
    assert (payload["id"], payload["state"]) == (SNAP_ID, "ready")
    assert (payload["digest"], payload["spec_hash"]) == ("sha256:abc", "h1")


def test_snapshot_build_failure_exits_1_with_the_reason(api, spec_file):
    mock_build(api, build_sse("error", reason="pip install failed"))

    result = invoke(["snapshot", "build", str(spec_file)])

    assert result.exit_code == 1
    assert LOG_LINES[0] in result.stdout
    assert "ended error: pip install failed" in result.stderr


def test_snapshot_build_log_cut_short_exits_1(api, spec_file):
    mock_build(api, build_sse(final=False))

    result = invoke(["snapshot", "build", str(spec_file)])

    assert result.exit_code == 1
    assert "before the final state" in result.stderr


def test_snapshot_build_reused_skips_following(api, spec_file):
    ready = snapshot_json(spec_hash="h1", reused=True)
    api.post(BUILDS_URL).respond(200, json=envelope(ready))
    logs = api.get(BUILD_LOGS_URL).respond(200, content=build_sse(), headers=SSE_HEADERS)

    result = invoke(["snapshot", "build", str(spec_file)])

    assert result.exit_code == 0, result.output
    assert not logs.called
    assert "(reused)" in result.stdout


@pytest.mark.parametrize(
    ("content", "message"),
    [(None, "cannot read spec file"), ("{nope", "not valid json"), ("[1]", "json object")],
)
def test_snapshot_build_rejects_a_bad_spec_file_before_posting(api, tmp_path, content, message):
    path = tmp_path / "spec.json"
    if content is not None:
        path.write_text(content)

    result = invoke(["snapshot", "build", str(path)])

    assert result.exit_code == 1
    assert message in result.stderr
    assert api.calls.call_count == 0


# --- volume commands -----------------------------------------------------------------------


@pytest.mark.parametrize("as_json", [False, True])
def test_volume_create_posts_the_name(api, as_json):
    route = api.post(VOLUMES_URL).respond(201, json=envelope(volume_json(size_bytes=None)))

    result = invoke(["volume", "create", "data"], as_json=as_json)

    assert result.exit_code == 0, result.output
    assert json.loads(route.calls.last.request.content) == {"name": "data"}
    if as_json:
        payload = json.loads(result.stdout)
        assert (payload["id"], payload["size_bytes"]) == (VOL_ID, None)
    else:
        assert VOL_ID in result.stdout and "ready" in result.stdout


@pytest.mark.parametrize("as_json", [False, True])
def test_volume_list_follows_pages(api, as_json):
    route = api.get(VOLUMES_URL)
    route.side_effect = [
        httpx.Response(200, json=envelope([volume_json()], next_cursor="c1")),
        httpx.Response(200, json=envelope([volume_json(volume_id=OTHER_VOL_ID, name="b")])),
    ]

    result = invoke(["volume", "list"], as_json=as_json)

    assert result.exit_code == 0, result.output
    assert route.call_count == 2
    if as_json:
        assert [item["id"] for item in json.loads(result.stdout)] == [VOL_ID, OTHER_VOL_ID]
    else:
        for expected in (VOL_ID, OTHER_VOL_ID, "4096"):
            assert expected in result.stdout


@pytest.mark.parametrize("as_json", [False, True])
@pytest.mark.parametrize(("command", "method", "state"), GET_AND_RM)
def test_volume_get_and_rm(api, command, method, state, as_json):
    route = api.request(method, VOLUME_URL).respond(200, json=envelope(volume_json(state)))

    result = invoke(["volume", command, VOL_ID], as_json=as_json)

    assert result.exit_code == 0, result.output
    assert route.call_count == 1
    if as_json:
        assert json.loads(result.stdout)["state"] == state
    elif command == "rm":  # r65: rm prints the id alone, like the other rm commands
        assert result.stdout == f"{VOL_ID}\n"
    else:
        assert VOL_ID in result.stdout and state in result.stdout


def test_volume_rm_while_mounted_exits_1(api):
    api.delete(VOLUME_URL).respond(409, json=error_envelope("CONFLICT", "volume is mounted"))

    result = invoke(["volume", "rm", VOL_ID])

    assert result.exit_code == 1
    assert "volume is mounted" in result.stderr


# --- sandbox create --mount ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (f"{VOL_ID}:/data", VolumeMount(VOL_ID, "/data")),
        (" vol_3 : /x ", VolumeMount("vol_3", "/x")),
    ],
)
def test_parse_mount_splits_at_the_first_colon(value, expected):
    assert parse_mount(value) == expected


MOUNT_SHAPE_TEXT = "expected VOLUME:PATH[:ro|rw]"


@pytest.mark.parametrize(
    ("value", "text"),
    [
        ("no-colon", MOUNT_SHAPE_TEXT),
        (":/data", MOUNT_SHAPE_TEXT),
        (f"{VOL_ID}:", MOUNT_SHAPE_TEXT),
        (" : ", MOUNT_SHAPE_TEXT),
        (f"{VOL_ID}:/data:RW", "mode must be ro or rw"),
        (f"{VOL_ID}:/data:", "mode must be ro or rw"),
        ("vol_2:/srv/a:b", "contains ':'"),
    ],
)
def test_parse_mount_rejects_malformed_values(value, text):
    with pytest.raises(typer.BadParameter, match=re.escape(text)):
        parse_mount(value)


def test_sandbox_create_sends_repeated_mounts(api):
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json()))

    result = invoke(
        ["sandbox", "create", "demo", "-m", f"{VOL_ID}:/data", "--mount", f"{OTHER_VOL_ID}:/c"]
    )

    assert result.exit_code == 0, result.output
    assert json.loads(route.calls.last.request.content)["volumes"] == [
        {"volume_id": VOL_ID, "mount_path": "/data"},
        {"volume_id": OTHER_VOL_ID, "mount_path": "/c"},
    ]


def test_sandbox_create_resolves_mounted_volume_names_to_ids(api):
    listing = api.get(VOLUMES_URL).respond(
        200,
        json=envelope(
            [
                volume_json(volume_id=VOL_ID, name="data"),
                volume_json(volume_id=OTHER_VOL_ID, name="cache"),
            ]
        ),
    )
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json()))

    result = invoke(["sandbox", "create", "demo", "-m", "data:/data", "--mount", "cache:/c"])

    assert result.exit_code == 0, result.output
    assert listing.calls.last.request.url.params["limit"] == "100"
    assert json.loads(route.calls.last.request.content)["volumes"] == [
        {"volume_id": VOL_ID, "mount_path": "/data"},
        {"volume_id": OTHER_VOL_ID, "mount_path": "/c"},
    ]


def test_sandbox_create_without_mounts_sends_no_volumes(api):
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json()))

    result = invoke(["sandbox", "create", "demo"])

    assert result.exit_code == 0, result.output
    assert "volumes" not in json.loads(route.calls.last.request.content)


def test_sandbox_create_sends_repeated_egress_hosts(api):
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json()))

    result = invoke(
        ["sandbox", "create", "demo", "--egress", "pypi.org", "--egress", "api.example.com"]
    )

    assert result.exit_code == 0, result.output
    assert json.loads(route.calls.last.request.content)["egress_allowlist"] == [
        "pypi.org",
        "api.example.com",
    ]


def test_sandbox_create_without_egress_sends_no_egress_allowlist(api):
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json()))

    result = invoke(["sandbox", "create", "demo"])

    assert result.exit_code == 0, result.output
    assert "egress_allowlist" not in json.loads(route.calls.last.request.content)


def test_sandbox_create_with_a_bad_mount_fails_before_any_request(api):
    result = invoke(["sandbox", "create", "demo", "--mount", "no-colon"])

    assert result.exit_code == 2
    assert MOUNT_SHAPE_TEXT in " ".join(re.sub(r"[│╭╮╰╯─]", " ", result.stderr).split())
    assert api.calls.call_count == 0


def test_sandbox_create_sends_lifecycle_env_labels_and_resources(api):
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json()))

    result = invoke(
        [
            "sandbox", "create", "demo",
            "--auto-delete", "30",
            "--env", "A=1", "-e", "B=x=y",
            "--label", "team=ci",
            "--memory-mib", "2048",
        ]
    )  # fmt: skip

    assert result.exit_code == 0, result.output
    body = json.loads(route.calls.last.request.content)
    assert body["auto_delete_minutes"] == 30
    assert body["env"] == {"A": "1", "B": "x=y"}
    assert body["labels"] == {"team": "ci"}
    assert body["resources"] == {"cpu_millicores": 1000, "memory_mib": 2048, "disk_gib": 3}
    assert "auto_stop_minutes" not in body


def test_sandbox_create_sends_auto_stop_and_all_resources(api):
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json()))

    result = invoke(
        [
            "sandbox", "create", "demo", "--auto-stop", "15", "--auto-delete", "-1",
            "--cpu-millicores", "500", "--memory-mib", "256", "--disk-gib", "1",
        ]
    )  # fmt: skip

    assert result.exit_code == 0, result.output
    body = json.loads(route.calls.last.request.content)
    assert (body["auto_stop_minutes"], body["auto_delete_minutes"]) == (15, -1)
    assert body["resources"] == {"cpu_millicores": 500, "memory_mib": 256, "disk_gib": 1}


def test_sandbox_create_without_the_new_knobs_sends_none_of_them(api):
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json()))

    result = invoke(["sandbox", "create", "demo"])

    assert result.exit_code == 0, result.output
    body = json.loads(route.calls.last.request.content)
    for field in ("auto_stop_minutes", "auto_delete_minutes", "env", "labels", "resources"):
        assert field not in body


@pytest.mark.parametrize(
    ("option", "value"),
    [("--env", "NOEQUALS"), ("--env", "=value"), ("--label", "NOEQUALS"), ("--label", "=v")],
)
def test_sandbox_create_rejects_a_malformed_pair_before_any_request(api, option, value):
    result = invoke(["sandbox", "create", "demo", option, value])

    assert result.exit_code != 0
    assert "KEY=VALUE" in result.stderr
    assert api.calls.call_count == 0


def test_snapshot_create_wait_polls_until_ready(api):
    pending = snapshot_json("pending", source_sandbox_id=SID)
    ready = snapshot_json("ready", source_sandbox_id=SID)
    api.post(f"{SNAPSHOTS_URL}/from-sandbox").respond(202, json=envelope(pending))
    poll = api.get(SNAPSHOT_URL).mock(
        side_effect=[
            httpx.Response(200, json=envelope(pending)),
            httpx.Response(200, json=envelope(ready)),
        ]
    )

    result = invoke(["snapshot", "create", SID, "mine", "--wait"], as_json=True)

    assert result.exit_code == 0, result.output
    assert poll.call_count == 2
    assert json.loads(result.stdout)["state"] == "ready"


def test_snapshot_create_without_wait_does_not_poll(api):
    pending = snapshot_json("pending", source_sandbox_id=SID)
    api.post(f"{SNAPSHOTS_URL}/from-sandbox").respond(202, json=envelope(pending))
    poll = api.get(SNAPSHOT_URL).respond(200, json=envelope(snapshot_json()))

    result = invoke(["snapshot", "create", SID, "mine"], as_json=True)

    assert result.exit_code == 0, result.output
    assert poll.call_count == 0
    assert json.loads(result.stdout)["state"] == "pending"


# --- sandbox list filters, block-network, error details -------------------------------------


def test_sandbox_list_forwards_state_and_label_filters(api):
    route = api.get(SANDBOXES_URL).respond(200, json=envelope([sandbox_json()]))

    result = invoke(
        ["sandbox", "list", "--state", "started", "--label", "team=ci", "-l", "env=dev"]
    )

    assert result.exit_code == 0, result.output
    params = route.calls.last.request.url.params
    assert params.get("state") == "started"
    assert sorted(params.get_list("label")) == ["env=dev", "team=ci"]


def test_sandbox_list_without_filters_sends_no_filter_params(api):
    route = api.get(SANDBOXES_URL).respond(200, json=envelope([sandbox_json()]))

    result = invoke(["sandbox", "list"])

    assert result.exit_code == 0, result.output
    params = route.calls.last.request.url.params
    assert "state" not in params and "label" not in params


def test_sandbox_list_rejects_a_malformed_label_before_any_request(api):
    result = invoke(["sandbox", "list", "--label", "NOEQUALS"])

    assert result.exit_code != 0
    assert "KEY=VALUE" in result.stderr
    assert api.calls.call_count == 0


def test_sandbox_create_block_network_sends_block_all(api):
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json()))

    result = invoke(["sandbox", "create", "demo", "--block-network"])

    assert result.exit_code == 0, result.output
    assert json.loads(route.calls.last.request.content)["network"] == {"block_all": True}


def test_sandbox_create_without_block_network_sends_no_network(api):
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json()))

    result = invoke(["sandbox", "create", "demo"])

    assert result.exit_code == 0, result.output
    assert "network" not in json.loads(route.calls.last.request.content)


def test_sandbox_create_no_block_network_sends_an_explicit_false(api):
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json()))

    result = invoke(["sandbox", "create", "demo", "--no-block-network"])

    assert result.exit_code == 0, result.output
    assert json.loads(route.calls.last.request.content)["network"] == {"block_all": False}


def test_error_details_are_rendered_on_one_stderr_line(api):
    maximum = {"cpu_millicores": 4000, "memory_mib": 8192, "disk_gib": 20}
    details = {"maximum": maximum, "requested": {**maximum, "memory_mib": 65536}}
    message = "requested resources exceed the per-sandbox maximum"
    api.post(SANDBOXES_URL).respond(422, json=error_envelope("UNPROCESSABLE", message, details))

    result = invoke(["sandbox", "create", "demo", "--memory-mib", "65536"])

    assert result.exit_code == 1
    lines = result.stderr.splitlines()
    assert len(lines) == 1
    assert lines[0].startswith(f"error: UNPROCESSABLE: {message} (")
    assert '"memory_mib":8192' in lines[0]


def test_error_without_details_renders_exactly_as_before(api):
    api.get(f"{SANDBOXES_URL}/{SID}").respond(
        404, json=error_envelope("NOT_FOUND", "no such sandbox")
    )

    result = invoke(["sandbox", "get", SID])

    assert result.exit_code == 1
    assert result.stderr == "error: NOT_FOUND: no such sandbox (request id req_1)\n"


# --- shell exit code -----------------------------------------------------------------------


class EndedShellSession:
    """A pty session whose remote shell already ended with ``exit_code`` (``None``: unreported)."""

    def __init__(self, exit_code):
        self.exit_code = exit_code
        self.closed = False

    def __iter__(self):
        return iter([b"logout\r\n"])

    def send_bytes(self, data):
        raise AssertionError("nothing is typed in this test")

    def resize(self, rows, cols):
        raise AssertionError("the terminal is never resized in this test")

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()


class QuietTerminal:
    """Terminal seam with no typed input; records the output and the restore calls."""

    def __init__(self):
        self.output = []
        self.restore_calls = 0

    def size(self):
        return 24, 80

    def require_interactive(self):
        pass

    def enter_raw(self):
        pass

    def restore(self):
        self.restore_calls += 1

    def watch_resize(self, on_resize):
        pass

    def read_input(self, timeout_s):
        return None  # nothing typed: the shell ends on its own

    def write_output(self, data):
        self.output.append(data)


def run_shell_command(monkeypatch, session):
    """Invoke ``sandfort shell`` against a stub client whose pty yields ``session``."""
    sandbox = SimpleNamespace(pty=SimpleNamespace(create=lambda rows, cols: session))
    client = SimpleNamespace(get=lambda sandbox_id: sandbox)

    @contextlib.contextmanager
    def open_stub_client():
        yield client

    monkeypatch.setattr(shell_cmd, "open_client", open_stub_client)
    terminal = QuietTerminal()
    result = RUNNER.invoke(create_app(terminal), ["shell", SID])
    return result, terminal


@pytest.mark.parametrize("exit_code", [1, 3, 127, 255])
def test_shell_exits_with_the_exit_code_of_the_remote_shell(monkeypatch, exit_code):
    session = EndedShellSession(exit_code)

    result, terminal = run_shell_command(monkeypatch, session)

    assert result.exit_code == exit_code, result.output
    assert terminal.output == [b"logout\r\n"]
    assert (terminal.restore_calls, session.closed) == (1, True)


@pytest.mark.parametrize("exit_code", [0, None])
def test_shell_exits_zero_when_the_remote_shell_succeeded_or_reported_nothing(
    monkeypatch, exit_code
):
    result, terminal = run_shell_command(monkeypatch, EndedShellSession(exit_code))

    assert result.exit_code == 0, result.output
    assert terminal.restore_calls == 1
